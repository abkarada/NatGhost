#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <sys/mman.h>
#include <netdb.h>
#include <stdatomic.h>

#define MAX_STUN      128
#define STUN_LEN      20
#define BATCH         64
#define MAGIC_COOKIE  0x2112A442
#define TIMEOUT_MS    300        /* toplam tarama süresi (ms)        */
#define SHM_NAME      "/natghost_shm"
#define SLOT_NUM      256        /* ring-buffer eleman sayısı         */
#define SLOT_SIZE     22         /* "255.255.255.255:65535\0"         */

typedef struct {
    struct sockaddr_in addr;
    char     ip[INET_ADDRSTRLEN];
    uint8_t  tid[12];
} ctx_t;

/* ---------- shared memory ring-buffer ---------- */
typedef struct {
    atomic_uint  widx;                         /* yazma indisi         */
    char         slot[SLOT_NUM][SLOT_SIZE];    /* döngüsel alan        */
} shm_ring_t;

static shm_ring_t *shm_init(void)
{
    int fd = shm_open(SHM_NAME, O_CREAT|O_RDWR, 0666);
    ftruncate(fd, sizeof(shm_ring_t));
    void *m = mmap(NULL, sizeof(shm_ring_t),
                   PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    close(fd);
    memset(m, 0, sizeof(shm_ring_t));
    return (shm_ring_t *)m;
}

static void shm_push_and_print(shm_ring_t *r, const char *txt)
{
    uint32_t i = atomic_fetch_add_explicit(&r->widx, 1,
                                           memory_order_relaxed) % SLOT_NUM;
    strncpy(r->slot[i], txt, SLOT_SIZE - 1);
    r->slot[i][SLOT_SIZE - 1] = '\0';

    /* ekrana bas + flush */
    printf("[STUN-MAP] %s\n", txt);
    fflush(stdout);
}
/* ------------------------------------------------ */

static ctx_t list[MAX_STUN];
static int   scnt   = 0;
static int   sockfd;

/* STUN sunucularını yükle */
static void load_targets(void)
{
    const char *srv[] = {
        "stun.l.google.com","stun1.l.google.com","stun2.l.google.com",
        "stun3.l.google.com","stun4.l.google.com","stun.ekiga.net",
        "stun.ideasip.com","stun.voipbuster.com","stun.voipstunt.com",
        "stun.voipzoom.com","stun.linphone.org","stun.antisip.com",
        "stun.gmx.net","stun.sipnet.net","stun.12voip.com","stun.3cx.com",
        "stun.iptel.org","stun.counterpath.com","stun.freeswitch.org",
        "stun.callwithus.com","stun.callcentric.com"
    };
    struct addrinfo hints = {0}, *res;
    hints.ai_family   = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;

    for (size_t i = 0; i < sizeof(srv) / sizeof(srv[0]); i++) {
        if (getaddrinfo(srv[i], "3478", &hints, &res) == 0) {
            memcpy(&list[scnt].addr, res->ai_addr, sizeof(struct sockaddr_in));
            inet_ntop(AF_INET,
                      &((struct sockaddr_in *)res->ai_addr)->sin_addr,
                      list[scnt].ip, INET_ADDRSTRLEN);
            freeaddrinfo(res);
            if (++scnt == MAX_STUN) break;
        }
    }
}

/* XOR-MAPPED-ADDRESS ayrıştırıcı */
static int parse_xor(uint8_t *buf, int len, char *out_ip, uint16_t *out_port)
{
    if (len < 20) return -1;
    uint8_t *p   = buf + 20;
    int      rem = len - 20;

    while (rem >= 4) {
        uint16_t type = (p[0] << 8) | p[1];
        uint16_t alen = (p[2] << 8) | p[3];

        if (type == 0x0020 && alen >= 8 && p[5] == 0x01) {          /* IPv4 */
            uint16_t xp = ((p[6] << 8) | p[7]) ^ (MAGIC_COOKIE >> 16);
            uint32_t ip;
            memcpy(&ip, p + 8, 4);
            ip ^= htonl(MAGIC_COOKIE);
            inet_ntop(AF_INET, &ip, out_ip, INET_ADDRSTRLEN);
            *out_port = xp;
            return 0;
        }

        int skip = 4 + alen;
        if (alen % 4) skip += 4 - (alen % 4);
        p   += skip;
        rem -= skip;
    }
    return -1;
}

/* Tüm STUN taleplerini gönder */
static void send_all(void)
{
    struct mmsghdr msg[MAX_STUN];
    struct iovec  iov[MAX_STUN];
    uint8_t       pkt[MAX_STUN][STUN_LEN];

    for (int i = 0; i < scnt; i++) {
        pkt[i][0] = 0x00; pkt[i][1] = 0x01;        /* Binding Request   */
        pkt[i][2] = pkt[i][3] = 0x00;              /* length = 0        */
        uint32_t cookie = htonl(MAGIC_COOKIE);
        memcpy(pkt[i] + 4, &cookie, 4);
        for (int j = 0; j < 12; j++)
            pkt[i][8 + j] = list[i].tid[j] = rand() & 0xFF;

        iov[i] = (struct iovec){ pkt[i], STUN_LEN };
        msg[i].msg_hdr = (struct msghdr){
            .msg_name    = &list[i].addr,
            .msg_namelen = sizeof(struct sockaddr_in),
            .msg_iov     = &iov[i],
            .msg_iovlen  = 1
        };
    }
    sendmmsg(sockfd, msg, scnt, 0);
}

/* Yanıtları dinle, paylaş ve yazdır */
static void recv_loop(shm_ring_t *ring)
{
    int ep = epoll_create1(0);
    struct epoll_event ev = { .events = EPOLLIN, .data.fd = sockfd };
    epoll_ctl(ep, EPOLL_CTL_ADD, sockfd, &ev);

    struct mmsghdr      msg[BATCH];
    struct iovec        iov[BATCH];
    uint8_t             buf[BATCH][512];
    struct sockaddr_in  from[BATCH];

    struct timespec start;
    clock_gettime(CLOCK_MONOTONIC, &start);

    while (1) {
        int wait = TIMEOUT_MS;
        struct timespec now;
        clock_gettime(CLOCK_MONOTONIC, &now);
        long elapsed = (now.tv_sec  - start.tv_sec) * 1000 +
                       (now.tv_nsec - start.tv_nsec) / 1000000;
        if (elapsed >= TIMEOUT_MS) break;
        wait -= elapsed;

        if (epoll_wait(ep, &ev, 1, wait) <= 0) continue;

        for (int i = 0; i < BATCH; i++) {
            iov[i] = (struct iovec){ buf[i], sizeof(buf[i]) };
            msg[i].msg_hdr = (struct msghdr){
                .msg_name    = &from[i],
                .msg_namelen = sizeof(from[i]),
                .msg_iov     = &iov[i],
                .msg_iovlen  = 1
            };
        }
        int n = recvmmsg(sockfd, msg, BATCH, 0, NULL);
        for (int m = 0; m < n; m++) {
            if (msg[m].msg_len < 20) continue;
            char     pub_ip [INET_ADDRSTRLEN];
            uint16_t pub_port;
            if (parse_xor(buf[m], msg[m].msg_len, pub_ip, &pub_port) == 0) {
                char slot[SLOT_SIZE];
                snprintf(slot, SLOT_SIZE, "%s:%u", pub_ip, pub_port);
                shm_push_and_print(ring, slot);     /* ▲ hem paylaşıp hem yaz */
            }
        }
    }
    close(ep);
}

int main(void)
{
    srand(time(NULL));
    setvbuf(stdout, NULL, _IONBF, 0);
    load_targets();

    sockfd = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0);
    struct sockaddr_in local = { .sin_family = AF_INET,
                                 .sin_addr.s_addr = INADDR_ANY,
                                 .sin_port   = 0 };
    bind(sockfd, (struct sockaddr *)&local, sizeof(local));

    shm_ring_t *ring = shm_init();      /* ring-buffer hazır */

    send_all();
    recv_loop(ring);

    munmap(ring, sizeof(shm_ring_t));
    printf("Tarama bitti; portlar paylaşımlı belleğe yazıldı.\n");
    return 0;
}
