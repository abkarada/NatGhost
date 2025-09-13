// burst_wawe.c - Symmetric NAT UDP Wave Burst

/*Motivasyon:Sysmmetric NAT arkasında olan cihazlar birbirlerine 
aynı anda tüm portları kaplayan bir UDP Wawe gönderirler
bu UDP Wawe ler çıkarken NAT Table da 1-5s lik registry oluşturur
bu süre içinde karşıdan gelen Wawe ile çarpışırsa veya 1-5sn içinde
Wawe NAT a ulaşırsa karşılıklı delik açılma olasılığı neredeyse %100
e çıkar çünkü Symmetric NAT ın kırılamamasının sebebi rastgele port atayarak
tahmin edilemezlik sağlamak ama bunun olasılık uzayı donanıma bağlı olarak
65.536 ile sınırlıdır bu sayı çok görünebilir ama bir bilgisayar için 
bu kadar porta aynı anda paket göndermek çokta zor değildir.
Şayet deliğin açılıp açılmadığını gönderilen 65.536 porttan dinlemek
tahmin edilebileceği üzere ciddi şekilde kaynak tüketir.Bu sebepten dolayı
portlar sadece gönderilmek için kullanılacak geri dönen cevaplar ise
promiscuous mode da dinlenecektir.*/

/*
  Bu sistem her biri 512 portluk wave gönderen 128 thread oluşturur.
  Her thread aynı anda çalışır. 
  Bu sayede symmetric NAT'ın tüm UDP port uzayı eş zamanlı doldurulur.
  Gerçek eş zamanlılık sağlanır. 
*/

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>

#define THREAD_COUNT 128
#define PORTS_PER_THREAD 512
#define PAYLOAD_SIZE 20

#define SHARE_NAME "/shrmem"

typedef struct {
	char targetIP[128];
	char myIP[128];

}burstInfo;


typedef struct {
    int base_port;
    char target_ip[128];
    int target_port_start;
    int target_port_end;
} thread_args_t;

void *burst_worker(void *arg) {
    thread_args_t *args = (thread_args_t*)arg;
    int base_port = args->base_port;
    
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("socket");
        pthread_exit(NULL);
    }

    struct mmsghdr msgs[PORTS_PER_THREAD];
    struct iovec iovecs[PORTS_PER_THREAD];
    struct sockaddr_in addrs[PORTS_PER_THREAD];
    uint8_t payload[PORTS_PER_THREAD][PAYLOAD_SIZE];

    for (int i = 0; i < PORTS_PER_THREAD; i++) {
        int target_port = args->target_port_start + (base_port + i) % (args->target_port_end - args->target_port_start + 1);
        
        snprintf((char *)payload[i], PAYLOAD_SIZE, "NATPUNCH%05d", base_port + i);
        iovecs[i].iov_base = payload[i];       
        iovecs[i].iov_len  = PAYLOAD_SIZE;

        memset(&addrs[i], 0, sizeof(struct sockaddr_in));
        addrs[i].sin_family = AF_INET;
        addrs[i].sin_port = htons(target_port);
        inet_pton(AF_INET, args->target_ip, &addrs[i].sin_addr);

        memset(&msgs[i], 0, sizeof(struct mmsghdr));
        msgs[i].msg_hdr.msg_name = &addrs[i];
        msgs[i].msg_hdr.msg_namelen = sizeof(struct sockaddr_in);
        msgs[i].msg_hdr.msg_iov = &iovecs[i];
        msgs[i].msg_hdr.msg_iovlen = 1;
    }

    int sent = sendmmsg(sock, msgs, PORTS_PER_THREAD, 0);
    printf("[Thread %d] Sent %d UDP packets (target ports %d-%d)\n", 
           base_port / PORTS_PER_THREAD, sent, args->target_port_start, args->target_port_end);

    close(sock);
    pthread_exit(NULL);
}

int main(int argc, char *argv[]) {
    if (argc != 4) {
        printf("Usage: %s <target_ip> <start_port> <end_port>\n", argv[0]);
        printf("Example: %s 192.168.1.100 32768 65535\n", argv[0]);
        return 1;
    }
    
    char target_ip[128];
    int start_port = atoi(argv[2]);
    int end_port = atoi(argv[3]);
    
    strncpy(target_ip, argv[1], sizeof(target_ip) - 1);
    target_ip[sizeof(target_ip) - 1] = '\0';
    
    printf("🚀 NAT Burst Wave Attack\n");
    printf("Target: %s\n", target_ip);
    printf("Port range: %d - %d (%d ports)\n", start_port, end_port, end_port - start_port + 1);
    printf("Threads: %d\n", THREAD_COUNT);
    printf("Ports per thread: %d\n", PORTS_PER_THREAD);
    printf("Total packets: %d\n", THREAD_COUNT * PORTS_PER_THREAD);
    printf("\n⚠️  WARNING: This will generate massive UDP traffic!\n\n");
    
    // Confirm before proceeding
    printf("Press ENTER to continue or Ctrl+C to abort...");
    getchar();
    
    pthread_t threads[THREAD_COUNT];
    thread_args_t thread_args[THREAD_COUNT];
    
    struct timespec start_time, end_time;
    clock_gettime(CLOCK_MONOTONIC, &start_time);
    
    for (int i = 0; i < THREAD_COUNT; i++) {
        thread_args[i].base_port = i * PORTS_PER_THREAD;
        strncpy(thread_args[i].target_ip, target_ip, sizeof(thread_args[i].target_ip) - 1);
        thread_args[i].target_port_start = start_port;
        thread_args[i].target_port_end = end_port;
        
        pthread_create(&threads[i], NULL, burst_worker, &thread_args[i]);
    }

    for (int i = 0; i < THREAD_COUNT; i++) {
        pthread_join(threads[i], NULL);
    }
    
    clock_gettime(CLOCK_MONOTONIC, &end_time);
    
    double duration = (end_time.tv_sec - start_time.tv_sec) + 
                     (end_time.tv_nsec - start_time.tv_nsec) / 1e9;
    
    int total_packets = THREAD_COUNT * PORTS_PER_THREAD;
    double packets_per_second = total_packets / duration;
    
    printf("\n✅ Burst wave complete!\n");
    printf("Duration: %.3f seconds\n", duration);
    printf("Rate: %.0f packets/second\n", packets_per_second);
    printf("Total packets sent: %d\n", total_packets);
    
    return 0;
}
