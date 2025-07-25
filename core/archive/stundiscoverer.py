# StunDiscover.py
import socket 
from scapy.all import *
import struct 
from multiprocessing import Process, Queue
import multiprocessing
import dns.resolver
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
import time 
import random
import dns
from dns import reversename, resolver
import asyncio
import requests
from ipwhois import IPWhois
import ipaddress
from netaddr import IPNetwork

stun_servers = [
    ("stun.1und1.de", 3478),
    ("stun.gmx.net", 3478),
    ("stun.stunprotocol.org", 3478),
    ("stun.sipnet.net", 3478),
    ("stun.sipnet.ru", 3478),
    ("stun.12connect.com", 3478),
    ("stun.12voip.com", 3478),
    ("stun.3cx.com", 3478),
    ("stun.acrobits.cz", 3478),
    ("stun.actionvoip.com", 3478),
    ("stun.advfn.com", 3478),
    ("stun.altar.com.pl", 3478),
    ("stun.antisip.com", 3478),
    ("stun.avigora.fr", 3478),
    ("stun.bluesip.net", 3478),
    ("stun.cablenet-as.net", 3478),
    ("stun.callromania.ro", 3478),
    ("stun.callwithus.com", 3478),
    ("stun.cheapvoip.com", 3478),
    ("stun.cloopen.com", 3478),
    ("stun.commpeak.com", 3478),
    ("stun.cope.es", 3478),
    ("stun.counterpath.com", 3478),
    ("stun.counterpath.net", 3478),
    ("stun.dcalling.de", 3478),
    ("stun.demos.ru", 3478),
    ("stun.dus.net", 3478),
    ("stun.easycall.pl", 3478),
    ("stun.easyvoip.com", 3478),
    ("stun.ekiga.net", 3478),
    ("stun.epygi.com", 3478),
    ("stun.etoilediese.fr", 3478),
    ("stun.faktortel.com.au", 3478),
    ("stun.freecall.com", 3478),
    ("stun.freeswitch.org", 3478),
    ("stun.freevoipdeal.com", 3478),
    ("stun.gmx.de", 3478),
    ("stun.gradwell.com", 3478),
    ("stun.halonet.pl", 3478),
    ("stun.hellonanu.com", 3478),
    ("stun.hoiio.com", 3478),
    ("stun.hosteurope.de", 3478),
    ("stun.ideasip.com", 3478),
    ("stun.infra.net", 3478),
    ("stun.internetcalls.com", 3478),
    ("stun.intervoip.com", 3478),
    ("stun.ipcomms.net", 3478),
    ("stun.ipfire.org", 3478),
    ("stun.ippi.fr", 3478),
    ("stun.ipshka.com", 3478),
    ("stun.irian.at", 3478),
    ("stun.it1.hr", 3478),
    ("stun.ivao.aero", 3478),
    ("stun.jumblo.com", 3478),
    ("stun.justvoip.com", 3478),
    ("stun.linphone.org", 3478),
    ("stun.liveo.fr", 3478),
    ("stun.lowratevoip.com", 3478),
    ("stun.lundimatin.fr", 3478),
    ("stun.mit.de", 3478),
    ("stun.miwifi.com", 3478),
    ("stun.modulus.gr", 3478),
    ("stun.myvoiptraffic.com", 3478),
    ("stun.netappel.com", 3478),
    ("stun.netgsm.com.tr", 3478),
    ("stun.nfon.net", 3478),
    ("stun.nonoh.net", 3478),
    ("stun.nottingham.ac.uk", 3478),
    ("stun.ooma.com", 3478),
    ("stun.ozekiphone.com", 3478),
    ("stun.pjsip.org", 3478),
    ("stun.poivy.com", 3478),
    ("stun.powervoip.com", 3478),
    ("stun.ppdi.com", 3478),
    ("stun.qq.com", 3478),
    ("stun.rackco.com", 3478),
    ("stun.rockenstein.de", 3478),
    ("stun.rolmail.net", 3478),
    ("stun.roundsapp.com", 3478),
    ("stun.rynga.com", 3478),
    ("stun.schlund.de", 3478),
    ("stun.sipdiscount.com", 3478),
    ("stun.sipgate.net", 3478),
    ("stun.sipgate.net", 10000),
    ("stun.siplogin.de", 3478),
    ("stun.sipnet.net", 3478),
    ("stun.sipnet.ru", 3478),
    ("stun.sippeer.dk", 3478),
    ("stun.sipphone.com", 3478),
    ("stun.siptraffic.com", 3478),
    ("stun.smartvoip.com", 3478),
    ("stun.smsdiscount.com", 3478),
    ("stun.snafu.de", 3478),
    ("stun.softjoys.com", 3478),
    ("stun.solcon.nl", 3478),
    ("stun.sonetel.com", 3478),
    ("stun.sonetel.net", 3478),
    ("stun.sovtest.ru", 3478),
    ("stun.speedy.com.ar", 3478),
    ("stun.spokn.com", 3478),
    ("stun.srce.hr", 3478),
    ("stun.stunprotocol.org", 3478),
    ("stun.symform.com", 3478),
    ("stun.symplicity.com", 3478),
    ("stun.sysadminman.net", 3478),
    ("stun.t-online.de", 3478),
    ("stun.tiscali.com", 3478),
    ("stun.tng.de", 3478),
    ("stun.twt.it", 3478),
    ("stun.u-blox.com", 3478),
    ("stun.ucallweconn.net", 3478),
    ("stun.ucsb.edu", 3478),
    ("stun.ucw.cz", 3478),
    ("stun.ulsan.ac.kr", 3478),
    ("stun.unseen.is", 3478),
    ("stun.usfamily.net", 3478),
    ("stun.viva.gr", 3478),
    ("stun.vivox.com", 3478),
    ("stun.vo.lu", 3478),
    ("stun.vodafone.ro", 3478),
    ("stun.voicetrading.com", 3478),
    ("stun.voip.aebc.com", 3478),
    ("stun.voip.blackberry.com", 3478),
    ("stun.voip.eutelia.it", 3478),
    ("stun.voiparound.com", 3478),
    ("stun.voipbuster.com", 3478),
    ("stun.voipbusterpro.com", 3478),
    ("stun.voipcheap.co.uk", 3478),
    ("stun.voipcheap.com", 3478),
    ("stun.voipfibre.com", 3478),
    ("stun.voipgate.com", 3478),
    ("stun.voipinfocenter.com", 3478),
    ("stun.voipplanet.nl", 3478),
    ("stun.voippro.com", 3478),
    ("stun.voipraider.com", 3478),
    ("stun.voipstunt.com", 3478),
    ("stun.voipwise.com", 3478),
    ("stun.voipzoom.com", 3478),
    ("stun.vopium.com", 3478),
    ("stun.voys.nl", 3478),
    ("stun.voztele.com", 3478),
    ("stun.webcalldirect.com", 3478),
    ("stun.wifirst.net", 3478),
    ("stun.wirefree.in", 3478),
    ("stun.wirelessmoves.com", 3478),
    ("stun.xs4all.nl", 3478),
    ("stun.zadarma.com", 3478),
    ("stun.zadv.com", 3478),
    ("stun.zoiper.com", 3478)
]


dynamic_found = set()
dynamic_lock = threading.Lock()

results = []
bullet_funcs = []

def get_cidr_block(public_ip):
    obj = IPWhois(public_ip)
    result = obj.lookup_rdap()
    return result.get('network', {}).get('cidr')

def get_hosts_from_cidr(cidr):
    net = ipaddress.ip_network(cidr, strict=False)
    return [str(ip) for ip in net.hosts()]



def thread_worker(name, targets):
    for host, port in targets:  # unpack tuple
        with dynamic_lock:
            if host in dynamic_found:
                continue
        forgeStunPacket(host, port)

        
        
def process1_static_threader():
    n = len(stun_servers)
    threads = []
    
    ranges = [
        stun_servers[0:n//2],
        stun_servers[n//2:n],
        list(reversed(stun_servers)),
        stun_servers[n//4:3*n//4]
    ]

    for i, chunk in enumerate(ranges):
        t = threading.Thread(target=thread_worker, args=(f"P1-Thread-{i}", chunk))
        threads.append(t)
        t.start()
    for t in threads:
        t.join()




def process2_static_threader():
    domains = [
    "_stun._udp.google.com",
    "_stun._udp.1und1.de",
    "_stun._udp.linphone.org",
    "_stun._udp.counterpath.net",
    "_stun._udp.callwithus.com",
    "_stun._udp.sipgate.net",
    "_stun._udp.gmx.net",
    "_stun._udp.iptel.org",
    "_stun._udp.schlund.de",
    "_stun._udp.voipbuster.com",
    "_stun._udp.12connect.com",
    "_stun._udp.3cx.com",
    "_stun._udp.t-online.de",
    "_stun._udp.vline.com",
    "_stun._udp.miwifi.com",
    "_stun._udp.voiparound.com",
    "_stun._udp.ekiga.net",
    "_stun._udp.jumblo.com",

            ]   
    srv_domains = [f"_stun._udp.{d}" for d in domains]

    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = [executor.submit(resolve_all_types, d) for d in srv_domains + domains]

        for future in as_completed(futures):
            pass  # 




def resolve_record(domain, rtype):
    try:
        answers = dns.resolver.resolve(domain, rtype, lifetime=2)
        with dynamic_lock:
            for r in answers:
                if rtype == "SRV":
                    dynamic_found.add(str(r.target).rstrip('.'))
                else:
                    dynamic_found.add(str(r).rstrip('.'))
    except:
        pass

def resolve_all_types(domain):
    with ThreadPoolExecutor(max_workers=3) as executor:
        executor.submit(resolve_record, domain, "SRV")
        executor.submit(resolve_record, domain, "A")
        executor.submit(resolve_record, domain, "AAAA")

def estimate_cidr_block(ip, bits=24):
    from netaddr import IPNetwork
    try:
        return str(IPNetwork(f"{ip}/{bits}"))
    except:
        return None

def reverse_bruteforce():
    found_domains = set()

    for ip in dynamic_found:
        try:
            ip = str(ip)
            if not ipaddress.ip_address(ip).is_global:
                continue
        except ValueError:
            continue

        # Tahmini CIDR bloğunu al (örneğin /24)
        cidr = estimate_cidr_block(ip, bits=24)
        if not cidr:
            continue

        # Reverse brute-force yap
        for host in IPNetwork(cidr):
            try:
                rev_name = reversename.from_address(str(host))
                answer = resolver.resolve(rev_name, "PTR", lifetime=2)
                for r in answer:
                    r_str = str(r).rstrip('.')
                    if "stun" in r_str.lower():
                        found_domains.add(r_str)
                        print(f"[PTR ✓] {host} → {r_str}")
            except:
                continue

    return list(found_domains)


class ParallelVectorEngine:
    def __init__(self, func, data, max_workers=None):

        self.func = func
        self.data = data
        self.max_workers = max_workers or len(data)
        self.queue = Queue()

    def _worker(self, idx, item):
        
        result = self.func(idx, item)
        self.queue.put((idx, result))

    def run(self):
        processes = []

        for idx, item in enumerate(self.data):
            p = Process(target=self._worker, args=(idx, item))
            processes.append(p)
            if len(processes) == self.max_workers:
                self._launch_and_clear(processes)

        
        if processes:
            self._launch_and_clear(processes)


        results = [None] * len(self.data)
        while not self.queue.empty():
            idx, val = self.queue.get()
            results[idx] = val

        return results

    def _launch_and_clear(self, processes):
        for p in processes:
            p.start()
        for p in processes:
            p.join()
        processes.clear()


"""
MUST be UDP Packet For Binding Request
MUST start with a 20-byte header followed by zero or more Attributes
MUST contains:
>STUN Message Type 
>Magic Cookie
>Transaction ID
>Message Length
*The most significant bit 2 bits of every STUN Message MUST be zeroes.


"""  
def random_ID():
    return bytes([random.randint(0, 255) for _ in range(12)])
def forgeStunPacket(ip, port=3478):
    try:
        m_type = 0x0001 
        m_length = 0 
        magic_cookie = 0x2112A442 
        transaction_ID = random_ID() 

        stunHeader = struct.pack("!HHI12s", m_type, m_length, magic_cookie, transaction_ID)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(3)

        try:
            start_time = time.time()
            sock.sendto(stunHeader, (ip, port))
            data, _ = sock.recvfrom(1024)
            end_time = time.time()
        except socket.timeout:
            print(f"[×] Timeout: {ip}")
            return
        except Exception as e:
            print(f"[×] General Error: {ip} → {e}")
            return
        finally:
            sock.close()

        if data[0:2] == b'\x01\x01' and data[4:8] == b'\x21\x12\xa4\x42':
            rtt = round((end_time - start_time) * 1000, 2)
            results.append({
                'ip': ip,
                'port': port,
                'rtt': rtt,
                'timestamp': end_time
            })
            print(f"[✓] Reply from {ip}:{port} → RTT = {rtt} ms")
        else:
            print(f"[!] Invalid STUN reply from {ip}:{port}")

    except Exception as e:
        print(f"[×] Error: {ip}:{port} → {e}")


 
def reload_and_fire():
    engine = ParallelVectorEngine(lambda i, pair: forgeStunPacket(pair[0], pair[1]), stun_servers, max_workers=60)
    engine.run()
    print("[*] Reloading and firing STUN packets...")


def run_p1():
    process1_static_threader()  

def run_p2():
    process2_static_threader()

def run_reverse_brute():
    reverse_bruteforce()
    found = reverse_bruteforce()
    print(f"[*] Reverse DNS brute-force found {len(found)} stun-related domains.")
def deduplicate_dynamic_results():

    global results
    with dynamic_lock:
        dynamic_hosts = set(dynamic_found)
    before = len(results)
    results = [r for r in results if r['ip'] not in dynamic_hosts]
    after = len(results)
    print(f"[!] {before - after} entry removed due to overlap with dynamic results")

def main():
    p1 = multiprocessing.Process(target=run_p1)
    p2 = multiprocessing.Process(target=run_p2)
    p3 = multiprocessing.Process(target=run_reverse_brute)

    print("[*] Starting P1 (ParallelVectorEngine fire)...")
    p1.start()
    print("[*] Starting P2 (DNS-based)...")
    p2.start()
    print("[*] Starting P3 (Reverse brute)...")
    p3.start()

    p1.join()
    p2.join()
    p3.join()

    print("\n[*] Deduplicating overlapping entries...")
    deduplicate_dynamic_results()

    print("\n[*] Final RTT Analysis (Best 5 STUN Servers):")
    sorted_results = sorted(results, key=lambda x: x['rtt'])
    for r in sorted_results[:5]:
        print(f"→ {r['ip']}:{r['port']} | RTT: {r['rtt']} ms")


if __name__ == "__main__":
    main()