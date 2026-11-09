"""用 Scapy 合成一份测试抓包，用于冒烟验证检测规则。

这份样本全部是人工构造的报文，不含任何真实数据；
正式演示建议用自己在实验环境里抓的真实流量替换。
"""

import os
import sys

from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.l2 import ARP, Ether
from scapy.utils import wrpcap

BASE_TIME = 1762500000.0
GATEWAY_IP = "192.168.1.1"
GATEWAY_MAC = "aa:bb:cc:00:11:01"
HOST_IP = "192.168.1.10"
HOST_MAC = "aa:bb:cc:00:11:0a"
ATTACKER_MAC = "de:ad:be:ef:00:66"
CLIENT_PORT = 50123


def at(offset):
    return BASE_TIME + offset


def arp_packet(op, hwsrc, psrc, hwdst, pdst, dst_mac="ff:ff:ff:ff:ff:ff", offset=0):
    pkt = Ether(src=hwsrc, dst=dst_mac) / ARP(op=op, hwsrc=hwsrc, psrc=psrc, hwdst=hwdst, pdst=pdst)
    pkt.time = at(offset)
    return pkt


def tcp_packet(src, dst, sport, dport, flags, seq=1000, ack=0, payload=b"", offset=0, src_mac=HOST_MAC, dst_mac=GATEWAY_MAC):
    pkt = (Ether(src=src_mac, dst=dst_mac) /
           IP(src=src, dst=dst) /
           TCP(sport=sport, dport=dport, flags=flags, seq=seq, ack=ack) /
           payload)
    pkt.time = at(offset)
    return pkt


def udp_packet(src, dst, sport, dport, payload, offset=0):
    pkt = Ether(src=HOST_MAC, dst=GATEWAY_MAC) / IP(src=src, dst=dst) / UDP(sport=sport, dport=dport) / payload
    pkt.time = at(offset)
    return pkt


def dns_query(qname, txid, offset):
    dns = DNS(id=txid, qr=0, rd=1, qd=DNSQR(qname=qname))
    return udp_packet(HOST_IP, "8.8.8.8", 53100, 53, dns, offset)


def dns_answer(qname, txid, answers, offset):
    records = [DNSRR(rrname=qname, type="A", ttl=120, rdata=addr) for addr in answers]
    dns = DNS(id=txid, qr=1, aa=1, rd=1, ra=1, qd=DNSQR(qname=qname), an=records)
    return udp_packet("8.8.8.8", HOST_IP, 53, 53100, dns, offset)


def icmp_packet(src, dst, itype, offset, payload=b"abcdefghij"):
    pkt = Ether(src=HOST_MAC, dst=GATEWAY_MAC) / IP(src=src, dst=dst) / ICMP(type=itype) / payload
    pkt.time = at(offset)
    return pkt


def build_packets():
    packets = []

    packets.append(arp_packet(1, HOST_MAC, HOST_IP, "00:00:00:00:00:00", GATEWAY_IP, offset=0.0))
    for i in range(4):
        packets.append(arp_packet(2, GATEWAY_MAC, GATEWAY_IP, HOST_MAC, HOST_IP,
                                  dst_mac=HOST_MAC, offset=0.02 + i * 0.6))

    packets.append(tcp_packet(HOST_IP, "93.184.216.34", CLIENT_PORT, 80, "S", seq=1000, offset=1.0))
    packets.append(tcp_packet("93.184.216.34", HOST_IP, 80, CLIENT_PORT, "SA", seq=5000, ack=1001, offset=1.05,
                              src_mac=GATEWAY_MAC, dst_mac=HOST_MAC))
    packets.append(tcp_packet(HOST_IP, "93.184.216.34", CLIENT_PORT, 80, "A", seq=1001, ack=5001, offset=1.06))
    packets.append(tcp_packet(HOST_IP, "93.184.216.34", CLIENT_PORT, 80, "PA", seq=1001, ack=5001,
                              payload=b"GET /index.html HTTP/1.1\r\nHost: www.example.com\r\n\r\n", offset=1.08))
    packets.append(tcp_packet("93.184.216.34", HOST_IP, 80, CLIENT_PORT, "PA", seq=5001, ack=1100,
                              payload=b"HTTP/1.1 200 OK\r\nContent-Length: 612\r\n\r\n" + b"x" * 612,
                              offset=1.20, src_mac=GATEWAY_MAC, dst_mac=HOST_MAC))

    packets.append(tcp_packet(HOST_IP, "104.18.32.7", 50555, 443, "S", seq=7000, offset=2.0))
    packets.append(tcp_packet("104.18.32.7", HOST_IP, 443, 50555, "SA", seq=9000, ack=7001, offset=2.06,
                              src_mac=GATEWAY_MAC, dst_mac=HOST_MAC))
    packets.append(tcp_packet(HOST_IP, "104.18.32.7", 50555, 443, "A", seq=7001, ack=9001, offset=2.07))
    packets.append(tcp_packet(HOST_IP, "104.18.32.7", 50555, 443, "PA", seq=7001, ack=9001,
                              payload=b"\x16\x03\x01\x02\x00\x01\x00\x01\xfc\x03\x03", offset=2.10))

    packets.append(dns_query("www.example.com", 0x1234, 3.0))
    packets.append(dns_answer("www.example.com", 0x1234, ["93.184.216.34"], 3.03))
    packets.append(dns_query("cdn.demo-site.com", 0x2001, 3.5))
    packets.append(dns_answer("cdn.demo-site.com", 0x2001, ["104.18.32.7", "104.18.33.9"], 3.53))

    packets.append(icmp_packet(HOST_IP, "8.8.8.8", 8, 4.0))
    packets.append(icmp_packet("8.8.8.8", HOST_IP, 0, 4.02))

    packets.append(tcp_packet(HOST_IP, "192.168.1.1", 51000, 8080, "S", seq=3300, offset=5.0))
    packets.append(tcp_packet("192.168.1.1", HOST_IP, 8080, 51000, "RA", seq=0, ack=3301, offset=5.02,
                              src_mac=GATEWAY_MAC, dst_mac=HOST_MAC))

    for i in range(5):
        packets.append(arp_packet(2, ATTACKER_MAC, GATEWAY_IP, HOST_MAC, HOST_IP,
                                  dst_mac=HOST_MAC, offset=20.0 + i * 0.5))

    for i, ip in enumerate(("192.168.1.20", "192.168.1.30", "192.168.1.40", "192.168.1.50")):
        packets.append(arp_packet(2, ATTACKER_MAC, ip, HOST_MAC, HOST_IP,
                                  dst_mac=HOST_MAC, offset=21.0 + i * 0.5))

    packets.append(dns_query("www.bank-demo.com", 0x3001, 30.0))
    packets.append(dns_answer("www.bank-demo.com", 0x3001, ["203.0.113.20"], 30.03))
    packets.append(dns_query("www.bank-demo.com", 0x3002, 31.0))
    packets.append(dns_answer("www.bank-demo.com", 0x3002, ["45.77.20.99"], 31.03))

    packets.append(tcp_packet(HOST_IP, "198.51.100.7", 52000, 22, "S", seq=12000, offset=40.0))
    packets.append(tcp_packet(HOST_IP, "198.51.100.7", 52000, 22, "S", seq=12000, offset=43.0))

    return sorted(packets, key=lambda p: float(p.time))


def main():
    out_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "test_pcaps")
    os.makedirs(out_dir, exist_ok=True)
    out_path = os.path.join(out_dir, "sample_mixed.pcap")
    packets = build_packets()
    wrpcap(out_path, packets)
    print(f"已生成 {len(packets)} 个报文：{out_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
