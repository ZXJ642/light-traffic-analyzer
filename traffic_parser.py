"""离线 pcap / pcapng 流量解析与统计。

只负责读包、分类、计数，不做任何主动探测行为。
"""

import os
from collections import Counter, defaultdict
from datetime import datetime

from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.l2 import ARP
from scapy.utils import PcapNgReader, PcapReader

PROTOCOLS = ("TCP", "UDP", "ICMP", "ARP", "DNS", "Other")
MAX_TRACKED_FLOWS = 20000
MAX_TRACKED_DOMAINS = 5000

TCP_FIN = 0x01
TCP_SYN = 0x02
TCP_RST = 0x04
TCP_PSH = 0x08
TCP_ACK = 0x10


def _text(value):
    if isinstance(value, bytes):
        return value.decode("utf-8", "ignore")
    return str(value)


def _domain(value):
    return _text(value).rstrip(".").lower()


def _answer_records(dns):
    """Scapy 2.8 起 an 字段可能返回列表，旧版本是 DNSRR 链式结构，这里统一处理。"""
    answers = dns.an
    if isinstance(answers, list):
        return [rr for rr in answers if isinstance(rr, DNSRR)]
    records = []
    rr = answers
    while isinstance(rr, DNSRR):
        records.append(rr)
        rr = getattr(rr, "payload", None)
    return records


def _question_records(dns):
    questions = dns.qd
    if isinstance(questions, list):
        return [q for q in questions if isinstance(q, DNSQR)]
    return [questions] if isinstance(questions, DNSQR) else []


def open_reader(path):
    """按扩展名选择读取器，读不动时换另一种格式再试一次。"""
    if not os.path.exists(path):
        raise FileNotFoundError(f"文件不存在：{path}")
    if os.path.isdir(path):
        raise IsADirectoryError(f"这是一个目录：{path}")

    prefer_ng = path.lower().endswith(".pcapng")
    first = PcapNgReader if prefer_ng else PcapReader
    second = PcapReader if prefer_ng else PcapNgReader
    try:
        return first(path)
    except Exception:
        return second(path)


class TrafficAnalyzer:
    """一次解析，聚合出报告需要的所有统计量。"""

    def __init__(self, path, ip_filter=None, proto_filter=None, max_packets=0):
        self.path = path
        self.ip_filter = (ip_filter or "").strip() or None
        self.proto_filter = (proto_filter or "").strip().upper() or None
        self.max_packets = int(max_packets or 0)
        self.file_size = os.path.getsize(path) if os.path.isfile(path) else 0

        self.total_packets = 0
        self.total_bytes = 0
        self.filtered_packets = 0
        self.bad_packets = 0
        self.truncated = False
        self.dropped_flows = 0
        self.dns_truncated = False
        self.first_time = None
        self.last_time = None

        self.protocol_counts = Counter()
        self.protocol_bytes = Counter()
        self.transport_counts = Counter()
        self.src_ip_counts = Counter()
        self.dst_ip_counts = Counter()
        self.src_bytes = Counter()
        self.dst_bytes = Counter()
        self.dst_port_counts = Counter()
        self.tcp_flag_counts = Counter()

        self.flows = {}
        self.tcp_flows = {}
        self.tcp_handshakes_completed = 0
        self.tcp_rst_count = 0

        self.arp_ops = Counter()
        self.arp_bindings = defaultdict(lambda: defaultdict(int))
        self.arp_mac_ips = defaultdict(set)

        self.dns_answers = defaultdict(set)
        self.dns_answer_counts = Counter()
        self.dns_query_counts = Counter()
        self.dns_response_count = 0
        self.dns_query_count = 0

    def parse(self):
        reader = None
        try:
            reader = open_reader(self.path)
            for pkt in reader:
                if self.max_packets and self.total_packets >= self.max_packets:
                    self.truncated = True
                    break
                try:
                    self._handle(pkt)
                except Exception:
                    self.bad_packets += 1
        finally:
            if reader is not None:
                try:
                    reader.close()
                except Exception:
                    pass
        return self

    def _classify(self, pkt):
        if ARP in pkt:
            return "ARP"
        if DNS in pkt:
            return "DNS"
        if TCP in pkt:
            return "TCP"
        if UDP in pkt:
            return "UDP"
        if ICMP in pkt:
            return "ICMP"
        return "Other"

    def _ip_match(self, pkt):
        if self.ip_filter is None:
            return True
        if IP not in pkt:
            return False
        return pkt[IP].src == self.ip_filter or pkt[IP].dst == self.ip_filter

    def _handle(self, pkt):
        ts = float(pkt.time)
        category = self._classify(pkt)
        if not self._ip_match(pkt):
            self.filtered_packets += 1
            return
        if self.proto_filter and category != self.proto_filter:
            self.filtered_packets += 1
            return

        size = len(pkt)
        self.total_packets += 1
        self.total_bytes += size
        self.protocol_counts[category] += 1
        self.protocol_bytes[category] += size
        if self.first_time is None or ts < self.first_time:
            self.first_time = ts
        if self.last_time is None or ts > self.last_time:
            self.last_time = ts

        if ARP in pkt:
            self._handle_arp(pkt)
        if IP in pkt:
            self._handle_ip(pkt, size)
        if DNS in pkt:
            self._handle_dns(pkt)

    def _handle_arp(self, pkt):
        arp = pkt[ARP]
        self.arp_ops[int(arp.op)] += 1
        psrc, hwsrc = str(arp.psrc), str(arp.hwsrc).lower()
        if psrc and hwsrc:
            self.arp_bindings[psrc][hwsrc] += 1
            self.arp_mac_ips[hwsrc].add(psrc)

    def _handle_ip(self, pkt, size):
        ip = pkt[IP]
        src, dst = str(ip.src), str(ip.dst)
        self.src_ip_counts[src] += 1
        self.dst_ip_counts[dst] += 1
        self.src_bytes[src] += size
        self.dst_bytes[dst] += size

        if TCP in pkt:
            self._handle_tcp(pkt, src, dst, size)
        elif UDP in pkt:
            udp = pkt[UDP]
            self.transport_counts["UDP"] += 1
            self.dst_port_counts[("UDP", int(udp.dport))] += 1
            self._track_flow("UDP", src, int(udp.sport), dst, int(udp.dport), size, float(pkt.time))
        elif ICMP in pkt:
            self.transport_counts["ICMP"] += 1

    def _handle_tcp(self, pkt, src, dst, size):
        tcp = pkt[TCP]
        sport, dport = int(tcp.sport), int(tcp.dport)
        flags = int(tcp.flags)
        ts = float(pkt.time)
        self.transport_counts["TCP"] += 1
        self.dst_port_counts[("TCP", dport)] += 1

        syn = bool(flags & TCP_SYN)
        ack = bool(flags & TCP_ACK)
        if syn:
            self.tcp_flag_counts["SYN"] += 1
        if ack:
            self.tcp_flag_counts["ACK"] += 1
        if flags & TCP_RST:
            self.tcp_flag_counts["RST"] += 1
            self.tcp_rst_count += 1
        if flags & TCP_FIN:
            self.tcp_flag_counts["FIN"] += 1
        if flags & TCP_PSH:
            self.tcp_flag_counts["PSH"] += 1

        self._track_flow("TCP", src, sport, dst, dport, size, ts)

        key = (src, sport, dst, dport)
        rev = (dst, dport, src, sport)

        if syn and ack:
            flow = self._new_tcp_flow(rev, size, ts)
            if flow is not None:
                flow["synack"] += 1
                flow["packets"] += 1
                flow["bytes"] += size
                flow["last"] = ts
            return

        if syn:
            flow = self._new_tcp_flow(key, size, ts)
            if flow is not None:
                flow["syn"] += 1
                flow["packets"] += 1
                flow["bytes"] += size
                flow["last"] = ts
            return

        for k in (key, rev):
            flow = self.tcp_flows.get(k)
            if flow is None:
                continue
            flow["packets"] += 1
            flow["bytes"] += size
            flow["last"] = ts
            if flags & TCP_RST:
                flow["rst"] += 1
            elif flags & TCP_FIN:
                flow["fin"] += 1
            elif ack and flow["syn"] and flow["synack"] and not flow["completed"]:
                flow["completed"] = True
                self.tcp_handshakes_completed += 1
                break

    def _new_tcp_flow(self, key, size, ts):
        flow = self.tcp_flows.get(key)
        if flow is not None:
            return flow
        if len(self.tcp_flows) >= MAX_TRACKED_FLOWS:
            self.dropped_flows += 1
            return None
        flow = {
            "syn": 0, "synack": 0, "rst": 0, "fin": 0,
            "packets": 0, "bytes": 0, "first": ts, "last": ts, "completed": False,
        }
        self.tcp_flows[key] = flow
        return flow

    def _track_flow(self, proto, src, sport, dst, dport, size, ts):
        key = (proto, src, sport, dst, dport)
        flow = self.flows.get(key)
        if flow is None:
            if len(self.flows) >= MAX_TRACKED_FLOWS * 2:
                self.dropped_flows += 1
                return
            self.flows[key] = {"packets": 1, "bytes": size, "first": ts, "last": ts}
            return
        flow["packets"] += 1
        flow["bytes"] += size
        flow["last"] = ts

    def _handle_dns(self, pkt):
        dns = pkt[DNS]
        if dns.qr == 1:
            self.dns_response_count += 1
            for rr in _answer_records(dns):
                if int(rr.type) in (1, 28):
                    name = _domain(rr.rrname)
                    addr = _text(rr.rdata)
                    if name and addr:
                        self._add_answer(name, addr)
        else:
            self.dns_query_count += 1
            for query in _question_records(dns):
                name = _domain(query.qname)
                if name:
                    self.dns_query_counts[name] += 1

    def _add_answer(self, name, addr):
        if name not in self.dns_answers and len(self.dns_answers) >= MAX_TRACKED_DOMAINS:
            self.dns_truncated = True
            return
        self.dns_answers[name].add(addr)
        self.dns_answer_counts[name] += 1

    @property
    def duration(self):
        if self.first_time is None or self.last_time is None:
            return 0.0
        return max(self.last_time - self.first_time, 0.0)

    @property
    def start_time_text(self):
        if self.first_time is None:
            return "-"
        return datetime.fromtimestamp(self.first_time).strftime("%Y-%m-%d %H:%M:%S")

    @property
    def end_time_text(self):
        if self.last_time is None:
            return "-"
        return datetime.fromtimestamp(self.last_time).strftime("%Y-%m-%d %H:%M:%S")

    @property
    def packets_per_second(self):
        return self.total_packets / self.duration if self.duration > 0 else 0.0

    @property
    def bits_per_second(self):
        return (self.total_bytes * 8) / self.duration if self.duration > 0 else 0.0

    def top_flows(self, limit=10):
        items = sorted(self.flows.items(), key=lambda kv: (-kv[1]["bytes"], -kv[1]["packets"]))
        return items[:limit]

    def tcp_stats(self):
        syn_flows = sum(1 for f in self.tcp_flows.values() if f["syn"])
        unanswered = sum(
            1 for f in self.tcp_flows.values()
            if f["syn"] and not f["synack"] and not f["rst"]
        )
        reset_by_server = sum(1 for f in self.tcp_flows.values() if f["rst"])
        return {
            "flows": len(self.tcp_flows),
            "syn_flows": syn_flows,
            "completed": self.tcp_handshakes_completed,
            "unanswered": unanswered,
            "reset_flows": reset_by_server,
            "rst_packets": self.tcp_rst_count,
        }

    def dns_stats(self):
        answered = len(self.dns_answers)
        multi = sum(1 for ips in self.dns_answers.values() if len(ips) > 1)
        return {
            "queries": self.dns_query_count,
            "responses": self.dns_response_count,
            "domains": answered,
            "multi_ip_domains": multi,
            "unique_query_names": len(self.dns_query_counts),
        }
