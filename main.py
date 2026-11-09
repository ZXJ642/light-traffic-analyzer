"""命令行入口：读取 pcap -> 统计 -> 异常检测 -> 输出控制台摘要与 Markdown 报告。"""

import argparse
import os
import sys
import tempfile

from anomaly_detect import run_all, summarize
from report_generator import (
    build_markdown, human_bytes, human_rate,
    plot_protocol_pie, plot_top_ips, setup_font,
)
from traffic_parser import PROTOCOLS, TrafficAnalyzer

VERSION = "1.0.0"


def setup_stdio():
    """打包成 exe 后 Windows 控制台默认按 GBK 解码，这里统一改成 UTF-8，避免中文乱码。"""
    if sys.platform == "win32":
        try:
            import ctypes
            ctypes.windll.kernel32.SetConsoleOutputCP(65001)
        except Exception:
            pass
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass


def build_parser():
    parser = argparse.ArgumentParser(
        prog="light-traffic-analyzer",
        description="轻量级离线 pcap/pcapng 流量分析工具：协议分布、TOP 统计、ARP/DNS 异常检测。",
        epilog="仅用于分析自己有权抓取的流量，禁止对公网或他人网络使用。",
    )
    parser.add_argument("pcap", nargs="?", help="本地 .pcap / .pcapng 文件路径")
    parser.add_argument("-o", "--output", default="report.md", help="Markdown 报告输出路径（默认 report.md）")
    parser.add_argument("--top", type=int, default=10, help="TOP 列表长度（默认 10）")
    parser.add_argument("--ip", dest="ip_filter", help="只统计与该 IP 相关的报文")
    parser.add_argument("--proto", dest="proto_filter", choices=[p.lower() for p in PROTOCOLS],
                        help="只统计某类协议：tcp/udp/icmp/arp/dns/other")
    parser.add_argument("--max-packets", type=int, default=0, help="最多解析前 N 个报文（默认全量）")
    parser.add_argument("--no-chart", action="store_true", help="不生成图表")
    parser.add_argument("--live", action="store_true", help="实时抓包后分析（需自行确认抓包权限）")
    parser.add_argument("--iface", help="实时抓包网卡名，如 eth0 / WLAN")
    parser.add_argument("--duration", type=int, default=30, help="实时抓包时长秒数（默认 30）")
    parser.add_argument("--confirm-authorized", action="store_true",
                        help="确认抓包目标为自有网络，配合 --live 使用")
    parser.add_argument("-v", "--version", action="version", version=f"%(prog)s {VERSION}")
    return parser


def capture_live(iface, duration, max_packets):
    """实时抓包先落盘成临时 pcap，再走同一套离线分析流程。"""
    from scapy.all import sniff, wrpcap

    packets = sniff(iface=iface, timeout=duration,
                    count=max_packets or 0, store=True)
    if not packets:
        raise RuntimeError("未抓到任何报文，请检查网卡名与权限（Windows 需安装 Npcap）")
    fd, path = tempfile.mkstemp(prefix="lta_live_", suffix=".pcap")
    os.close(fd)
    wrpcap(path, packets)
    return path


def print_console(analyzer, findings, severity_stats, report_path):
    total = analyzer.total_packets or 1
    line = "-" * 62
    print()
    print("流量分析结果")
    print(line)
    print(f"文件        : {analyzer.path}")
    print(f"报文数      : {analyzer.total_packets}    字节数 : {human_bytes(analyzer.total_bytes)}")
    print(f"抓包时长    : {analyzer.duration:.2f} s    平均速率 : {human_rate(analyzer.bits_per_second)}")
    print(f"起止时间    : {analyzer.start_time_text} -> {analyzer.end_time_text}")
    print(line)
    print("协议分布")
    for proto in ("TCP", "UDP", "ICMP", "ARP", "DNS", "Other"):
        count = analyzer.protocol_counts.get(proto, 0)
        if count == 0:
            continue
        bar_len = int(count / total * 30)
        percent = count / total * 100
        print(f"  {proto:<5} {count:>6}  {percent:>5.1f}%  {'#' * bar_len}")
    print(line)
    print("源 IP TOP5")
    for ip, count in analyzer.src_ip_counts.most_common(5):
        print(f"  {ip:<18} {count:>6} 包  {human_bytes(analyzer.src_bytes[ip])}")
    print("目的 IP TOP5")
    for ip, count in analyzer.dst_ip_counts.most_common(5):
        print(f"  {ip:<18} {count:>6} 包  {human_bytes(analyzer.dst_bytes[ip])}")
    print(line)
    tcp = analyzer.tcp_stats()
    print(f"TCP 流 {tcp['flows']} 条，完成握手 {tcp['completed']} 条，"
          f"SYN 无应答 {tcp['unanswered']} 条，RST 报文 {tcp['rst_packets']} 个")
    dns = analyzer.dns_stats()
    print(f"DNS 查询 {dns['queries']} 个，应答 {dns['responses']} 个，"
          f"解析过 {dns['domains']} 个域名，多 IP 域名 {dns['multi_ip_domains']} 个")
    print(line)
    if findings:
        print(f"异常检测：命中 {len(findings)} 条"
              f"（高 {severity_stats.get('高', 0)} / 中 {severity_stats.get('中', 0)}"
              f" / 低 {severity_stats.get('低', 0)}）")
        for idx, item in enumerate(findings, 1):
            print(f"  {idx}. [{item['severity']}] {item['title']}")
    else:
        print("异常检测：未命中 ARP / DNS 规则，无明显可疑流量")
    print(line)
    print(f"报告已写入：{report_path}")
    if analyzer.bad_packets:
        print(f"提示：{analyzer.bad_packets} 个报文解析失败，已跳过")
    print()


def main(argv=None):
    setup_stdio()
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.live:
        if not args.confirm_authorized:
            parser.error("实时抓包需要加 --confirm-authorized，并确认目标是你自己的网络")
        try:
            pcap_path = capture_live(args.iface, args.duration, args.max_packets)
        except Exception as exc:
            print(f"实时抓包失败：{exc}", file=sys.stderr)
            return 2
    else:
        if not args.pcap:
            parser.error("请指定要分析的 pcap/pcapng 文件，或使用 --live 实时抓包")
        pcap_path = args.pcap

    if not os.path.isfile(pcap_path):
        print(f"文件不存在：{pcap_path}", file=sys.stderr)
        return 2

    try:
        analyzer = TrafficAnalyzer(
            pcap_path,
            ip_filter=args.ip_filter,
            proto_filter=args.proto_filter,
            max_packets=args.max_packets,
        ).parse()
    except Exception as exc:
        print(f"读取抓包文件失败：{exc}", file=sys.stderr)
        return 2

    if analyzer.total_packets == 0:
        print("没有可统计的报文（文件为空，或过滤条件过滤掉了全部报文）", file=sys.stderr)
        return 3

    findings = run_all(analyzer)
    severity_stats = summarize(findings)

    chart_paths = {}
    if not args.no_chart:
        report_dir = os.path.dirname(os.path.abspath(args.output))
        chart_dir = os.path.join(report_dir, "charts")
        os.makedirs(chart_dir, exist_ok=True)
        chinese_ok = setup_font()
        try:
            pie = plot_protocol_pie(analyzer.protocol_counts,
                                    os.path.join(chart_dir, "protocol_pie.png"), chinese_ok)
            if pie:
                chart_paths["pie"] = pie
            top_ip = plot_top_ips(analyzer.src_ip_counts, analyzer.dst_ip_counts,
                                  os.path.join(chart_dir, "top_ips.png"), args.top, chinese_ok)
            if top_ip:
                chart_paths["top_ip"] = top_ip
        except Exception as exc:
            print(f"图表生成失败（报告其余内容不受影响）：{exc}", file=sys.stderr)

    report_path = build_markdown(analyzer, findings, severity_stats, chart_paths, args.output)
    print_console(analyzer, findings, severity_stats, report_path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
