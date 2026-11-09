"""图表绘制与 Markdown 报告生成。"""

import os
from datetime import datetime

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib import font_manager

CHINESE_FONTS = (
    "Microsoft YaHei", "SimHei", "Noto Sans CJK SC",
    "Source Han Sans SC", "WenQuanYi Micro Hei", "PingFang SC",
)
PROTOCOL_LABELS_EN = {
    "TCP": "TCP", "UDP": "UDP", "ICMP": "ICMP",
    "ARP": "ARP", "DNS": "DNS", "Other": "Other",
}

CHART_COLORS = ["#4E79A7", "#F28E2B", "#59A14F", "#E15759", "#76B7B2", "#B07AA1"]


def setup_font():
    """有中文字体就用中文标签，没有就退回英文，避免图中出现方块字。"""
    available = {f.name for f in font_manager.fontManager.ttflist}
    for name in CHINESE_FONTS:
        if name in available:
            plt.rcParams["font.sans-serif"] = [name, "DejaVu Sans"]
            plt.rcParams["axes.unicode_minus"] = False
            return True
    plt.rcParams["font.sans-serif"] = ["DejaVu Sans"]
    plt.rcParams["axes.unicode_minus"] = False
    return False


def human_bytes(value):
    units = ("B", "KB", "MB", "GB", "TB")
    size = float(value)
    for unit in units:
        if size < 1024 or unit == units[-1]:
            return f"{size:.2f} {unit}" if unit != "B" else f"{int(size)} B"
        size /= 1024
    return f"{size:.2f} TB"


def human_rate(bits):
    if bits >= 1_000_000:
        return f"{bits / 1_000_000:.2f} Mbps"
    if bits >= 1_000:
        return f"{bits / 1_000:.2f} Kbps"
    return f"{bits:.2f} bps"


def plot_protocol_pie(counts, out_path, chinese_ok=True):
    labels, values, colors = [], [], []
    for idx, proto in enumerate(("TCP", "UDP", "ICMP", "ARP", "DNS", "Other")):
        value = counts.get(proto, 0)
        if value <= 0:
            continue
        labels.append(proto if chinese_ok or proto not in PROTOCOL_LABELS_EN else PROTOCOL_LABELS_EN[proto])
        values.append(value)
        colors.append(CHART_COLORS[idx % len(CHART_COLORS)])

    if not values:
        return None

    fig, ax = plt.subplots(figsize=(7.0, 5.4), dpi=150)
    _wedges, _texts, autotexts = ax.pie(
        values,
        labels=labels,
        autopct="%1.1f%%",
        startangle=110,
        colors=colors,
        textprops={"fontsize": 10},
        labeldistance=1.14,
        pctdistance=0.66,
        wedgeprops={"edgecolor": "white", "linewidth": 1.2},
    )
    for text in autotexts:
        text.set_fontsize(9)
    ax.set_title("协议分布" if chinese_ok else "Protocol distribution", fontsize=13, pad=18)
    ax.axis("equal")
    fig.tight_layout()
    fig.savefig(out_path, bbox_inches="tight")
    plt.close(fig)
    return out_path


def plot_top_ips(src_counts, dst_counts, out_path, limit=10, chinese_ok=True):
    fig, axes = plt.subplots(1, 2, figsize=(10.5, 4.6), dpi=150)
    for ax, counts, title in (
        (axes[0], src_counts, "源 IP TOP" if chinese_ok else "Top source IPs"),
        (axes[1], dst_counts, "目的 IP TOP" if chinese_ok else "Top destination IPs"),
    ):
        items = counts.most_common(limit)
        if not items:
            ax.set_visible(False)
            continue
        items = list(reversed(items))
        labels = [ip for ip, _ in items]
        values = [count for _, count in items]
        ax.barh(labels, values, color="#4E79A7", height=0.62)
        ax.set_title(title, fontsize=12)
        ax.set_xlabel("报文数" if chinese_ok else "packets", fontsize=9)
        ax.tick_params(axis="y", labelsize=8)
        ax.tick_params(axis="x", labelsize=8)
        for spine in ("top", "right"):
            ax.spines[spine].set_visible(False)
        ax.grid(axis="x", linestyle=":", alpha=0.5)
    fig.tight_layout()
    fig.savefig(out_path, bbox_inches="tight")
    plt.close(fig)
    return out_path


def _md_table(headers, rows):
    lines = ["| " + " | ".join(headers) + " |",
             "| " + " | ".join("---" for _ in headers) + " |"]
    for row in rows:
        lines.append("| " + " | ".join(str(cell) for cell in row) + " |")
    return "\n".join(lines)


def _relative(path, base_dir):
    try:
        rel = os.path.relpath(path, base_dir)
        return rel.replace(os.sep, "/")
    except Exception:
        return path


def build_markdown(analyzer, findings, severity_stats, chart_paths, out_path, chinese_ok=True):
    base_dir = os.path.dirname(os.path.abspath(out_path))
    proto_total = analyzer.total_packets or 1

    meta_rows = [
        ("抓包文件", os.path.basename(analyzer.path)),
        ("文件大小", human_bytes(analyzer.file_size)),
        ("开始时间", analyzer.start_time_text),
        ("结束时间", analyzer.end_time_text),
        ("抓包时长", f"{analyzer.duration:.2f} s"),
        ("总报文数", f"{analyzer.total_packets}"),
        ("总字节数", f"{analyzer.total_bytes} ({human_bytes(analyzer.total_bytes)})"),
        ("平均速率", f"{analyzer.packets_per_second:.2f} 包/秒，{human_rate(analyzer.bits_per_second)}"),
    ]
    if analyzer.filtered_packets:
        meta_rows.append(("被过滤报文", f"{analyzer.filtered_packets}（过滤条件 ip={analyzer.ip_filter or '-'} proto={analyzer.proto_filter or '-'}）"))
    if analyzer.bad_packets:
        meta_rows.append(("解析失败报文", f"{analyzer.bad_packets}"))

    proto_rows = []
    for proto in ("TCP", "UDP", "ICMP", "ARP", "DNS", "Other"):
        count = analyzer.protocol_counts.get(proto, 0)
        if count == 0:
            continue
        proto_rows.append((proto, count, f"{count / proto_total * 100:.2f}%",
                           human_bytes(analyzer.protocol_bytes.get(proto, 0))))

    top_src = analyzer.src_ip_counts.most_common(10)
    top_dst = analyzer.dst_ip_counts.most_common(10)
    top_flows = analyzer.top_flows(10)
    top_ports = analyzer.dst_port_counts.most_common(10)

    tcp = analyzer.tcp_stats()
    dns = analyzer.dns_stats()

    dns_rows = []
    for name, ips in sorted(analyzer.dns_answers.items(),
                            key=lambda kv: (-len(kv[1]), kv[0]))[:10]:
        dns_rows.append((name, len(ips), "、".join(sorted(ips)[:4]) + ("…" if len(ips) > 4 else "")))

    out = []
    out.append("# 流量分析报告")
    out.append("")
    out.append(f"生成时间：{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}　｜　"
               f"分析对象：`{analyzer.path}`")
    out.append("")
    out.append("> 本工具面向离线 pcap 复盘与学习，检测规则为启发式判断，"
               "结论仅供排错参考，不替代专业 IDS/流量审计系统。")
    out.append("")

    if analyzer.truncated:
        out.append(f"> 注意：已按 `--max-packets {analyzer.max_packets}` 截断，"
                   "以下统计只覆盖前 N 个报文。")
        out.append("")

    out.append("## 一、抓包概览")
    out.append("")
    out.append(_md_table(["项目", "值"], meta_rows))
    out.append("")

    out.append("## 二、协议分布")
    out.append("")
    out.append(_md_table(["协议", "报文数", "占比", "字节数"], proto_rows))
    out.append("")
    if chart_paths.get("pie"):
        out.append(f"![协议分布]({_relative(chart_paths['pie'], base_dir)})")
        out.append("")

    out.append("## 三、流量 TOP 统计")
    out.append("")
    out.append("### 源 IP TOP10")
    out.append("")
    out.append(_md_table(["源 IP", "报文数", "发送字节"],
                         [(ip, cnt, human_bytes(analyzer.src_bytes[ip])) for ip, cnt in top_src]))
    out.append("")
    out.append("### 目的 IP TOP10")
    out.append("")
    out.append(_md_table(["目的 IP", "报文数", "接收字节"],
                         [(ip, cnt, human_bytes(analyzer.dst_bytes[ip])) for ip, cnt in top_dst]))
    out.append("")
    if chart_paths.get("top_ip"):
        out.append(f"![TOP IP]({_relative(chart_paths['top_ip'], base_dir)})")
        out.append("")

    out.append("### 会话 TOP10（按字节排序）")
    out.append("")
    out.append(_md_table(["协议", "源", "目的", "报文数", "字节数"],
                         [(proto, f"{src}:{sport}", f"{dst}:{dport}", f["packets"], human_bytes(f["bytes"]))
                          for (proto, src, sport, dst, dport), f in top_flows]))
    out.append("")
    out.append("### 目的端口 TOP10")
    out.append("")
    out.append(_md_table(["协议/端口", "报文数"],
                         [(f"{proto}/{port}", cnt) for (proto, port), cnt in top_ports]))
    out.append("")

    out.append("## 四、TCP 连接概况")
    out.append("")
    out.append(_md_table(["指标", "数值"], [
        ("跟踪到的 TCP 流", tcp["flows"]),
        ("发起 SYN 的流", tcp["syn_flows"]),
        ("完成三次握手的流", tcp["completed"]),
        ("SYN 无应答的流", tcp["unanswered"]),
        ("出现 RST 的流", tcp["reset_flows"]),
        ("RST 报文总数", tcp["rst_packets"]),
        ("SYN 报文数", analyzer.tcp_flag_counts.get("SYN", 0)),
        ("FIN 报文数", analyzer.tcp_flag_counts.get("FIN", 0)),
    ]))
    out.append("")
    out.append("> “SYN 无应答”可能是对端关闭端口、防火墙丢包或链路不可达，"
               "也可能只是抓包位置看不到回包，需结合抓包点判断。")
    out.append("")

    out.append("## 五、DNS 解析概况")
    out.append("")
    out.append(_md_table(["指标", "数值"], [
        ("DNS 查询报文", dns["queries"]),
        ("DNS 应答报文", dns["responses"]),
        ("出现过的查询域名", dns["unique_query_names"]),
        ("有 A/AAAA 应答的域名", dns["domains"]),
        ("解析到多个 IP 的域名", dns["multi_ip_domains"]),
    ]))
    out.append("")
    if dns_rows:
        out.append("### 解析结果域名 TOP10")
        out.append("")
        out.append(_md_table(["域名", "解析 IP 数", "IP 样本"], dns_rows))
        out.append("")

    out.append("## 六、异常检测结果")
    out.append("")
    out.append(f"共命中 **{len(findings)}** 条：高 {severity_stats.get('高', 0)} 条、"
               f"中 {severity_stats.get('中', 0)} 条、低 {severity_stats.get('低', 0)} 条。")
    out.append("")
    if not findings:
        out.append("未命中 ARP 映射冲突或 DNS 多 IP 异常规则，未发现明显可疑流量。")
        out.append("")
    for idx, item in enumerate(findings, 1):
        out.append(f"### {idx}. [{item['severity']}] {item['title']}")
        out.append("")
        out.append(f"- 类型：{item['category']}　规则：`{item['rule']}`")
        out.append(f"- 说明：{item['detail']}")
        out.append(f"- 证据：{item['evidence']}")
        out.append(f"- 建议：{item['advice']}")
        out.append("")

    out.append("## 七、复现方式")
    out.append("")
    out.append("```bash")
    out.append(f"python main.py {os.path.basename(analyzer.path)} -o report.md")
    out.append("```")
    out.append("")
    out.append("## 八、说明与免责")
    out.append("")
    out.append("- 解析基于 Scapy 读取链路层帧，协议分类优先级：ARP > DNS > TCP > UDP > ICMP > 其他；")
    out.append("- 当前检测规则共 %d 类：ARP 的 IP-MAC 冲突/单 MAC 多 IP、DNS 的多 IP 跨网段解析；" % 2)
    out.append("- 规则为学习型启发式判断，存在误报（如 CDN、代理 ARP、网关迁移），不构成入侵取证结论；")
    out.append("- 仅用于离线分析自己有权抓取的流量，禁止对公网或他人网络抓包探测。")
    out.append("")

    content = "\n".join(out)
    with open(out_path, "w", encoding="utf-8") as fp:
        fp.write(content)
    return out_path
