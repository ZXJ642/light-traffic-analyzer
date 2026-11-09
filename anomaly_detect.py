"""轻量规则检测：ARP 映射冲突、DNS 多 IP 解析异常。

只做启发式判断，不是 IDS，结论都要结合抓包环境人工复核。
"""

import ipaddress

SEVERITY_ORDER = {"高": 0, "中": 1, "低": 2, "提示": 3}


def _ipv4_network(addr):
    try:
        return ipaddress.IPv4Address(addr)
    except Exception:
        try:
            return ipaddress.IPv6Address(addr)
        except Exception:
            return None


def _prefix16(addr):
    ip = _ipv4_network(addr)
    if ip is None:
        return None
    if isinstance(ip, ipaddress.IPv4Address):
        return f"{ip.exploded.split('.')[0]}.{ip.exploded.split('.')[1]}.0.0/16"
    return f"{ip.exploded.split(':')[0]}::/16"


def detect_arp_conflicts(analyzer):
    findings = []
    for ip_addr, macs in sorted(analyzer.arp_bindings.items()):
        if len(macs) < 2:
            continue
        items = sorted(macs.items(), key=lambda kv: (-kv[1], kv[0]))
        total = sum(count for _, count in items)
        evidence = "，".join(f"{mac}（{count} 次）" for mac, count in items)
        others = items[1:]
        severity = "高" if others[0][1] >= 3 else "中"
        findings.append({
            "category": "ARP",
            "severity": severity,
            "rule": "arp_ip_mac_conflict",
            "title": f"IP {ip_addr} 出现多个 MAC 映射",
            "detail": (
                f"抓包中共有 {len(items)} 个 MAC 声称自己是 {ip_addr}，"
                f"合计 {total} 次 ARP 报文。正常情况下同一 IP 应只对应一个 MAC，"
                "多 MAC 并存是 ARP 欺骗（中间人/网关冒充）的典型特征。"
            ),
            "evidence": evidence,
            "advice": "先确认是否做过网关迁移或网卡更换；否则对比交换机 ARP 表与真实终端 MAC 定位来源。",
        })

    for mac, ips in sorted(analyzer.arp_mac_ips.items()):
        if len(ips) < 5:
            continue
        findings.append({
            "category": "ARP",
            "severity": "中",
            "rule": "arp_mac_multi_ip",
            "title": f"MAC {mac} 声明了 {len(ips)} 个不同 IP",
            "detail": (
                "单个 MAC 在 ARP 报文中声明多个 IP，可能是 ARP 扫描、伪造应答，"
                "也可能是 DHCP 频繁续租或代理 ARP 的正常行为，需要结合时间线判断。"
            ),
            "evidence": "、".join(sorted(ips)[:10]) + ("…" if len(ips) > 10 else ""),
            "advice": "对照 DHCP 租约记录与交换机端口 MAC 表，确认该 MAC 是否长期对应单一主机。",
        })
    return findings


def detect_dns_anomalies(analyzer):
    findings = []
    for name, ips in sorted(analyzer.dns_answers.items()):
        if len(ips) < 2:
            continue
        groups = sorted({g for g in (_prefix16(ip) for ip in ips) if g})
        count = analyzer.dns_answer_counts.get(name, len(ips))
        address_list = sorted(ips)
        evidence = "、".join(address_list[:8]) + ("…" if len(address_list) > 8 else "")

        if len(groups) >= 2:
            severity = "高" if len(groups) >= 3 else "中"
            detail = (
                f"域名 {name} 在同一份抓包里解析到 {len(ips)} 个 IP，且分布在 {len(groups)} 个不同 /16 网段。"
                "同一域名短时间返回跨网段的不同地址，可能是 DNS 劫持、缓存投毒或投毒式负载均衡；"
                "但大型 CDN 也会返回多地域节点地址，需结合 TTL 与请求时间点排除误报。"
            )
        else:
            severity = "低"
            detail = (
                f"域名 {name} 解析到 {len(ips)} 个不同 IP（同一 /16 网段内）。"
                "多 A 记录本身常见于负载均衡场景，仅作为备案式提示，不构成告警。"
            )

        findings.append({
            "category": "DNS",
            "severity": severity,
            "rule": "dns_multi_ip",
            "title": f"域名 {name} 出现 {len(ips)} 个解析结果，涉及 {max(len(groups), 1)} 个网段",
            "detail": detail,
            "evidence": f"应答记录 {count} 条；IP：{evidence}",
            "advice": "用 dig 多次查询对比权威 DNS 结果，并检查本地 DNS 服务器与网关配置是否被篡改。",
        })
    return findings


def run_all(analyzer):
    findings = detect_arp_conflicts(analyzer)
    findings += detect_dns_anomalies(analyzer)
    findings.sort(key=lambda f: (SEVERITY_ORDER.get(f["severity"], 9), f["category"]))
    return findings


def summarize(findings):
    stats = {"高": 0, "中": 0, "低": 0, "提示": 0}
    for item in findings:
        stats[item["severity"]] = stats.get(item["severity"], 0) + 1
    return stats
