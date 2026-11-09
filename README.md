# 轻量级网络流量分析工具（Light Traffic Analyzer）

基于 Python + Scapy 的**离线** pcap/pcapng 流量分析命令行工具：解析报文、统计协议分布与 TOP 流量、
基于简单规则识别 ARP 欺骗与 DNS 多地址异常，输出控制台摘要和一份带图表的 Markdown 报告。

面向网络工程与安全方向的初学者：把 TCP/IP、ARP、DNS 学到的报文结构，变成一个能跑、能讲、能排错的小工具。

> 定位是**学习型流量复盘工具**，不是 IDS/IPS，不做入侵检测、不做主动探测、不做端口扫描。

---

## 功能

| 模块 | 内容 |
| --- | --- |
| 报文解析 | 读取本地 `.pcap` / `.pcapng`，逐包解析以太网、IP、TCP、UDP、ICMP、ARP、DNS |
| 协议分布 | TCP / UDP / ICMP / ARP / DNS / 其他 六类占比 + 字节数，输出饼图 |
| TOP 统计 | 源 IP、目的 IP、会话（五元组）、目的端口 |
| TCP 分析 | 跟踪 TCP 流，统计完成三次握手、SYN 无应答、RST 复位的数量 |
| DNS 分析 | 查询/应答数量、出现过查询的域名、每个域名的 A/AAAA 解析结果集合 |
| 异常检测 | ARP：IP-MAC 映射冲突、单 MAC 声明多 IP；DNS：同一域名多 IP 且跨 /16 网段 |
| 报告输出 | 控制台摘要 + Markdown 报告（含协议饼图、TOP IP 条形图） |
| 过滤 | 按 IP、按协议（tcp/udp/icmp/arp/dns/other）只看关心的流量 |
| 实时抓包（可选） | `--live` 抓包后落盘再走同一套离线分析流程，需显式确认目标为自有网络 |

---

## 环境要求

- Python 3.8+
- 依赖：`scapy`、`matplotlib`
- 实时抓包另需 Npcap（Windows）/ libpcap（Linux、macOS）

```bash
pip install -r requirements.txt
```

---

## 快速开始

```bash
# 1. 分析自己的抓包文件，生成 report.md 与 charts/ 图表
python main.py test_pcaps/sample_mixed.pcap -o report.md

# 2. 仓库自带的合成样本（用于冒烟验证，非真实流量）
python tools/make_sample_pcap.py
python main.py test_pcaps/sample_mixed.pcap
```

控制台输出示例：

```text
流量分析结果
--------------------------------------------------------------
文件        : test_pcaps\sample_mixed.pcap
报文数      : 37    字节数 : 2.82 KB
抓包时长    : 43.00 s    平均速率 : 536.37 bps
--------------------------------------------------------------
协议分布
  TCP       13   35.1%  ##########
  ICMP       2    5.4%  #
  ARP       14   37.8%  ###########
  DNS        8   21.6%  ######
--------------------------------------------------------------
异常检测：命中 4 条（高 1 / 中 2 / 低 1）
  1. [高] IP 192.168.1.1 出现多个 MAC 映射
  2. [中] MAC de:ad:be:ef:00:66 声明了 5 个不同 IP
  3. [中] 域名 www.bank-demo.com 出现 2 个解析结果，涉及 2 个网段
  4. [低] 域名 cdn.demo-site.com 出现 2 个解析结果，涉及 1 个网段
```

完整示例报告见 [docs/sample_report.md](docs/sample_report.md)，对应图表在 `docs/charts/`。

---

## 参数说明
```text
python main.py <pcap文件> [选项]

-o, --output PATH      Markdown 报告路径（默认 report.md）
--top N                TOP 列表长度（默认 10）
--ip ADDR              只统计与该 IP 相关的报文
--proto {tcp,udp,icmp,arp,dns,other}
                       只统计某一类协议
--max-packets N        最多解析前 N 个报文（大文件快速抽样）
--no-chart             不生成图表（只出 Markdown 文本）
--live                 实时抓包后分析
--iface NAME           抓包网卡，如 WLAN / eth0
--duration N           抓包时长，默认 30 秒
--confirm-authorized   配合 --live，确认目标为自有网络
-v, --version          版本号
```

常用组合：

```bash
python main.py capture.pcapng --ip 192.168.1.10 -o a.md          # 只看某台主机
python main.py capture.pcap --proto dns --no-chart                # 只复盘 DNS
python main.py big.pcap --max-packets 50000 --no-chart            # 抽样看趋势
```

---

## 检测规则

规则都是启发式判断，命中不等于攻击，需要结合抓包点人工复核。

| 规则 ID | 类型 | 判断条件 | 说明与常见误报 |
| --- | --- | --- | --- |
| `arp_ip_mac_conflict` | ARP | 同一 IP 在 ARP 报文里出现 ≥2 个不同 MAC | ARP 欺骗/网关冒充的典型特征；网关迁移、网卡更换、双机热备也会命中 |
| `arp_mac_multi_ip` | ARP | 单个 MAC 声明 ≥5 个不同 IP | ARP 扫描、伪造应答；代理 ARP、DHCP 频繁续租也会命中 |
| `dns_multi_ip` | DNS | 同一域名解析到 ≥2 个 IP，且分布在 ≥2 个 /16 网段时升级为「中」；跨 ≥3 个网段为「高」 | DNS 劫持、缓存投毒；大型 CDN 返回多地域节点是主要误报来源 |
| `dns_multi_ip`（低） | DNS | 同一域名 ≥2 个 IP 但都在同一 /16 内 | 负载均衡的正常表现，只做备案提示 |

分级：`高` / `中` / `低`，报告中按等级排序，并给出每条告警的证据与排查建议。

---

## 输出文件

```text
report.md            分析报告（表格 + 告警详情 + 复现命令）
charts/
├── protocol_pie.png 协议分布饼图
└── top_ips.png      源/目的 IP TOP 条形图
```

报告里的图片使用相对路径，把 `report.md` 和 `charts/` 一起搬走即可，GitHub 上也能直接预览。
中文字体缺失时图表自动回退英文标签，不会出现方块字。

---

## 仓库结构

```text
light-traffic-analyzer/
├── main.py                 # 命令行入口、参数解析、控制台摘要
├── traffic_parser.py       # 报文读取、分类、统计、TCP/DNS 状态跟踪
├── anomaly_detect.py       # ARP / DNS 规则检测
├── report_generator.py     # 图表绘制与 Markdown 报告
├── tools/
│   └── make_sample_pcap.py # 合成测试抓包
├── test_pcaps/
│   └── sample_mixed.pcap   # 合成样本（含正常流量 + ARP/DNS 异常）
├── docs/
│   ├── sample_report.md    # 示例报告
│   └── charts/             # 示例报告图表
├── requirements.txt
├── LICENSE
└── README.md
```

---

## 实现要点（面试可讲的部分）

1. **逐包流式解析**：用 `PcapReader` / `PcapNgReader` 迭代读取，不在内存里堆整份抓包，大文件只保留聚合计数；`.pcap` 与 `.pcapng` 读失败会自动换另一种读取器重试一次。
2. **协议分类优先级**：ARP > DNS > TCP > UDP > ICMP > 其他，保证饼图六类互斥且占比之和为 100%，避免 DNS 被同时算进 UDP 造成重复计数。
3. **TCP 三次握手判定**：以「客户端四元组」为键，记录 `SYN → SYN+ACK → ACK` 三个阶段，只有看到对向 SYN+ACK 且随后出现纯 ACK 才计为「握手完成」，因此能区分「只发起未建立」和「建立了」。
4. **ARP 映射表**：维护 `IP → {MAC: 次数}` 与 `MAC → {IP}` 两个方向，既能发现「一个 IP 多个 MAC」，也能发现「一个 MAC 冒充多个 IP」。
5. **DNS 记录聚合**：按 `域名 → {解析 IP 集合}` 聚合应答里的 A/AAAA 记录；Scapy 新版本 `an`/`qd` 字段可能是列表、旧版本是链式结构，代码里统一做了兼容。
6. **告警可解释**：每条告警都带规则 ID、原始证据（MAC 出现次数、IP 列表）和排查建议，避免只给一个「可疑」结论。
7. **合规设计**：默认只读本地文件；实时抓包要 `--live` 加 `--confirm-authorized` 双开关，README 与报告都写明禁止对公网抓包。

---

## 局限与误报

- 只做离线分析，不做流量重放、不做阻断；
- ARP 检测依赖抓到 ARP 报文，跨网段或交换后抓包可能看不到冲突；
- DNS 检测无法区分 CDN 与劫持，多 A 记录场景建议对照权威 DNS 解析结果；
- 不解析 IPv6 扩展头的完整链路，IPv6 流量多数归入「其他」；
- 大流量下 TCP 流表有上限（2 万条），超出后停止跟踪新流，统计会略有偏差。

把“误报”写清楚，比强行宣称 100% 准确更专业。

---

## 测试流量怎么造

1. **自己抓真实流量**：Wireshark 选自己网卡抓 30 秒（或在 eNSP/HCL 里抓实验拓扑），保存为 `.pcap`，只抓内网，不上公网镜像；
2. **合成流量**：`python tools/make_sample_pcap.py` 用 Scapy 构造 37 个报文，包含一次完整 HTTP 握手、TLS 握手、ICMP 往返、DNS 正常解析，以及网关被冒充、同一域名跨网段解析等异常；
3. **异常复现**：想验证 ARP 规则，可在虚拟机里用 `arpspoof` 对自己的实验网络做一次网关冒充（仅限隔离实验环境），再抓包分析。

**不要**下载来源不明的恶意流量数据集：许可不清、可能夹带真实隐私数据。

---

## 打包成 Windows 可执行程序

```bash
pip install pyinstaller
python -m PyInstaller --noconfirm --clean --console --name lta --onedir main.py
python -m PyInstaller --noconfirm --clean --console --name lta-portable --onefile main.py
```

| 产物 | 说明 |
| --- | --- |
| `dist/lta/` | 目录版，含 `lta.exe` 与 `_internal/`，启动快、最稳定，整个目录一起分发 |
| `dist/lta-portable.exe` | 单文件版（约 40 MB），传输方便，首次启动解压约 7 秒 |

打包注意：

- 目录版不能单独拷走 `lta.exe`，必须和 `_internal/` 放在一起；
- 打包后 Windows 控制台默认按 GBK 解码，`main.py` 启动时会重设代码页为 UTF-8，避免告警文字乱码；
- PyInstaller 产物容易被杀软误报，属于打包器特征，可添加信任或改用目录版分发；
- `build/`、`dist/`、`*.spec` 已在 `.gitignore` 中忽略，不要把二进制推进仓库。

**关于 APK**：本项目依赖 Scapy 的原始套接字抓包和 Matplotlib 绘图，不适合直接转成 Android 应用；真要做移动端需要 Kivy/BeeWare 重写界面，且 Android 上抓包通常需要 root。因此只提供 Windows 桌面版。

---

## 合规声明

本工具仅用于**分析自己有权抓取的流量**，用于学习、复盘与排错。

- 禁止对公网、他人网络或未授权设备抓包、探测；
- 禁止将本工具改造为扫描器、爆破工具或攻击工具；
- 由使用者自行承担使用范围合规责任。

---

## 后续可扩展

- 增加 TCP 重传、零窗口、异常 MSS 的识别；
- 支持 IPv6 与 ICMPv6（NDP 欺骗检测）；
- 导出 JSON 结果，便于接入 Grafana 或做批量对比；
- 引入时间窗统计，检测周期性 Beacon 行为。

---

## License

MIT，见 [LICENSE](LICENSE)。
