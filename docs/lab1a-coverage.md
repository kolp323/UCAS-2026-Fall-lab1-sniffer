# Lab 1A 课程覆盖与技术复核

实验题目为带 GUI 的网络嗅探器。页码对应原始《实验 1 讲解 2026.pdf》。实现基线为 `4dbed34`，展示与归档随后的修改另有 Git 记录。课程原文只明确了要求与加分方向，未给各项数值权重。

| 性质 | 原始依据与验收项 | 当前实现与结果 | 可复查的证据或边界 |
|---|---|---|---|
| 硬要求 | p5、p9，带 GUI 的真实 NPS（网络报文嗅探） | Npcap 回环接口实际捕获，界面可选择接口、设置捕获条件、开始及停止。 | [最终回环 PCAP](../evidence/runs/review-20261121-final/local-protocols.pcap) 和 [实验结果](../evidence/runs/review-20261121-final/results.json)。输入限本机受控流量。 |
| 基础 | p9、p14，NPA 分析与分层理解 | 区分链路、网络、传输和应用解析。Ethernet、有限 VLAN 与 DLT_NULL 区分，字段保留字节位置，供 GUI 高亮。 | [解析器](../src/parser.cpp)，[固定样本逐字段对照](../evidence/runs/lab-20261121T020736Z-3d27c844/checks/results.json)。报告使用真实 DLT_NULL 报文。 |
| 基础 | p14，IPv4/IPv6、TCP/UDP、ICMP | 捕获两族 TCP 与 ICMP Echo，UDP 走实际抓包。用长度边界、扩展头、分片和截断用例验证解析，所测的 IPv6 Fragment 保留位被展示且不参与分片决策。 | [回环 TShark](../evidence/runs/review-20261121-final/tshark.csv)、[ICMP 原字节](../evidence/runs/review-20261121-final/icmp-oracle.json)。支持范围见 README。 [RFC 8200 §4.5](https://www.rfc-editor.org/rfc/rfc8200#section-4.5)、[RFC 4302 §2.2](https://www.rfc-editor.org/rfc/rfc4302#section-2.2) |
| 基础 | p14，HTTP 识别和过滤 | 只识别单个 TCP 段内完整、可见的 HTTP/1.x 起始行与语法可辨的头字段。在同一服务端口上，格式正确的请求及响应被识别，坏头字段样本不标 HTTP。 | [发送端原文](../evidence/runs/review-20261121-final/socket-oracle.json)、[解析明细](../evidence/runs/review-20261121-final/parsed.json)；分段头、密文和未覆盖的方法含义另见报告。 [RFC 9112](https://www.rfc-editor.org/rfc/rfc9112) |
| 基础与增强 | p14，协议过滤及技术区分 | BPF 在返回给应用前选择字节。显示过滤对保留条目求值，新增 AND、OR、NOT、括号和字段比较，与下拉协议条件取交集。 | [BPF 预期纠错](../tests/BPF-oracle-audit.md)、[过滤断言](../evidence/runs/lab-20261121T020736Z-3d27c844/checks/results.json) 和 [GUI 截图](../evidence/runs/review-20261121-final/expression.png)。 [Npcap 过滤文档](https://npcap.com/guide/wpcap/pcap-filter.html) |
| 实验完整性 | GUI 字节定位、离线读写与异常处理 | 实时和离线均可定位原始字节。导出整个保留窗口，显示条件不影响内容。坏 PCAP、超界长度和错误表达式有清楚反馈。 | [GUI 验证数据](../evidence/runs/review-20261121-final/gui-review.json)，精确核对 279 条导出记录的顺序。PCAP 字节预览 4096 B，导出保留记录的完整捕获字节。 |
| 实验完整性 | 连续输入、反复启停、容量 | 三次持续发送时停止，另测空闲停止。2050 条小记录保留 2000 条。300 条 60,000 B 记录保留 279 条，共 16,740,000 B。 | [停止试验与容量](../evidence/runs/review-20261121-final/gui-review.json)。停止的处理耗时 3.44–16.22 ms，采集时 GUI 心跳间隔最大值为 77、81、117 ms。驱动统计、应用超长拒绝与保留淘汰独立。 |
| 明确加分 | p14，基于 IP/Port 的 TCP 流追踪 | 选中完整 TCP 段后查看保留窗口内的双方地址端口、方向、时间、包数、载荷字节数与握手、FIN/ACK、RST 等可见事件。 | [流窗口截图](../evidence/runs/review-20261121-final/tcp-flow.png)，两族 HTTP 流各 11 段，方向计数均 6/5，载荷分别 38/59 B 和 39/59 B。与 TShark 逐段对照。累计载荷含重复段，未做流重组。 [RFC 9293](https://www.rfc-editor.org/rfc/rfc9293) |
| 明确加分 | p14，某进程的全部 TCP 流 | 本轮未实现。Windows IP Helper 可给出当前端点与 PID，但短连接、复用端口、进程退出和抓包时刻的关联需额外采集及验证。 | 学生汇报时可讲端点归组与 PID 归属的区别。 [GetExtendedTcpTable](https://learn.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-getextendedtcptable) |
| 明确加分 | p9，基于 Wireshark 的良好二次开发 | 本轮用 TShark 作对照工具，未实现 dissector 或插件。插件适合自定义协议展示，需另做版本兼容、插件负载与发布测试。 | [Wireshark 开发指南](https://www.wireshark.org/docs/wsdg_html_chunked/ChDissectAdd.html) |
| 课程建议 | p15 推荐 API，p25–29 BPF 背景，p64–65 排障与教学建议 | 调用 Npcap API，使用真实 BPF 排查案例准备课堂展示。GUI 演示、PPT 和报告共享关键例子。 | Linux eBPF 不是本题额外必做。择优展示由课程安排。 |
| 提交 | p2–3，命名、报告含 Git 链接、MP4、源码与完整 Git、未加密 ZIP | 交付源文件、报告和视频以课件实名命名，PPT另附。 | [公开仓库](https://github.com/kolp323/UCAS-2026-Fall-lab1-sniffer)。课件截止为 2026-11-24 23:55，课程网站通知及上传回执由本人确认。 |

## 改动与复验

- `src/parser.cpp` 读取 IPv4 分片标志、IPv6 Fragment 标识和保留位，区分零载荷 No Next Header 的链路填充，核对 IPv6 AH 长度对齐和 HTTP 头字段格式。原始字节跨度始终受捕获长度约束。
- `src/display_filter.cpp` 编译显示条件。优先级依次为 NOT、AND、OR。缺字段时比较为假，语法错误保留上次结果。CLI 与 GUI 共用求值规则。
- `src/tcp_flow.cpp` 用相向端点找出当前连接片段。同一 SYN 重复仍归在同次观测。新的起始 SYN 可区分同端口组合的后继连接。界面展示观测到的事件。
- `tests/verify.py` 覆盖原回归和新增独立的表达式、长度、Fragment 和 AH 预期，共 120 项通过。`tests/review.py` 与 `probes/review/review.cpp` 检查真实回环、GUI 与停止响应，`tests/check-icmp.py` 对照 ICMP 原始字节。
- 实验入口用环境变量或 PATH 定位工具。使用新目录重编并运行最终测试，另用隔离 PATH 的本机运行包验证 GUI 与 CLI 能启动。验证仍依赖本机 Npcap 驱动和 Windows VC 运行时。
- 最终测量使用 [运行索引](../evidence/final-index.json) 对应版本。旧的 BPF 预期失败和早期改进试验原样留存。

## 仍有价值的扩展

首先用序号范围和方向识别可观测的重传与缺口，再考虑重组。需专门覆盖中途开始、乱序、重叠和序号回绕。连接重组、TLS 解密、进程归属和重用四元组的歧义处理超出当前实验的实现范围。

