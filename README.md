# 实验1A：可验证的网络嗅探器

工程已迁移到 E:\users\VScodeProject\C++\UCAS-2026-Fall_Software-and-system-security\lab1-sniffer。历史证据保留运行当时的路径。实现采用 C++17、MSVC2022 x64、Qt5.15.2 Widgets/Network、Npcap1.83/SDK1.17，TShark4.6.2独立核对。实验源码由AI协助生成；报告应如实说明，学生需理解并能解释核心。

## 构建与启动

需要 Visual Studio 2022 C++工具、CMake3.26、Qt5.15 MSVC版、Npcap运行时。官方SDK1.17解压到`.deps/npcap-sdk-1.17`，或给CMake传`NPCAP_SDK_DIR`。本机Qt目录是`E:/Anaconda3/Library`；其他机器需替换为实际路径，不要依赖环境碰巧存在。

```powershell
cmake -S . -B build -G 'Visual Studio 17 2022' -A x64 '-DCMAKE_PREFIX_PATH=E:/Anaconda3/Library'
cmake --build build --config Release
./scripts/start-gui.ps1
./scripts/run-lab.ps1 -Live
```

`run-lab`每次创建新运行目录，保存构建日志、固定输入、回归与可选真实回环抓包；失败不会运行旧二进制。`-InjectFailure`预期失败并退出非零，用于验证失败可见性。`-InjectTimeout`用受控父子进程验证Windows超时清理，阶段退出124、总流程失败；清理只针对本次PID进程树，不保证特殊脱离进程。脚本需Python3；性能脚本还需psutil/matplotlib。图表可单独由`derive-results.py --run 已有perf目录`重生成，不触发抓包。固定样本不可覆盖，使用`generate-fixtures.py --out 新目录`。

## 操作与职责

- 选择捕获接口，填写可选BPF（如`udp`），点击Start/Stop。仅在有授权的网络捕获。
- Display protocol根据已解析字段筛选；HTTP依赖可见完整起始行与头部特征，不能仅凭端口。捕获过滤和显示过滤语法不同。
- Open PCAP离线分析；选择报文与字段，黄色高亮对应原始字节。
- Export retained PCAP导出全部保留记录，不受显示过滤影响；被容量上限淘汰的旧记录不在导出中，界面明确提示。当前不是无限制全流量归档器。
- 内存窗口最多2000包或16MiB原字节。每次读取64包或约5ms，计时预算不包含全部解析/渲染成本；没有工作线程队列。驱动丢包、显示淘汰、超长拒绝分开统计。

## 支持与边界

支持Ethernet、最多两层VLAN、DLT_NULL；IPv4/v6、有限扩展头、TCP/UDP、ICMP、HTTP/1.x头部特征。状态区分valid/truncated/malformed/unsupported/fragment。valid仅表示结构检查通过，不验证校验和；无TCP/IP完整重组、无TLS解密、无进程关联。合成样本故意包含错误和未计算的IPv6传输层校验和，不把它们说成真实合法抓包。

CLI：`build/Release/lab1_cli.exe --read fixtures/v2/ethernet.pcap --json 新输出.json`。支持`--capture-filter udp`、`--display-filter HTTP`。输入128MiB、单包65535字节、最多10万条、序列化预算64MiB；达到限制退出3并标incomplete，不能当完整处理成功。序列化预算不等于进程总内存。

## 证据与学习入口

- `docs/learning/`：五节零基础讲解与自测；先预测，再运行，再对照。
- `tests/verify.py`：固定预期、TShark、原字节、过滤与异常检查。
- `tests/BPF-oracle-audit.md`：真实的测试预期纠错，不伪造解析bug。
- `evidence/runs/lab-20261120T024100Z-61e311e4/`：最终全流程通过。
- `evidence/runs/visual-20261120T024203Z-3f5e5ed1/`：真实GUI渲染图、自动操作演示MP4、10包真实回环输入和5000包容量验证。
- `evidence/runs/perf-20261120T023937Z-a8e44a33/`：1次试运行与3次独立离线进程测量，含启动/JSON输出；不是实时抓包吞吐。
- `evidence/runs/portable-20261120/`：同机仅System32 PATH且无Anaconda模块的运行核对；仍需系统Npcap/VC运行库，非干净OS测试。

## 提交边界

公开源码与完整Git历史：[GitHub仓库](https://github.com/kolp323/UCAS-2026-Fall-lab1-sniffer)。实名报告与提交包在本机deliverables目录；不把学生身份写入公开示例配置。课程p2–3要求报告、视频、源码与Git链接、未加密ZIP；PPT是额外展示。报告已使用用户提供的身份与真实Git链接。最终提交包按课件p3命名，课程平台提交需另行操作。截止据PDF为2026-11-24 23:55，课程网站未复核。dist仅本机依赖隔离验证；正式源码包不附第三方驱动或未完整附许可的运行库。

## 最终验证与演示

C++实现基线为`9727f836f99928d83611ebc60de5cf4b1e839e3b`；后续提交补充脚本、证据和交付说明。`evidence/final-index.json`是结果索引。`clean-final-9727f83`为同机新源码/新构建目录100项通过；`portable-final-9727f83`为同机隔离PATH启动通过。

`deliverables/lab1A-demo.mp4`以GUI功能展示为主：选择接口与捕获条件、开始和停止抓包、导出PCAP、打开样本、筛选协议、点击字段定位原始字节，以及阅读HTTP请求行。中文字幕随当前操作解释核心机制。生成入口为`python scripts/record-gui-tour.py`；录制工具复用现有Window实现，实际操作控件、套接字和PCAP文件。构建与测试记录继续保存在实验材料中。

自主源码使用MIT许可，见LICENSE；外部库、课件和参考规范不受此许可覆盖。仓库不附Npcap SDK/驱动或Qt第三方运行库；用官方来源另行取得。演示运行的runtime、重复源码和中间帧只在本机保留；公开证据保留命令、输入归档、日志、时间线、哈希、验证结果和可重生成脚本。性能解析大JSON可由固定PCAP重生成，不重复入库。
