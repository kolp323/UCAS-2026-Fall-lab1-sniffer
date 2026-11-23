# 图形化网络嗅探器的设计与实现

软件与系统安全实验 1A · Windows · C++17 / Qt 5 / Npcap

选中一条报文，可以看到协议字段对应的原始字节，也可以沿同一 TCP 连接找到请求、响应和观测到的连接事件。程序支持实时抓包、离线分析和 PCAP 导出。

[课程报告（PDF）](lab1A-report.pdf) · [界面演示（MP4，1 分 36 秒）](lab1A-demo.mp4)

## 从报文到连接

- **抓包与分析**：在网卡或回环接口上开始捕获，也可用 **Open…** 打开 PCAP 或 PCAPNG。程序解析 IPv4、IPv6、TCP、UDP、ICMP 和 ICMPv6，并在单个 TCP 段中识别完整的明文 HTTP/1.x 首部。
- **捕获与显示过滤**：捕获条件在报文进入程序前生效，例如 `udp`。显示条件筛选已保留的报文，可组合协议和字段，例如 `HTTP AND tcp.dstport == 4311`。**Export…** 导出整个保留窗口，窗口最多容纳 2,000 条报文和 16 MiB 原始字节。
- **双向 TCP 流**：选中一条完整的 TCP 报文后打开 **TCP flow**，按捕获顺序查看双向报文、载荷字节数、握手和关闭事件。统计以实际捕获的段为准，重传的载荷会再次计入。
- **进程连接**：在 **Process flows…** 输入本机进程标识符（PID），查看观测到的 IPv4 和 IPv6 连接。实时抓包时，可从进程连接筛出保留窗口里的双向报文。连接表每 250 ms 采样一次，短连接可能落在两次采样之间。

## 构建与启动

准备 Visual Studio 2022 的 C++ 桌面开发工具、CMake 3.20 或更高版本、Qt 5.15 的 MSVC x64 版，以及 Npcap 运行时和 SDK 1.17。将 SDK 解压到 `.deps/npcap-sdk-1.17`，也可在 CMake 配置时用 `-DNPCAP_SDK_DIR` 指定目录。

从仓库根目录运行以下 PowerShell 命令，将 Qt 路径替换为本机安装目录。

~~~powershell
$labQt = 'C:\Qt\5.15.2\msvc2019_64'
cmake -S . -B build -G 'Visual Studio 17 2022' -A x64 "-DCMAKE_PREFIX_PATH=$labQt"
cmake --build build --config Release
$env:PATH = (Join-Path $labQt 'bin') + [IO.Path]::PathSeparator + $env:PATH
$env:QT_QPA_PLATFORM_PLUGIN_PATH = Join-Path $labQt 'plugins\platforms'
.\build\Release\lab1_sniffer.exe
~~~

也可用命令行读取自己的抓包文件。下例把识别出的 HTTP 报文写入 JSON。

~~~powershell
.\build\Release\lab1_cli.exe --read .\capture.pcap --display-filter HTTP --json .\build\http.json
~~~

## 用 Wireshark 汇总 TCP 流

Lua 插件复用 Wireshark 的流编号，统计两个方向的报文数、载荷字节数，以及携带 SYN、FIN、RST 标志的报文数。加载插件后，从 **Tools → Lab 1A → TCP stream summary** 打开统计窗口。TShark 可以输出同一张表。

以下命令在 Wireshark 4.6.2 上验证。请将 `capture.pcap` 换成自己的样本，并确保可从 PowerShell 启动 Wireshark 和 TShark。

~~~powershell
Wireshark.exe -X lua_script:plugins/lab1_tcp.lua -r capture.pcap
tshark.exe -X lua_script:plugins/lab1_tcp.lua -r capture.pcap -q -z lab1,flows
~~~

## 实验验证

在本机回环抓包中，使用 TShark 逐段核对 IPv4 和 IPv6 的连接方向、序号、确认号与载荷长度。进程视图显示的端点与两个客户端各自记录的连接一致。Lua 插件在两份 TCP 样本和一份纯 UDP 样本中分别汇总出 3、3、0 条 TCP 流，计数与原始字节一致。过程、截图和适用范围见[课程报告](lab1A-report.pdf)。

自主源码采用 [MIT 许可](LICENSE)。
