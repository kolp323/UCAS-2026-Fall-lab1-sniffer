# 实验 1A · 带图形界面的网络嗅探器

这是一个用 C++17、Qt 5 Widgets 和 Npcap 实现的 Windows 网络嗅探器。程序支持实时抓包和离线分析。三栏界面同时显示报文列表、协议字段与原始字节，点击字段即可高亮相应的字节。系统设计、协议解析和实验结果见[实验报告（PDF）](lab1A-report.pdf)。

## 构建与运行

准备 Visual Studio 2022 的 C++ 工具、CMake 3.20 或更新版本、Qt 5.15 的 MSVC x64 版本、Npcap 运行时以及 Npcap SDK 1.17。将 SDK 解压到 `.deps/npcap-sdk-1.17`，或在配置时用 `-DNPCAP_SDK_DIR` 指定实际位置。

从仓库根目录运行以下 PowerShell 命令，将 Qt 路径替换为本机安装目录。

~~~powershell
$qtRoot = 'C:\Qt\5.15.2\msvc2019_64'
cmake -S . -B build -G 'Visual Studio 17 2022' -A x64 "-DCMAKE_PREFIX_PATH=$qtRoot"
cmake --build build --config Release
$env:PATH = (Join-Path $qtRoot 'bin') + [IO.Path]::PathSeparator + $env:PATH
$env:QT_QPA_PLATFORM_PLUGIN_PATH = Join-Path $qtRoot 'plugins\platforms'
.\build\Release\lab1_sniffer.exe
~~~

## 使用

- 选择网卡或回环接口，填写可选捕获条件，例如 `udp`，然后点击 **Start**。抓包应在有授权的网络中进行。
- 通过 **Open PCAP** 读取 PCAP 或 PCAPNG。程序解析 Ethernet、VLAN、回环封装、IPv4、IPv6、TCP、UDP 和 ICMP，并识别单个 TCP 段中完整的明文 HTTP/1.x 首部。
- 显示过滤按解析结果筛选报文。例如 `HTTP OR (IPV6 AND UDP AND udp.dstport == 5300)`。协议下拉框与表达式取交集。
- 选中 TCP 报文后打开 **TCP flow** 查看窗口内两个方向的报文、载荷字节及可见的连接事件。**Export retained PCAP** 导出整个保留窗口，显示过滤不影响其内容。窗口最多保留 2000 包或 16 MiB 原始报文字节。

也可用命令行解析已有的样本，生成 JSON 供核对。

~~~powershell
.\build\Release\lab1_cli.exe --read .\capture.pcap --display-filter HTTP --json .\result.json
~~~

## 按进程观察 TCP 连接

打开 **Process flows…**，输入本机 PID 并点击 **Track PID**。窗口每 250 ms 读取 Windows 的 IPv4 和 IPv6 TCP 连接表，保留端点、状态和观测时间。实时抓包时可以选中一行，点击 **Filter captured endpoints** 查看保留窗口内四元组相同的双向报文。短连接可能落在两次采样之间。同一四元组再次使用时，需要结合观测时间判断归属。

## Wireshark 扩展

插件按 Wireshark 的 TCP 流编号统计两个方向的报文数、载荷字节，以及带 SYN、FIN 和 RST 标志的段数。A 是最先观察到的发送端。重传的载荷按实际出现次数累计。用 Wireshark 4.6.2 打开自己的样本后，在 **Tools → Lab 1A → TCP stream summary** 查看。也可直接运行 TShark。

~~~powershell
Wireshark.exe -X lua_script:plugins/lab1_tcp.lua -r capture.pcap
tshark.exe -X lua_script:plugins/lab1_tcp.lua -r capture.pcap -q -z lab1,flows
~~~

自主源码采用 [MIT 许可](LICENSE)。
