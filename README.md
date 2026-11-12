# 软件与系统安全实验 1A

工程位置由用户确认。本目录此前不存在。当前只有A01范围记录与环境探针，尚无完整嗅探器。GUI、解析、过滤和健壮性由后续任务实现。

## 已验证的开发基线

Windows x64；C++17；Visual Studio 2022/MSVC 19.44；CMake 3.26.0；已有Qt Widgets 5.15.2（MSVC版，Anaconda qt-main 5.15.2 h19c9488_12）；Npcap运行时1.83与SDK1.17；独立判据TShark4.6.2。

当前Qt路径是本机配置，不保证其他机器存在。Npcap SDK来自 https://npcap.com/dist/npcap-sdk-1.17.zip，解压到`.deps/npcap-sdk-1.17`或通过`NPCAP_SDK_DIR`指定。SDK ZIP SHA256：AB7E1A6CB8D07427E0071EC11BE380BD9D2BB19AE6AB3F5EDE0698C301638258。不要把驱动安装程序或整个Anaconda复制进提交包。

## 构建环境探针

```powershell
cmake -S . -B build -G 'Visual Studio 17 2022' -A x64 '-DCMAKE_PREFIX_PATH=E:/Anaconda3/Library'
cmake --build build --config Release
```

配置或构建失败就停止，不能运行旧二进制。运行时仅给本次PowerShell子进程增加`E:\Anaconda3\Library\bin`的PATH，并设置`QT_QPA_PLATFORM_PLUGIN_PATH=E:\Anaconda3\Library\plugins\platforms`和`QT_QPA_PLATFORM=windows`；不要更改系统PATH。

探针路径为`build/Release/lab1_env_probe.exe`。工作目录必须是新的证据运行目录。设置20秒超时并保存stdout、stderr和退出码。探针仅绑定本机回环和动态端口，捕获自己发送的3个UDP报文，生成`loopback.pcap`和隐藏Qt控件的实际渲染图`qt-widget.png`。这不是用户交互截图，不证明GUI业务实现。

使用TShark导出字段，再把`probes/environment/verify_bytes.py`复制进该运行目录执行，以比较固定输入、原字节和TShark字段。具体已执行记录、边界和来源见[环境记录](docs/A01-范围与环境验证记录.md)。本探针不是通用解析器，也不是A07的一键实验流程。

## 工程与证据位置

- `probes/environment`：A01最小验证代码与独立字节检查。
- `docs`：范围、环境、来源和复现说明。
- `evidence/runs`：按运行编号保留的自建实验数据；不存无关网络流量。
- `.deps`、`build`：本机依赖与构建产物，不进入Git。

第一次临时目录验证保留原manifest与构建路径；正式工程复验另开目录，不修改旧结果。Git远程仓库尚未创建或发布。后续发布时再记录课程提交所需链接。
