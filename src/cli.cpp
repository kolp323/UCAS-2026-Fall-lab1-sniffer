#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <windows.h>
#include <pcap.h>
#include "parser.h"
#include "display_filter.h"
#include <QCoreApplication>
#include <QCommandLineParser>
#include <QJsonDocument>
#include <QJsonArray>
#include <QFile>
#include <QFileInfo>
#include <QElapsedTimer>
#include <iostream>
#include <memory>
int main(int argc,char** argv){
    QCoreApplication app(argc,argv); QCommandLineParser args;args.addHelpOption();
    args.addOption({"read","Read saved PCAP","path"});args.addOption({"json","Output JSON path","path"});
    args.addOption({"capture-filter","libpcap BPF filter","expression"});args.addOption({"display-filter","Display expression: protocol names, field comparisons, AND/OR/NOT","expression","ALL"});
    args.addOption({"limit","Maximum emitted packets (1..100000)","count","100000"});args.process(app);
    if(!args.isSet("read")){std::cerr<<"--read is required\n";return 2;}
    bool ok=false;int limit=args.value("limit").toInt(&ok);
    if(!ok||limit<1||limit>100000){std::cerr<<"Invalid limit\n";return 2;}
    const QString filter=args.value("display-filter");
    QString error;
    const auto matches=lab1::compileDisplayFilter(filter,error);
    if(!matches){std::cerr<<error.toStdString()<<'\n';return 2;}
    wchar_t sys[MAX_PATH];GetSystemDirectoryW(sys,MAX_PATH);std::wstring dir=std::wstring(sys)+L"\\Npcap";
    SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_DEFAULT_DIRS);if(!AddDllDirectory(dir.c_str())){std::cerr<<"Npcap DLL directory unavailable\n";return 2;}
    char err[PCAP_ERRBUF_SIZE]{};pcap_init(PCAP_CHAR_ENC_UTF_8,err);
    const QFileInfo inputInfo(args.value("read")); if(!inputInfo.exists() || inputInfo.size()>134217728){std::cerr<<"Missing input or input exceeds 128 MiB limit\n";return 2;}
    const QByteArray name=args.value("read").toUtf8();
    std::unique_ptr<pcap_t,decltype(&pcap_close)> cap(pcap_open_offline(name.constData(),err),pcap_close);
    if(!cap){std::cerr<<err<<'\n';return 2;}
    if(args.isSet("capture-filter")){
        bpf_program program{};const QByteArray expr=args.value("capture-filter").toUtf8();
        if(pcap_compile(cap.get(),&program,expr.constData(),1,PCAP_NETMASK_UNKNOWN)!=0){std::cerr<<pcap_geterr(cap.get())<<'\n';return 2;}
        const int rc=pcap_setfilter(cap.get(),&program);pcap_freecode(&program);
        if(rc!=0){std::cerr<<pcap_geterr(cap.get())<<'\n';return 2;}
    }
    const int link=pcap_datalink(cap.get());QJsonArray rows;int read=0;bool limited=false;QString limitReason;constexpr qint64 jsonBudget=64LL*1024*1024;qint64 jsonBytes=1024+name.size()*6;QElapsedTimer timer;timer.start();
    for(;;){
        pcap_pkthdr* hdr=nullptr;const u_char* bytes=nullptr;const int rc=pcap_next_ex(cap.get(),&hdr,&bytes);
        if(rc==-2)break;if(rc==0)continue;if(rc<0){std::cerr<<pcap_geterr(cap.get())<<'\n';return 2;}
        if(read>=limit){limited=true;limitReason="record_limit";break;}++read;
        if(hdr->caplen>65535){std::cerr<<"Packet exceeds 65535-byte safety limit\n";return 2;}
        const auto packet=lab1::parsePacket(QByteArray(reinterpret_cast<const char*>(bytes),static_cast<int>(hdr->caplen)),link,hdr->len);
        if(!matches(packet))continue;
        auto obj=lab1::packetJson(packet);obj["number"]=read;obj["caplen"]=static_cast<int>(hdr->caplen);obj["wirelen"]=static_cast<int>(hdr->len);
        obj["timestamp"]=QString::number(hdr->ts.tv_sec)+"."+QString("%1").arg(hdr->ts.tv_usec,6,10,QChar('0'));const qint64 rowBytes=QJsonDocument(obj).toJson(QJsonDocument::Compact).size()+1;if(jsonBytes+rowBytes>jsonBudget){limited=true;limitReason="json_budget";break;}jsonBytes+=rowBytes;rows.append(obj);
    }
    QJsonObject result{{"input",args.value("read")},{"linktype",link},{"read_count",read},{"displayed_count",rows.size()},{"elapsed_ms",static_cast<double>(timer.elapsed())},{"complete",!limited},{"limit_reason",limitReason},{"json_budget_bytes",static_cast<double>(jsonBudget)},{"capture_filter",args.value("capture-filter")},{"display_filter",filter},{"packets",rows}};
    const QByteArray output=QJsonDocument(result).toJson(QJsonDocument::Compact);
    if(args.isSet("json")){QFile file(args.value("json"));if(!file.open(QIODevice::WriteOnly|QIODevice::NewOnly)){std::cerr<<"Refusing missing-parent/existing/unwritable output\n";return 2;}if(file.write(output)!=output.size()){std::cerr<<"Output write failed\n";return 2;}}
    else std::cout.write(output.constData(),output.size());
    if(limited){std::cerr<<"Packet or JSON budget reached; output incomplete\n";return 3;}
    return 0;
}


