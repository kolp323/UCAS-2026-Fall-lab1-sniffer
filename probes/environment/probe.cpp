#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <windows.h>
#include <pcap.h>
#include <QApplication>
#include <QLabel>
#include <QTimer>
#include <QPixmap>
#include <QSysInfo>
#include <iostream>
#include <chrono>
#include <thread>
#include <cstring>
#include <string>
#include <stdexcept>
static void require(bool ok, const char* msg) { if(!ok) throw std::runtime_error(msg); }
int main(int argc, char** argv) {
 try {
  wchar_t sys[MAX_PATH]; GetSystemDirectoryW(sys, MAX_PATH);
  std::wstring npcap = std::wstring(sys) + L"\\Npcap";
  require(SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_DEFAULT_DIRS)!=0, "DLL policy");
  require(AddDllDirectory(npcap.c_str())!=nullptr,"Npcap DLL path");
  std::cout << "qt=" << qVersion() << " compiler=" << _MSC_VER << " arch=" << QSysInfo::currentCpuArchitecture().toStdString() << std::endl;
  std::cout << "capture_library=" << pcap_lib_version() << std::endl;
  char err[PCAP_ERRBUF_SIZE]{}; pcap_if_t* devices=nullptr;
  require(pcap_findalldevs(&devices,err)==0,err);
  int interfaces=0; bool loopback=false;
  for(auto* d=devices; d; d=d->next){ ++interfaces; if(std::string(d->name)=="\\Device\\NPF_Loopback") loopback=true; }
  pcap_freealldevs(devices);
  std::cout << "interfaces=" << interfaces << " loopback=" << loopback << std::endl;
  require(loopback,"loopback missing");
  WSADATA wsa{}; require(WSAStartup(MAKEWORD(2,2),&wsa)==0,"WSAStartup");
  SOCKET rx=socket(AF_INET,SOCK_DGRAM,IPPROTO_UDP), tx=socket(AF_INET,SOCK_DGRAM,IPPROTO_UDP);
  require(rx!=INVALID_SOCKET && tx!=INVALID_SOCKET,"socket");
  sockaddr_in addr{}; addr.sin_family=AF_INET; addr.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
  require(bind(rx,(sockaddr*)&addr,sizeof(addr))==0,"bind rx");
  require(bind(tx,(sockaddr*)&addr,sizeof(addr))==0,"bind tx");
  sockaddr_in dst{},src{}; int sz=sizeof(dst);
  require(getsockname(rx,(sockaddr*)&dst,&sz)==0,"getsockname rx"); sz=sizeof(src);
  require(getsockname(tx,(sockaddr*)&src,&sz)==0,"getsockname tx");
  auto* cap=pcap_open_live("\\Device\\NPF_Loopback",65535,0,50,err); require(cap!=nullptr,err);
  const std::string filter="ip and udp and src host 127.0.0.1 and dst host 127.0.0.1 and src port "+std::to_string(ntohs(src.sin_port))+" and dst port "+std::to_string(ntohs(dst.sin_port));
  bpf_program program{}; require(pcap_compile(cap,&program,filter.c_str(),1,PCAP_NETMASK_UNKNOWN)==0,pcap_geterr(cap));
  require(pcap_setfilter(cap,&program)==0,pcap_geterr(cap)); pcap_freecode(&program);
  require(pcap_setnonblock(cap,1,err)==0,err);
  auto* dump=pcap_dump_open(cap,"loopback.pcap"); require(dump!=nullptr,pcap_geterr(cap));
  std::cout << "linktype=" << pcap_datalink(cap) << " filter=" << filter << std::endl;
  const std::string payload="A01-own-loopback-probe-v1";
  for(int i=0;i<3;++i) require(sendto(tx,payload.data(),(int)payload.size(),0,(sockaddr*)&dst,sizeof(dst))==(int)payload.size(),"sendto");
  DWORD rxtimeout=1000; setsockopt(rx,SOL_SOCKET,SO_RCVTIMEO,(char*)&rxtimeout,sizeof(rxtimeout));
  int received=0; for(int i=0;i<3;++i){ char buf[128]{}; int n=recv(rx,buf,sizeof(buf),0); require(n==(int)payload.size() && memcmp(buf,payload.data(),n)==0,"socket payload"); ++received; }
  int captured=0; auto until=std::chrono::steady_clock::now()+std::chrono::seconds(3);
  while(std::chrono::steady_clock::now()<until){
   pcap_pkthdr* hdr=nullptr; const u_char* bytes=nullptr; int rc=pcap_next_ex(cap,&hdr,&bytes);
   require(rc>=0,pcap_geterr(cap));
   if(rc==1){ require(hdr->caplen>=payload.size(),"truncated capture"); require(memcmp(bytes+hdr->caplen-payload.size(),payload.data(),payload.size())==0,"captured payload"); pcap_dump((u_char*)dump,hdr,bytes); ++captured; }
   else std::this_thread::sleep_for(std::chrono::milliseconds(10));
  }
  pcap_stat stats{}; int sr=pcap_stats(cap,&stats);
  std::cout << "sent=3 received=" << received << " captured=" << captured << " stats_rc=" << sr << " ps_recv=" << stats.ps_recv << " ps_drop=" << stats.ps_drop << std::endl;
  pcap_dump_close(dump); pcap_close(cap); closesocket(rx); closesocket(tx); WSACleanup();
  require(captured==3,"capture count mismatch");
  QApplication app(argc,argv); QLabel label("A01 Qt Widgets + MSVC + Npcap\n3 local UDP packets captured\nFeasibility probe only");
  label.resize(480,160); label.setAttribute(Qt::WA_DontShowOnScreen); label.show();
  int ticks=0; bool imageSaved=false; QTimer timer;
  QObject::connect(&timer,&QTimer::timeout,[&]{++ticks; if(ticks==3){ QPixmap pix(label.size()); label.render(&pix); imageSaved=pix.save("qt-widget.png"); app.quit(); }});
  timer.start(50); app.exec(); require(ticks==3 && imageSaved,"Qt render/event loop");
  std::cout << "qt_platform=" << QGuiApplication::platformName().toStdString() << " timer_ticks=" << ticks << " image_saved=" << imageSaved << " result=PASS" << std::endl;
  return 0;
 } catch(const std::exception& e){std::cerr << "result=FAIL reason=" << e.what()<<std::endl;return 1;}
}
