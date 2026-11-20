#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <winsock2.h>
#include <windows.h>
#include <psapi.h>
#pragma comment(lib,"psapi.lib")
#include <pcap.h>
#include <QtWidgets>
#include <QUdpSocket>
#include <QHostAddress>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>
#include <QElapsedTimer>
#include <memory>
#include "parser.h"

namespace {
constexpr int kRetainedLimit=2000;
constexpr int kReadBatch=64;
constexpr int kMaxPacket=65535;
constexpr qint64 kRawBytesLimit=16*1024*1024;
struct Record { quint64 id; QByteArray bytes; pcap_pkthdr header; lab1::Packet packet; };
class PacketModel : public QAbstractTableModel {
public:
 QVector<Record> records;
 QVector<int> visible;
 QString filter="ALL";
 quint64 evicted=0;
 qint64 retainedBytes=0;
 explicit PacketModel(QObject* p):QAbstractTableModel(p){}
 int rowCount(const QModelIndex& p={})const override{return p.isValid()?0:visible.size();}
 int columnCount(const QModelIndex& p={})const override{return p.isValid()?0:8;}
 QVariant headerData(int s,Qt::Orientation o,int r)const override{
  if(r!=Qt::DisplayRole || o!=Qt::Horizontal)return {};
  static const QStringList names={"No.","Source","Destination","Protocol","Bytes","Status","Ports","Summary"};return names.value(s);
 }
 QVariant data(const QModelIndex& i,int role)const override{
  if(!i.isValid()||i.row()>=visible.size())return {};
  const auto& r=records[visible[i.row()]];
  if(role==Qt::ForegroundRole){if(r.packet.status=="malformed")return QColor("#ae2435");if(r.packet.status!="valid")return QColor("#936000");return {};}
  if(role!=Qt::DisplayRole)return {};
  switch(i.column()){
   case 0:return QVariant::fromValue<qulonglong>(r.id);case 1:return r.packet.src;case 2:return r.packet.dst;
   case 3:return r.packet.protocol;case 4:return int(r.header.caplen);case 5:return r.packet.status;
   case 6:return r.packet.srcPort>=0?QString("%1 → %2").arg(r.packet.srcPort).arg(r.packet.dstPort):QString();
   case 7:return r.packet.info;default:return {};
  }
 }
 void rebuild(){visible.clear();for(int i=0;i<records.size();++i)if(lab1::matchesDisplayFilter(records[i].packet,filter))visible.append(i);}
 void reset(){beginResetModel();records.clear();visible.clear();evicted=0;retainedBytes=0;endResetModel();}
 void setFilter(const QString& f){beginResetModel();filter=f;rebuild();endResetModel();}
 void append(QVector<Record>& rows){if(rows.isEmpty())return;beginResetModel();for(auto& r:rows){retainedBytes+=r.bytes.size();records.append(std::move(r));}int excess=0;while(records.size()-excess>kRetainedLimit || retainedBytes>kRawBytesLimit){retainedBytes-=records[excess].bytes.size();++excess;}if(excess>0){records.erase(records.begin(),records.begin()+excess);evicted+=excess;}rebuild();endResetModel();}
};
class Window : public QMainWindow {
public:
 PacketModel* model;
 QComboBox *interfaces,*display;
 QLineEdit *captureFilter;
 QPushButton *startButton,*stopButton,*openButton,*saveButton;
 QLabel *state,*counts,*sourceLabel;
 QTableView* table;
 QTableWidget* fields;
 QPlainTextEdit* hex;
 QTimer poll, uiHeartbeat;
 pcap_t* cap=nullptr;
 int linktype=1;
 quint64 captured=0, oversized=0, heartbeatTicks=0;
 unsigned driverReceived=0,driverDropped=0;
 bool statsAvailable=false;
 QElapsedTimer heartbeatClock;
 qint64 lastHeartbeat=0,maxHeartbeatGap=0;
 QJsonArray resourceTrace;
 QString lastError,highlightedField,highlightedHex;
 int highlightedOffset=-1,highlightedLength=0;
 QFile offlineFile;
 pcap_t* offline=nullptr;
 QTimer offlinePoll;
 QString offlinePath;
 bool offlineLoaded=false;
 std::function<void(bool)> loadFinished;
 explicit Window(){
  setWindowTitle("Lab 1A | Packet Observatory");resize(1240,840);
  auto* central=new QWidget;auto* layout=new QVBoxLayout(central);layout->setContentsMargins(20,16,20,16);layout->setSpacing(10);
  auto* title=new QLabel("PACKET OBSERVATORY  /  LAB 1A");title->setStyleSheet("font-size:22px;font-weight:700;color:#17314b;");layout->addWidget(title);
  auto* sub=new QLabel("Capture bytes · explain fields · keep evidence");sub->setStyleSheet("color:#53677b;");layout->addWidget(sub);
  auto* captureRow=new QHBoxLayout;interfaces=new QComboBox;interfaces->setMinimumWidth(280);captureFilter=new QLineEdit;captureFilter->setPlaceholderText("Capture BPF, e.g. udp or tcp port 80 (empty = all)");
  startButton=new QPushButton("Start capture");stopButton=new QPushButton("Stop");stopButton->setEnabled(false);
  captureRow->addWidget(interfaces,2);captureRow->addWidget(captureFilter,3);captureRow->addWidget(startButton);captureRow->addWidget(stopButton);layout->addLayout(captureRow);
  auto* viewRow=new QHBoxLayout;viewRow->addWidget(new QLabel("Display protocol"));display=new QComboBox;display->addItems({"ALL","ETHERNET","IPV4","IPV6","TCP","UDP","ICMP","ICMPV6","HTTP"});viewRow->addWidget(display);viewRow->addStretch();openButton=new QPushButton("Open PCAP / PCAPNG");saveButton=new QPushButton("Export retained PCAP");viewRow->addWidget(openButton);viewRow->addWidget(saveButton);layout->addLayout(viewRow);
  sourceLabel=new QLabel("No source loaded. Choose an interface or open a fixed sample.");sourceLabel->setWordWrap(true);layout->addWidget(sourceLabel);
  state=new QLabel("READY · Capture filter selects incoming packets; display filter only changes the retained view.");state->setWordWrap(true);state->setStyleSheet("background:#e8eff5;color:#17314b;padding:9px;border-radius:5px;");layout->addWidget(state);
  counts=new QLabel;layout->addWidget(counts);
  model=new PacketModel(this);table=new QTableView;table->setModel(model);table->setSelectionBehavior(QAbstractItemView::SelectRows);table->setSelectionMode(QAbstractItemView::SingleSelection);table->setAlternatingRowColors(true);table->setSortingEnabled(false);table->verticalHeader()->hide();table->verticalHeader()->setDefaultSectionSize(24);table->horizontalHeader()->setStretchLastSection(true);table->setColumnWidth(0,55);table->setColumnWidth(1,150);table->setColumnWidth(2,150);table->setColumnWidth(3,90);table->setColumnWidth(4,65);table->setColumnWidth(5,95);table->setColumnWidth(6,120);
  auto* split=new QSplitter(Qt::Vertical);split->addWidget(table);
  auto* details=new QSplitter(Qt::Horizontal);fields=new QTableWidget;fields->setColumnCount(4);fields->setHorizontalHeaderLabels({"Field","Value","Offset","Length"});fields->setEditTriggers(QAbstractItemView::NoEditTriggers);fields->setSelectionBehavior(QAbstractItemView::SelectRows);fields->horizontalHeader()->setStretchLastSection(true);fields->setColumnWidth(0,140);fields->setColumnWidth(1,180);fields->setColumnWidth(2,65);fields->verticalHeader()->hide();fields->verticalHeader()->setDefaultSectionSize(24);hex=new QPlainTextEdit;hex->setReadOnly(true);hex->setFont(QFont("Consolas",10));details->addWidget(fields);details->addWidget(hex);details->setSizes({560,640});split->addWidget(details);split->setSizes({360,260});layout->addWidget(split,1);
  auto* foot=new QLabel("Bounded storage: 2,000 packets / 16 MiB raw · retained eviction ≠ driver drop · HTTP requires payload evidence · no TCP reassembly / TLS decryption");foot->setWordWrap(true);foot->setStyleSheet("color:#596b7d;font-size:11px;");layout->addWidget(foot);setCentralWidget(central);
  setStyleSheet("QMainWindow,QWidget{background:#f7f9fc;color:#1c3044;font-family:'Segoe UI';font-size:12px;} QPushButton{background:#e3ebf4;border:1px solid #bdccdc;border-radius:4px;padding:7px 12px;} QPushButton:disabled{color:#9aa4b0;} QLineEdit,QComboBox{background:white;border:1px solid #bdccdc;border-radius:4px;padding:6px;} QTableView,QPlainTextEdit{background:white;alternate-background-color:#eef4f8;border:1px solid #c9d5e2;} QHeaderView::section{background:#e6edf5;padding:6px;border:0;font-weight:600;}");
  connect(startButton,&QPushButton::clicked,this,[this]{startCapture();});connect(stopButton,&QPushButton::clicked,this,[this]{stopCapture();});
  connect(display,&QComboBox::currentTextChanged,this,[this](const QString& s){model->setFilter(s);clearDetails();if(model->rowCount())table->selectRow(0);updateCounts();});
  connect(openButton,&QPushButton::clicked,this,[this]{auto p=QFileDialog::getOpenFileName(this,"Open fixed capture",QString(),"Captures (*.pcap *.pcapng);;All files (*)");if(!p.isEmpty())openCapture(p);});
  connect(saveButton,&QPushButton::clicked,this,[this]{auto p=QFileDialog::getSaveFileName(this,"Export retained packets",QString(),"PCAP (*.pcap)");if(!p.isEmpty())exportCapture(p);});
  connect(table->selectionModel(),&QItemSelectionModel::selectionChanged,this,[this]{showSelected();});
  connect(fields,&QTableWidget::cellClicked,this,[this](int row,int){highlightField(row);});
  poll.setInterval(20);connect(&poll,&QTimer::timeout,this,[this]{readLive();});offlinePoll.setInterval(0);connect(&offlinePoll,&QTimer::timeout,this,[this]{readOffline();});
  heartbeatClock.start();uiHeartbeat.setInterval(50);connect(&uiHeartbeat,&QTimer::timeout,this,[this]{
   ++heartbeatTicks;qint64 now=heartbeatClock.elapsed();if(cap)maxHeartbeatGap=qMax(maxHeartbeatGap,now-lastHeartbeat);lastHeartbeat=now;
   PROCESS_MEMORY_COUNTERS memory{};memory.cb=sizeof(memory);bool memOk=GetProcessMemoryInfo(GetCurrentProcess(),&memory,sizeof(memory))!=0;
   FILETIME creation{},exit{},kernel{},user{};bool cpuOk=GetProcessTimes(GetCurrentProcess(),&creation,&exit,&kernel,&user)!=0;
   auto ticks=[](const FILETIME& f){return (quint64(f.dwHighDateTime)<<32)|f.dwLowDateTime;};
   resourceTrace.append(QJsonObject{{"elapsed_ms",double(now)},{"capturing",cap!=nullptr},{"captured",double(captured)},{"retained",model->records.size()},{"retained_raw_bytes",double(model->retainedBytes)},{"evicted",double(model->evicted)},{"working_set_bytes",memOk?double(memory.WorkingSetSize):-1.0},{"cpu_ms",cpuOk?double(ticks(kernel)+ticks(user))/10000.0:-1.0}});
   if(resourceTrace.size()>2400)resourceTrace.removeFirst();
  });uiHeartbeat.start();enumerate();updateCounts();
 }
 ~Window(){stopCapture(false);closeOffline();}
 void error(const QString& s){lastError=s;state->setText("ERROR · "+s);state->setStyleSheet("background:#fee9eb;color:#9f2332;padding:9px;border-radius:5px;");qWarning().noquote()<<s;}
 void status(const QString& s){state->setStyleSheet("background:#e8eff5;color:#17314b;padding:9px;border-radius:5px;");state->setText(s);}
 void clearDetails(){fields->setRowCount(0);hex->clear();hex->setExtraSelections({});highlightedField.clear();highlightedHex.clear();highlightedOffset=-1;highlightedLength=0;}
 void updateCounts(){counts->setText(QString("Read: %1    Retained: %2    Displayed: %3    Evicted: %4    Oversize rejected: %5    Driver received/drop: %6").arg(captured).arg(model->records.size()).arg(model->rowCount()).arg(model->evicted).arg(oversized).arg(statsAvailable?QString("%1 / %2").arg(driverReceived).arg(driverDropped):"not available / offline"));}
 void enumerate(){interfaces->clear();char err[PCAP_ERRBUF_SIZE]{};pcap_if_t* list=nullptr;if(pcap_findalldevs(&list,err)!=0){error(QString::fromUtf8(err));return;}for(auto* d=list;d;d=d->next){interfaces->addItem(d->description?QString::fromUtf8(d->description):QString::fromUtf8(d->name),QString::fromUtf8(d->name));}pcap_freealldevs(list);if(interfaces->count()==0)error("No capture interfaces. Check Npcap and permissions.");}
 void closeOffline(){offlinePoll.stop();if(offline){pcap_close(offline);offline=nullptr;}offlineFile.close();}
 void resetData(){model->reset();captured=oversized=0;driverReceived=driverDropped=0;statsAvailable=false;clearDetails();updateCounts();}
 bool startCapture(){
  if(cap)return true;closeOffline();if(interfaces->currentIndex()<0){error("Choose a capture interface.");return false;}
  char err[PCAP_ERRBUF_SIZE]{};QByteArray name=interfaces->currentData().toString().toUtf8();pcap_t* c=pcap_create(name.constData(),err);if(!c){error(QString::fromUtf8(err));return false;}
  auto fail=[&](const QString& why){pcap_close(c);error(why);return false;};
  if(pcap_set_snaplen(c,65535)!=0||pcap_set_promisc(c,0)!=0||pcap_set_timeout(c,20)!=0||pcap_set_buffer_size(c,4*1024*1024)!=0)return fail("Could not configure capture parameters");
  int active=pcap_activate(c);if(active<0)return fail(QString::fromUtf8(pcap_geterr(c)));
  if(!captureFilter->text().trimmed().isEmpty()){bpf_program f{};QByteArray expr=captureFilter->text().toUtf8();if(pcap_compile(c,&f,expr.constData(),1,PCAP_NETMASK_UNKNOWN)<0)return fail("Invalid capture filter: "+QString::fromUtf8(pcap_geterr(c)));int rc=pcap_setfilter(c,&f);pcap_freecode(&f);if(rc<0)return fail(QString::fromUtf8(pcap_geterr(c)));}
  if(pcap_setnonblock(c,1,err)<0)return fail(QString::fromUtf8(err));
  cap=c;linktype=pcap_datalink(cap);resetData();lastHeartbeat=heartbeatClock.elapsed();maxHeartbeatGap=0;startButton->setEnabled(false);stopButton->setEnabled(true);interfaces->setEnabled(false);captureFilter->setEnabled(false);openButton->setEnabled(false);sourceLabel->setText(QString("LIVE · %1 · linktype %2 · BPF: %3").arg(interfaces->currentText()).arg(linktype).arg(captureFilter->text().isEmpty()?"(all)":captureFilter->text()));status("CAPTURING · Bounded nonblocking reads; stop remains available.");poll.start();return true;
 }
 void stopCapture(bool announce=true){poll.stop();if(cap){pcap_stat s{};statsAvailable=pcap_stats(cap,&s)==0;if(statsAvailable){driverReceived=s.ps_recv;driverDropped=s.ps_drop;}pcap_close(cap);cap=nullptr;if(announce)status("STOPPED · Captured records remain available for inspection and export.");}startButton->setEnabled(true);stopButton->setEnabled(false);interfaces->setEnabled(true);captureFilter->setEnabled(true);openButton->setEnabled(true);updateCounts();}
 void addRecord(QVector<Record>& batch,const pcap_pkthdr* h,const u_char* data){++captured;if(h->caplen>kMaxPacket){++oversized;return;}Record r;r.id=captured;r.header=*h;r.bytes=QByteArray(reinterpret_cast<const char*>(data),int(h->caplen));r.packet=lab1::parsePacket(r.bytes,linktype,h->len);batch.append(std::move(r));}
 void acceptBatch(QVector<Record>& batch){if(batch.isEmpty())return;quint64 selected=0;auto index=table->currentIndex();if(index.isValid()&&index.row()<model->visible.size())selected=model->records[model->visible[index.row()]].id;model->append(batch);int found=-1;for(int i=0;i<model->visible.size();++i)if(model->records[model->visible[i]].id==selected){found=i;break;}if(found>=0)table->selectRow(found);else{clearDetails();if(model->rowCount())table->selectRow(0);}updateCounts();}
 void readLive(){if(!cap)return;QVector<Record> batch;QElapsedTimer budget;budget.start();for(int i=0;i<kReadBatch&&budget.elapsed()<5;++i){pcap_pkthdr* h=nullptr;const u_char* data=nullptr;int rc=pcap_next_ex(cap,&h,&data);if(rc==0)break;if(rc<0){QString err=QString::fromUtf8(pcap_geterr(cap));stopCapture(false);error("Capture read failed: "+err);break;}addRecord(batch,h,data);}acceptBatch(batch);}
 bool openCapture(const QString& path){stopCapture(false);closeOffline();offlineLoaded=false;QFileInfo info(path);if(!info.isFile()||info.size()>128*1024*1024){error("Input must be a regular capture file of at most 128 MiB.");if(loadFinished)loadFinished(false);return false;}char err[PCAP_ERRBUF_SIZE]{};offline=pcap_open_offline(path.toUtf8().constData(),err);if(!offline){error(QString::fromUtf8(err));if(loadFinished)loadFinished(false);return false;}linktype=pcap_datalink(offline);resetData();offlinePath=path;sourceLabel->setText(QString("OFFLINE · %1 · linktype %2").arg(QFileInfo(path).fileName()).arg(linktype));status("LOADING · Fixed capture; newest 2,000 packets are retained.");openButton->setEnabled(false);startButton->setEnabled(false);offlinePoll.start();return true;}
 void readOffline(){if(!offline)return;QVector<Record> batch;bool finished=false,ok=true;QString why;QElapsedTimer budget;budget.start();for(int i=0;i<kReadBatch&&budget.elapsed()<5;++i){pcap_pkthdr* h=nullptr;const u_char* data=nullptr;int rc=pcap_next_ex(offline,&h,&data);if(rc==-2){finished=true;break;}if(rc<0){finished=true;ok=false;why=QString::fromUtf8(pcap_geterr(offline));break;}if(rc==0)break;addRecord(batch,h,data);}acceptBatch(batch);if(finished){closeOffline();openButton->setEnabled(true);startButton->setEnabled(true);offlineLoaded=ok;if(ok)status("LOADED · Select a packet, then inspect fields and original bytes. Non-valid states are preserved.");else error("Capture file read failed: "+why);if(model->rowCount())table->selectRow(0);if(loadFinished)loadFinished(ok);}}
 bool exportCapture(const QString& path){if(model->records.isEmpty()){error("No retained packets to export.");return false;}auto* dead=pcap_open_dead(linktype,kMaxPacket);if(!dead){error("Could not create PCAP writer.");return false;}auto* writer=pcap_dump_open(dead,path.toUtf8().constData());if(!writer){error(QString::fromUtf8(pcap_geterr(dead)));pcap_close(dead);return false;}for(const auto& r:model->records)pcap_dump(reinterpret_cast<u_char*>(writer),&r.header,reinterpret_cast<const u_char*>(r.bytes.constData()));int rc=pcap_dump_flush(writer);pcap_dump_close(writer);pcap_close(dead);if(rc!=0){error("PCAP flush failed.");return false;}status(QString("EXPORTED · %1 retained packets (all display protocols), evicted %2 are not included.").arg(model->records.size()).arg(model->evicted));return true;}
 void highlightField(int row,bool explain=true){
  if(row<0||row>=fields->rowCount())return;
  auto index=table->currentIndex();if(!index.isValid()||index.row()>=model->visible.size())return;
  const auto& r=model->records[model->visible[index.row()]];
  int offset=fields->item(row,2)->text().toInt(),length=fields->item(row,3)->text().toInt();
  if(offset<0||length<0||offset>r.bytes.size()||length>r.bytes.size()-offset)return;
  highlightedField=fields->item(row,0)->text();highlightedOffset=offset;highlightedLength=length;
  highlightedHex=QString::fromLatin1(r.bytes.mid(offset,length).toHex());
  QList<QTextEdit::ExtraSelection> selections;int end=qMin(offset+length,4096);
  for(int at=offset;at<end;){int line=at/16,column=at%16,run=qMin(end-at,16-column);QTextBlock b=hex->document()->findBlockByNumber(3+line);if(!b.isValid())break;QTextEdit::ExtraSelection sel;sel.cursor=QTextCursor(b);sel.cursor.setPosition(b.position()+6+column*3);sel.cursor.movePosition(QTextCursor::Right,QTextCursor::KeepAnchor,run*3-1);sel.format.setBackground(QColor("#ffe08a"));sel.format.setForeground(QColor("#182d40"));selections.append(sel);at+=run;}
  hex->setExtraSelections(selections);
  if(!selections.isEmpty()){QTextCursor cursor=selections.first().cursor;cursor.clearSelection();hex->setTextCursor(cursor);hex->ensureCursorVisible();}
  if(explain)status(QString("FIELD · %1 = %2 · raw bytes [%3, %4), hex %5%6").arg(highlightedField,fields->item(row,1)->text()).arg(offset).arg(offset+length).arg(highlightedHex.left(80),offset>=4096?" (outside preview; full bytes retained)":""));
 }
 void showSelected(){auto index=table->currentIndex();if(!index.isValid()||index.row()>=model->visible.size())return;const auto& r=model->records[model->visible[index.row()]];fields->setRowCount(r.packet.fields.size());for(int i=0;i<r.packet.fields.size();++i){const auto& f=r.packet.fields[i];QStringList cells={f.name,f.value,QString::number(f.offset),QString::number(f.length)};for(int j=0;j<4;++j)fields->setItem(i,j,new QTableWidgetItem(cells[j]));}QString dump=QString("Packet %1 | %2 | %3\nCaptured %4 bytes / original %5 bytes\n\n").arg(r.id).arg(r.packet.protocol,r.packet.status).arg(r.header.caplen).arg(r.header.len);int show=qMin(4096,r.bytes.size());for(int off=0;off<show;off+=16){QString hexPart,ascii;for(int j=0;j<16;++j){if(off+j<show){unsigned b=static_cast<unsigned char>(r.bytes[off+j]);hexPart+=QString("%1 ").arg(b,2,16,QChar('0'));ascii+=(b>=32&&b<127)?QChar(b):QChar('.');}else hexPart+="   ";}dump+=QString("%1  %2 %3\n").arg(off,4,16,QChar('0')).arg(hexPart,ascii);}if(show<r.bytes.size())dump+="\nPreview limited to 4096 bytes; retained/exported data is complete.\n";hex->setPlainText(dump);if(fields->rowCount()){int selected=qMin(1,fields->rowCount()-1);fields->setCurrentCell(selected,0);highlightField(selected,false);}}
 void closeEvent(QCloseEvent* e)override{stopCapture(false);closeOffline();QMainWindow::closeEvent(e);}
};
bool saveJson(const QString& path,const QJsonObject& o){QSaveFile f(path);if(!f.open(QIODevice::WriteOnly))return false;f.write(QJsonDocument(o).toJson());return f.commit();}
}
int main(int argc,char** argv){
 wchar_t sys[MAX_PATH]{};GetSystemDirectoryW(sys,MAX_PATH);std::wstring np=std::wstring(sys)+L"\\Npcap";SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_DEFAULT_DIRS);AddDllDirectory(np.c_str());
 QApplication app(argc,argv);app.setApplicationName("Lab1 Packet Observatory");char pcapError[PCAP_ERRBUF_SIZE]{};if(pcap_init(PCAP_CHAR_ENC_UTF_8,pcapError)!=0){qCritical()<<pcapError;return 2;}
 QCommandLineParser args;args.addHelpOption();args.addOption({"record-frames","Save actual application renders every 100 ms (max 300 frames).","directory"});args.addOption({"demo","Load a fixed PCAP and optionally save an actual GUI render.","pcap"});args.addOption({"screenshot","Save current GUI render after offline load.","png"});args.addOption({"live-count","Number of controlled UDP datagrams, 1 to 5000 (default 10).","count"});args.addOption({"live-demo","Run controlled local UDP capture with rejection/recovery evidence.","directory"});args.addOption({"auto-exit","Quit after this many milliseconds from launch (default 6000 for live demo).","milliseconds"});args.addOption({"display-filter","Set initial retained display protocol.","protocol"});args.addOption({"select-status","After offline load select first row with this parser status.","status"});args.process(app);
 bool countOk=true;const int liveCount=args.isSet("live-count")?args.value("live-count").toInt(&countOk):10;
 if(!countOk||liveCount<1||liveCount>5000){qCritical()<<"live-count must be 1 to 5000";return 2;}
 const int burstSize=liveCount<=10?1:50,burstIntervalMs=liveCount<=10?70:30;
 const int sendDurationMs=((liveCount+burstSize-1)/burstSize-1)*burstIntervalMs;
 const int liveFinishMs=qMax(3500,1200+sendDurationMs+1500);
 Window w;w.show();int exitCode=0;if(args.isSet("display-filter")){QString f=args.value("display-filter").toUpper();int ix=w.display->findText(f);if(ix<0){qCritical()<<"Unknown display protocol";return 2;}w.display->setCurrentIndex(ix);}
  if(args.isSet("record-frames")){
  QString dir=QDir(args.value("record-frames")).absolutePath();if(!QDir().mkpath(dir)||QFileInfo::exists(dir+"/frame-00000.png")){qCritical()<<"Use a fresh frame recording directory";return 2;}
  auto* recorder=new QTimer(&w);auto number=std::make_shared<int>(0);auto times=std::make_shared<QJsonArray>();auto elapsed=std::make_shared<QElapsedTimer>();elapsed->start();recorder->setInterval(100);
  QObject::connect(recorder,&QTimer::timeout,&w,[&,dir,number,recorder,times,elapsed]{QString file=dir+QString("/frame-%1.png").arg(*number,5,10,QChar('0'));if(!w.grab().save(file)){exitCode=1;recorder->stop();w.error("Rendered frame save failed");return;}times->append(QJsonObject{{"frame",*number},{"elapsed_ms",double(elapsed->elapsed())}});++*number;if(*number>=300)recorder->stop();});recorder->start();QObject::connect(&app,&QCoreApplication::aboutToQuit,&w,[dir,number,times]{saveJson(dir+"/frames.json",QJsonObject{{"frame_count",*number},{"nominal_interval_ms",100},{"actual_times",*times},{"provenance","Automated actual QWidget renders, not human interaction or desktop capture; elapsed times may differ from nominal playback"}});});
 }
 if(args.isSet("demo")){
  w.loadFinished=[&](bool ok){if(!ok){exitCode=1;QTimer::singleShot(300,&app,&QCoreApplication::quit);return;}QString wanted=args.value("select-status");if(!wanted.isEmpty())for(int i=0;i<w.model->visible.size();++i)if(w.model->records[w.model->visible[i]].packet.status==wanted){w.table->selectRow(i);break;}if(args.isSet("screenshot"))QTimer::singleShot(250,&w,[&]{bool saved=w.grab().save(args.value("screenshot"));QJsonObject counts;for(const auto& r:w.model->records){QString key=r.packet.status;counts[key]=counts[key].toInt()+1;}QJsonObject report{{"outcome",saved?"pass":"fail"},{"input",args.value("demo")},{"loaded",double(w.captured)},{"retained",w.model->records.size()},{"displayed",w.model->rowCount()},{"display_filter",w.model->filter},{"retained_raw_bytes",double(w.model->retainedBytes)},{"raw_byte_limit",double(kRawBytesLimit)},{"evicted",double(w.model->evicted)},{"oversize_rejected",double(w.oversized)},{"statuses",counts},{"highlighted_field",w.highlightedField},{"highlighted_offset",w.highlightedOffset},{"highlighted_length",w.highlightedLength},{"highlighted_hex",w.highlightedHex},{"ui_timer_ticks",double(w.heartbeatTicks)},{"provenance","Actual application QWidget grab after asynchronous PCAP load; automated, not manually operated"}};if(!saveJson(args.value("screenshot")+".json",report)||!saved){exitCode=1;w.error("Screenshot or report save failed");}});};QTimer::singleShot(50,&w,[&]{w.openCapture(args.value("demo"));});
 }
 if(args.isSet("live-demo")){
  QString out=QDir(args.value("live-demo")).absolutePath();if(!QDir().mkpath(out)||QFileInfo::exists(out+"/live-demo.json")||QFileInfo::exists(out+"/live.pcap")){qCritical()<<"Use a fresh live-demo directory";return 2;}
  auto* receiver=new QUdpSocket(&w);auto* sender=new QUdpSocket(&w);
  if(!receiver->bind(QHostAddress(QHostAddress::LocalHost),quint16(0))||!sender->bind(QHostAddress(QHostAddress::LocalHost),quint16(0))){qCritical()<<"Local UDP bind failed";return 2;}
  auto received=std::make_shared<int>(0);auto payloadOk=std::make_shared<bool>(true);auto rejected=std::make_shared<bool>(false);auto sent=std::make_shared<int>(0);auto firstSend=std::make_shared<qint64>(-1);auto lastSend=std::make_shared<qint64>(-1);
  const QByteArray payload("LAB1-GUI-LIVE-CONTROLLED");
  QObject::connect(receiver,&QUdpSocket::readyRead,&w,[=]{while(receiver->hasPendingDatagrams()){QByteArray b;b.resize(int(receiver->pendingDatagramSize()));receiver->readDatagram(b.data(),b.size());++*received;if(b!=payload)*payloadOk=false;}});
  QTimer::singleShot(300,&w,[&,out,receiver,sender,rejected,sent,payload,firstSend,lastSend]{
   int found=-1;for(int i=0;i<w.interfaces->count();++i)if(w.interfaces->itemData(i).toString()=="\\Device\\NPF_Loopback")found=i;
   if(found<0){w.error("Loopback interface unavailable");exitCode=1;return;}
   w.interfaces->setCurrentIndex(found);w.captureFilter->setText("udp and (");*rejected=!w.startCapture();w.grab().save(out+"/invalid-filter.png");
   QTimer::singleShot(800,&w,[&,out,receiver,sender,rejected,sent,payload,firstSend,lastSend]{
    w.captureFilter->setText(QString("ip and udp and src host 127.0.0.1 and dst host 127.0.0.1 and src port %1 and dst port %2").arg(sender->localPort()).arg(receiver->localPort()));
    if(!w.startCapture()){exitCode=1;return;}
    for(int offset=0;offset<liveCount;offset+=burstSize){int amount=qMin(burstSize,liveCount-offset);int batch=offset/burstSize;QTimer::singleShot(100+batch*burstIntervalMs,&w,[&,sender,receiver,payload,sent,firstSend,lastSend,amount]{
     qint64 now=w.heartbeatClock.elapsed();if(*firstSend<0)*firstSend=now;
     for(int j=0;j<amount;++j)if(sender->writeDatagram(payload,QHostAddress::LocalHost,receiver->localPort())==payload.size())++*sent;
     *lastSend=w.heartbeatClock.elapsed();
    });}
   });
  });
  QTimer::singleShot(liveFinishMs,&w,[&,out,receiver,sender,received,payloadOk,rejected,sent,payload,firstSend,lastSend]{
   w.readLive();QElapsedTimer stop;stop.start();w.stopCapture();qint64 stopMs=stop.elapsed();
   bool exported=w.exportCapture(out+"/live.pcap");if(w.model->rowCount())w.table->selectRow(0);bool shot=w.grab().save(out+"/live.png");
   int expectedRetained=qMin(liveCount,kRetainedLimit);
   bool countsPass=*sent==liveCount&&*received==liveCount&&w.captured==quint64(liveCount)&&w.model->records.size()==expectedRetained&&w.model->evicted==quint64(liveCount-expectedRetained);
   bool responsePass=stopMs<=200&&w.maxHeartbeatGap<=500;
   bool pass=*rejected&&countsPass&&responsePass&&*payloadOk&&w.heartbeatTicks>0&&exported&&shot;
   QJsonObject result{{"outcome",pass?"pass":"fail"},{"expected_count",liveCount},{"sent",*sent},{"socket_received",*received},{"payload_matches",*payloadOk},{"captured",double(w.captured)},{"retained",w.model->records.size()},{"retained_raw_bytes",double(w.model->retainedBytes)},{"evicted",double(w.model->evicted)},{"invalid_filter_rejected",*rejected},{"stop_ms",double(stopMs)},{"stop_threshold_ms",200},{"max_capture_heartbeat_gap_ms",double(w.maxHeartbeatGap)},{"heartbeat_gap_threshold_ms",500},{"responsiveness_pass",responsePass},{"counts_pass",countsPass},{"ui_timer_ticks",double(w.heartbeatTicks)},{"driver_stats_available",w.statsAvailable},{"driver_received",double(w.driverReceived)},{"driver_dropped",double(w.driverDropped)},{"source_port",int(sender->localPort())},{"destination_port",int(receiver->localPort())},{"payload_hex",QString::fromLatin1(payload.toHex())},{"linktype",w.linktype},{"pcap_exported",exported},{"gui_render_saved",shot},{"highlighted_field",w.highlightedField},{"highlighted_offset",w.highlightedOffset},{"highlighted_length",w.highlightedLength},{"highlighted_hex",w.highlightedHex},{"capture_library",QString::fromUtf8(pcap_lib_version())},{"last_error",w.lastError},{"burst_size",burstSize},{"burst_interval_ms",burstIntervalMs},{"nominal_burst_rate_pps",1000.0*burstSize/burstIntervalMs},{"first_send_elapsed_ms",double(*firstSend)},{"last_send_elapsed_ms",double(*lastSend)},{"resource_trace",w.resourceTrace},{"threshold_origin","engineering acceptance choices, not course thresholds or real-time guarantees"},{"boundary","Finite self-generated loopback UDP run; total working set is distinct from retained raw bytes; stop_ms is handler duration, heartbeat covers capture only; no arbitrary-load or external-network claim"}};
   if(!saveJson(out+"/live-demo.json",result))pass=false;if(!pass)exitCode=1;
   w.status(pass?QString("LIVE DEMO PASSED · %1 local UDP packets; bounded retention; stop/export completed.").arg(liveCount):"LIVE DEMO FAILED · Inspect live-demo.json and logs.");
  });
 }
 if(args.isSet("auto-exit")||args.isSet("live-demo")){bool ok=true;int ms=args.isSet("auto-exit")?args.value("auto-exit").toInt(&ok):qMax(6000,liveFinishMs+1500);if(!ok||ms<3000||(args.isSet("live-demo")&&ms<liveFinishMs+500)){qCritical()<<"auto-exit must be >=3000 ms and at least live finish deadline +500 ms";return 2;}QTimer::singleShot(ms,&app,&QCoreApplication::quit);}
 app.exec();if(args.isSet("demo")&&!w.offlineLoaded)exitCode=1;return exitCode;
}





