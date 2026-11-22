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
#include "display_filter.h"
#include "tcp_flow.h"
#include "process_view.h"

namespace {
constexpr int kRetainedLimit=2000;
constexpr int kReadBatch=64;
constexpr int kMaxPacket=65535;
constexpr qint64 kRawBytesLimit=16*1024*1024;

const char* const kWindowStyle=R"qss(
QWidget { font-family: "Segoe UI"; font-size: 15px; }
QWidget#workspace, QDialog#flowDialog { background: #f5f6f8; color: #222936; }
QFrame#toolbar, QFrame#pane { background: #ffffff; border: 1px solid #dce1e7; }
QLabel#paneTitle { color: #252d3a; font-weight: 600; }
QLabel#muted { color: #596677; }
QLabel#status { color: #475569; }
QLabel#muted, QLabel#status { font-size: 13px; }
QLineEdit, QComboBox, QPushButton {
  background: #ffffff; color: #273445; border: 1px solid #ccd4de;
  border-radius: 4px; padding: 4px 9px; min-height: 20px;
}
QComboBox { padding-right: 21px; }
QComboBox QAbstractItemView {
  background: #ffffff; color: #273445; selection-background-color: #dce7fa;
  selection-color: #173862; border: 1px solid #c5cedb;
}
QLineEdit:focus, QComboBox:focus, QPushButton:focus { border-color: #42649a; }
QPushButton:hover { background: #edf2f8; }
QPushButton:pressed { background: #dce7fa; }
QPushButton:disabled, QComboBox:disabled, QLineEdit:disabled {
  color: #657181; background: #f3f5f7; border-color: #e0e5eb;
}
QPushButton#startCapture { background: #214d89; border-color: #214d89; color: #ffffff; font-weight: 600; }
QPushButton#startCapture:hover { background: #2b5b9c; }
QPushButton#startCapture:pressed { background: #193d70; }
QPushButton#startCapture:focus { border-color: #7ba3d9; }
QPushButton#startCapture:disabled { background: #f3f5f7; color: #657181; border-color: #e0e5eb; }
QPushButton#stopCapture { color: #963b36; border-color: #d5ada8; font-weight: 600; }
QPushButton#stopCapture:hover { background: #fbefed; }
QPushButton#stopCapture:focus { border-color: #963b36; }
QTableView, QPlainTextEdit { border: none; background: #ffffff; color: #222d3b; }
QPlainTextEdit { font-family: "Consolas"; font-size: 14px; padding: 4px; }
QTableView::item { padding: 0 7px; }
QTableView { alternate-background-color: #f7f9fb; selection-background-color: #dae7fb; selection-color: #183a68; }
QHeaderView::section {
  background: #eff2f6; color: #475467; border: none;
  border-bottom: 1px solid #dce1e7; padding: 4px 7px; font-weight: 600;
}
QSplitter::handle { background: #f5f6f8; }
QScrollBar { border: none; background: #f2f4f7; }
QScrollBar:vertical { width: 11px; }
QScrollBar:horizontal { height: 11px; }
QScrollBar::handle { background: #bcc6d3; border: 2px solid #f2f4f7; border-radius: 4px; min-width: 22px; min-height: 22px; }
QScrollBar::add-line, QScrollBar::sub-line { width: 0; height: 0; }
QScrollBar::add-page, QScrollBar::sub-page { background: transparent; }
)qss";

void configureTable(QTableView* view){
 view->setSelectionBehavior(QAbstractItemView::SelectRows);
 view->setSelectionMode(QAbstractItemView::SingleSelection);
 view->setAlternatingRowColors(true);
 view->setShowGrid(false);
 view->setEditTriggers(QAbstractItemView::NoEditTriggers);
 view->verticalHeader()->hide();
 view->verticalHeader()->setDefaultSectionSize(25);
 view->horizontalHeader()->setSectionsClickable(false);
 view->horizontalHeader()->setDefaultAlignment(Qt::AlignLeft | Qt::AlignVCenter);
 view->horizontalHeader()->setStretchLastSection(true);
}

QFrame* makePane(const QString& title,QWidget* content,QWidget* trailing=nullptr){
 auto* pane=new QFrame;
 pane->setObjectName("pane");
 auto* layout=new QVBoxLayout(pane);
 layout->setContentsMargins(1,1,1,1);
 layout->setSpacing(0);
 auto* heading=new QHBoxLayout;
 heading->setContentsMargins(10,5,8,5);
 auto* label=new QLabel(title);
 label->setObjectName("paneTitle");
 label->setMinimumHeight(24);
 heading->addWidget(label);
 heading->addStretch();
 if(trailing)heading->addWidget(trailing);
 layout->addLayout(heading);
 layout->addWidget(content,1);
 return pane;
}
struct Record { quint64 id; QByteArray bytes; pcap_pkthdr header; lab1::Packet packet; };
class PacketModel : public QAbstractTableModel {
public:
 QVector<Record> records;
 QVector<int> visible;
 QString filter="ALL";
 lab1::DisplayPredicate predicate;
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
  if(role==Qt::TextAlignmentRole && (i.column()==0 || i.column()==4))
   return int(Qt::AlignRight | Qt::AlignVCenter);
  if(role==Qt::ForegroundRole && i.column()==5){
   if(r.packet.status=="malformed")return QColor("#a53137");
   if(r.packet.status!="valid")return QColor("#82581f");
   return QColor("#596677");
  }
  if(role!=Qt::DisplayRole && role!=Qt::ToolTipRole)return {};
  switch(i.column()){
   case 0:return QVariant::fromValue<qulonglong>(r.id);case 1:return r.packet.src;case 2:return r.packet.dst;
   case 3:return r.packet.protocol;case 4:return int(r.header.caplen);case 5:return r.packet.status;
   case 6:return r.packet.srcPort>=0?QString("%1 → %2").arg(r.packet.srcPort).arg(r.packet.dstPort):QString();
   case 7:return r.packet.info;default:return {};
  }
 }
 void rebuild(){visible.clear();for(int i=0;i<records.size();++i)if((!predicate||predicate(records[i].packet))&&lab1::matchesDisplayFilter(records[i].packet,filter))visible.append(i);}
 void reset(){beginResetModel();records.clear();visible.clear();evicted=0;retainedBytes=0;endResetModel();}
 void setFilter(const QString& f){beginResetModel();filter=f;rebuild();endResetModel();}
 void append(QVector<Record>& rows){if(rows.isEmpty())return;beginResetModel();for(auto& r:rows){retainedBytes+=r.bytes.size();records.append(std::move(r));}int excess=0;while(records.size()-excess>kRetainedLimit || retainedBytes>kRawBytesLimit){retainedBytes-=records[excess].bytes.size();++excess;}if(excess>0){records.erase(records.begin(),records.begin()+excess);evicted+=excess;}rebuild();endResetModel();}
};
class Window : public QMainWindow {
public:
 PacketModel* model;
 QComboBox *interfaces,*display;
 QLineEdit *captureFilter,*displayExpression;
 QPushButton *applyExpression,*flowButton;
 QPushButton *startButton,*stopButton,*openButton,*saveButton;
 QLabel *state,*counts,*sourceLabel,*byteRange;
 QStackedWidget* captureAction;
 QTableView* table;
 QTableWidget* fields;
 QPlainTextEdit* hex;
 QSplitter* panes;
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
  setWindowTitle("Lab 1A · Packet Analyzer");
  resize(1320,820);
  setMinimumSize(960,620);
  setStyleSheet(kWindowStyle);

  auto* central=new QWidget;
  central->setObjectName("workspace");
  auto* layout=new QVBoxLayout(central);
  layout->setContentsMargins(10,10,10,6);
  layout->setSpacing(8);

  auto* toolbar=new QFrame;
  toolbar->setObjectName("toolbar");
  auto* controls=new QGridLayout(toolbar);
  controls->setContentsMargins(10,8,10,8);
  controls->setHorizontalSpacing(8);
  controls->setVerticalSpacing(7);
  controls->setColumnStretch(3,1);
  interfaces=new QComboBox;
  interfaces->setMinimumWidth(216);
  interfaces->setMaximumWidth(290);
  interfaces->setSizeAdjustPolicy(QComboBox::AdjustToMinimumContentsLengthWithIcon);
  captureFilter=new QLineEdit;
  captureFilter->setPlaceholderText("Optional BPF expression");
  captureFilter->setToolTip("Capture filter. Leave empty to capture all packets on this interface.");
  startButton=new QPushButton("Start capture");
  startButton->setObjectName("startCapture");
  stopButton=new QPushButton("Stop capture");
  stopButton->setObjectName("stopCapture");
  captureAction=new QStackedWidget;
  captureAction->addWidget(startButton);
  captureAction->addWidget(stopButton);
  stopButton->setEnabled(false);
  openButton=new QPushButton("Open…");
  openButton->setToolTip("Open a PCAP or PCAPNG file");
  saveButton=new QPushButton("Export…");
  saveButton->setToolTip("Export all retained packets as PCAP");
  controls->addWidget(new QLabel("Interface"),0,0);
  controls->addWidget(interfaces,0,1);
  controls->addWidget(new QLabel("Capture filter"),0,2);
  controls->addWidget(captureFilter,0,3);
  controls->addWidget(captureAction,0,4);
  controls->addWidget(openButton,0,5);
  controls->addWidget(saveButton,0,6);

  display=new QComboBox;
  display->addItems({"ALL","ETHERNET","IPV4","IPV6","TCP","UDP","ICMP","ICMPV6","HTTP"});
  displayExpression=new QLineEdit;
  displayExpression->setMaxLength(512);
  displayExpression->setPlaceholderText("Optional field expression");
  displayExpression->setToolTip("Example: HTTP AND tcp.dstport == 80. Combines with the protocol selection.");
  applyExpression=new QPushButton("Apply");
  flowButton=new QPushButton("TCP flow");
  flowButton->setToolTip("Inspect the selected TCP connection");
  controls->addWidget(new QLabel("Protocol"),1,0);
  controls->addWidget(display,1,1);
  controls->addWidget(new QLabel("Display filter"),1,2);
  controls->addWidget(displayExpression,1,3);
  controls->addWidget(applyExpression,1,4);
  auto* processes = new QPushButton("Process flows…");
  processes->setObjectName("processFlows");
  processes->setToolTip("Track live Windows TCP connections by local process ID");
  controls->addWidget(processes,1,5,1,2);
  connect(processes, &QPushButton::clicked, this, [this]{
      lab1::ProcessView::MatchPackets match;
      if (cap) match = [this](const QString& expression){
          display->setCurrentText("ALL");
          displayExpression->setText(expression);
          applyDisplayExpression();
      };
      lab1::ProcessView dialog(this, match);
      dialog.exec();
  });
  layout->addWidget(toolbar);

  model=new PacketModel(this);
  table=new QTableView;
  table->setModel(model);
  configureTable(table);
  table->setColumnWidth(0,52);
  table->setColumnWidth(1,153);
  table->setColumnWidth(2,153);
  table->setColumnWidth(3,94);
  table->setColumnWidth(4,62);
  table->setColumnWidth(5,90);
  table->setColumnWidth(6,132);

  fields=new QTableWidget;
  fields->setColumnCount(4);
  fields->setHorizontalHeaderLabels({"Field","Value","Offset","Length"});
  configureTable(fields);
  fields->setColumnWidth(0,163);
  auto* fieldColumns=fields->horizontalHeader();
  fieldColumns->setStretchLastSection(false);
  fieldColumns->setSectionResizeMode(1,QHeaderView::Stretch);
  fields->setColumnWidth(2,72);
  fields->setColumnWidth(3,72);

  hex=new QPlainTextEdit;
  hex->setReadOnly(true);
  hex->setLineWrapMode(QPlainTextEdit::NoWrap);
  hex->setPlaceholderText("Select a packet to inspect its bytes.");
  byteRange=new QLabel;
  byteRange->setObjectName("muted");
  byteRange->setTextFormat(Qt::PlainText);
  byteRange->setSizePolicy(QSizePolicy::Fixed,QSizePolicy::Preferred);
  byteRange->setAlignment(Qt::AlignRight | Qt::AlignVCenter);

  auto* details=new QSplitter(Qt::Horizontal);
  details->setChildrenCollapsible(false);
  details->setHandleWidth(8);
  details->addWidget(makePane("Protocol fields",fields));
  details->addWidget(makePane("Packet bytes",hex,byteRange));
  details->setSizes({615,680});

  panes=new QSplitter(Qt::Vertical);
  panes->setChildrenCollapsible(false);
  panes->setHandleWidth(8);
  panes->addWidget(makePane("Packets",table,flowButton));
  panes->addWidget(details);
  panes->setSizes({315,390});
  layout->addWidget(panes,1);

  auto* footer=new QHBoxLayout;
  sourceLabel=new QLabel("No capture source");
  sourceLabel->setObjectName("muted");
  sourceLabel->setTextFormat(Qt::PlainText);
  sourceLabel->setSizePolicy(QSizePolicy::Ignored,QSizePolicy::Preferred);
  state=new QLabel;
  state->setTextFormat(Qt::PlainText);
  state->setObjectName("status");
  state->setSizePolicy(QSizePolicy::Ignored,QSizePolicy::Preferred);
  counts=new QLabel;
  counts->setObjectName("muted");
  footer->addWidget(sourceLabel,2);
  footer->addWidget(state,3);
  footer->addWidget(counts);
  layout->addLayout(footer);
  setCentralWidget(central);
  connect(startButton,&QPushButton::clicked,this,[this]{startCapture();});connect(stopButton,&QPushButton::clicked,this,[this]{stopCapture();});
  connect(display,&QComboBox::currentTextChanged,this,[this](const QString& s){model->setFilter(s);clearDetails();if(model->rowCount())table->selectRow(0);updateCounts();});
  connect(applyExpression,&QPushButton::clicked,this,[this]{applyDisplayExpression();});
  connect(displayExpression,&QLineEdit::returnPressed,this,[this]{applyDisplayExpression();});
  connect(flowButton,&QPushButton::clicked,this,[this]{showFlow();});
  connect(openButton,&QPushButton::clicked,this,[this]{auto p=QFileDialog::getOpenFileName(this,"Open fixed capture",QString(),"Captures (*.pcap *.pcapng);;All files (*)");if(!p.isEmpty())openCapture(p);});
  connect(saveButton,&QPushButton::clicked,this,[this]{auto p=QFileDialog::getSaveFileName(this,"Export retained packets",QString(),"PCAP (*.pcap)");if(!p.isEmpty())exportCapture(p);});
  connect(table->selectionModel(),&QItemSelectionModel::selectionChanged,this,[this]{showSelected();});
  connect(fields,&QTableWidget::currentCellChanged,this,[this](int row,int,int,int){highlightField(row);});
  poll.setInterval(20);connect(&poll,&QTimer::timeout,this,[this]{readLive();});offlinePoll.setInterval(0);connect(&offlinePoll,&QTimer::timeout,this,[this]{readOffline();});
  heartbeatClock.start();uiHeartbeat.setInterval(50);connect(&uiHeartbeat,&QTimer::timeout,this,[this]{
   ++heartbeatTicks;qint64 now=heartbeatClock.elapsed();if(cap)maxHeartbeatGap=qMax(maxHeartbeatGap,now-lastHeartbeat);lastHeartbeat=now;
   PROCESS_MEMORY_COUNTERS memory{};memory.cb=sizeof(memory);bool memOk=GetProcessMemoryInfo(GetCurrentProcess(),&memory,sizeof(memory))!=0;
   FILETIME creation{},exit{},kernel{},user{};bool cpuOk=GetProcessTimes(GetCurrentProcess(),&creation,&exit,&kernel,&user)!=0;
   auto ticks=[](const FILETIME& f){return (quint64(f.dwHighDateTime)<<32)|f.dwLowDateTime;};
   resourceTrace.append(QJsonObject{{"elapsed_ms",double(now)},{"capturing",cap!=nullptr},{"captured",double(captured)},{"retained",model->records.size()},{"retained_raw_bytes",double(model->retainedBytes)},{"evicted",double(model->evicted)},{"working_set_bytes",memOk?double(memory.WorkingSetSize):-1.0},{"cpu_ms",cpuOk?double(ticks(kernel)+ticks(user))/10000.0:-1.0}});
   if(resourceTrace.size()>2400)resourceTrace.removeFirst();
  });uiHeartbeat.start();clearDetails();enumerate();updateCounts();
 }
 ~Window(){stopCapture(false);closeOffline();}
 void error(const QString& s){
  lastError=s;
  status(s);
  state->setStyleSheet("color: #a53137;");
  qWarning().noquote()<<s;
 }
 void status(const QString& s){
  state->setStyleSheet(QString());
  state->setText(s);
  state->setToolTip(s);
 }
 void setSource(const QString& name,const QString& details){
  sourceLabel->setText(name);
  sourceLabel->setToolTip(details);
 }
 bool applyDisplayExpression(){
  QString why;
  auto compiled=lab1::compileDisplayFilter(displayExpression->text(),why);
  if(!compiled){error("Display expression: "+why+". Previous expression retained.");return false;}
  model->predicate=std::move(compiled);
  model->setFilter(display->currentText());
  clearDetails();
  if(model->rowCount())table->selectRow(0);
  updateCounts();
  status(cap?"Capturing":QString());
  return true;
 }
 lab1::TcpFlow selectedFlow() const {
  const auto index=table->currentIndex();
  if(!index.isValid()||index.row()>=model->visible.size())return {};
  QVector<lab1::FlowSegment> input;
  input.reserve(model->records.size());
  for(const auto& r:model->records){
   const auto time=qint64(r.header.ts.tv_sec)*1000000+r.header.ts.tv_usec;
   input.append({r.id,time,&r.packet});
  }
  return lab1::followTcp(input,model->records[model->visible[index.row()]].id);
 }
 void showFlow(){
  const auto flow=selectedFlow();
  if(flow.rows.isEmpty()){error("Select a complete TCP packet to inspect its flow.");return;}
  QDialog dialog(this);
  dialog.setObjectName("flowDialog");
  dialog.setWindowTitle("TCP flow");
  dialog.resize(1100,468);
  auto* layout=new QVBoxLayout(&dialog);
  layout->setContentsMargins(12,12,12,10);
  layout->setSpacing(8);
  auto* endpoints=new QLabel(QString("A  %1     ↔     B  %2").arg(flow.endpoint[0],flow.endpoint[1]));
  endpoints->setTextFormat(Qt::PlainText);
  endpoints->setObjectName("paneTitle");
  layout->addWidget(endpoints);
  auto* summary=new QLabel(QString("A → B   %1 packets / %2 B     ·     B → A   %3 packets / %4 B     ·     %5")
                           .arg(flow.counts[0]).arg(flow.bytes[0]).arg(flow.counts[1]).arg(flow.bytes[1]).arg(flow.state));
  summary->setObjectName("muted");
  summary->setTextFormat(Qt::PlainText);
  summary->setToolTip("Payload totals include repeated segments in the retained capture window.");
  layout->addWidget(summary);
  auto* rows=new QTableWidget(flow.rows.size(),8);
  rows->setHorizontalHeaderLabels({"No.","Time (ms)","Direction","Flags","Seq","Ack","Payload B","Event"});
  configureTable(rows);
  rows->verticalHeader()->setMinimumSectionSize(22);
  rows->verticalHeader()->setDefaultSectionSize(28);
  for(int i=0;i<flow.rows.size();++i){
   const auto& r=flow.rows[i];
   const QStringList cells={QString::number(r.id),QString::number((r.micros-flow.rows.first().micros)/1000.0,'f',3),
     r.direction==0?"A → B":"B → A",lab1::tcpFlags(r.flags),QString::number(r.seq),
     QString::number(r.ack),QString::number(r.payloadBytes),r.event};
   for(int j=0;j<cells.size();++j){
    auto* cell=new QTableWidgetItem(cells[j]);
    if(j==0 || j==1 || (j>=4 && j<=6))cell->setTextAlignment(Qt::AlignRight | Qt::AlignVCenter);
    rows->setItem(i,j,cell);
   }
  }
  rows->horizontalHeader()->setMinimumSectionSize(65);
  rows->horizontalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);
  rows->horizontalHeader()->setStretchLastSection(true);
  auto* frame=new QFrame;
  frame->setObjectName("pane");
  auto* tableLayout=new QVBoxLayout(frame);
  tableLayout->setContentsMargins(1,1,1,1);
  tableLayout->addWidget(rows);
  layout->addWidget(frame,1);
  auto* close=new QPushButton("Close");
  layout->addWidget(close,0,Qt::AlignRight);
  connect(close,&QPushButton::clicked,&dialog,&QDialog::accept);
  close->setFocus();
  dialog.exec();
 }
 void clearDetails(){fields->setRowCount(0);hex->clear();byteRange->clear();byteRange->setToolTip(QString());flowButton->setEnabled(false);hex->setExtraSelections({});highlightedField.clear();highlightedHex.clear();highlightedOffset=-1;highlightedLength=0;}
 void updateCounts(){
  saveButton->setEnabled(!model->records.isEmpty());
  QString summary=QString("%1 shown / %2 retained").arg(model->rowCount()).arg(model->records.size());
  if(model->evicted)summary+=QString("   ·   %1 evicted").arg(model->evicted);
  if(oversized)summary+=QString("   ·   %1 rejected").arg(oversized);
  if(statsAvailable && driverDropped)summary+=QString("   ·   %1 driver drops").arg(driverDropped);
  counts->setText(summary);
  counts->setToolTip(QString("Read: %1   ·   Raw bytes: %2 / %3   ·   Retained limit: %4\\n"
                            "Evicted: %5   ·   Oversize rejected: %6   ·   Driver received / dropped: %7")
                     .arg(captured).arg(model->retainedBytes).arg(kRawBytesLimit).arg(kRetainedLimit)
                     .arg(model->evicted).arg(oversized)
                     .arg(statsAvailable?QString("%1 / %2").arg(driverReceived).arg(driverDropped):"unavailable"));
 }
 void enumerate(){
  interfaces->clear();
  char err[PCAP_ERRBUF_SIZE]{};
  pcap_if_t* list=nullptr;
  if(pcap_findalldevs(&list,err)!=0){error(QString::fromUtf8(err));return;}
  for(auto* device=list;device;device=device->next){
   const QString name=QString::fromUtf8(device->name);
   const QString description=device->description?QString::fromUtf8(device->description):name;
   const QString label=name.endsWith("NPF_Loopback")?"Npcap Loopback":description;
   interfaces->addItem(label,name);
   interfaces->setItemData(interfaces->count()-1,description,Qt::ToolTipRole);
  }
  pcap_freealldevs(list);
  if(interfaces->count()==0)error("No capture interfaces. Check Npcap and permissions.");
 }
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
  cap=c;linktype=pcap_datalink(cap);resetData();lastHeartbeat=heartbeatClock.elapsed();maxHeartbeatGap=0;startButton->setEnabled(false);stopButton->setEnabled(true);captureAction->setCurrentWidget(stopButton);interfaces->setEnabled(false);captureFilter->setEnabled(false);openButton->setEnabled(false);setSource(interfaces->currentText(),QString("Link type %1 · BPF: %2").arg(linktype).arg(captureFilter->text().isEmpty()?"(all)":captureFilter->text()));status("Capturing");poll.start();return true;
 }
 void stopCapture(bool announce=true){poll.stop();if(cap){pcap_stat s{};statsAvailable=pcap_stats(cap,&s)==0;if(statsAvailable){driverReceived=s.ps_recv;driverDropped=s.ps_drop;}pcap_close(cap);cap=nullptr;if(announce)status("Capture stopped");}startButton->setEnabled(true);stopButton->setEnabled(false);captureAction->setCurrentWidget(startButton);interfaces->setEnabled(true);captureFilter->setEnabled(true);openButton->setEnabled(true);updateCounts();}
 void addRecord(QVector<Record>& batch,const pcap_pkthdr* h,const u_char* data){++captured;if(h->caplen>kMaxPacket){++oversized;return;}Record r;r.id=captured;r.header=*h;r.bytes=QByteArray(reinterpret_cast<const char*>(data),int(h->caplen));r.packet=lab1::parsePacket(r.bytes,linktype,h->len);batch.append(std::move(r));}
 void acceptBatch(QVector<Record>& batch){if(batch.isEmpty())return;quint64 selected=0;auto index=table->currentIndex();if(index.isValid()&&index.row()<model->visible.size())selected=model->records[model->visible[index.row()]].id;model->append(batch);int found=-1;for(int i=0;i<model->visible.size();++i)if(model->records[model->visible[i]].id==selected){found=i;break;}if(found>=0)table->selectRow(found);else{clearDetails();if(model->rowCount())table->selectRow(0);}updateCounts();}
 void readLive(){if(!cap)return;QVector<Record> batch;QElapsedTimer budget;budget.start();for(int i=0;i<kReadBatch&&budget.elapsed()<5;++i){pcap_pkthdr* h=nullptr;const u_char* data=nullptr;int rc=pcap_next_ex(cap,&h,&data);if(rc==0)break;if(rc<0){QString err=QString::fromUtf8(pcap_geterr(cap));stopCapture(false);error("Capture read failed: "+err);break;}addRecord(batch,h,data);}acceptBatch(batch);}
 bool openCapture(const QString& path){stopCapture(false);closeOffline();offlineLoaded=false;QFileInfo info(path);if(!info.isFile()||info.size()>128*1024*1024){error("Input must be a regular capture file of at most 128 MiB.");if(loadFinished)loadFinished(false);return false;}char err[PCAP_ERRBUF_SIZE]{};offline=pcap_open_offline(path.toUtf8().constData(),err);if(!offline){error(QString::fromUtf8(err));if(loadFinished)loadFinished(false);return false;}linktype=pcap_datalink(offline);resetData();offlinePath=path;setSource(info.fileName(),QString("%1 · Link type %2").arg(info.absoluteFilePath()).arg(linktype));status("Opening capture…");openButton->setEnabled(false);startButton->setEnabled(false);offlinePoll.start();return true;}
 void readOffline(){if(!offline)return;QVector<Record> batch;bool finished=false,ok=true;QString why;QElapsedTimer budget;budget.start();for(int i=0;i<kReadBatch&&budget.elapsed()<5;++i){pcap_pkthdr* h=nullptr;const u_char* data=nullptr;int rc=pcap_next_ex(offline,&h,&data);if(rc==-2){finished=true;break;}if(rc<0){finished=true;ok=false;why=QString::fromUtf8(pcap_geterr(offline));break;}if(rc==0)break;addRecord(batch,h,data);}acceptBatch(batch);if(finished){closeOffline();openButton->setEnabled(true);startButton->setEnabled(true);offlineLoaded=ok;if(ok)status(QString());else error("Capture file read failed: "+why);if(model->rowCount())table->selectRow(0);if(loadFinished)loadFinished(ok);}}
 bool exportCapture(const QString& path){if(model->records.isEmpty()){error("No retained packets to export.");return false;}auto* dead=pcap_open_dead(linktype,kMaxPacket);if(!dead){error("Could not create PCAP writer.");return false;}auto* writer=pcap_dump_open(dead,path.toUtf8().constData());if(!writer){error(QString::fromUtf8(pcap_geterr(dead)));pcap_close(dead);return false;}for(const auto& r:model->records)pcap_dump(reinterpret_cast<u_char*>(writer),&r.header,reinterpret_cast<const u_char*>(r.bytes.constData()));int rc=pcap_dump_flush(writer);pcap_dump_close(writer);pcap_close(dead);if(rc!=0){error("PCAP flush failed.");return false;}status(QString("Exported %1 retained packets").arg(model->records.size()));return true;}
 void highlightField(int row){
  if(row<0||row>=fields->rowCount()||!fields->item(row,3))return;
  auto index=table->currentIndex();if(!index.isValid()||index.row()>=model->visible.size())return;
  const auto& r=model->records[model->visible[index.row()]];
  int offset=fields->item(row,2)->text().toInt(),length=fields->item(row,3)->text().toInt();
  if(offset<0||length<0||offset>r.bytes.size()||length>r.bytes.size()-offset)return;
  highlightedField=fields->item(row,0)->text();highlightedOffset=offset;highlightedLength=length;
  highlightedHex=QString::fromLatin1(r.bytes.mid(offset,length).toHex());
  QList<QTextEdit::ExtraSelection> selections;int end=qMin(offset+length,4096);
  for(int at=offset;at<end;){int line=at/16,column=at%16,run=qMin(end-at,16-column);QTextBlock b=hex->document()->findBlockByNumber(line);if(!b.isValid())break;QTextEdit::ExtraSelection sel;sel.cursor=QTextCursor(b);sel.cursor.setPosition(b.position()+6+column*3);sel.cursor.movePosition(QTextCursor::Right,QTextCursor::KeepAnchor,run*3-1);sel.format.setBackground(QColor("#f4d47c"));sel.format.setForeground(QColor("#182d40"));selections.append(sel);at+=run;}
  hex->setExtraSelections(selections);
  if(!selections.isEmpty()){QTextCursor cursor=selections.first().cursor;cursor.clearSelection();hex->setTextCursor(cursor);hex->ensureCursorVisible();}
  const QString range=QString("[%1, %2)").arg(offset).arg(offset+length);
  const QString label=offset>=4096?range+" outside preview":range;
  byteRange->setText(label);
  byteRange->setToolTip(highlightedField+" · "+label);
 }
 void showSelected(){
  const auto index=table->currentIndex();
  if(!index.isValid()||index.row()>=model->visible.size()){clearDetails();return;}
  const auto& r=model->records[model->visible[index.row()]];
  const QSignalBlocker blockFieldSignals(fields);
  fields->setRowCount(r.packet.fields.size());
  for(int i=0;i<r.packet.fields.size();++i){
   const auto& f=r.packet.fields[i];
   const QStringList cells={f.name,f.value,QString::number(f.offset),QString::number(f.length)};
   for(int j=0;j<cells.size();++j)fields->setItem(i,j,new QTableWidgetItem(cells[j]));
  }
  QString dump;
  const int show=qMin(4096,r.bytes.size());
  for(int off=0;off<show;off+=16){
   QString hexPart,ascii;
   for(int j=0;j<16;++j){
    if(off+j<show){
     const unsigned b=static_cast<unsigned char>(r.bytes[off+j]);
     hexPart+=QString("%1 ").arg(b,2,16,QChar('0'));
     ascii+=(b>=32&&b<127)?QChar(b):QChar('.');
    }else hexPart+="   ";
   }
   dump+=QString("%1  %2 %3\n").arg(off,4,16,QChar('0')).arg(hexPart,ascii);
  }
  if(show<r.bytes.size())dump+="\nPreview: first 4096 bytes\n";
  hex->setPlainText(dump);
  byteRange->setText(QString("%1 / %2 B").arg(r.header.caplen).arg(r.header.len));
  byteRange->setToolTip("Captured / original bytes");
  flowButton->setEnabled(r.packet.transport=="TCP" && r.packet.status=="valid"
                         && r.packet.srcPort>=0 && !r.packet.src.isEmpty());
  if(fields->rowCount()){
   const int selected=qMin(1,fields->rowCount()-1);
   fields->setCurrentCell(selected,0);
   highlightField(selected);
  }
 }
 void closeEvent(QCloseEvent* e)override{stopCapture(false);closeOffline();QMainWindow::closeEvent(e);}
};
bool saveJson(const QString& path,const QJsonObject& o){QSaveFile f(path);if(!f.open(QIODevice::WriteOnly))return false;f.write(QJsonDocument(o).toJson());return f.commit();}
}
int main(int argc,char** argv){
 wchar_t sys[MAX_PATH]{};GetSystemDirectoryW(sys,MAX_PATH);std::wstring np=std::wstring(sys)+L"\\Npcap";SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_DEFAULT_DIRS);AddDllDirectory(np.c_str());
 QApplication app(argc,argv);app.setApplicationName("Lab 1A Packet Analyzer");char pcapError[PCAP_ERRBUF_SIZE]{};if(pcap_init(PCAP_CHAR_ENC_UTF_8,pcapError)!=0){qCritical()<<pcapError;return 2;}
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





