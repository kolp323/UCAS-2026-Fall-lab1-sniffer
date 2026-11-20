// New recording harness: exercises the existing Window; production GUI is unchanged.
#define main lab1_original_main
#include "../../src/gui.cpp"
#undef main
#include <QPainter>

int main(int argc,char** argv){
 wchar_t sys[MAX_PATH]{};GetSystemDirectoryW(sys,MAX_PATH);std::wstring np=std::wstring(sys)+L"\\Npcap";
 SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_DEFAULT_DIRS);AddDllDirectory(np.c_str());
 QCoreApplication::setAttribute(Qt::AA_DontUseNativeDialogs);
 QApplication app(argc,argv);char err[PCAP_ERRBUF_SIZE]{};if(pcap_init(PCAP_CHAR_ENC_UTF_8,err)!=0)return 2;
 const QString out=app.arguments().value(1),sample=app.arguments().value(2);
 if(out.isEmpty()||sample.isEmpty())return 2;QDir().mkpath(out+"/raw");
 Window w;w.resize(1440,820);w.move(40,40);w.show();
 QElapsedTimer clock;clock.start();QJsonArray frames,events,checks,sentPayloads;
 QTimer record;int frame=0,sent=0,received=0;bool failed=false;quint64 liveCaptured=0;
 auto note=[&](const QString& action){events.append(QJsonObject{{"elapsed_ms",double(clock.elapsed())},{"action",action},{"read",double(w.captured)},{"retained",w.model->records.size()},{"displayed",w.model->rowCount()},{"filter",w.model->filter},{"highlighted_field",w.highlightedField}});};
 auto check=[&](const QString& name,bool ok){checks.append(QJsonObject{{"name",name},{"pass",ok}});if(!ok)failed=true;};
 auto receiver=new QUdpSocket(&w);auto sender=new QUdpSocket(&w);
 check("bind local receiver",receiver->bind(QHostAddress(QHostAddress::LocalHost),quint16(0)));
 QObject::connect(receiver,&QUdpSocket::readyRead,&w,[&]{while(receiver->hasPendingDatagrams()){QByteArray b(int(receiver->pendingDatagramSize()),0);receiver->readDatagram(b.data(),b.size());++received;}});
 auto at=[&](int ms,std::function<void()> fn){QTimer::singleShot(ms,&w,std::move(fn));};
 auto field=[&](const QString& key){for(int i=0;i<w.fields->rowCount();++i)if(w.fields->item(i,0)->text()==key){w.fields->setCurrentCell(i,0);w.fields->scrollToItem(w.fields->item(i,0),QAbstractItemView::PositionAtCenter);QMetaObject::invokeMethod(w.fields,"cellClicked",Qt::DirectConnection,Q_ARG(int,i),Q_ARG(int,0));note("select field "+key);check("highlight "+key,w.highlightedField==key);return;}check("field exists "+key,false);};
 auto filter=[&](const QString& name){w.display->showPopup();QTimer::singleShot(800,&w,[&,name]{w.display->setCurrentText(name);w.display->hidePopup();note("display filter "+name);});};
 auto dialog=[&](QPushButton* button,const QString& file,const QString& label){
  QTimer::singleShot(450,&w,[&,file,label]{auto* d=qobject_cast<QFileDialog*>(QApplication::activeModalWidget());if(!d){check("file dialog "+label,false);return;}d->resize(900,500);d->move(w.mapToGlobal(QPoint(260,160)));d->setDirectory(QFileInfo(file).absolutePath());QTimer::singleShot(500,d,[d,file]{d->selectFile(file);auto* name=d->findChild<QLineEdit*>("fileNameEdit");if(name){name->setText(file);QMetaObject::invokeMethod(name,"textEdited",Qt::DirectConnection,Q_ARG(QString,file));}});note("file dialog "+label);QTimer::singleShot(1600,d,[&,d,label]{QMetaObject::invokeMethod(d,"accept",Qt::DirectConnection);note("confirm "+label);});});
  button->animateClick(180);
 };
 QObject::connect(&record,&QTimer::timeout,&w,[&]{
  QPixmap image=w.grab();QPainter painter(&image);const QPoint origin=w.mapToGlobal(QPoint(0,0));
  for(QWidget* top:QApplication::topLevelWidgets())if(top!=&w&&top->isVisible()&&top->windowType()!=Qt::ToolTip){QPoint pos=top->mapToGlobal(QPoint(0,0))-origin;painter.drawPixmap(pos,top->grab());}
  painter.end();QString name=QString("raw/frame-%1.png").arg(frame++,5,10,QChar('0'));check("save frame",image.save(out+"/"+name));
  frames.append(QJsonObject{{"frame",frame-1},{"file",name},{"elapsed_ms",double(clock.elapsed())},{"read",double(w.captured)},{"displayed",w.model->rowCount()},{"filter",w.model->filter},{"field",w.highlightedField}});
 });record.start(250);
 at(500,[&]{w.interfaces->showPopup();});
 at(2200,[&]{int found=-1;for(int i=0;i<w.interfaces->count();++i)if(w.interfaces->itemData(i).toString().contains("NPF_Loopback"))found=i;check("loopback interface",found>=0);if(found>=0)w.interfaces->setCurrentIndex(found);w.interfaces->hidePopup();note("choose loopback");});
 at(6200,[&]{w.captureFilter->setFocus();w.captureFilter->setText("udp port "+QString::number(receiver->localPort()));note("set capture filter");});
 at(12300,[&]{w.startButton->animateClick(220);note("click start");});
 at(12800,[&]{check("capture active",w.cap!=nullptr);});
 for(int i=0;i<30;++i)at(13200+i*350,[&,i]{QByteArray b="LAB1 GUI DEMO / packet "+QByteArray::number(i+1);if(sender->writeDatagram(b,QHostAddress::LocalHost,receiver->localPort())==b.size())++sent;sentPayloads.append(QString::fromLatin1(b.toHex()));});
 at(19200,[&]{if(w.model->rowCount()>4)w.table->selectRow(4);note("select live packet");});
 at(25300,[&]{w.stopButton->animateClick(220);note("click stop");});
 at(26000,[&]{liveCaptured=w.captured;check("30 datagrams sent received captured",sent==30&&received==30&&w.captured==30);check("capture stopped",w.cap==nullptr);note("capture stopped");});
 at(31300,[&]{dialog(w.saveButton,out+"/live-export.pcap","export PCAP");});
 at(35100,[&]{check("export exists",QFileInfo::exists(out+"/live-export.pcap"));note("export completed");});
 at(37300,[&]{dialog(w.openButton,sample,"open sample");});
 at(41300,[&]{check("sample loaded",w.offlineLoaded&&w.model->records.size()==10);note("sample loaded");});
 at(43200,[&]{filter("HTTP");});
 at(46800,[&]{check("one HTTP row",w.model->rowCount()==1);});
 at(49300,[&]{w.table->selectRow(0);note("select HTTP packet");});
 at(56300,[&]{field("ip.src");});
 at(64300,[&]{field("http.start_line");});
 at(72300,[&]{filter("IPV6");});
 at(76800,[&]{check("IPv6 rows",w.model->rowCount()>0);});
 at(78300,[&]{filter("ALL");});
 at(81800,[&]{check("all ten sample rows",w.model->rowCount()==10);});
 at(88000,[&]{record.stop();saveJson(out+"/tour.json",QJsonObject{{"outcome",failed?"fail":"pass"},{"sent",sent},{"received",received},{"captured",double(liveCaptured)},{"payloads_hex",sentPayloads},{"events",events},{"frames",frames},{"checks",checks},{"duration_ms",double(clock.elapsed())},{"provenance","Independent recording harness includes the unchanged production Window implementation; actual signals, dialogs, sockets and pcap operations."}});app.exit(failed?1:0);});
 return app.exec();
}


