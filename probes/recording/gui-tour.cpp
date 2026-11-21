// Recording harness for the production Window and its normal widget input paths.
#define main lab1_original_main
#include "../../src/gui.cpp"
#undef main

#include <QDialogButtonBox>
#include <QPainter>
#include <QPointer>
#include <QThread>
#include <atomic>
#include <QVariantAnimation>
#include <QtTest/QtTest>

int main(int argc, char** argv) {
 wchar_t sys[MAX_PATH]{};
 GetSystemDirectoryW(sys, MAX_PATH);
 const std::wstring np = std::wstring(sys) + L"\\Npcap";
 SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_DEFAULT_DIRS);
 AddDllDirectory(np.c_str());
 QCoreApplication::setAttribute(Qt::AA_DontUseNativeDialogs);
 QApplication app(argc, argv);
 char err[PCAP_ERRBUF_SIZE]{};
 if (pcap_init(PCAP_CHAR_ENC_UTF_8, err) != 0) return 2;
 const QString out = app.arguments().value(1), sample = app.arguments().value(2);
 const QString liveSample=app.arguments().value(3), serverPort=app.arguments().value(4);
 if (out.isEmpty() || sample.isEmpty() || liveSample.isEmpty() || serverPort.isEmpty()) return 2;
 QDir().mkpath(out + "/raw");

 Window w;
 w.resize(1440, 820);
 w.move(40, 40);
 w.show();

 QElapsedTimer clock;
 clock.start();
 QJsonArray frames, events, checks, sentPayloads, pointer, clicks;
 QTimer record;
 QThread frameWriter;
 auto* worker = new QObject;
 worker->moveToThread(&frameWriter);
 QObject::connect(&frameWriter, &QThread::finished, worker, &QObject::deleteLater);
 std::atomic<int> failedSaves{0};
 frameWriter.start();
 int frame = 0, sent = 0, received = 0;
 bool failed = false;
 quint64 liveCaptured = 0;
 QPoint cursor = w.mapToGlobal(QPoint(48, 76));
 auto note = [&](const QString& action) {
  events.append(QJsonObject{{"elapsed_ms", double(clock.elapsed())}, {"action", action},
   {"read", double(w.captured)}, {"retained", w.model->records.size()},
   {"displayed", w.model->rowCount()}, {"filter", w.model->filter},
   {"highlighted_field", w.highlightedField}});
 };
 auto check = [&](const QString& name, bool ok) {
  checks.append(QJsonObject{{"name", name}, {"pass", ok}});
  failed |= !ok;
 };
 auto at = [&](int ms, std::function<void()> fn) { QTimer::singleShot(ms, Qt::PreciseTimer, &w, std::move(fn)); };
 auto position = [&] {
  const QPoint local = w.mapFromGlobal(cursor);
  return QJsonObject{{"elapsed_ms", double(clock.elapsed())}, {"x", local.x()}, {"y", local.y()}};
 };
 pointer.append(position());

 // Drive the exposed Qt windows using pointer events. The video uses these same
 // positions, even when the Windows desktop cursor is outside the recording.
 auto movePointer = [&](const QPoint& global) {
  cursor = global;
  pointer.append(position());
  QWidget* top = QApplication::activePopupWidget();
  if (!top) top = QApplication::activeModalWidget();
  if (!top) top = &w;
  const QPoint local = top->mapFromGlobal(global);
  if (auto* target = top->childAt(local)) {
   QMouseEvent move(QEvent::MouseMove, target->mapFromGlobal(global), global,
                    Qt::NoButton, Qt::NoButton, Qt::NoModifier);
   QCoreApplication::sendEvent(target, &move);
  }
 };
 auto click = [&](const QString& action, QWidget* widget, QPoint local,
                  std::function<void()> after = {}, std::function<void()> beforeRelease = {}) {
  if (!widget || !widget->isVisible() || !widget->rect().contains(local)) {
   check("visible target " + action, false);
   return;
  }
  const QPoint global = widget->mapToGlobal(local);
  const QPointer<QWidget> target(widget);
  auto* motion = new QVariantAnimation(&w);
  motion->setStartValue(cursor);
  motion->setEndValue(global);
  motion->setDuration(620);
  motion->setEasingCurve(QEasingCurve::InOutCubic);
  QObject::connect(motion, &QVariantAnimation::valueChanged, &w, [&](const QVariant& value) {
   movePointer(value.toPoint());
  });
  QObject::connect(motion, &QVariantAnimation::finished, &w, [&, action, target, global, after, beforeRelease] {
   if (!target || !target->isVisible() || !target->isEnabled()) {
    check("clickable target " + action, false);
    return;
   }
   const QPointer<QWindow> window(target->window()->windowHandle());
   if (!window) { check("window for " + action, false); return; }
   const QPoint pos = window->mapFromGlobal(global);
   const auto pressed = clock.elapsed();
   QTest::mousePress(window, Qt::LeftButton, Qt::NoModifier, pos, 0);
   QTimer::singleShot(140, Qt::PreciseTimer, &w, [&, window, pos, action, after, beforeRelease, pressed] {
    if (!window) { check("release " + action, false); return; }
    auto entry = position();
    entry.insert("action", action);
    entry.insert("pressed_ms", double(pressed));
    clicks.append(entry);
    if (beforeRelease) beforeRelease();
    QTest::mouseRelease(window, Qt::LeftButton, Qt::NoModifier, pos, 0);
    note(action);
    if (after) after();
   });
  });
  motion->start(QAbstractAnimation::DeleteWhenStopped);
 };
 auto button = [&](const QString& action, QPushButton* control) {
  click(action, control, control->rect().center());
 };
 auto combo = [&](QComboBox* control, int index, const QString& action) {
  check("option exists " + action, index >= 0);
  if (index < 0) return;
  click("open choices for " + action, control, QPoint(control->width()-12, control->height()/2), [&, control, index, action] {
   at(650, [&, control, index, action] {
    auto* view = control->view();
    const QModelIndex item = control->model()->index(index, control->modelColumn(), control->rootModelIndex());
    view->scrollTo(item);
    click(action, view->viewport(), view->visualRect(item).center(), [&, control, index, action] {
     check("selection " + action, control->currentIndex() == index && !control->view()->isVisible());
    });
   });
  });
 };
 auto packet = [&](int row, const QString& action) {
  const QModelIndex cell = w.model->index(row, 1);
  w.table->scrollTo(cell);
  click(action, w.table->viewport(), w.table->visualRect(cell).center(), [&, row, action] {
   check("selection " + action, w.table->currentIndex().row() == row);
  });
 };
 auto field = [&](const QString& key, const QString& hex) {
  for (int i = 0; i < w.fields->rowCount(); ++i) {
   auto* item = w.fields->item(i, 0);
   if (item->text() != key) continue;
   w.fields->scrollToItem(item, QAbstractItemView::PositionAtCenter);
   click("select field " + key, w.fields->viewport(), w.fields->visualItemRect(item).center(), [&, key, hex] {
    check("highlight " + key, w.highlightedField == key && w.highlightedHex == hex);
   });
   return;
  }
  check("field exists " + key, false);
 };
 auto type = [&](QLineEdit* input, const QString& value, std::function<void()> done) {
  input->selectAll();
  for (int i = 0; i < value.size(); ++i) {
   QTimer::singleShot(i*36, Qt::PreciseTimer, input, [input, ch=value.mid(i,1)] {
    QTest::keyClicks(input, ch, Qt::NoModifier, 0);
   });
  }
  QTimer::singleShot(value.size()*36+180, Qt::PreciseTimer, input, std::move(done));
 };
 auto dialog = [&](QPushButton* control, const QString& file, const QString& action, bool save) {
  // The release opens a modal QFileDialog and blocks until it closes.
  click(action, control, control->rect().center(), {}, [&, file, action, save] {
   at(250, [&, file, action, save] {
    auto* d = qobject_cast<QFileDialog*>(QApplication::activeModalWidget());
    check("file dialog " + action, d != nullptr);
    if (!d) return;
    d->resize(900, 500);
    d->move(w.mapToGlobal(QPoint(260, 160)));
    d->setDirectory(QFileInfo(file).absolutePath());
    auto* name = d->findChild<QLineEdit*>("fileNameEdit");
    auto* buttons = d->findChild<QDialogButtonBox*>();
    auto* confirm = buttons ? buttons->button(save ? QDialogButtonBox::Save : QDialogButtonBox::Open) : nullptr;
    check("dialog controls " + action, name && confirm);
    if (!name || !confirm) return;
    if (save) {
     click("focus filename for " + action, name, QPoint(80, name->height()/2),
      [&, name, confirm, file, action] {
       type(name, QFileInfo(file).fileName(), [&, confirm, action] {
        button("confirm " + action, confirm);
       });
      });
     return;
    }
    // Select the existing capture from the file list, then click Open.
    QTimer::singleShot(350, Qt::PreciseTimer, d, [&, d, name, confirm, file, action] {
     // The saved Qt dialog view preference can be either list or detail.
     auto* list = d->findChild<QAbstractItemView*>("listView");
     if (!list || !list->isVisible()) list = d->findChild<QAbstractItemView*>("treeView");
     const QString filename = QFileInfo(file).fileName();
     if (list && list->isVisible() && list->model()) {
      for (int i = 0; i < list->model()->rowCount(list->rootIndex()); ++i) {
       const QModelIndex index = list->model()->index(i, 0, list->rootIndex());
       if (index.data().toString() != filename) continue;
       list->scrollTo(index);
       const QRect visible = list->visualRect(index).intersected(list->viewport()->rect());
       click("choose sample file", list->viewport(), visible.center(),
        [&, name, confirm, filename, action] {
         check("selected sample name", name->text() == filename);
         at(400, [&, confirm, action] { button("confirm " + action, confirm); });
        });
       return;
      }
     }
     check("sample visible in file list", false);
    });
   });
  });
 };

 auto* receiver = new QUdpSocket(&w);
 auto* sender = new QUdpSocket(&w);
 check("bind local receiver", receiver->bind(QHostAddress(QHostAddress::LocalHost), quint16(0)));
 QObject::connect(receiver, &QUdpSocket::readyRead, &w, [&] {
  while (receiver->hasPendingDatagrams()) {
   QByteArray bytes(int(receiver->pendingDatagramSize()), 0);
   receiver->readDatagram(bytes.data(), bytes.size());
   ++received;
  }
 });
 QObject::connect(&record, &QTimer::timeout, &w, [&] {
  const auto elapsed = clock.elapsed();
  QPixmap image = w.grab();
  QPainter painter(&image);
  const QPoint origin = w.mapToGlobal(QPoint());
  for (QWidget* top : QApplication::topLevelWidgets()) {
   if (top != &w && top->isVisible() && top->windowType() != Qt::ToolTip)
    painter.drawPixmap(top->mapToGlobal(QPoint()) - origin, top->grab());
  }
  painter.end();
  const QString name = QString("raw/frame-%1.png").arg(frame++, 5, 10, QChar('0'));
  QMetaObject::invokeMethod(worker, [snapshot=image.toImage(), path=out+"/"+name, &failedSaves] {
   if (!snapshot.save(path, "PNG", 95)) ++failedSaves;
  }, Qt::QueuedConnection);
  frames.append(QJsonObject{{"frame", frame-1}, {"file", name}, {"elapsed_ms", double(elapsed)},
   {"read", double(w.captured)}, {"displayed", w.model->rowCount()}, {"filter", w.model->filter},
   {"field", w.highlightedField}});
 });
 record.setTimerType(Qt::PreciseTimer);
 record.start(220);

 at(520, [&] {
  int found = -1;
  for (int i = 0; i < w.interfaces->count(); ++i)
   if (w.interfaces->itemData(i).toString().contains("NPF_Loopback")) found = i;
  combo(w.interfaces, found, "choose loopback");
 });
 at(6250, [&] {
  click("focus capture filter", w.captureFilter, QPoint(110, w.captureFilter->height()/2), [&] {
   const QString expression = "udp port " + QString::number(receiver->localPort());
   type(w.captureFilter, expression, [&, expression] {
    check("capture expression was entered", w.captureFilter->text() == expression);
    note("set capture filter");
   });
  });
 });
 at(12200, [&] { button("click start", w.startButton); });
 at(13280, [&] { check("capture active", w.cap != nullptr); });
 for (int i = 0; i < 30; ++i) at(13400+i*335, [&, i] {
  const QByteArray bytes = "LAB1 GUI DEMO / packet " + QByteArray::number(i+1);
  if (sender->writeDatagram(bytes, QHostAddress::LocalHost, receiver->localPort()) == bytes.size()) ++sent;
  sentPayloads.append(QString::fromLatin1(bytes.toHex()));
 });
 at(19400, [&] { packet(4, "select live packet"); });
 at(25300, [&] { button("click stop", w.stopButton); });
 at(28000, [&] {
  liveCaptured = w.captured;
  check("30 datagrams sent received captured", sent == 30 && received == 30 && w.captured == 30);
  check("capture stopped", w.cap == nullptr);
  note("capture stopped");
 });
 at(31200, [&] { dialog(w.saveButton, out+"/live-export.pcap", "export PCAP", true); });
 at(35900, [&] {
  check("export exists", QFileInfo::exists(out+"/live-export.pcap"));
  note("export completed");
 });
 at(37150, [&] { dialog(w.openButton, sample, "open sample", false); });
 at(41800, [&] {
  check("sample loaded", w.offlineLoaded && w.model->records.size() == 10);
  note("sample loaded");
 });
 auto filter = [&](const QString& name) {
  combo(w.display, w.display->findText(name), "display filter " + name);
 };
 at(43200, [&] { filter("HTTP"); });
 at(46800, [&] { check("one HTTP row", w.model->rowCount() == 1); });
 at(49300, [&] { packet(0, "select HTTP packet"); });
 at(56240, [&] { field("ip.src", "c0000201"); });
 at(64240, [&] { field("http.start_line", "474554202f6c616220485454502f312e31"); });
 at(72300, [&] { filter("IPV6"); });
 at(76800, [&] { check("four IPv6 rows", w.model->rowCount() == 4); });
 at(78300, [&] { filter("ALL"); });
 at(81800, [&] { check("all ten sample rows", w.model->rowCount() == 10); });
 at(84000, [&] { dialog(w.openButton, liveSample, "open real TCP capture", false); });
 at(88700, [&] {
  check("real capture loaded", w.offlineLoaded && w.model->records.size()>=22);
  click("focus display expression",w.displayExpression,QPoint(90,w.displayExpression->height()/2),[&]{
   const QString expression="HTTP AND (IPV4 OR IPV6) AND tcp.dstport == "+serverPort;
   type(w.displayExpression,expression,[&]{button("apply compound display filter",w.applyExpression);});
  });
 });
 at(94000, [&] {
  check("compound expression selects one request",w.model->rowCount()==1);
  check("flow has observed close",w.selectedFlow().state=="Close exchange observed");
  click("show TCP flow",w.flowButton,w.flowButton->rect().center(),{},[&]{
   at(350,[&]{
    auto* d=qobject_cast<QDialog*>(QApplication::activeModalWidget());
    check("TCP flow dialog displayed",d && d->windowTitle().startsWith("TCP flow"));
    if(d){d->resize(1220,510);d->move(w.mapToGlobal(QPoint(110,185)));}
   });
  });
 });
 at(107000, [&] {
  if(auto* d=qobject_cast<QDialog*>(QApplication::activeModalWidget()))d->accept();
  record.stop();
  QMetaObject::invokeMethod(worker, [] {}, Qt::BlockingQueuedConnection);
  frameWriter.quit();
  frameWriter.wait();
  check("save all frames", failedSaves.load() == 0);
  check("all twenty-seven clicks recorded", clicks.size() == 27);
  const int detailTop = w.fields->mapTo(&w, QPoint()).y();
  saveJson(out+"/tour.json", QJsonObject{{"outcome", failed ? "fail" : "pass"},
   {"sent", sent}, {"received", received}, {"captured", double(liveCaptured)}, {"payloads_hex", sentPayloads},
   {"events", events}, {"frames", frames}, {"checks", checks}, {"duration_ms", double(clock.elapsed())},
   {"pointer", pointer}, {"clicks", clicks}, {"detail_top", detailTop},
   {"provenance", "Production Window driven by Qt mouse move, press and release events; same coordinates used to render the recorded pointer."}});
  app.exit(failed ? 1 : 0);
 });
 return app.exec();
}

