// Exercises the production capture window with local sockets and controlled files.
#define main lab1_original_main
#include "../../src/gui.cpp"
#undef main

#include <atomic>
#include <chrono>
#include <thread>

namespace {
void waitFor(int milliseconds) {
    QEventLoop loop;
    QTimer::singleShot(milliseconds, &loop, &QEventLoop::quit);
    loop.exec();
}

QJsonObject flowJson(const lab1::TcpFlow& flow) {
    QJsonArray rows;
    for (const auto& r : flow.rows) {
        rows.append(QJsonObject{{"id", double(r.id)}, {"elapsed_us", double(r.micros-flow.rows.first().micros)},
            {"direction", r.direction}, {"flags", int(r.flags)}, {"payload_bytes", r.payloadBytes},
            {"seq", double(r.seq)}, {"ack", double(r.ack)}, {"event", r.event}});
    }
    return {{"a", flow.endpoint[0]}, {"b", flow.endpoint[1]}, {"state", flow.state},
            {"packets", QJsonArray{flow.counts[0], flow.counts[1]}},
            {"payload_bytes", QJsonArray{double(flow.bytes[0]), double(flow.bytes[1])}},
            {"rows", rows}};
}
}

int main(int argc, char** argv) {
    wchar_t system[MAX_PATH]{};
    GetSystemDirectoryW(system, MAX_PATH);
    const std::wstring np = std::wstring(system) + L"\\Npcap";
    SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_DEFAULT_DIRS);
    AddDllDirectory(np.c_str());
    QApplication app(argc, argv);
    char error[PCAP_ERRBUF_SIZE]{};
    if (pcap_init(PCAP_CHAR_ENC_UTF_8, error)) return 2;
    const auto args = app.arguments();
    if (args.size() != 5) return 2;
    const QString dir = args[1], liveBpf = args[2], http4 = args[3], http6 = args[4];

    Window w;
    w.resize(1440, 840);
    w.show();
    QJsonArray checks;
    bool pass = true;
    auto check = [&](QString name, bool ok) {
        checks.append(QJsonObject{{"name", name}, {"pass", ok}});
        pass &= ok;
    };
    check("idle exposes start, export and flow await data",
          w.startButton->isVisible() && !w.stopButton->isVisible()
          && !w.saveButton->isEnabled() && !w.flowButton->isEnabled());
    // Deliberately reuse the same endpoints after an observed reset.
    QVector<lab1::Packet> vector;
    for (int i=0;i<5;++i) {
        lab1::Packet p;
        p.transport="TCP"; p.src="192.0.2.1"; p.dst="192.0.2.2";
        p.srcPort=31000; p.dstPort=8080; p.tcpFlags=2; p.tcpSeq=i<3?300:800;
        if(i==2 || i==4) {
            std::swap(p.src,p.dst);std::swap(p.srcPort,p.dstPort);
            p.tcpFlags=i==2?20:16;
        }
        vector.append(p);
    }
    QVector<lab1::FlowSegment> sequence;
    for(int i=0;i<vector.size();++i)sequence.append({quint64(i+1),i*100,&vector[i]});
    const auto first=lab1::followTcp(sequence,1);
    const auto second=lab1::followTcp(sequence,4);
    const auto partial=lab1::followTcp({sequence[4]},5);
    check("repeat SYN stays in occurrence and reused tuple splits",first.rows.size()==3 && second.rows.size()==2);
    check("RST and partial windows are distinct",first.state=="Reset observed" && partial.state=="Handshake not observed");
    int loopback = -1;
    for (int i = 0; i < w.interfaces->count(); ++i) {
        if (w.interfaces->itemData(i).toString().contains("NPF_Loopback")) loopback = i;
    }
    check("Npcap loopback available", loopback >= 0);
    w.interfaces->setCurrentIndex(loopback);
    w.captureFilter->setText(liveBpf);
    w.startButton->click();
    check("live capture opens", w.cap != nullptr);
    check("active capture exposes stop and locks source controls",
          w.stopButton->isVisible() && !w.startButton->isVisible() && !w.openButton->isEnabled());
    if (w.cap) {
        QFile ready(dir+"/ready");
        if (ready.open(QIODevice::WriteOnly)) ready.close();
        QElapsedTimer clock;
        clock.start();
        while (!QFileInfo::exists(dir+"/done") && clock.elapsed()<20000) waitFor(100);
        check("traffic sender finished", QFileInfo::exists(dir+"/done"));
        waitFor(350);
        w.stopButton->click();
        check("export live", w.exportCapture(dir+"/local-protocols.pcap"));
    }
    const double packets = double(w.captured);
    const int retained = w.model->records.size();
    auto selectRequest = [&](const QString& port, const QString& tag) {
        w.displayExpression->setText("HTTP AND tcp.dstport == "+port);
        w.applyExpression->click();
        check("one HTTP request "+tag, w.model->rowCount()==1);
        w.table->selectRow(0);
        const auto flow = w.selectedFlow();
        check("observed bidirectional TCP open and close "+tag,
              flow.state=="Close exchange observed" && flow.bytes[0]>0 && flow.bytes[1]>0);
        return flow;
    };
    const auto flow4 = selectRequest(http4, "IPv4");
    const int matched = w.model->rowCount();
    check("stopped capture exposes start, export and TCP flow",
          w.startButton->isVisible() && !w.stopButton->isVisible()
          && w.saveButton->isEnabled() && w.flowButton->isEnabled());
    for (int row=0; row<w.fields->rowCount(); ++row) {
        auto* field=w.fields->item(row,0);
        if (field->text()=="ip.src") {
            w.fields->scrollToItem(field,QAbstractItemView::PositionAtCenter);
            w.fields->setCurrentCell(row,0);
            break;
        }
    }
    const auto selections=w.hex->extraSelections();
    check("field selection links the byte range to the actual hex text",
          w.highlightedField=="ip.src" && w.highlightedOffset==16 && w.highlightedLength==4
          && w.byteRange->text()=="[16, 20)" && selections.size()==1
          && selections.first().cursor.selectedText()=="7f 00 00 01");
    const auto paneSizes=w.panes->sizes();
    w.panes->setSizes({160,515});
    check("expression screenshot", w.grab().save(dir+"/expression.png"));
    w.panes->setSizes(paneSizes);
    w.displayExpression->setText("HTTP AND (");
    w.applyExpression->click();
    check("invalid filter preserves the last result",
          w.lastError.startsWith("Display expression:") && w.model->rowCount()==matched);
    w.displayExpression->setText("HTTP AND tcp.dstport == "+http4);
    w.applyExpression->click();
    if (!flow4.rows.isEmpty()) {
        QTimer::singleShot(180, &w, [&] {
            auto* d = qobject_cast<QDialog*>(QApplication::activeModalWidget());
            check("visible flow dialog", d && d->grab().save(dir+"/tcp-flow.png"));
            if (d) d->accept();
        });
        w.flowButton->click();
    }
    const auto flow6 = selectRequest(http6, "IPv6");
    w.displayExpression->clear();
    w.applyExpression->click();

    QJsonArray stops;
    QUdpSocket sink;
    check("owned UDP sink binds", sink.bind(QHostAddress(QHostAddress::LocalHost), quint16(0)));
    QObject::connect(&sink, &QUdpSocket::readyRead, &w, [&] {
        QByteArray data(256, '\0');
        while (sink.hasPendingDatagrams()) sink.readDatagram(data.data(), data.size());
    });
    w.captureFilter->setText("udp port "+QString::number(sink.localPort()));
    for (int run=0; run<3; ++run) {
        w.startButton->click();
        check("repeated start", w.cap != nullptr);
        std::atomic<int> sent{0};
        std::atomic<bool> continueSending{true};
        const auto port = sink.localPort();
        std::thread sender([&] {
            QUdpSocket socket;
            const QByteArray payload(128, 'L');
            while (continueSending) {
                if (socket.writeDatagram(payload, QHostAddress(QHostAddress::LocalHost), port)==payload.size()) ++sent;
                std::this_thread::sleep_for(std::chrono::milliseconds(2));
            }
        });
        waitFor(1400);
        const int before=sent.load();
        QElapsedTimer stop;
        stop.start();
        w.stopButton->click();
        const double stopMs=stop.nsecsElapsed()/1000000.0;
        const auto read=w.captured;
        const auto heartbeat=w.maxHeartbeatGap;
        waitFor(250);
        continueSending=false;
        sender.join();
        const int after=sent.load();
        check("stop during input keeps capture frozen", !w.cap && read>0 && read==w.captured && after>before && stopMs<200);
        stops.append(QJsonObject{{"sent_at_stop", before}, {"sent_after_wait", after},
           {"read_at_stop", double(read)}, {"read_after_wait", double(w.captured)}, {"stop_ms", stopMs},
           {"max_heartbeat_gap_ms", double(heartbeat)}, {"driver_drop", double(w.driverDropped)},
           {"driver_stats_available", w.statsAvailable}});
    }
    w.startButton->click();
    const bool idleStarted=w.cap!=nullptr;
    waitFor(240);
    w.stopButton->click();
    check("idle stop", idleStarted && !w.cap && w.captured==0);

    auto offline = [&](const QString& file, bool expectSuccess) {
        bool completed=false, ok=false;
        w.loadFinished=[&](bool result){completed=true;ok=result;};
        w.openCapture(dir+"/"+file);
        for(int i=0;i<100&&!completed;++i)waitFor(50);
        if(!completed)w.closeOffline();
        w.loadFinished={};
        check(file+" completion", completed && (ok==expectSuccess));
    };
    offline("count-capacity.pcap",true);
    const int countRetained=w.model->records.size();
    check("2000 packet limit", w.captured==2050 && countRetained==2000 && w.model->evicted==50);
    offline("byte-capacity.pcap",true);
    const int byteRetained=w.model->records.size();
    const double bytes=double(w.model->retainedBytes);
    check("16 MiB byte limit", w.captured==300 && byteRetained==279 && w.model->evicted==21 && bytes==279*60000);
    w.displayExpression->setText("HTTP");
    w.applyExpression->click();
    check("export is independent of display expression",
          w.model->rowCount()==0 && w.exportCapture(dir+"/retained-byte-capacity.pcap"));
    offline("broken-record.pcap",false);

    const QJsonObject result{{"outcome", pass?"pass":"fail"}, {"checks",checks},
        {"live_packets",packets}, {"live_retained",retained}, {"flow_ipv4",flowJson(flow4)}, {"flow_ipv6",flowJson(flow6)},
        {"stop_trials",stops},{"count_retained",countRetained},{"byte_retained",byteRetained},{"raw_bytes_retained",bytes},
        {"npcap",QString::fromUtf8(pcap_lib_version())}};
    if (!saveJson(dir+"/gui-review.json",result)) return 2;
    return pass?0:1;
}

