#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <winsock2.h>
#include <windows.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <QtWidgets>
#include <QHostAddress>
#include "process_view.h"

namespace lab1 {
namespace {
struct EndpointPair {
    QHostAddress local, peer;
    quint16 localPort, peerPort;
    DWORD state;
};

QHostAddress ipv6(const UCHAR* address, DWORD scope) {
    QHostAddress result(address);
    if (scope) result.setScopeId(QString::number(scope));
    return result;
}

DWORD connections(ULONG family, DWORD pid, QVector<EndpointPair>& rows) {
    DWORD bytes = 0;
    DWORD result = GetExtendedTcpTable(nullptr, &bytes, FALSE, family, TCP_TABLE_OWNER_PID_CONNECTIONS, 0);
    for (int attempt = 0; result == ERROR_INSUFFICIENT_BUFFER && attempt < 4; ++attempt) {
        if (bytes > 32 * 1024 * 1024) return ERROR_NOT_ENOUGH_MEMORY;
        QByteArray storage(int(bytes), 0);
        result = GetExtendedTcpTable(storage.data(), &bytes, FALSE, family, TCP_TABLE_OWNER_PID_CONNECTIONS, 0);
        if (result != NO_ERROR) continue;
        if (family == AF_INET) {
            auto* table = reinterpret_cast<const MIB_TCPTABLE_OWNER_PID*>(storage.constData());
            for (DWORD i = 0; i < table->dwNumEntries; ++i) {
                const auto& r = table->table[i];
                if (r.dwOwningPid == pid)
                    rows.append({QHostAddress(ntohl(r.dwLocalAddr)), QHostAddress(ntohl(r.dwRemoteAddr)),
                                 ntohs(u_short(r.dwLocalPort)), ntohs(u_short(r.dwRemotePort)), r.dwState});
            }
        } else {
            auto* table = reinterpret_cast<const MIB_TCP6TABLE_OWNER_PID*>(storage.constData());
            for (DWORD i = 0; i < table->dwNumEntries; ++i) {
                const auto& r = table->table[i];
                if (r.dwOwningPid == pid)
                    rows.append({ipv6(r.ucLocalAddr, r.dwLocalScopeId), ipv6(r.ucRemoteAddr, r.dwRemoteScopeId),
                                 ntohs(u_short(r.dwLocalPort)), ntohs(u_short(r.dwRemotePort)), r.dwState});
            }
        }
    }
    return result;
}

QString endpoint(const QHostAddress& address, quint16 port) {
    const auto pattern = address.protocol() == QAbstractSocket::IPv6Protocol ? "[%1]:%2" : "%1:%2";
    return QString(pattern).arg(address.toString()).arg(port);
}

QString stateName(DWORD state) {
    static const QStringList names = {"?", "CLOSED", "LISTEN", "SYN-SENT", "SYN-RECEIVED", "ESTABLISHED",
        "FIN-WAIT-1", "FIN-WAIT-2", "CLOSE-WAIT", "CLOSING", "LAST-ACK", "TIME-WAIT", "DELETE-TCB"};
    return names.value(int(state), QString::number(state));
}

QString filter(const EndpointPair& r) {
    if (!r.local.scopeId().isEmpty() || !r.peer.scopeId().isEmpty()) return {};
    const QString pattern = "(src == %1 AND tcp.srcport == %2 AND dst == %3 AND tcp.dstport == %4)";
    return pattern.arg(r.local.toString()).arg(r.localPort).arg(r.peer.toString()).arg(r.peerPort)
        + " OR " + pattern.arg(r.peer.toString()).arg(r.peerPort).arg(r.local.toString()).arg(r.localPort);
}
}

ProcessView::ProcessView(QWidget* parent, MatchPackets match) : QDialog(parent) {
    setWindowTitle("Process TCP flows");
    resize(760, 400);
    auto* layout = new QVBoxLayout(this);
    auto* controls = new QHBoxLayout;
    input = new QLineEdit;
    input->setPlaceholderText("Local process ID");
    input->setMaximumWidth(150);
    auto* start = new QPushButton("Track PID");
    controls->addWidget(input);
    controls->addWidget(start);
    controls->addStretch();
    layout->addLayout(controls);
    table = new QTableWidget(0, 5);
    table->setObjectName("processConnections");
    table->setHorizontalHeaderLabels({"Local endpoint", "Peer endpoint", "Last TCP state", "First seen", "Last seen"});
    table->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
    table->setSelectionBehavior(QAbstractItemView::SelectRows);
    table->setSelectionMode(QAbstractItemView::SingleSelection);
    table->setEditTriggers(QAbstractItemView::NoEditTriggers);
    layout->addWidget(table);
    status = new QLabel("Live Windows endpoints · samples every 250 ms");
    layout->addWidget(status);
    timer = new QTimer(this);
    timer->setInterval(250);
    connect(timer, &QTimer::timeout, this, &ProcessView::refresh);
    connect(start, &QPushButton::clicked, this, [this]{ watch(input->text().toUInt()); });
    connect(input, &QLineEdit::returnPressed, start, &QPushButton::click);
    if (match) {
        auto* packets = new QPushButton("Filter captured endpoints");
        packets->setEnabled(false);
        controls->addWidget(packets);
        connect(table, &QTableWidget::itemSelectionChanged, this, [=]{
            auto* item = table->item(table->currentRow(), 0);
            packets->setEnabled(item && !item->data(Qt::UserRole).toString().isEmpty());
        });
        connect(packets, &QPushButton::clicked, this, [=]{
            auto* item = table->item(table->currentRow(), 0);
            if (item) { match(item->data(Qt::UserRole).toString()); accept(); }
        });
    }
}
ProcessView::~ProcessView() { if (process) CloseHandle(process); }

void ProcessView::stop(const QString& reason) {
    timer->stop();
    if (process) { CloseHandle(process); process = nullptr; }
    status->setText(reason);
}

void ProcessView::clearHistory() {
    active.clear();
    table->setRowCount(0);
}

void ProcessView::watch(quint32 pid) {
    stop({});
    clearHistory();
    watchedPid = pid;
    input->setText(QString::number(pid));
    if (pid) process = OpenProcess(SYNCHRONIZE, FALSE, pid);
    if (!process) { status->setText("Choose an accessible running process."); return; }
    timer->start();
    refresh();
}

void ProcessView::refresh() {
    if (WaitForSingleObject(process, 0) != WAIT_TIMEOUT) { stop("Process exited · observations retained"); return; }
    QVector<EndpointPair> rows;
    for (auto family : {AF_INET, AF_INET6}) {
        DWORD rc = connections(family, watchedPid, rows);
        if (rc) { stop(QString("Windows TCP table error %1").arg(rc)); return; }
    }
    if (WaitForSingleObject(process, 0) != WAIT_TIMEOUT) { stop("Process exited · observations retained"); return; }
    const QString now = QTime::currentTime().toString("HH:mm:ss.zzz");
    QHash<QString,int> next;
    for (const auto& r : rows) {
        const QString local = endpoint(r.local, r.localPort), peer = endpoint(r.peer, r.peerPort);
        const QString key = local + "|" + peer;
        int row = active.value(key, -1);
        if (row < 0) {
            row = table->rowCount();
            if (row >= 2000) { stop("2000 observations retained · start a new watch to continue"); return; }
            table->insertRow(row);
            const QStringList cells = {local, peer, {}, now, {}};
            for (int col = 0; col < cells.size(); ++col)
                table->setItem(row, col, new QTableWidgetItem(cells[col]));
            table->item(row, 0)->setData(Qt::UserRole, filter(r));
        }
        table->item(row, 2)->setText(stateName(r.state));
        table->item(row, 4)->setText(now);
        next.insert(key, row);
    }
    active = std::move(next);
    status->setText(QString("PID %1 · %2 current · %3 observed · 250 ms samples")
                    .arg(watchedPid).arg(active.size()).arg(table->rowCount()));
}
}
