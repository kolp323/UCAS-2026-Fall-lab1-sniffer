#include "tcp_flow.h"

namespace lab1 {
namespace {
constexpr unsigned Fin = 0x01, Syn = 0x02, Rst = 0x04, Ack = 0x10;

bool eligible(const Packet& p) {
    return p.transport == "TCP" && p.status == "valid" && p.srcPort >= 0 && !p.src.isEmpty();
}

QString endpoint(const QString& ip, int port) {
    return ip.contains(':') ? QString("[%1]:%2").arg(ip).arg(port)
                            : QString("%1:%2").arg(ip).arg(port);
}

struct Connection {
    TcpFlow flow;
    bool opened = false, synAck = false, established = false, reset = false;
    bool fin[2] = {}, acknowledged[2] = {};
    quint32 finEnd[2] = {};
    quint32 firstSeq = 0, replySeq = 0;

    void add(const FlowSegment& segment, int direction) {
        const Packet& p = *segment.packet;
        const unsigned flags = p.tcpFlags;
        const int reverse = 1 - direction;
        QString event;
        if ((flags & (Syn | Ack | Rst | Fin)) == Syn) {
            if (!opened) { opened = true; firstSeq = p.tcpSeq; }
            event = "SYN";
        } else if (direction == 1 && opened && (flags & (Syn | Ack)) == (Syn | Ack) &&
                   p.tcpAck == firstSeq + 1) {
            synAck = true;
            replySeq = p.tcpSeq;
            event = "SYN acknowledged";
        } else if (direction == 0 && synAck && !established && (flags & Ack) &&
                   !(flags & (Syn | Rst)) && p.tcpAck == replySeq + 1 &&
                   p.tcpSeq == firstSeq + 1) {
            established = true;
            event = "Handshake observed";
        }

        if ((flags & Ack) && fin[reverse] && quint32(p.tcpAck - finEnd[reverse]) < 0x80000000u)
            acknowledged[reverse] = true;
        if (flags & Fin) {
            fin[direction] = true;
            finEnd[direction] = p.tcpSeq + quint32(p.tcpPayloadBytes) + 1;
            event = "FIN observed";
        }
        if (flags & Rst) { reset = true; event = "RST observed"; }

        if (reset) flow.state = "Reset observed";
        else if (fin[0] && fin[1] && acknowledged[0] && acknowledged[1]) {
            if (flow.state != "Close exchange observed" && event.isEmpty()) event = "Close exchange observed";
            flow.state = "Close exchange observed";
        } else if (fin[0] || fin[1]) flow.state = "Closing observed";
        else if (established) flow.state = "Handshake observed";
        else if (synAck) flow.state = "SYN and SYN+ACK observed";
        else if (opened) flow.state = "SYN observed";

        ++flow.counts[direction];
        flow.bytes[direction] += quint64(p.tcpPayloadBytes);
        flow.rows.append({segment.id, segment.micros, direction, flags, p.tcpSeq,
                          p.tcpAck, p.tcpPayloadBytes, event});
    }
};
}

TcpFlow followTcp(const QVector<FlowSegment>& segments, quint64 selectedId) {
    QString a, b;
    for (const auto& segment : segments) {
        if (segment.id != selectedId || !eligible(*segment.packet)) continue;
        const Packet& p = *segment.packet;
        a = endpoint(p.src, p.srcPort);
        b = endpoint(p.dst, p.dstPort);
        break;
    }
    if (a.isEmpty() || a == b) return {};

    Connection current;
    bool containsSelected = false;
    for (const auto& segment : segments) {
        const Packet& p = *segment.packet;
        if (!eligible(p)) continue;
        const QString src = endpoint(p.src, p.srcPort), dst = endpoint(p.dst, p.dstPort);
        if (!((src == a && dst == b) || (src == b && dst == a))) continue;
        const bool opening = (p.tcpFlags & (Syn | Ack | Fin | Rst)) == Syn;
        const bool sameSyn = opening && current.opened && !current.reset &&
                             !current.fin[0] && !current.fin[1] &&
                             src == current.flow.endpoint[0] && p.tcpSeq == current.firstSeq;
        if (opening && !sameSyn && !current.flow.rows.isEmpty()) {
            if (containsSelected) return current.flow;
            current = {};
        }
        if (current.flow.rows.isEmpty()) {
            current.flow.endpoint[0] = src;
            current.flow.endpoint[1] = dst;
        }
        current.add(segment, src == current.flow.endpoint[0] ? 0 : 1);
        containsSelected |= segment.id == selectedId;
    }
    return containsSelected ? current.flow : TcpFlow{};
}

QString tcpFlags(unsigned flags) {
    static const char* const names[] = {"FIN", "SYN", "RST", "PSH", "ACK", "URG", "ECE", "CWR"};
    QStringList result;
    for (int i = 0; i < 8; ++i) if (flags & (1u << i)) result << QLatin1String(names[i]);
    return result.isEmpty() ? QStringLiteral("-") : result.join('+');
}
}

