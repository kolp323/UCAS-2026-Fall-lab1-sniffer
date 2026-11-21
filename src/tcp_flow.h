#pragma once

#include "parser.h"

namespace lab1 {

struct FlowSegment {
    quint64 id;
    qint64 micros;
    const Packet* packet;
};

struct FlowRow {
    quint64 id;
    qint64 micros;
    int direction;
    unsigned flags;
    quint32 seq, ack;
    int payloadBytes;
    QString event;
};

struct TcpFlow {
    QString endpoint[2];
    QVector<FlowRow> rows;
    int counts[2] = {};
    quint64 bytes[2] = {};
    QString state = "Handshake not observed";
};

// Endpoints and connection events describe only the supplied capture window.
TcpFlow followTcp(const QVector<FlowSegment>& segments, quint64 selectedId);
QString tcpFlags(unsigned flags);
}

