#pragma once
#include <QByteArray>
#include <QString>
#include <QVector>
#include <QJsonObject>
namespace lab1 {
struct Field { QString name,value; int offset=0,length=0; };
struct Packet {
    QString protocol="Unknown",src,dst,status="valid",info,network,transport;
    int srcPort=-1,dstPort=-1,ipVersion=0;
    bool fragmented=false;
    QVector<Field> fields;
};
Packet parsePacket(const QByteArray& bytes,int linktype,unsigned originalLength=0);
QJsonObject packetJson(const Packet& packet);
bool matchesDisplayFilter(const Packet& packet,const QString& expression);
}
