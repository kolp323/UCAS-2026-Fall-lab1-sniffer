#include "parser.h"
#include <QJsonArray>
#include <QRegularExpression>
namespace lab1 {
namespace {
struct Reader {
    const QByteArray& b; Packet p;
    int size() const {return b.size();}
    unsigned u8(int o) const {return static_cast<unsigned char>(b.at(o));}
    unsigned be16(int o) const {return (u8(o)<<8)|u8(o+1);}
    unsigned be32(int o) const {return (be16(o)<<16)|be16(o+2);}
    bool need(int o,int n,int end,const QString& what) {
        if(o<0||n<0||o>end||n>end-o){p.status="malformed";p.info=what+": declared length too short";return false;}
        if(o>size()||n>size()-o){p.status="truncated";p.info=what+": captured bytes missing";return false;}
        return true;
    }
    void field(QString n,QString v,int o,int l){p.fields.push_back({n,v,o,l});}
    void number(QString n,unsigned v,int o,int l){field(n,QString::number(v),o,l);}
    QString ip4(int o)const{return QString("%1.%2.%3.%4").arg(u8(o)).arg(u8(o+1)).arg(u8(o+2)).arg(u8(o+3));}
    QString ip6(int o)const{QStringList parts;for(int j=0;j<16;j+=2)parts<<QString::number(be16(o+j),16);return parts.join(':');}
    QString mac(int o)const{QStringList parts;for(int j=0;j<6;++j)parts<<QString("%1").arg(u8(o+j),2,16,QChar('0'));return parts.join(':');}
    Packet bad(QString why){p.status="malformed";p.info=why;return p;}
    void http(int o,int n) {
        if(n<=0)return;
        // Recognition is evidence from a complete HTTP/1.x start line and header block.
        // No cross-segment reassembly; port numbers never establish HTTP identity.
        const QByteArray payload=b.mid(o,n);
        const int lineEnd=payload.indexOf("\r\n");
        if(lineEnd<0){p.info="TCP payload; no complete HTTP start line (no reassembly)";return;}
        const QString line=QString::fromLatin1(payload.left(lineEnd));
        static const QRegularExpression request("^(GET|HEAD|POST|PUT|DELETE|OPTIONS|TRACE|CONNECT|PATCH) [^ \\r\\n]+ HTTP/1\\.[01]$");
        static const QRegularExpression response("^HTTP/1\\.[01] [1-5][0-9][0-9]( .*)?$");
        if(!request.match(line).hasMatch()&&!response.match(line).hasMatch())return;
        const int headerEnd=payload.indexOf("\r\n\r\n");
        if(headerEnd<0){p.info="HTTP-like start line, incomplete headers; identification pending";return;}
        static const QRegularExpression headerName("^[!#$%&'*+.^_`|~0-9a-zA-Z-]+$");
        for(int start=lineEnd+2;start<headerEnd;){
            const int end=payload.indexOf("\r\n",start);
            if(end<0||end>headerEnd)return;
            const int colon=payload.indexOf(':',start);
            if(colon<0||colon>=end||!headerName.match(QString::fromLatin1(payload.mid(start,colon-start))).hasMatch())return;
            for(int i=colon+1;i<end;++i){
                const auto c=static_cast<unsigned char>(payload.at(i));
                if((c<32&&c!=9)||c==127)return;
            }
            start=end+2;
        }
        p.protocol="HTTP";p.info=line;
        field("http.start_line",line,o,lineEnd);
        number("http.header_bytes",headerEnd+4,o,headerEnd+4);
    }
};
}
Packet parsePacket(const QByteArray& bytes,int linktype,unsigned originalLength){
    Reader r{bytes,{}};
    int off=0;unsigned type=0;
    // Bounds checks precede every read. No pointer casts or unaligned integer reads.
    if(linktype==1){
        r.p.protocol="Ethernet";
        if(!r.need(0,14,2147483647,"Ethernet header"))return r.p;
        r.field("eth.dst",r.mac(0),0,6);r.field("eth.src",r.mac(6),6,6);
        type=r.be16(12);r.number("eth.type",type,12,2);off=14;
        int tags=0;
        while(type==0x8100||type==0x88a8){
            if(++tags>2){r.p.status="unsupported";r.p.info="More than two VLAN tags";return r.p;}
            if(!r.need(off,4,2147483647,"VLAN header"))return r.p;
            r.number("vlan.id",r.be16(off)&4095,off,2);type=r.be16(off+2);off+=4;
        }
    }else if(linktype==0){
        if(!r.need(0,4,2147483647,"DLT_NULL header"))return r.p;
        unsigned family=r.u8(0)|(r.u8(1)<<8)|(r.u8(2)<<16)|(r.u8(3)<<24);
        if(family!=2&&family!=24&&family!=28&&family!=30){family=r.be32(0);}
        r.number("null.family",family,0,4);off=4;
        type=family==2?0x0800:(family==24||family==28||family==30?0x86dd:0);
    }else{r.p.status="unsupported";r.p.info="Unsupported link type "+QString::number(linktype);return r.p;}
    int end=0;unsigned next=0;
    if(type==0x0800){
        r.p.network=r.p.protocol="IPv4";r.p.ipVersion=4;
        if(!r.need(off,20,2147483647,"IPv4 header"))return r.p;
        const unsigned version=r.u8(off)>>4,ihl=(r.u8(off)&15)*4,total=r.be16(off+2);
        r.number("ip.version",version,off,1);r.number("ip.ihl_bytes",ihl,off,1);r.number("ip.total_length",total,off+2,2);
        if(version!=4||ihl<20||total<ihl)return r.bad("Invalid IPv4 version/IHL/total length");
        if(!r.need(off,static_cast<int>(ihl),2147483647,"IPv4 options"))return r.p;
        r.p.src=r.ip4(off+12);r.p.dst=r.ip4(off+16);r.field("ip.src",r.p.src,off+12,4);r.field("ip.dst",r.p.dst,off+16,4);
        next=r.u8(off+9);r.number("ip.protocol",next,off+9,1);
        const unsigned frag=r.be16(off+6);
        r.number("ip.fragment_offset",frag&8191,off+6,2);
        r.number("ip.mf",(frag>>13)&1,off+6,2);
        r.number("ip.df",(frag>>14)&1,off+6,2);
        if(!r.need(off,static_cast<int>(total),2147483647,"IPv4 packet"))return r.p;
        end=off+static_cast<int>(total);off+=static_cast<int>(ihl);
        if(frag&0x3fff){r.p.fragmented=true;r.p.status="fragment";r.p.info="IPv4 fragment; transport not parsed without reassembly";return r.p;}
    }else if(type==0x86dd){
        r.p.network=r.p.protocol="IPv6";r.p.ipVersion=6;
        if(!r.need(off,40,2147483647,"IPv6 header"))return r.p;
        if((r.u8(off)>>4)!=6)return r.bad("Invalid IPv6 version");
        unsigned plen=r.be16(off+4);next=r.u8(off+6);
        r.p.src=r.ip6(off+8);r.p.dst=r.ip6(off+24);
        r.number("ipv6.payload_length",plen,off+4,2);r.field("ipv6.src",r.p.src,off+8,16);r.field("ipv6.dst",r.p.dst,off+24,16);
        r.number("ipv6.next_header",next,off+6,1);
        if(plen==0&&next==0&&r.size()>off+40){r.p.status="unsupported";r.p.info="Zero-length IPv6 payload with Hop-by-Hop header; jumbograms not supported";return r.p;}
        if(!r.need(off,40+static_cast<int>(plen),2147483647,"IPv6 packet"))return r.p;
        end=off+40+static_cast<int>(plen);off+=40;
        int extensionCount=0;
        while(next==0||next==43||next==60||next==44||next==51){
            if(++extensionCount>8){r.p.status="unsupported";r.p.info="IPv6 extension count exceeds limit 8";return r.p;}
            if(!r.need(off,2,end,"IPv6 extension"))return r.p;
            unsigned following=r.u8(off);int length=next==44?8:(next==51?(r.u8(off+1)+2)*4:(r.u8(off+1)+1)*8);
            if(next==51&&(length<12||length%8!=0))return r.bad("Invalid IPv6 AH length or alignment");
            if(!r.need(off,length,end,"IPv6 extension length"))return r.p;
            r.number("ipv6.extension_type",next,off,length);
            if(next==44){
                const unsigned bits=r.be16(off+2);
                r.number("ipv6.fragment.offset",bits>>3,off+2,2);
                r.number("ipv6.fragment.more",bits&1,off+2,2);
                r.number("ipv6.fragment.reserved_octet",r.u8(off+1),off+1,1);
                r.number("ipv6.fragment.reserved_bits",(bits>>1)&3,off+2,2);
                r.number("ipv6.fragment.id",r.be32(off+4),off+4,4);
                if(bits&0xfff9){r.p.fragmented=true;r.p.status="fragment";r.p.info="IPv6 fragment; transport not parsed without reassembly";return r.p;}
            }
            next=following;off+=length;
        }
        if(next==59){r.p.info="IPv6 No Next Header";return r.p;}
    }else{r.p.status="unsupported";r.p.info="Unsupported network type "+QString::number(type,16);return r.p;}
    if((next==1&&r.p.ipVersion!=4)||(next==58&&r.p.ipVersion!=6)){r.p.status="unsupported";r.p.info="ICMP protocol does not match IP version";return r.p;}
    if(next==6){
        r.p.protocol=r.p.transport="TCP";
        if(!r.need(off,20,end,"TCP header"))return r.p;
        const int header=(r.u8(off+12)>>4)*4;
        if(header<20)return r.bad("TCP data offset below 20 bytes");
        if(!r.need(off,header,end,"TCP options"))return r.p;
        r.p.srcPort=r.be16(off);r.p.dstPort=r.be16(off+2);
        r.number("tcp.srcport",r.p.srcPort,off,2);r.number("tcp.dstport",r.p.dstPort,off+2,2);
        r.p.tcpSeq=r.be32(off+4);r.p.tcpAck=r.be32(off+8);
        r.p.tcpFlags=r.u8(off+13);r.p.tcpPayloadBytes=end-off-header;
        r.number("tcp.seq",r.p.tcpSeq,off+4,4);r.number("tcp.ack",r.p.tcpAck,off+8,4);
        r.number("tcp.header_bytes",header,off+12,1);r.number("tcp.flags",r.u8(off+13),off+13,1);
        if(end>off+header)r.field("tcp.payload",r.b.mid(off+header,qMin(64,end-off-header)).toHex(' '),off+header,end-off-header);
        r.http(off+header,end-off-header);
    }else if(next==17){
        r.p.protocol=r.p.transport="UDP";
        if(!r.need(off,8,end,"UDP header"))return r.p;
        const int length=r.be16(off+4);if(length<8)return r.bad("UDP length below 8");
        if(!r.need(off,length,end,"UDP payload length"))return r.p;
        r.p.srcPort=r.be16(off);r.p.dstPort=r.be16(off+2);
        r.number("udp.srcport",r.p.srcPort,off,2);r.number("udp.dstport",r.p.dstPort,off+2,2);r.number("udp.length",length,off+4,2);
        if(length>8)r.field("udp.payload",r.b.mid(off+8,qMin(64,length-8)).toHex(' '),off+8,length-8);
    }else if(next==1||next==58){
        r.p.protocol=r.p.transport=next==1?"ICMP":"ICMPv6";
        if(!r.need(off,4,end,"ICMP header"))return r.p;
        r.number("icmp.type",r.u8(off),off,1);r.number("icmp.code",r.u8(off+1),off+1,1);
    }else{r.p.status="unsupported";r.p.info="Unsupported next protocol "+QString::number(next);}
    if(originalLength>static_cast<unsigned>(bytes.size())&&r.p.status=="valid") {r.p.status="truncated";r.p.info="Capture length below original frame length";}
    return r.p;
}
QJsonObject packetJson(const Packet& p){
    QJsonArray fields;for(const auto& f:p.fields)fields.append(QJsonObject{{"name",f.name},{"value",f.value},{"offset",f.offset},{"length",f.length}});
    return {{"protocol",p.protocol},{"network",p.network},{"transport",p.transport},{"src",p.src},{"dst",p.dst},{"srcPort",p.srcPort},{"dstPort",p.dstPort},{"ipVersion",p.ipVersion},{"status",p.status},{"info",p.info},{"fragmented",p.fragmented},{"fields",fields}};
}
bool matchesDisplayFilter(const Packet& p,const QString& expression){
    const QString f=expression.trimmed().toUpper();
    if(f.isEmpty()||f=="ALL")return true;
    if(f=="IPV4")return p.ipVersion==4;
    if(f=="IPV6")return p.ipVersion==6;
    if(f=="TCP"||f=="UDP")return p.transport.toUpper()==f;
    if(f=="ICMP")return p.transport=="ICMP"||p.transport=="ICMPv6";
    if(f=="ICMPV6")return p.transport=="ICMPv6";
    if(f=="HTTP")return p.protocol=="HTTP";
    if(f=="ETHERNET"){for(const auto& x:p.fields)if(x.name=="eth.type")return true;}
    return false;
}
}

