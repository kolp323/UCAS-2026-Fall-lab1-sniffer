"""Deterministic isolated protocol samples, generated from explicit wire layouts.
No packets are transmitted. Existing output directories are refused.
"""
import argparse, hashlib, ipaddress, json, struct
from pathlib import Path

def checksum(data):
    if len(data)%2:data+=b'\0'
    total=sum(struct.unpack('!%dH'%(len(data)//2),data))
    while total>>16:total=(total&65535)+(total>>16)
    return (~total)&65535

def ip4(body,proto=17,frag=0,src='192.0.2.1',dst='198.51.100.2'):
    h=struct.pack('!BBHHHBBH4s4s',0x45,0,20+len(body),100,frag,64,proto,0,ipaddress.ip_address(src).packed,ipaddress.ip_address(dst).packed)
    return h[:10]+struct.pack('!H',checksum(h))+h[12:]+body

def ip6(body,next=17):
    return struct.pack('!IHBB16s16s',6<<28,len(body),next,64,ipaddress.ip_address('2001:db8::1').packed,ipaddress.ip_address('2001:db8::2').packed)+body

def udp(data=b'LAB1',sport=12000,dport=5300):return struct.pack('!HHHH',sport,dport,len(data)+8,0)+data

def tcp(data=b'',sport=12001,dport=8080):return struct.pack('!HHIIBBHHH',sport,dport,1000,0,0x50,0x18,4096,0,0)+data

def eth(body,type=0x800):return bytes.fromhex('020000000002020000000001')+struct.pack('!H',type)+body

def icmp(kind):
    b=struct.pack('!BBHHH',kind,0,0,1,1)+b'PING'
    return b[:2]+struct.pack('!H',checksum(b))+b[4:]

def write_pcap(path,frames,link):
    raw=struct.pack('<IHHiIII',0xa1b2c3d4,2,4,0,0,65535,link)
    for i,f in enumerate(frames):
        data=f['bytes']; orig=f.get('orig',len(data))
        raw+=struct.pack('<IIII',1700000000+i,1000,len(data),orig)+data
    path.write_bytes(raw)
    return hashlib.sha256(raw).hexdigest()

def generate(out):
    out.mkdir(parents=True,exist_ok=False)
    frames=[]
    def add(id,data,expected,orig=None):
        item={'id':id,'bytes':data,'expected':expected}
        if orig is not None:item['orig']=orig
        frames.append(item)
    add('ipv4-udp',eth(ip4(udp())),dict(protocol='UDP',network='IPv4',status='valid',src='192.0.2.1',dst='198.51.100.2',srcPort=12000,dstPort=5300))
    add('http-nonstandard-port',eth(ip4(tcp(b'GET /lab HTTP/1.1\r\nHost: local.test\r\n\r\n'),6)),dict(protocol='HTTP',status='valid',dstPort=8080))
    add('port80-not-http',eth(ip4(tcp(b'not-http-binary\x00\xff',dport=80),6)),dict(protocol='TCP',status='valid',dstPort=80))
    add('icmp4',eth(ip4(icmp(8),1)),dict(protocol='ICMP',status='valid'))
    add('ipv6-udp',eth(ip6(udp()),0x86dd),dict(protocol='UDP',network='IPv6',status='valid',srcPort=12000,dstPort=5300))
    add('ipv6-tcp',eth(ip6(tcp(),6),0x86dd),dict(protocol='TCP',network='IPv6',status='valid'))
    add('icmp6',eth(ip6(icmp(128),58),0x86dd),dict(protocol='ICMPv6',status='valid'))
    vlan=bytes.fromhex('0200000000020200000000018100002a0800')+ip4(udp(b'VLAN'))
    add('vlan42',vlan,dict(protocol='UDP',status='valid'))
    add('ipv4-fragment',eth(ip4(udp(),17,0x2000)),dict(protocol='IPv4',status='fragment',fragmented=True,srcPort=-1))
    full=eth(ip4(udp(b'truncated')))
    add('truncated-ip-payload',full[:-3],dict(protocol='IPv4',status='truncated'),len(full))
    bad=bytearray(ip4(udp()));bad[0]=0x44
    add('invalid-ip-ihl',eth(bytes(bad)),dict(protocol='IPv4',status='malformed'))
    badudp=struct.pack('!HHHH',1,2,7,0)
    add('invalid-udp-length',eth(ip4(badudp)),dict(protocol='UDP',status='malformed'))
    badtcp=bytearray(tcp());badtcp[12]=0x40
    add('invalid-tcp-offset',eth(ip4(bytes(badtcp),6)),dict(protocol='TCP',status='malformed'))
    add('http-split-header',eth(ip4(tcp(b'GET /lab HTTP/1.1\r\nHost: loc'),6)),dict(protocol='TCP',status='valid'))
    add('ipv6-hop-udp',eth(ip6(bytes([17,0])+b'\0'*6+udp(),0),0x86dd),dict(protocol='UDP',status='valid',network='IPv6'))
    add('ipv6-fragment',eth(ip6(struct.pack('!BBHI',17,0,1,42)+udp(),44),0x86dd),dict(protocol='IPv6',status='fragment',fragmented=True))
    add('ipv6-esp-unknown',eth(ip6(b'\0'*16,50),0x86dd),dict(protocol='IPv6',status='unsupported'))
    add('short-ethernet',b'\0'*8,dict(protocol='Ethernet',status='truncated'),14)
    add('ipv6-bad-extension-length',eth(ip6(bytes([17,4])+b'\0'*6,0),0x86dd),dict(protocol='IPv6',status='malformed'))
    add('arp-unsupported',eth(b'\0'*28,0x806),dict(protocol='Ethernet',status='unsupported'))
    # No checksum validity claims: IPv6 transport pseudoheader checksums intentionally zero in fixtures.
    loop=[{'id':'loopback-ipv4-udp','bytes':struct.pack('<I',2)+ip4(udp(b'LOOP')),'expected':dict(protocol='UDP',status='valid',ipVersion=4)}, {'id':'loopback-ipv6-udp','bytes':struct.pack('<I',24)+ip6(udp(b'LOOP6')),'expected':dict(protocol='UDP',status='valid',ipVersion=6)}]
    unknown=[{'id':'unsupported-linktype','bytes':b'\0'*32,'expected':dict(status='unsupported')}]
    source={}
    for name,items,link in [('ethernet.pcap',frames,1),('loopback.pcap',loop,0),('unsupported.pcap',unknown,147)]:
        sha=write_pcap(out/name,items,link)
        source[name]={'sha256':sha,'linktype':link,'frames':[{'number':i+1,'id':f['id'],'caplen':len(f['bytes']),'wirelen':f.get('orig',len(f['bytes'])),'expected':f['expected']} for i,f in enumerate(items)]}
    # Same bytes at higher repeat count are throughput input, not independent trials.
    source['load.pcap']={'sha256':write_pcap(out/'load.pcap',[frames[0]]*5000,1),'linktype':1,'count':5000,'purpose':'fixed offline parsing input; no live-capture performance inference'}
    expected={'schema_version':1,'origin':'synthetic standard-library generator; reserved documentation addresses; no captured user traffic','checksum_scope':'Structural parser tests only. IPv6 UDP/TCP/ICMP pseudoheader checksums are not computed; no checksum correctness claim.','files':source,'display_sets':{'IPV4':[1,2,3,4,8,9,10,11,12,13,14],'IPV6':[5,6,7,15,16,17,19],'TCP':[2,3,6,13,14],'UDP':[1,5,8,12,15],'ICMP':[4,7],'ICMPV6':[7],'HTTP':[2]},'capture_bpf':{'expression':'udp','expected_source_frame_numbers':[1,5,9,10,11,12,16],'basis':'Hand-evaluate Ethernet BPF instruction offsets: ethertype[12], IPv4 protocol[23], IPv6 next[20], immediate Fragment next[54]. See tests/BPF-oracle-audit.md. Not the display UDP set.'}}
    (out/'expected.json').write_text(json.dumps(expected,ensure_ascii=False,indent=2),encoding='utf-8')
    (out/'README.md').write_text('# Fixed synthetic packet fixtures\n\nGenerated deterministically by scripts/generate-fixtures.py. Each frame has a case ID and manually selected semantic expectation in expected.json. PCAP SHA256 fixes the exact test input.\n\nMalformed, truncated, unsupported and fragmented inputs are deliberate. Checksums are outside parser scope; IPv6 transport checksums are not valid. Never present these synthetic samples as real captured traffic. load.pcap repeats 5000 copies of one frame for offline throughput measurement only.\n',encoding='utf-8')
    print(json.dumps({'out':str(out),'files':len(source),'cases':sum(len(x.get('frames',[])) for x in source.values())}))
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--out',required=True,type=Path);a=p.parse_args();generate(a.out)

