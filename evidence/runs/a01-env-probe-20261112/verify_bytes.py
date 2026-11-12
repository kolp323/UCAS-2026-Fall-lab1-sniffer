import csv,json,struct,hashlib
from pathlib import Path
p=Path(__file__).parent
raw=(p/'loopback.pcap').read_bytes()
assert raw[:4]==b'\xd4\xc3\xb2\xa1', 'expected little endian classic PCAP'
magic,major,minor,tz,sig,snap,dlt=struct.unpack('<IHHiIII',raw[:24])
assert dlt==0
packets=[]; pos=24
expected=b'A01-own-loopback-probe-v1'
while pos<len(raw):
    assert pos+16<=len(raw)
    sec,usec,n,orig=struct.unpack_from('<IIII',raw,pos); pos+=16
    frame=raw[pos:pos+n]; pos+=n
    assert len(frame)==n==orig==57
    assert struct.unpack_from('<I',frame,0)[0]==2
    ip=frame[4:]; ihl=(ip[0]&15)*4
    assert ip[0]>>4==4 and ihl==20 and ip[9]==17
    assert ip[12:16]==ip[16:20]==bytes([127,0,0,1])
    total=struct.unpack_from('!H',ip,2)[0]
    assert total==53
    sport,dport,ulen,check=struct.unpack_from('!HHHH',ip,ihl)
    assert ulen==33 and total==ihl+ulen and ip[ihl+8:]==expected
    packets.append({'srcport':sport,'dstport':dport,'payload_hex':expected.hex()})
assert pos==len(raw) and len(packets)==3
rows=list(csv.DictReader((p/'tshark-fields.csv').open(encoding='utf-8-sig')))
assert len(rows)==3
for pkt,row in zip(packets,rows):
    assert int(row['udp.srcport'])==pkt['srcport']
    assert int(row['udp.dstport'])==pkt['dstport']
    assert row['udp.payload']==pkt['payload_hex']
    assert row['ip.src']==row['ip.dst']=='127.0.0.1'
    assert int(row['frame.len'])==57 and int(row['udp.length'])==33
result={'outcome':'pass','packet_count':3,'linktype':0,'family':2,'ip_version':4,'ip_header_bytes':20,'ip_total_bytes':53,'udp_bytes':33,'payload_bytes':25,'frame_bytes':57,'pcap_sha256':hashlib.sha256(raw).hexdigest(),'checks':['raw byte lengths and fields','controlled payload identity','TShark fields equal raw bytes'],'boundary':'Only this controlled 3-packet IPv4 UDP loopback sample; not production parser or Ethernet/IPv6/performance validation'}
(p/'independent-check.json').write_text(json.dumps(result,indent=2),encoding='utf-8')
print(json.dumps(result))
