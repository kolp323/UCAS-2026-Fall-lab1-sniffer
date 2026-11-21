"""Record and check a repeatable local-only acceptance experiment."""
import argparse
import csv
import hashlib
import io
import json
import os
from pathlib import Path
import socket
import struct
import subprocess
import time


def dump(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')


def pcap(path, records):
    with path.open('wb') as out:
        out.write(struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for i, payload in enumerate(records, 1):
            out.write(struct.pack('<IIII', 1700000000, i, len(payload), len(payload)))
            out.write(payload)


def read_pcap(path):
    data = path.read_bytes()
    assert data[:4] == b'\xd4\xc3\xb2\xa1'
    records = []
    pos = 24
    while pos < len(data):
        _, _, length, _ = struct.unpack_from('<IIII', data, pos)
        pos += 16
        records.append(data[pos:pos+length])
        pos += length
    assert pos == len(data)
    return records


def listen(family, host):
    listener = socket.socket(family)
    listener.settimeout(3)
    listener.bind((host, 0))
    listener.listen()
    return listener


def receive_all(sock):
    chunks = []
    while True:
        chunk = sock.recv(4096)
        if not chunk:
            return b''.join(chunks)
        chunks.append(chunk)


def receive_exact(sock, size):
    data = bytearray()
    while len(data) < size:
        piece = sock.recv(size-len(data))
        if not piece:
            raise EOFError("Unexpected end of local byte stream")
        data.extend(piece)
    return bytes(data)


def exchange(listener, request, response):
    with socket.create_connection(listener.getsockname()[:2], timeout=3) as client:
        with listener.accept()[0] as server:
            server.settimeout(3)
            port = client.getsockname()[1]
            client.sendall(request)
            if receive_exact(server, len(request)) != request:
                raise RuntimeError('Local request length differs')
            server.sendall(response)
            received = receive_exact(client,len(response))
            client.shutdown(socket.SHUT_WR)
            assert receive_all(server) == b''
            server.shutdown(socket.SHUT_WR)
            assert receive_all(client) == b''
            assert received == response
            return port


def main(args):
    out=args.out.resolve()
    out.mkdir(parents=True)
    env=os.environ.copy()
    if env.get('LAB1_QT_ROOT'):
        qt=Path(env['LAB1_QT_ROOT'])
        env['PATH']=str(qt/'bin')+os.pathsep+env.get('PATH','')
        env['QT_QPA_PLATFORM_PLUGIN_PATH']=str(qt/'plugins/platforms')

    expected=[]
    results={'outcome':'incomplete','checks':{},'commands':[]}
    dump(out/'results.json',results)
    error=None
    def run(cmd, name):
        results['commands'].append([str(x) for x in cmd])
        r=subprocess.run(cmd,capture_output=True,text=True,encoding='utf-8',errors='replace',env=env,timeout=35)
        (out/(name+'.stderr.log')).write_text(r.stderr,encoding='utf-8')
        return r

    frame=(b'\x02'+b'\0'*11+b'\x12\x34')
    pcap(out/'count-capacity.pcap',(frame+struct.pack('<I',i) for i in range(2050)))
    pcap(out/'byte-capacity.pcap',(frame+struct.pack('<I',i)+b'\0'*(60000-18) for i in range(300)))
    pcap(out/'broken-record.pcap',[frame])
    with (out/'broken-record.pcap').open('ab') as f:
        f.write(struct.pack('<IIII',1700000001,0,30,30)+b'\0'*9)

    try:
        with listen(socket.AF_INET,'127.0.0.1') as srv4, listen(socket.AF_INET6,'::1') as srv6:
            port4,port6=srv4.getsockname()[1],srv6.getsockname()[1]
            expression=f'(tcp and (port {port4} or port {port6})) or (icmp and host 127.0.0.1) or (icmp6 and host ::1)'
            cmd=[str(args.probe.resolve()),str(out),expression,str(port4),str(port6)]
            results['commands'].append(cmd)
            with (out/'gui.log').open('wb') as log, subprocess.Popen(cmd,env=env,stdout=log,stderr=log) as proc:
                try:
                    for _ in range(125):
                        if (out/'ready').is_file(): break
                        if proc.poll() is not None: raise RuntimeError('GUI exited before ready')
                        time.sleep(.08)
                    else: raise RuntimeError('GUI was not ready')
                    response=b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK'
                    for srv, family, path, reply in [
                        (srv4,4,b'GET /lab HTTP/1.1\r\nHost: localhost\r\n\r\n',response),
                        (srv6,6,b'GET /ipv6 HTTP/1.1\r\nHost: localhost\r\n\r\n',response),
                        (srv4,4,b'GET /fake HTTP/1.1\r\nbad header\r\n\r\n',b'LAB1 not HTTP'),
                    ]:
                        client=exchange(srv,path,reply)
                        expected.append({'family':family,'client':client,'server':srv.getsockname()[1],
                                         'request_hex':path.hex(),'response_hex':reply.hex()})
                    for family,host in [(4,'127.0.0.1'),(6,'::1')]:
                        ping=run(['ping.exe',f'-{family}','-n','1','-w','1000',host],f'ping{family}')
                        (out/f'ping{family}.log').write_text(ping.stdout,encoding='utf-8')
                        results['checks'][f'ping{family}_socket']=ping.returncode==0
                finally:
                    dump(out/'socket-oracle.json',expected)
                    (out/'done').touch()
                results['gui_exit']=proc.wait(timeout=35)
        gui=json.loads((out/'gui-review.json').read_text(encoding='utf-8'))
        results['checks']['gui_checks']=gui['outcome']=='pass' and results['gui_exit']==0
        cap=out/'local-protocols.pcap'
        tsfields=['frame.number','frame.time_epoch','ip.version','ipv6.version','tcp.stream',
                  'tcp.srcport','tcp.dstport','tcp.flags','tcp.seq_raw','tcp.ack_raw','tcp.len',
                  'tcp.payload','icmp.type','icmpv6.type']
        cmd=[str(args.tshark),'-r',str(cap),'-T','fields','-E','header=y','-E','separator=,']
        for f in tsfields:cmd.extend(['-e',f])
        ts=run(cmd,'tshark')
        (out/'tshark.csv').write_text(ts.stdout,encoding='utf-8')
        results['checks']['tshark_read']=ts.returncode==0
        tsrows=list(csv.DictReader(io.StringIO(ts.stdout)))
        for field,values in [('icmp.type',{'0','8'}),('icmpv6.type',{'128','129'})]:
            results['checks'][field]=values.issubset({r[field] for r in tsrows})
        cmd=[str(args.cli),'--read',str(cap),'--json',str(out/'parsed.json')]
        results['checks']['cli_read']=run(cmd,'cli').returncode==0
        parsed=json.loads((out/'parsed.json').read_text(encoding='utf-8'))['packets']
        raw=read_pcap(cap)
        assert len(raw)==len(tsrows)==len(parsed)
        for i,ex in enumerate(expected):
            client,server=ex['client'],ex['server']
            rs=[r for r in tsrows if {r['tcp.srcport'],r['tcp.dstport']}=={str(client),str(server)}
                and (6 if r['ipv6.version'] else 4)==ex['family']]
            sent=[]
            for port in [client,server]:
                sent.append(''.join(r['tcp.payload'].replace(':','') for r in rs if int(r['tcp.srcport'])==port))
            results['checks'][f'flow{i}_socket_payloads']=sent==[ex['request_hex'],ex['response_hex']]
            results['checks'][f'flow{i}_tshark_stream']=len({r['tcp.stream'] for r in rs})==1
            declared=[]
            for r in rs:
                j=int(r['frame.number'])-1
                field=next((f for f in parsed[j]['fields'] if f['name']=='tcp.payload'),None)
                observed=raw[j][field['offset']:field['offset']+field['length']].hex() if field else ''
                declared.append(observed==r['tcp.payload'].replace(':',''))
            results['checks'][f'flow{i}_raw_spans']=bool(declared) and all(declared)
            http_ids=[p['number'] for p in parsed if p['protocol']=='HTTP' and
                      {p['srcPort'],p['dstPort']}=={client,server} and p['ipVersion']==ex['family']]
            results['checks'][f'flow{i}_http_labels']=len(http_ids)==(2 if i<2 else 0)
            if i<2:
                flow=gui['flow_ipv'+str(ex['family'])]
                correct=[]
                for approw,ref in zip(flow['rows'],rs):
                    correct.append((int(approw['id']),approw['direction'],approw['flags'],
                                    int(approw['seq']),int(approw['ack']),approw['payload_bytes'])==
                                   (int(ref['frame.number']),int(ref['tcp.srcport'])!=client,int(ref['tcp.flags'],16),
                                    int(ref['tcp.seq_raw']),int(ref['tcp.ack_raw']),int(ref['tcp.len'])))
                results['checks'][f'flow{i}_all_tshark_rows']=len(correct)==len(rs)==len(flow['rows']) and all(correct)
        saved=read_pcap(out/'retained-byte-capacity.pcap')
        results['checks']['pcap_retained_order_exact']=[struct.unpack_from('<I',f,14)[0] for f in saved]==list(range(21,300))
    except Exception as exc:
        error=repr(exc)
    finally:
        results.update(outcome='pass' if error is None and all(results['checks'].values()) else 'fail',
                       error=error, commit=subprocess.check_output(['git','rev-parse','HEAD'],text=True).strip(),
                       sha256={f.name:hashlib.sha256(f.read_bytes()).hexdigest() for f in out.glob('*.pcap')})
        dump(out/'results.json',results)
        print(json.dumps(results,ensure_ascii=True))
    return 0 if results['outcome']=='pass' else 1


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('probe','cli','out'):
        parser.add_argument('--'+name,required=True,type=Path)
    parser.add_argument('--tshark',default=os.environ.get('LAB1_TSHARK','tshark'))
    raise SystemExit(main(parser.parse_args()))

