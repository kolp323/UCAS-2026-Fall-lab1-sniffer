"""Acceptance runner with explicit expected values and TShark as independent reader.
Outputs are retained, including failure, and an existing output directory is refused.
"""
import argparse,csv,hashlib,ipaddress,json,os,random,struct,subprocess,sys,time
from pathlib import Path

def pcap_write(path,frames,link=1):
    raw=struct.pack('<IHHiIII',0xa1b2c3d4,2,4,0,0,65535,link)
    for i,(data,orig) in enumerate(frames):raw+=struct.pack('<IIII',1700000000+i,0,len(data),orig)+data
    path.write_bytes(raw)

def main(a):
    a.out.mkdir(parents=True,exist_ok=False)
    env=os.environ.copy();env['PATH']=r'E:\Anaconda3\Library\bin;'+env.get('PATH','')
    tests=[]; commands=[]
    def check(name,condition,detail=''):
        tests.append({'name':name,'outcome':'pass' if condition else 'fail','detail':detail})
    def cli(name,path,extra=(),expected_rc=0):
        output=a.out/(name+'.json')
        cmd=[str(a.exe),'--read',str(path),'--json',str(output),*extra]
        started=time.perf_counter()
        try:
            r=subprocess.run(cmd,capture_output=True,text=True,encoding='utf-8',errors='replace',env=env,timeout=30)
            code=r.returncode; stdout=r.stdout;stderr=r.stderr
        except subprocess.TimeoutExpired as e:code=124;stdout=str(e.stdout);stderr='TIMEOUT '+str(e.stderr)
        (a.out/(name+'.stdout.log')).write_text(stdout,encoding='utf-8');(a.out/(name+'.stderr.log')).write_text(stderr,encoding='utf-8')
        commands.append({'name':name,'command':cmd,'exit_code':code,'elapsed_seconds':time.perf_counter()-started})
        check(name+'.exit',code==expected_rc,'expected %s actual %s'%(expected_rc,code))
        return json.loads(output.read_text(encoding='utf-8-sig')) if output.exists() else None
    try:
        oracle=json.loads((a.fixtures/'expected.json').read_text(encoding='utf-8'))
        parsed={}
        for file,meta in oracle['files'].items():
            check(file+'.input-hash',hashlib.sha256((a.fixtures/file).read_bytes()).hexdigest()==meta['sha256'])
            if 'frames' not in meta:continue
            result=cli(file.replace('.','-'),a.fixtures/file)
            if not result:continue
            parsed[file]=result
            check(file+'.count',len(result['packets'])==len(meta['frames']) and result['complete'])
            for exp,row in zip(meta['frames'],result['packets']):
                differences={k:{'expected':v,'observed':row.get(k)} for k,v in exp['expected'].items() if row.get(k)!=v}
                check(exp['id'],not differences,json.dumps(differences))
                check(exp['id']+'.field-spans',all(f['offset']>=0 and f['length']>=0 and f['offset']+f['length']<=row['caplen'] for f in row['fields']))
        for filt,expected in oracle['display_sets'].items():
            result=cli('display-'+filt,a.fixtures/'ethernet.pcap',['--display-filter',filt])
            if result:check('display-'+filt+'.membership',[p['number'] for p in result['packets']]==expected)
        bpf=oracle['capture_bpf']
        # Independently hand-evaluate the observed Ethernet BPF branches, never parser output.
        pcap_bytes=(a.fixtures/'ethernet.pcap').read_bytes();pos=24;frame_id=0;manual=[]
        while pos<len(pcap_bytes):
            size=struct.unpack_from('<I',pcap_bytes,pos+8)[0];pos+=16;packet=pcap_bytes[pos:pos+size];pos+=size;frame_id+=1
            typ=int.from_bytes(packet[12:14],'big') if len(packet)>=14 else -1
            accepted=(typ==0x800 and len(packet)>23 and packet[23]==17) or (typ==0x86dd and len(packet)>20 and (packet[20]==17 or (packet[20]==44 and len(packet)>54 and packet[54]==17)))
            if accepted:manual.append(frame_id)
        check('capture-udp.independent-byte-predicate',manual==bpf['expected_source_frame_numbers'],json.dumps(manual))
        result=cli('capture-udp',a.fixtures/'ethernet.pcap',['--capture-filter',bpf['expression']])
        if result:
            observed=[int(p['timestamp'].split('.')[0])-1700000000+1 for p in result['packets']]
            check('capture-udp.membership',observed==bpf['expected_source_frame_numbers'],json.dumps(observed))
        cli('invalid-bpf',a.fixtures/'ethernet.pcap',['--capture-filter','udp and and'],2)
        cli('invalid-display',a.fixtures/'ethernet.pcap',['--display-filter','invented'],2)
        result=cli('bounded-output',a.fixtures/'ethernet.pcap',['--limit','1'],3)
        if result:check('limit-visible',result['complete'] is False and len(result['packets'])==1)
        cli('missing-file',a.out/'absent.pcap',expected_rc=2)
        corrupt=a.out/'invalid.pcap';corrupt.write_bytes(b'not-a-pcap');cli('invalid-pcap',corrupt,expected_rc=2)
        # Every proper prefix of a valid non-padded UDP Ethernet packet must be truncated.
        raw=(a.fixtures/'ethernet.pcap').read_bytes();n=struct.unpack_from('<I',raw,32)[0];frame=raw[40:40+n]
        prefixes=[(frame[:i],len(frame)) for i in range(len(frame))]
        prefix_file=a.out/'prefixes.pcap';pcap_write(prefix_file,prefixes)
        result=cli('prefix-sweep',prefix_file)
        if result:
            check('all-prefixes-truncated',len(result['packets'])==len(frame) and all(p['status']=='truncated' for p in result['packets']))
            check('prefix-fields-bounded',all(f['offset']+f['length']<=p['caplen'] for p in result['packets'] for f in p['fields']))
        # Bounded deterministic random corpus tests safety, not semantic correctness.
        rng=random.Random(20261120); random_frames=[]
        for i in range(1000):
            size=rng.randrange(0,257);data=bytes(rng.randrange(256) for _ in range(size));random_frames.append((data,size))
        random_file=a.out/'random.pcap';pcap_write(random_file,random_frames)
        result=cli('random-safety',random_file)
        if result:check('random-1000-safe-spans',len(result['packets'])==1000 and all(f['offset']+f['length']<=p['caplen'] for p in result['packets'] for f in p['fields']))
        # Independent TShark uses the SAME immutable input; compare address/port/length fields.
        fields=['frame.number','frame.cap_len','frame.len','ip.src','ip.dst','ipv6.src','ipv6.dst','tcp.srcport','tcp.dstport','udp.srcport','udp.dstport']
        for file in ['ethernet.pcap','loopback.pcap']:
            cmd=[str(a.tshark),'-r',str(a.fixtures/file),'-T','fields','-E','header=y','-E','separator=,']
            for f in fields:cmd+=['-e',f]
            r=subprocess.run(cmd,capture_output=True,text=True,encoding='utf-8',errors='replace',timeout=30)
            (a.out/(file+'.tshark.csv')).write_text(r.stdout,encoding='utf-8');(a.out/(file+'.tshark.stderr.log')).write_text(r.stderr,encoding='utf-8')
            check(file+'.tshark-exit',r.returncode==0)
            rows=list(csv.DictReader(r.stdout.splitlines()))
            valid=[p for p in parsed.get(file,{}).get('packets',[]) if p['status']=='valid']
            for p in valid:
                t=rows[p['number']-1]; issues=[]
                if int(t['frame.cap_len'])!=p['caplen'] or int(t['frame.len'])!=p['wirelen']:issues.append('length')
                for name in ['src','dst']:
                    value=t['ip.'+name] or t['ipv6.'+name]
                    if value and ipaddress.ip_address(value)!=ipaddress.ip_address(p[name]):issues.append(name)
                for name in ['src','dst']:
                    value=t['tcp.'+name+'port'] or t['udp.'+name+'port']
                    if value and int(value)!=p[name+'Port']:issues.append(name+'port')
                check(file+'.tshark-frame-'+str(p['number']),not issues,','.join(issues))
        # Raw-byte independent check for first Ethernet UDP record, no parser output in expected construction.
        udp_len=struct.unpack_from('!H',frame,14+20+4)[0]
        check('raw-first-frame-layout',len(frame)==46 and frame[12:14]==b'\x08\0' and frame[14]==0x45 and udp_len==12 and frame[42:]==b'LAB1')
        # Existing result cannot be overwritten by a rerun.
        r=subprocess.run([str(a.exe),'--read',str(a.fixtures/'ethernet.pcap'),'--json',str(a.out/'ethernet-pcap.json')],capture_output=True,env=env,timeout=30)
        check('output-overwrite-refused',r.returncode==2)
    except Exception as exc:
        tests.append({'name':'runner-exception','outcome':'fail','detail':repr(exc)})
    finally:
        result={'schema_version':1,'outcome':'fail' if any(t['outcome']!='pass' for t in tests) else 'pass','passed':sum(t['outcome']=='pass' for t in tests),'failed':sum(t['outcome']!='pass' for t in tests),'tests':tests,'commands':commands,'boundaries':['only declared structural parse scope','no checksum correctness claim','1000 random packets are a safety corpus, not proof against all malformed inputs','offline filters are not live-capture throughput','HTTP is complete-header heuristic without stream reassembly']}
        (a.out/'results.json').write_text(json.dumps(result,ensure_ascii=False,indent=2),encoding='utf-8')
        print(json.dumps({k:result[k] for k in ['outcome','passed','failed']}))
    return 0 if result['outcome']=='pass' else 1
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--exe',required=True,type=Path);p.add_argument('--fixtures',required=True,type=Path);p.add_argument('--out',required=True,type=Path);p.add_argument('--tshark',required=True,type=Path);sys.exit(main(p.parse_args()))

