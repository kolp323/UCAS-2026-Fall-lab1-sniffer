import argparse,csv,datetime,hashlib,json,os,platform,statistics,struct,subprocess,time,uuid
from pathlib import Path
import psutil
ROOT=Path(__file__).resolve().parents[1]
p=argparse.ArgumentParser();p.add_argument('--source',required=True);a=p.parse_args()
run=ROOT/'evidence/runs'/('perf-'+datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ')+'-'+uuid.uuid4().hex[:8]);run.mkdir(parents=True)
data=Path(a.source).read_bytes();pos=24;records=[]
while pos<len(data):
    n=struct.unpack_from('<I',data,pos+8)[0];records.append(data[pos:pos+16+n]);pos+=16+n
assert records
# Pilot and formal repetitions are distinguished, same fixed input for each process.
fixture=run/'load.pcap';fixture.write_bytes(data[:24]+b''.join(records[i%len(records)] for i in range(6000)))
config={'metric':'offline CLI full-process elapsed including JSON serialization; not wire capture rate','packets_per_run':6000,'formal_independent_processes':3,'pilot_processes':1,'timeout_seconds':30,'sampling_seconds':0.02,'threshold_source':'engineering guardrail 30s, not course requirement','fixture_sha256':hashlib.sha256(fixture.read_bytes()).hexdigest(),'platform':platform.platform(),'cpu':platform.processor(),'memory_bytes':psutil.virtual_memory().total}
(run/'config.json').write_text(json.dumps(config,indent=2))
env=os.environ.copy();env['PATH']=r'E:\Anaconda3\Library\bin;'+env['PATH'];rows=[];samples=[]
for i in range(4):
    out=run/f'parsed-{i}.json';start=time.perf_counter()
    with (run/f'stderr-{i}.log').open('wb') as err:
        proc=subprocess.Popen([str(ROOT/'build/Release/lab1_cli.exe'),'--read',str(fixture),'--json',str(out)],env=env,stderr=err,stdout=subprocess.DEVNULL)
        ps=psutil.Process(proc.pid);peak=0
        while proc.poll() is None:
            try:
                rss=ps.memory_info().rss;cpu=ps.cpu_times();peak=max(peak,rss);samples.append({'repeat':i,'seconds':time.perf_counter()-start,'rss_bytes':rss,'cpu_seconds':cpu.user+cpu.system})
            except psutil.Error:pass
            if time.perf_counter()-start>30:proc.kill();proc.wait();break
            time.sleep(.02)
        elapsed=time.perf_counter()-start
    observed=json.loads(out.read_text()) if out.exists() else {}
    rows.append({'repeat':i,'phase':'pilot' if i==0 else 'formal','wall_seconds':elapsed,'peak_sampled_rss_bytes':peak,'exit_code':proc.returncode,'read_count':observed.get('read_count',-1),'outcome':'pass' if proc.returncode==0 and observed.get('read_count')==6000 else 'fail'})
for name,rs in [('measurements.csv',rows),('resources.csv',samples)]:
    with (run/name).open('w',newline='') as f:
        w=csv.DictWriter(f,fieldnames=list(rs[0]));w.writeheader();w.writerows(rs)
(run/'summary.json').write_text(json.dumps({'outcome':'pass' if all(r['outcome']=='pass' for r in rows) else 'fail','runs':rows,'config':config,'boundary':'No throughput improvement claim; no real-network performance conclusion; RSS samples may miss peaks'},indent=2))
print(run)
