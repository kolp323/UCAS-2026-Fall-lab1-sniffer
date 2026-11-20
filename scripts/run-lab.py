import argparse,datetime,hashlib,json,os,platform,subprocess,sys,time,uuid
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
def sha(p): return hashlib.sha256(p.read_bytes()).hexdigest()
def execute(args):
    run=ROOT/'evidence/runs'/('lab-'+datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ')+'-'+uuid.uuid4().hex[:8])
    run.mkdir(parents=True,exist_ok=False)
    env=os.environ.copy(); env['PATH']=r'E:\Anaconda3\Library\bin;'+env['PATH'];env['QT_QPA_PLATFORM_PLUGIN_PATH']=r'E:\Anaconda3\Library\plugins\platforms';env['QT_QPA_PLATFORM']='windows'
    git=['git','-c','safe.directory='+str(ROOT),'-C',str(ROOT)]
    m={'run_id':run.name,'started':datetime.datetime.now(datetime.timezone.utc).isoformat(),'outcome':'incomplete','stages':[],'environment':{'platform':platform.platform(),'python':sys.version,'qt':'5.15.2','compiler':'MSVC x64','tshark':r'E:\APP\Wireshark\tshark.exe'},'git_commit':subprocess.check_output(git+['rev-parse','HEAD']).decode().strip(),'dirty':bool(subprocess.check_output(git+['status','--porcelain'])),'source_hashes':{},'input_hashes':{},'artifacts':{}}
    for d in ['src','scripts','tests']:
        for f in (ROOT/d).rglob('*'):
            if f.is_file() and '__pycache__' not in str(f):m['source_hashes'][f.relative_to(ROOT).as_posix()]=sha(f)
    def save(): (run/'manifest.json').write_text(json.dumps(m,ensure_ascii=False,indent=2),encoding='utf8')
    def stage(name,cmd,timeout=180):
        start=time.perf_counter(); r={'name':name,'command':[str(x) for x in cmd],'outcome':'incomplete'};m['stages'].append(r);save()
        with (run/(name+'.stdout.log')).open('wb') as out,(run/(name+'.stderr.log')).open('wb') as err:
            try:
                cp=subprocess.run([str(x) for x in cmd],cwd=ROOT,env=env,stdout=out,stderr=err,timeout=timeout)
                r.update(exit_code=cp.returncode,outcome='pass' if cp.returncode==0 else 'fail')
            except subprocess.TimeoutExpired:
                r.update(exit_code=124,outcome='fail',reason='timeout; owned child terminated');raise
            finally:r['seconds']=time.perf_counter()-start;save()
        if cp.returncode:raise RuntimeError(name+' failed; no fallback binary')
    try:
        stage('configure',['cmake','-S',ROOT,'-B',ROOT/'build','-G','Visual Studio 17 2022','-A','x64','-DCMAKE_PREFIX_PATH=E:/Anaconda3/Library'])
        stage('build',['cmake','--build',ROOT/'build','--config','Release'])
        stage('fixtures',[sys.executable,ROOT/'scripts/generate-fixtures.py','--out',run/'fixtures'])
        for f in (run/'fixtures').glob('*'):
            if f.is_file():m['input_hashes'][f.name]=sha(f)
        if args.inject_failure:stage('intentional-failure',[sys.executable,'-c','raise SystemExit(7)'])
        stage('regression',[sys.executable,ROOT/'tests/verify.py','--exe',ROOT/'build/Release/lab1_cli.exe','--fixtures',run/'fixtures','--out',run/'checks','--tshark',r'E:\APP\Wireshark\tshark.exe'])
        if args.live:
            stage('live',[ROOT/'build/Release/lab1_sniffer.exe','--live-demo',run/'live'],30)
        m['outcome']='pass'
    except Exception as e:m['outcome']='fail';m['error']=str(e)
    finally:
        m['ended']=datetime.datetime.now(datetime.timezone.utc).isoformat()
        m['artifacts']={p.relative_to(run).as_posix():sha(p) for p in run.rglob('*') if p.is_file() and p.name!='manifest.json'};save()
    print(json.dumps({'run':str(run),'outcome':m['outcome']},ensure_ascii=False))
    return 0 if m['outcome']=='pass' else 1
if __name__=='__main__':
    ap=argparse.ArgumentParser();ap.add_argument('--live',action='store_true');ap.add_argument('--inject-failure',action='store_true');sys.exit(execute(ap.parse_args()))

