import argparse,datetime,hashlib,json,os,platform,subprocess,sys,time,uuid
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
def sha(p): return hashlib.sha256(p.read_bytes()).hexdigest()
def execute(args):
    run=ROOT/'evidence/runs'/('lab-'+datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ')+'-'+uuid.uuid4().hex[:8])
    run.mkdir(parents=True,exist_ok=False)
    env=os.environ.copy()
    qt=Path(env['LAB1_QT_ROOT']).resolve() if env.get('LAB1_QT_ROOT') else None
    if qt:
        env['PATH']=str(qt/'bin')+os.pathsep+env['PATH']
        env['QT_QPA_PLATFORM_PLUGIN_PATH']=str(qt/'plugins/platforms')
    build=Path(env.get('LAB1_BUILD_DIR',ROOT/'build')).resolve()
    tshark=env.get('LAB1_TSHARK','tshark')
    prefix=['-DCMAKE_PREFIX_PATH='+str(qt)] if qt else []
    sdk=['-DNPCAP_SDK_DIR='+str(Path(env['LAB1_NPCAP_SDK']).resolve())] if env.get('LAB1_NPCAP_SDK') else []
    git=['git','-c','safe.directory='+str(ROOT),'-C',str(ROOT)]
    m={'run_id':run.name,'started':datetime.datetime.now(datetime.timezone.utc).isoformat(),'outcome':'incomplete','stages':[],'environment':{'platform':platform.platform(),'python':sys.version,'qt':'5.15.2','compiler':'MSVC x64','tshark':tshark},'git_commit':subprocess.check_output(git+['rev-parse','HEAD']).decode().strip(),'dirty':bool(subprocess.check_output(git+['status','--porcelain'])),'source_hashes':{},'input_hashes':{},'artifacts':{}}
    for d in ['src','scripts','tests']:
        for f in (ROOT/d).rglob('*'):
            if f.is_file() and f.suffix!='.bak' and '__pycache__' not in str(f):m['source_hashes'][f.relative_to(ROOT).as_posix()]=sha(f)
    m['source_hashes']['CMakeLists.txt']=sha(ROOT/'CMakeLists.txt')
    def save(): (run/'manifest.json').write_text(json.dumps(m,ensure_ascii=False,indent=2),encoding='utf8')
    def stage(name,cmd,timeout=180):
        start=time.perf_counter(); r={'name':name,'command':[str(x) for x in cmd],'outcome':'incomplete'};m['stages'].append(r);save()
        with (run/(name+'.stdout.log')).open('wb') as out,(run/(name+'.stderr.log')).open('wb') as err:
            startup=None
            if os.name=='nt':
                startup=subprocess.STARTUPINFO();startup.dwFlags|=subprocess.STARTF_USESHOWWINDOW;startup.wShowWindow=0
            proc=subprocess.Popen([str(x) for x in cmd],cwd=ROOT,env=env,stdout=out,stderr=err,startupinfo=startup)
            r['owned_pid']=proc.pid;save()
            try:
                code=proc.wait(timeout=timeout)
                r.update(exit_code=code,outcome='pass' if code==0 else 'fail')
            except subprocess.TimeoutExpired:
                r.update(exit_code=124,outcome='fail',reason='stage timeout; stop execution and clean only the owned process tree')
                cleanup={'owned_pid':proc.pid,'parent_alive_before_cleanup':proc.poll() is None}
                # Keep the owned parent alive until taskkill discovers its children.
                # Never use image-name matching or kill other build processes.
                if cleanup['parent_alive_before_cleanup']:
                    if os.name=='nt':
                        kill=[str(Path(os.environ.get('SYSTEMROOT',r'C:\Windows'))/'System32/taskkill.exe'),'/PID',str(proc.pid),'/T','/F']
                        cleanup['command']=kill
                        try:
                            with (run/(name+'.cleanup.stdout.log')).open('wb') as ko,(run/(name+'.cleanup.stderr.log')).open('wb') as ke:
                                kr=subprocess.run(kill,stdout=ko,stderr=ke,timeout=15,startupinfo=startup)
                            cleanup['taskkill_exit_code']=kr.returncode
                        except Exception as ce:cleanup['cleanup_error']=repr(ce)
                    else:
                        proc.kill();cleanup['boundary']='non-Windows fallback kills direct child only'
                try:proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill();proc.wait();cleanup['fallback_direct_kill']=True
                cleanup['parent_exit_code']=proc.returncode
                r['cleanup']=cleanup
                raise RuntimeError(name+' timed out; stage exit 124; see cleanup logs')
            finally:r['seconds']=time.perf_counter()-start;save()
        if code:raise RuntimeError(name+' failed; no fallback binary')
    try:
        if args.inject_timeout:
            # This test creates only a disposable parent and child, then deliberately times out.
            parent_code="import subprocess,sys,os,json,time; from pathlib import Path; child=subprocess.Popen([sys.executable,'-c','import time;time.sleep(60)']); Path(sys.argv[1]).write_text(json.dumps({'parent_pid':os.getpid(),'child_pid':child.pid}),encoding='utf-8'); time.sleep(60)"
            stage('intentional-timeout',[sys.executable,'-c',parent_code,run/'timeout-owned-pids.json'],2)
        stage('configure',['cmake','-S',ROOT,'-B',build,'-G','Visual Studio 17 2022','-A','x64',*prefix,*sdk])
        stage('build',['cmake','--build',build,'--config','Release'])
        stage('fixtures',[sys.executable,ROOT/'scripts/generate-fixtures.py','--out',run/'fixtures'])
        for f in (run/'fixtures').glob('*'):
            if f.is_file():m['input_hashes'][f.name]=sha(f)
        if args.inject_failure:stage('intentional-failure',[sys.executable,'-c','raise SystemExit(7)'])
        stage('regression',[sys.executable,ROOT/'tests/verify.py','--exe',build/'Release/lab1_cli.exe','--fixtures',run/'fixtures','--out',run/'checks','--tshark',tshark])
        if args.live:
            stage('live',[build/'Release/lab1_sniffer.exe','--live-demo',run/'live'],30)
        m['outcome']='pass'
    except Exception as e:m['outcome']='fail';m['error']=str(e)
    finally:
        m['ended']=datetime.datetime.now(datetime.timezone.utc).isoformat()
        m['artifacts']={p.relative_to(run).as_posix():sha(p) for p in run.rglob('*') if p.is_file() and p.name!='manifest.json'};save()
    print(json.dumps({'run':str(run),'outcome':m['outcome']},ensure_ascii=False))
    return 0 if m['outcome']=='pass' else 1
if __name__=='__main__':
    ap=argparse.ArgumentParser();ap.add_argument('--live',action='store_true');ap.add_argument('--inject-failure',action='store_true');ap.add_argument('--inject-timeout',action='store_true');sys.exit(execute(ap.parse_args()))

