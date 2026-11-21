"""Build and smoke-test a local portable runtime from PE imports, without installing drivers.
This is same-machine dependency isolation, NOT a clean operating-system test.
"""
import argparse,hashlib,json,os,re,shutil,subprocess,sys,time
from pathlib import Path
import psutil

def main(a):
    for name in ('out','evidence','fixture','build'):
        setattr(a,name,getattr(a,name).resolve())
    qt=Path(a.qt_root).resolve()
    a.out.mkdir(parents=True,exist_ok=False);a.evidence.mkdir(parents=True,exist_ok=False)
    dllroot=qt/'bin';sysroot=Path(os.environ.get('SYSTEMROOT',r'C:\Windows'))
    dumpbin=a.dumpbin
    queue=[];manifest=[];visited=set();imports={}
    def copy(src,dest):
        dest.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(src,dest)
        manifest.append({'source':str(src),'destination':str(dest.relative_to(a.out)),'sha256':hashlib.sha256(dest.read_bytes()).hexdigest()})
        queue.append(dest)
    for name in ['lab1_sniffer.exe','lab1_cli.exe']:copy(a.build/name,a.out/name)
    copy(qt/'plugins/platforms/qwindows.dll',a.out/'platforms/qwindows.dll')
    while queue:
        binary=queue.pop(0)
        if binary.name.lower() in visited:continue
        visited.add(binary.name.lower())
        r=subprocess.run([str(dumpbin),'/dependents',str(binary)],capture_output=True,text=True,errors='replace',timeout=30)
        if r.returncode:raise RuntimeError('dumpbin failed '+str(binary))
        (a.evidence/(binary.name+'.imports.txt')).write_text(r.stdout,encoding='utf-8')
        names=re.findall(r'^\s+([A-Za-z0-9_.-]+\.dll)\s*$',r.stdout,re.M|re.I);imports[binary.name]=names
        for name in names:
            if name.lower()=='wpcap.dll':continue # Explicit installed Npcap prerequisite.
            if name.lower().startswith(('api-ms-','ext-ms-')):continue # Windows API sets, not application files.
            if (sysroot/'System32'/name).exists():continue
            source=dllroot/name
            if not source.exists():raise FileNotFoundError('Unresolved dependency '+name)
            dest=a.out/name
            if not dest.exists():copy(source,dest)
    (a.out/'qt.conf').write_text('[Paths]\nPlugins=.\n',encoding='utf-8')
    readme='''# Local portable runtime verification package

Contains only the application, required Qt/third-party runtime DLLs discovered from PE imports, and the Windows platform plugin. Npcap is NOT bundled; the installed Npcap 1.83 driver/runtime and a compatible Microsoft Visual C++ runtime remain prerequisites. Source code lives in the parent project. This folder is a local development/test output, not a claim of licensed turnkey redistribution. Before redistribution, include the applicable Qt/third-party license notices and comply with their terms.

The smoke test runs on the SAME computer with PATH restricted to Windows System32 and Qt plugin paths pointed inside this package. A successful result proves independence from the Anaconda directory for the observed execution, not compatibility with a new operating system or all GUI operations. Evidence includes imported DLL lists, package hashes, loaded module paths, actual GUI render, exit status and independent CLI output.
'''
    (a.out/'README.md').write_text(readme,encoding='utf-8')
    (a.evidence/'package-files.json').write_text(json.dumps({'files':manifest,'imports':imports},indent=2),encoding='utf-8')
    env=os.environ.copy()
    for k in list(env):
        if k.startswith(('QT_','CONDA','PYTHON')):env.pop(k,None)
    env['PATH']=str(sysroot/'System32');env['QT_QPA_PLATFORM_PLUGIN_PATH']=str(a.out/'platforms');env['QT_PLUGIN_PATH']=str(a.out);env['QT_QPA_PLATFORM']='windows'
    startup=subprocess.STARTUPINFO();startup.dwFlags|=subprocess.STARTF_USESHOWWINDOW;startup.wShowWindow=0
    screenshot=a.evidence/'portable-gui.png'
    cmd=[str(a.out/'lab1_sniffer.exe'),'--demo',str(a.fixture),'--screenshot',str(screenshot),'--auto-exit','5000']
    started=time.time();modules=[]
    with (a.evidence/'gui.stdout.log').open('w',encoding='utf-8') as stdout,(a.evidence/'gui.stderr.log').open('w',encoding='utf-8') as stderr:
        proc=subprocess.Popen(cmd,env=env,cwd=a.out,stdout=stdout,stderr=stderr,startupinfo=startup)
        time.sleep(2)
        if proc.poll() is None:
            modules=sorted(set(m.path for m in psutil.Process(proc.pid).memory_maps() if m.path.lower().endswith(('.dll','.exe'))))
        try:code=proc.wait(timeout=15)
        except subprocess.TimeoutExpired:proc.kill();proc.wait();code=124
    (a.evidence/'loaded-modules.json').write_text(json.dumps(modules,indent=2),encoding='utf-8')
    cli=subprocess.run([str(a.out/'lab1_cli.exe'),'--read',str(a.fixture),'--json',str(a.evidence/'portable-cli.json')],env=env,cwd=a.out,capture_output=True,text=True,errors='replace',timeout=20)
    (a.evidence/'cli.stderr.log').write_text(cli.stderr,encoding='utf-8')
    qt_loaded=[x for x in modules if Path(x).name.lower().startswith('qt5')]
    foreign=[x for x in qt_loaded if not Path(x).is_relative_to(a.out)]
    pic_report=screenshot.with_suffix(screenshot.suffix+'.json')
    gui_report=json.loads(pic_report.read_text(encoding='utf-8')) if pic_report.exists() else {}
    result={'outcome':'pass' if code==0 and cli.returncode==0 and screenshot.exists() and gui_report.get('loaded')==20 and len(qt_loaded)>=4 and not foreign else 'fail','gui_exit_code':code,'cli_exit_code':cli.returncode,'elapsed_seconds':time.time()-started,'path':env['PATH'],'plugin_path':env['QT_QPA_PLATFORM_PLUGIN_PATH'],'loaded_module_count':len(modules),'qt_module_paths':qt_loaded,'external_qt_modules':foreign,'gui':gui_report,'package_file_count':len(manifest),'boundary':'Same machine with isolated runtime paths; Npcap and VC runtime installed. No clean OS, architecture portability, distribution licensing or full interactive GUI certification.'}
    (a.evidence/'result.json').write_text(json.dumps(result,indent=2),encoding='utf-8');print(json.dumps(result));return 0 if result['outcome']=='pass' else 1
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--build',type=Path,required=True);p.add_argument('--out',type=Path,required=True);p.add_argument('--evidence',type=Path,required=True);p.add_argument('--fixture',type=Path,required=True);p.add_argument('--qt-root',default=os.environ.get('LAB1_QT_ROOT'));p.add_argument('--dumpbin',default=os.environ.get('LAB1_DUMPBIN','dumpbin'))
    a=p.parse_args()
    if not a.qt_root:p.error('Set LAB1_QT_ROOT or supply --qt-root')
    sys.exit(main(a))
