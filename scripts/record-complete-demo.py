"""Execute a fresh build/deployment/regression and make a readable evidence video.
Frames render contemporaneous command output, not a simulated terminal or human desktop.
Full stdout, commands, return codes, elapsed times, input/source hashes remain beside video.
"""
import argparse,datetime,hashlib,json,os,queue,shutil,subprocess,sys,textwrap,threading,time,uuid,zipfile
from pathlib import Path
from PIL import Image,ImageDraw,ImageFont
ROOT=Path(__file__).resolve().parents[1]
FFMPEG=Path(shutil.which(os.environ.get('LAB1_FFMPEG','ffmpeg')) or os.environ.get('LAB1_FFMPEG','ffmpeg'))
FFPROBE=FFMPEG.with_name('ffprobe.exe')
FONT=Path(os.environ.get('SYSTEMROOT',r'C:\Windows'))/'Fonts/msyh.ttc'

def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def stamp():return datetime.datetime.now(datetime.timezone.utc).isoformat()

def main(a):
    run=ROOT/'evidence/runs'/('complete-demo-'+datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ')+'-'+uuid.uuid4().hex[:8]);run.mkdir(parents=True)
    frames=run/'frames';frames.mkdir();logs=run/'logs';logs.mkdir()
    git=['git','-c','safe.directory='+str(ROOT),'-C',str(ROOT)]
    commit=subprocess.check_output(git+['rev-parse',a.commit]).decode().strip()
    archive=run/'source.zip';subprocess.run(git+['archive','--format=zip','-o',str(archive),commit,'CMakeLists.txt','src','probes','tests','scripts'],check=True)
    source=run/'source';source.mkdir()
    with zipfile.ZipFile(archive) as z:z.extractall(source)
    env=os.environ.copy()
    if env.get('LAB1_QT_ROOT'):
        qt=Path(env['LAB1_QT_ROOT']).resolve()
        env['PATH']=str(qt/'bin')+os.pathsep+env['PATH']
        env['QT_QPA_PLATFORM_PLUGIN_PATH']=str(qt/'plugins/platforms')
    prefix=['-DCMAKE_PREFIX_PATH='+str(qt)] if env.get('LAB1_QT_ROOT') else []
    start=time.perf_counter();timeline=[];stages=[];frame_index=0
    titlefont=ImageFont.truetype(str(FONT),30);bodyfont=ImageFont.truetype(str(FONT),19);logfont=ImageFont.truetype(str(FONT),17);small=ImageFont.truetype(str(FONT),16)
    def render(title,why,command,output,status='运行中',mode='live'):
        nonlocal frame_index
        im=Image.new('RGB',(1280,720),'#f4f7fb');d=ImageDraw.Draw(im)
        d.rectangle((0,0,1280,10),fill='#194465');d.text((30,25),'实验 1A · 编译—部署—测试全过程',font=titlefont,fill='#17314b')
        d.text((30,78),'自动执行日志画面｜不是人工桌面录屏｜完整命令和日志随证据保留',font=bodyfont,fill='#53677b')
        d.text((30,118),title,font=bodyfont,fill='#17314b');d.text((30,150),why,font=small,fill='#53677b')
        d.rounded_rectangle((25,185,1255,655),radius=8,fill='#102333')
        cmdlines=textwrap.wrap(command,width=112,break_long_words=True) or ['(说明页，不执行命令)']
        y=200
        for line in cmdlines[:4]:d.text((40,y),line,font=logfont,fill='#a8d4f1');y+=23
        y+=12
        lines=[]
        for row in output:
            lines.extend(textwrap.wrap(row.expandtabs(2),width=116,break_long_words=True) or [''])
        room=max(1,int((640-y)/24))
        for line in lines[-room:]:d.text((40,y),line,font=logfont,fill='#eaf2f7');y+=24
        d.text((30,674),f'{status}  |  source {commit[:12]}  |  全量日志：logs/',font=small,fill='#257246' if status.startswith('通过') else '#53677b')
        file=frames/f'frame-{frame_index:05d}.png';im.save(file,compress_level=3)
        timeline.append({'frame':frame_index,'stage':title,'mode':mode,'wall_elapsed_seconds':time.perf_counter()-start,'rendered_log_lines':len(output),'status':status})
        frame_index+=1
    def hold(title,why,command,output,status,seconds=6):
        # Repeated frozen frames intentionally provide reading time; not extra measurements.
        render(title,why,command,output,status,'reading-hold')
        last=frames/f'frame-{frame_index-1:05d}.png'
        nonlocal_dummy=None
        for _ in range(seconds*2-1):
            nonlocal_add(last,title,status)
    def nonlocal_add(last,title,status):
        nonlocal frame_index
        dest=frames/f'frame-{frame_index:05d}.png';shutil.copyfile(last,dest)
        timeline.append({'frame':frame_index,'stage':title,'mode':'reading-hold','wall_elapsed_seconds':time.perf_counter()-start,'status':status});frame_index+=1
    def stage(name,title,why,cmd,expected=0,timeout=180):
        cmd=[str(x) for x in cmd];shown=subprocess.list2cmdline(cmd)
        meta={'name':name,'title':title,'command':cmd,'started':stamp(),'expected_exit':expected,'outcome':'incomplete'};stages.append(meta)
        (run/'stages.json').write_text(json.dumps(stages,ensure_ascii=False,indent=2),encoding='utf-8')
        q=queue.Queue();lines=[];t=time.perf_counter()
        startup=subprocess.STARTUPINFO();startup.dwFlags|=subprocess.STARTF_USESHOWWINDOW;startup.wShowWindow=0
        proc=subprocess.Popen(cmd,cwd=source,env=env,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,startupinfo=startup)
        def read():
            with (logs/(name+'.combined.log')).open('wb') as log:
                for raw in iter(proc.stdout.readline,b''):
                    log.write(raw);log.flush()
                    try:line=raw.decode('utf-8')
                    except UnicodeDecodeError:line=raw.decode('gb18030',errors='replace')
                    q.put(line.rstrip())
        thread=threading.Thread(target=read,daemon=True);thread.start()
        while proc.poll() is None or not q.empty() or thread.is_alive():
            while True:
                try:lines.append(q.get_nowait())
                except queue.Empty:break
            render(title,why,shown,lines,'运行中','live')
            if time.perf_counter()-t>timeout:
                proc.kill();proc.wait();meta['timeout']=True;break
            time.sleep(.5)
        thread.join(timeout=3)
        while not q.empty():lines.append(q.get())
        code=proc.wait();meta.update(exit_code=code,seconds=time.perf_counter()-t,ended=stamp(),outcome='pass' if code==expected and not meta.get('timeout') else 'fail')
        lines+=['',f'ACTUAL EXIT CODE: {code} | EXPECTED: {expected} | {meta["outcome"].upper()}']
        hold(title,why,shown,lines,('通过 · 预期拒绝' if expected else '通过') if meta['outcome']=='pass' else '失败 · 保留证据',6)
        (run/'stages.json').write_text(json.dumps(stages,ensure_ascii=False,indent=2),encoding='utf-8')
        if meta['outcome']!='pass':raise RuntimeError(name+' failed; no fallback binaries')
    manifest={'run_id':run.name,'source_commit':commit,'source_archive_sha256':sha(archive),'started':stamp(),'outcome':'incomplete','video_kind':'Contemporaneous automated stdout rendering plus prior actual GUI QWidget frames. Not human desktop recording. Reading holds stretch playback relative to execution time.','gui_clip_source':str(a.gui_clip),'gui_clip_sha256':sha(a.gui_clip)}
    try:
        hold('00 / 明确证据和边界','新目录构建，失败即停止；不会运行旧二进制。','git archive '+commit+' CMakeLists.txt src probes tests scripts',[
            'Source snapshot: '+commit,'This recording executes configure, build, tests and dependency deployment.',
            'GUI ending: reused actual rendered frames from visual-20261120T024203Z-3f5e5ed1.',
            'Same-machine PATH isolation is NOT a clean-operating-system test.',
            'Full commands, original output and real elapsed times remain in the evidence directory.'
        ],'说明 · 接下来实际执行',7)
        build=ROOT/'build'/('demo-'+uuid.uuid4().hex[:8]);manifest['fresh_build_directory']=str(build);fixture=run/'fixtures';checks=run/'checks'
        stage('configure','01 / 从空目录配置构建','识别编译器和 Qt / Npcap，明确环境，而不是复用旧缓存。',['cmake','-S',source,'-B',build,'-G','Visual Studio 17 2022','-A','x64',*prefix,'-DNPCAP_SDK_DIR='+str(Path(env.get('LAB1_NPCAP_SDK',ROOT/'.deps/npcap-sdk-1.17')).resolve())])
        stage('build','02 / 实际编译与链接','从源码生成 GUI 和 CLI；编译失败就停止，不回退旧程序。',['cmake','--build',build,'--config','Release'])
        stage('fixtures','03 / 生成固定输入','样本与独立预期一起生成；保存输入哈希，避免只挑成功报文。',[sys.executable,source/'scripts/generate-fixtures.py','--out',fixture])
        stage('regression','04 / 执行独立验收','固定预期 + TShark + 原始字节；过滤、边界、异常必须同时检查。',[sys.executable,source/'tests/verify.py','--exe',build/'Release/lab1_cli.exe','--fixtures',fixture,'--out',checks,'--tshark',env.get('LAB1_TSHARK','tshark')])
        stage('negative','05 / 故意提交错误过滤式','预期非零退出是正确拒绝；保留错误输出，不能改断言掩盖失败。',[build/'Release/lab1_cli.exe','--read',fixture/'ethernet.pcap','--capture-filter','udp and (','--json',run/'invalid-filter.json'],expected=2)
        stage('recovery','06 / 修正后重新运行','将过滤式修正为 udp；使用新的结果路径，避免覆盖旧证据。',[build/'Release/lab1_cli.exe','--read',fixture/'ethernet.pcap','--capture-filter','udp','--json',run/'corrected-filter.json'])
        stage('deploy','07 / 实际部署与隔离路径验证','收集必需 DLL，在仅 System32 PATH 下运行，检查加载模块路径。',[sys.executable,source/'scripts/package-runtime.py','--build',build/'Release','--out',run/'runtime','--evidence',run/'deployment','--fixture',fixture/'ethernet.pcap'],timeout=120)
        regression=json.loads((checks/'results.json').read_text(encoding='utf-8'));deployment=json.loads((run/'deployment/result.json').read_text(encoding='utf-8'))
        assert regression['outcome']==deployment['outcome']=='pass'
        hold('08 / 结果与下一段 GUI 演示','结论只覆盖实测范围；附完整日志后再看实际 GUI 行为。','Summary from checks/results.json and deployment/result.json',[
            f'Regression: {regression["passed"]} passed / {regression["failed"]} failed.',
            f'Deployment: GUI exit={deployment["gui_exit_code"]}, CLI exit={deployment["cli_exit_code"]}.',
            'Anaconda modules loaded in isolated deployment: '+str(deployment['anaconda_modules']),
            'Negative filter rejected, corrected filter accepted; both original logs retained.',
            'Next: prior actual GUI run, invalid-filter error -> recovery -> local capture -> stop/export.',
            'Not claimed: manual operation, clean OS, TCP reassembly, TLS decryption or arbitrary-load resilience.'
        ],'通过 · 范围与局限已注明',9)
        video1=run/'execution-log.mp4';part2=run/'gui-normalized.mp4';out=a.out
        out.parent.mkdir(parents=True,exist_ok=True)
        if out.exists():shutil.copy2(out,out.with_name(out.name+'.'+datetime.datetime.now().strftime('%Y%m%d-%H%M%S')+'.bak'))
        commands=[
            [str(FFMPEG),'-y','-framerate','2','-i',str(frames/'frame-%05d.png'),'-r','24','-c:v','libx264','-preset','fast','-crf','20','-pix_fmt','yuv420p',str(video1)],
            [str(FFMPEG),'-y','-i',str(a.gui_clip),'-vf','scale=1280:720:force_original_aspect_ratio=decrease,pad=1280:720:(ow-iw)/2:(oh-ih)/2:color=0x102333,setsar=1','-r','24','-an','-c:v','libx264','-preset','fast','-crf','20','-pix_fmt','yuv420p',str(part2)]
        ]
        for i,cmd in enumerate(commands):
            cp=subprocess.run(cmd,capture_output=True,timeout=180);(logs/f'encode-{i}.log').write_bytes(cp.stderr)
            if cp.returncode:raise RuntimeError('video encode failed')
        concat=run/'concat.txt';concat.write_text("file 'execution-log.mp4'\nfile 'gui-normalized.mp4'\n",encoding='utf-8')
        cp=subprocess.run([str(FFMPEG),'-y','-f','concat','-safe','0','-i',str(concat),'-c','copy','-movflags','+faststart',str(out)],capture_output=True,timeout=60);(logs/'concat.log').write_bytes(cp.stderr)
        if cp.returncode:raise RuntimeError('concat failed')
        probe=subprocess.run([str(FFPROBE),'-v','error','-show_entries','format=duration,size:stream=codec_name,width,height,r_frame_rate','-of','json',str(out)],capture_output=True,check=True)
        (run/'ffprobe.json').write_bytes(probe.stdout)
        validate=subprocess.run([str(FFMPEG),'-v','error','-i',str(out),'-f','null','-'],capture_output=True,timeout=180);(logs/'decode-validation.log').write_bytes(validate.stderr)
        if validate.returncode:raise RuntimeError('full video decode failed')
        manifest.update(outcome='pass',video_path=str(out),video_sha256=sha(out),ffprobe=json.loads(probe.stdout),regression={'passed':regression['passed'],'failed':regression['failed']},deployment_outcome=deployment['outcome'],frame_count=frame_index)
    except Exception as e:
        manifest.update(outcome='fail',error=repr(e));raise
    finally:
        manifest.update(ended=stamp(),stages=stages,frame_timeline='frame-timeline.json')
        (run/'frame-timeline.json').write_text(json.dumps(timeline,ensure_ascii=False,indent=2),encoding='utf-8')
        (run/'manifest.json').write_text(json.dumps(manifest,ensure_ascii=False,indent=2),encoding='utf-8')
        print(json.dumps({'run':str(run),'outcome':manifest['outcome'],'video':str(a.out)},ensure_ascii=False))
    return 0
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--commit',default='9727f83');p.add_argument('--gui-clip',required=True,type=Path);p.add_argument('--out',default=ROOT/'deliverables/lab1A-demo.mp4',type=Path);sys.exit(main(p.parse_args()))


