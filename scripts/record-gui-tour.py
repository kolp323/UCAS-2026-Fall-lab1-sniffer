"""Record the real GUI via an isolated harness, then add concise teaching captions."""
import datetime,hashlib,json,math,os,shutil,subprocess,sys,uuid
from bisect import bisect_right
from pathlib import Path
from PIL import Image,ImageDraw,ImageFont
ROOT=Path(__file__).resolve().parents[1]
FF=Path(shutil.which(os.environ.get('LAB1_FFMPEG','ffmpeg')) or os.environ.get('LAB1_FFMPEG','ffmpeg'))
TS=os.environ.get('LAB1_TSHARK','tshark')
CAPTIONS=[
(0,6,'01  选择接口','选择回环接口，观察本机程序之间的通信。'),
(6,12,'02  设置捕获条件','设置 UDP 端口条件，筛选这次通信。'),
(12,19,'03  开始捕获','点击开始，列表显示新到达的数据包。'),
(19,25,'03  开始捕获','每一行对应一个包，可以查看地址、协议和长度。'),
(25,31,'04  停止捕获','停止捕获后，仍可查看已捕获的数据包。'),
(31,37,'05  保存数据','导出当前保留的数据，保存为 PCAP 文件。'),
(37,43,'06  打开文件','打开示例文件，查看多种协议。'),
(43,49,'07  筛选协议','选择 HTTP，只显示已识别的 HTTP 报文。'),
(49,56,'08  查看字段','选中一行，下方同步显示字段和原始字节。'),
(56,64,'09  定位原始字节','点击源地址，右侧高亮它对应的 4 个字节。'),
(64,72,'10  阅读应用数据','请求行包含方法、路径和 HTTP 版本。'),
(72,78,'11  查看 IPv6','切换到 IPv6，查看不同的网络层格式。'),
(78,84,'12  查看全部','切回全部协议，查看所有保留的数据包。'),
(84,89,'13  打开回环实验记录','打开实际抓到的 TCP、HTTP 和 ICMP 报文。'),
(89,94,'14  组合显示条件','组合协议、IP 版本和目标端口，保留指定的 HTTP 请求。'),
(94,101,'15  查看双向 TCP 流','从一个报文找到同一连接的双方、方向和载荷字节数。'),
(101,107,'15  阅读连接过程','按时间看握手、数据段和连接关闭。')]
COMPACT_CAPTIONS=[
 (0,4,'在回环接口上观察本机通信。'),
 (4,8,'捕获过滤按 UDP 端口选取报文。'),
 (8,17.6,'开始捕获，每行显示一个报文。'),
 (17.6,21,'停止捕获，已收到的报文仍可查看。'),
 (21,27,'将保留的报文导出为 PCAP。'),
 (27,33,'打开一份真实的回环抓包记录。'),
 (33,41,'选择 HTTP，查看识别出的请求和响应。'),
 (41,46,'选择 IPv4 源地址，右侧高亮对应的四个字节。'),
 (46,51,'HTTP 请求行包含方法、路径和协议版本。'),
 (51,59,'切换到 IPv6，查看 IPv6 数据包。'),
 (59,65.6,'组合协议和目标端口，定位一条请求。'),
 (65.6,71,'从这条请求打开双向 TCP 流。'),
 (71,78,'按捕获顺序查看握手、数据和连接关闭。'),
]
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
FPS = 24

def ass_time(seconds):
    cs = round(100 * seconds)
    return f'{cs//360000}:{cs//6000%60:02d}:{cs//100%60:02d}.{cs%100:02d}'

def pointer_track(path, tour, timeline):
    """Render the recorded mouse positions at video rate, with a brief click ring."""
    points = tour['pointer']
    point_ms = [p['elapsed_ms'] for p in points]
    click_ms = [p.get('pressed_ms', p['elapsed_ms']) for p in tour['clicks']]
    frame_ms = [f['elapsed_seconds'] * 1000 for f in timeline]
    first_ms = frame_ms[0]
    track = ["""[Script Info]
ScriptType: v4.00+
PlayResX: 1920
PlayResY: 1080
[V4+ Styles]
Format: Name,Fontname,Fontsize,PrimaryColour,SecondaryColour,OutlineColour,BackColour,Bold,Italic,Underline,StrikeOut,ScaleX,ScaleY,Spacing,Angle,BorderStyle,Outline,Shadow,Alignment,MarginL,MarginR,MarginV,Encoding
Style: Pointer,Arial,20,&H00FFFFFF,&H00FFFFFF,&H001A2330,&H00000000,0,0,0,0,100,100,0,0,1,0,0,7,0,0,0,1
[Events]
Format: Layer,Start,End,Style,Name,MarginL,MarginR,MarginV,Effect,Text"""]

    def vector(layer, n, x, y, style, shape):
        begin, end = ass_time(n/FPS), ass_time((n+1)/FPS)
        tags = r'{\an7\pos(' + f'{round(x)},{round(y)})' + style + r'\p1}'
        track.append(f'Dialogue: {layer},{begin},{end},Pointer,,0,0,0,,{tags}{shape}')

    for n in range(math.ceil((round(tour['duration_ms']/1000)-first_ms/1000)*FPS)):
        ms = first_ms + 1000*n/FPS
        i = max(0, bisect_right(point_ms, ms)-1)
        a, b = points[i], points[min(i+1, len(points)-1)]
        span = b['elapsed_ms']-a['elapsed_ms']
        # Movement is logged at animation ticks. Hold at long rests.
        weight = (ms-a['elapsed_ms'])/span if 0 < span <= 120 else 0
        local_x = a['x'] + weight*(b['x']-a['x'])
        local_y = a['y'] + weight*(b['y']-a['y'])
        frame = timeline[max(0, bisect_right(frame_ms, ms)-1)]
        left, top, right, bottom = frame['crop']
        if not (left <= local_x < right and top <= local_y < bottom):
            continue
        origin_x, origin_y = frame['origin']
        width, height = frame['size']
        x = origin_x + (local_x-left)*width/(right-left)
        y = origin_y + (local_y-top)*height/(bottom-top)
        j = bisect_right(click_ms, ms)-1
        if j >= 0 and ms-click_ms[j] < 410:
            t = (ms-click_ms[j])/410
            radius = round(13+22*t)
            alpha = int(12+243*t)
            # Draw a ring with the center transparent to keep the target readable.
            r = radius
            k = round(r*0.5523)
            ring = (f'm {r} 0 b {r+k} 0 {2*r} {r-k} {2*r} {r} '
                    f'b {2*r} {r+k} {r+k} {2*r} {r} {2*r} '
                    f'b {r-k} {2*r} 0 {r+k} 0 {r} b 0 {r-k} {r-k} 0 {r} 0')
            vector(0, n, x-radius, y-radius,
                   r'\1a&HFF&\3c&H9D6810&\bord3\3a&H'+f'{alpha:02X}&', ring)
        vector(1, n, x, y, r'\1c&HFFFFFF&\3c&H202932&\bord2.2',
               'm 0 0 l 1 31 9 23 15 35 21 32 15 20 27 19')

    path.write_text('\n'.join(track)+'\n', encoding='utf-8')

def compose(run,tour,manifest,execute,save):
  duration_seconds = round(tour['duration_ms']/1000)
  compact = tour.get("caption_profile")=="compact"
  captions = [(a,b,"",line) for a,b,line in COMPACT_CAPTIONS] if compact else CAPTIONS if duration_seconds>=100 else CAPTIONS[:13]+[(84,88,'捕获 → 筛选 → 分析 → 保存','捕获、筛选、查看字段，再把数据保存下来。')]
  (run/'captions.json').write_text(json.dumps(captions,ensure_ascii=False,indent=2),encoding='utf-8')
  raw=tour['frames'];composed=run/('composed-'+uuid.uuid4().hex[:8]);composed.mkdir();timeline=[];concat=[]
  font=ImageFont.truetype(str(Path(os.environ.get('SYSTEMROOT',r'C:\Windows'))/'Fonts/msyh.ttc'),34);small=ImageFont.truetype(str(Path(os.environ.get('SYSTEMROOT',r'C:\Windows'))/'Fonts/msyh.ttc'),25);subtitle=ImageFont.truetype(str(Path(os.environ.get('SYSTEMROOT',r'C:\Windows'))/'Fonts/msyh.ttc'),37)
  for j,f in enumerate(raw):
   elapsed=f['elapsed_ms']/1000;cap=next((c for c in captions if c[0]<=elapsed<c[1]),captions[-1])
   im=Image.new('RGB',(1920,1080),'#edf2f6');d=ImageDraw.Draw(im)
   if not compact:
    d.text((48,18),'实验 1A · 网络嗅探器',font=font,fill='#16354b')
    d.text((1220,25),cap[2],font=small,fill='#246978')
   img=Image.open(run/f['file']).convert('RGB')
   zoom = 41.9 <= elapsed < 51 if compact else 56 <= elapsed < 72
   if zoom and compact:
    crop=(9,tour['detail_top']-37,img.width-9,img.height-32)
   elif zoom:
    crop=(20,tour.get('detail_top',568)-8,min(1260,img.width),img.height-12)
   else:
    crop=(0,0,img.width,img.height)
   img=img.crop(crop)
   maxw,maxh=(1868,973) if compact else (1824,880)
   scale=min(maxw/img.width,maxh/img.height)
   size=(round(img.width*scale),round(img.height*scale))
   img=img.resize(size,Image.Resampling.LANCZOS)
   x=(1920-size[0])//2
   y=(12 if compact else 78)+(maxh-size[1])//2
   im.paste(img,(x,y))
   if compact:
    d.rectangle((0,997,1920,1080),fill='#1f2937')
    d.text((960,1036),cap[3],font=subtitle,fill='white',anchor='mm')
   else:
    d.rectangle((0,975,1920,1080),fill='#17384b')
    bbox=d.textbbox((0,0),cap[3],font=subtitle)
    d.text(((1920-(bbox[2]-bbox[0]))//2,1002),cap[3],font=subtitle,fill='white')
   dest=composed/f'frame-{j:05d}.png';im.save(dest,compress_level=3)
   nexttime=raw[j+1]['elapsed_ms']/1000 if j+1<len(raw) else duration_seconds
   duration=max(.01,nexttime-elapsed)
   concat.extend(["file '"+dest.as_posix()+"'",'duration '+str(duration)])
   timeline.append({'frame':j,'source':f['file'],'elapsed_seconds':elapsed,'caption':cap[3],
                    'detail_crop':zoom, 'origin':(x,y), 'size':size, 'crop':crop})
  concat.append("file '"+dest.as_posix()+"'")
  listing=run/'composition.ffconcat';listing.write_text('\n'.join(concat),encoding='utf-8')
  (run/'composition.json').write_text(json.dumps(timeline,ensure_ascii=False,indent=2),encoding='utf-8')
  out=run/'lab1A-demo.mp4'
  effect=[]
  if tour.get('pointer'):
   pointer_path=run/'pointer.ass'
   pointer_track(pointer_path,tour,timeline)
   # Pass a repository-relative path to avoid special treatment of drive colons.
   effect=['-vf','fps=24,ass='+pointer_path.relative_to(ROOT).as_posix()]
  execute('encode',[FF,'-y','-f','concat','-safe','0','-i',listing,*effect,'-r',str(FPS),
                    '-c:v','libx264','-preset','fast','-crf','21','-pix_fmt','yuv420p',
                    '-movflags','+faststart',out],timeout=240)
  probe=subprocess.run([str(FF.with_name('ffprobe.exe')),'-v','error','-show_entries','format=duration,size:stream=codec_name,width,height,r_frame_rate','-of','json',str(out)],capture_output=True,check=True);metadata=json.loads(probe.stdout)
  (run/'ffprobe.json').write_text(json.dumps(metadata,indent=2))
  execute('decode',[FF,'-v','error','-xerror','-i',out,'-f','null','-'])
  keydir=run/'keyframes'/uuid.uuid4().hex[:8];keydir.mkdir(parents=True);manifest['keyframes_dir']=keydir.relative_to(run).as_posix()
  first=raw[0]['elapsed_ms']/1000
  samples=([3,12,20,24,29,38,43,48,54,63,70,74] if compact else
           [4,16,22,33,40,46,59,67,75,82]+([93.6,98.5,104] if duration_seconds>=100 else []))
  if tour.get('clicks'):
   samples.extend(p.get('pressed_ms',p['elapsed_ms'])/1000-first+0.075 for p in tour['clicks']
                  if p['action'] in {'choose loopback','click start','confirm export PCAP',
                                      'display filter HTTP','select field ip.src','select field http.start_line'})
  for sec in samples:
   subprocess.run([str(FF),'-v','error','-ss',f'{sec:.3f}','-i',str(out),'-frames:v','1',
                   str(keydir/f'{sec:06.3f}s.png')],check=True)
  manifest.update(outcome='pass',video_path=str(out),video_sha256=sha(out),ffprobe=metadata,
                  frame_count=len(raw),captions=captions,
                  gui={'sent':tour['sent'],'received':tour['received'],'captured':tour['captured']},
                  independent_export='pass', pointer_clicks=len(tour.get('clicks',[])),
                  form='GUI widget renders with concise teaching captions and a pointer composed from the mouse events used to operate the widgets.')
  save();print(json.dumps(manifest,ensure_ascii=False))

def main(review):
 run=ROOT/'evidence/runs'/('gui-tour-'+datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ')+'-'+uuid.uuid4().hex[:8]);run.mkdir(parents=True)
 work=ROOT/'build'/('tour-'+uuid.uuid4().hex[:8]);work.mkdir()
 cmake=f'''cmake_minimum_required(VERSION 3.20)
project(gui_tour LANGUAGES CXX)
set(CMAKE_CXX_STANDARD 17)
find_package(Qt5 5.15 REQUIRED COMPONENTS Widgets Network Test)
add_subdirectory("{ROOT.as_posix()}" app EXCLUDE_FROM_ALL)
add_executable(lab1_gui_tour "{(ROOT/'probes/recording/gui-tour.cpp').as_posix()}")
target_compile_options(lab1_gui_tour PRIVATE /utf-8 /W4)
target_link_libraries(lab1_gui_tour PRIVATE lab1_parser Qt5::Widgets Qt5::Network Qt5::Test)
capture_target(lab1_gui_tour)
'''
 (work/'CMakeLists.txt').write_text(cmake,encoding='utf-8')
 env=os.environ.copy()
 qt=Path(env['LAB1_QT_ROOT']).resolve() if env.get('LAB1_QT_ROOT') else None
 if qt:
  env['PATH']=str(qt/'bin')+os.pathsep+env['PATH']
  env['QT_QPA_PLATFORM_PLUGIN_PATH']=str(qt/'plugins/platforms')
 prefixes=['-DCMAKE_PREFIX_PATH='+str(qt)] if qt else []
 sdk=Path(env.get('LAB1_NPCAP_SDK',ROOT/'.deps/npcap-sdk-1.17')).resolve()
 manifest={'run_id':run.name,'outcome':'incomplete','gui_source_sha256':sha(ROOT/'src/gui.cpp'),'harness_sha256':sha(ROOT/'probes/recording/gui-tour.cpp'),'script_sha256':sha(Path(__file__)),'source_commit':subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip(),'commands':[]}
 def save(): (run/'manifest.json').write_text(json.dumps(manifest,ensure_ascii=False,indent=2),encoding='utf-8')
 def execute(name,cmd,timeout=180):
  manifest['commands'].append({'name':name,'argv':[str(x) for x in cmd]});save()
  with (run/(name+'.log')).open('wb') as log:
   cp=subprocess.run([str(x) for x in cmd],env=env,cwd=ROOT,stdout=log,stderr=subprocess.STDOUT,timeout=timeout)
  manifest['commands'][-1]['exit_code']=cp.returncode;save()
  if cp.returncode:raise RuntimeError(name+' failed')
 try:
  execute('configure',['cmake','-S',work,'-B',work/'b','-G','Visual Studio 17 2022','-A','x64',*prefixes,'-DNPCAP_SDK_DIR='+str(sdk)])
  execute('build',['cmake','--build',work/'b','--config','Release','--target','lab1_gui_tour'])
  real=run/'local-protocols.pcap'
  review=Path(review).resolve()
  verified=json.loads((review/'results.json').read_text(encoding='utf-8'))
  assert verified['outcome']=='pass'
  shutil.copy2(review/real.name,real)
  server_port=json.loads((review/'socket-oracle.json').read_text(encoding='utf-8'))[0]['server']
  assert sha(real)==verified['sha256'][real.name]
  manifest['real_input']={'run':review.name,'sha256':sha(real),'server_port':server_port};save()
  execute('gui',[work/'b/Release/lab1_gui_tour.exe',run,real,str(server_port)],timeout=145)
  tour=json.loads((run/'tour.json').read_text(encoding='utf-8'));assert tour['outcome']=='pass'
  check=subprocess.run([TS,'-r',str(run/'live-export.pcap'),'-T','fields','-e','udp.payload'],capture_output=True,check=True)
  payloads=check.stdout.decode().splitlines();assert payloads==tour['payloads_hex'] and len(payloads)==30
  (run/'independent-export-check.json').write_text(json.dumps({'outcome':'pass','tshark_payload_count':len(payloads),'payloads_match_in_order':True,'pcap_sha256':sha(run/'live-export.pcap')},indent=2))
  compose(run,tour,manifest,execute,save)
 except Exception as e:manifest.update(outcome='fail',error=str(e));save();print(run);raise
def recompose(run):
 run=Path(run).resolve();manifest=json.loads((run/'manifest.json').read_text(encoding='utf-8'));tour=json.loads((run/'tour.json').read_text(encoding='utf-8'))
 assert tour['outcome']=='pass'
 stamp=datetime.datetime.now().strftime('%Y%m%d-%H%M%S')
 for name in ['manifest.json','captions.json','composition.ffconcat','composition.json','ffprobe.json']:
  src=run/name
  if src.exists():shutil.copy2(src,src.with_name(src.name+'.'+stamp+'.bak'))
 manifest['recomposition']={'timestamp':stamp,'script_sha256':sha(Path(__file__)),'raw_tour_sha256':sha(run/'tour.json'),'purpose':'Rebuild the presentation from the saved GUI frames and input trace.'}
 def save():(run/'manifest.json').write_text(json.dumps(manifest,ensure_ascii=False,indent=2),encoding='utf-8')
 def execute(name,cmd,timeout=180):
  with (run/('recompose-'+name+'-'+stamp+'.log')).open('wb') as log:
   cp=subprocess.run([str(x) for x in cmd],stdout=log,stderr=subprocess.STDOUT,timeout=timeout)
  manifest['commands'].append({'name':'recompose-'+name,'argv':[str(x) for x in cmd],'exit_code':cp.returncode});save()
  if cp.returncode:raise RuntimeError(name+' failed')
 compose(run,tour,manifest,execute,save)
if __name__=='__main__':
 if len(sys.argv)==3 and sys.argv[1]=='--recompose':recompose(sys.argv[2])
 else:
  if len(sys.argv)!=3 or sys.argv[1]!='--review':sys.exit("Usage: record-gui-tour.py --review <passing live review directory>")
  main(sys.argv[2])
