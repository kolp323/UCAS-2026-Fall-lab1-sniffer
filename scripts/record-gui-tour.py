"""Record the real GUI via an isolated harness, then add concise teaching captions."""
import datetime,hashlib,json,os,shutil,struct,subprocess,sys,uuid
from pathlib import Path
from PIL import Image,ImageDraw,ImageFont
ROOT=Path(__file__).resolve().parents[1]
FF=Path(r'E:\ffmpeg\bin\ffmpeg.exe')
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
(84,88,'捕获 → 筛选 → 分析 → 保存','捕获、筛选、查看字段，再把数据保存下来。')]
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def compose(run,tour,manifest,execute,save):
  (run/'captions.json').write_text(json.dumps(CAPTIONS,ensure_ascii=False,indent=2),encoding='utf-8')
  raw=tour['frames'];composed=run/('composed-'+uuid.uuid4().hex[:8]);composed.mkdir();timeline=[];concat=[]
  font=ImageFont.truetype(r'C:\Windows\Fonts\msyh.ttc',34);small=ImageFont.truetype(r'C:\Windows\Fonts\msyh.ttc',25);subtitle=ImageFont.truetype(r'C:\Windows\Fonts\msyh.ttc',37)
  for j,f in enumerate(raw):
   elapsed=f['elapsed_ms']/1000;cap=next((c for c in CAPTIONS if c[0]<=elapsed<c[1]),CAPTIONS[-1])
   im=Image.new('RGB',(1920,1080),'#edf2f6');d=ImageDraw.Draw(im)
   d.text((48,18),'实验 1A · 网络嗅探器',font=font,fill='#16354b');d.text((1220,25),cap[2],font=small,fill='#246978')
   img=Image.open(run/f['file']).convert('RGB');zoom=56<=elapsed<72
   if zoom:img=img.crop((20,560,1260,img.height-33))
   maxw,maxh=(1824,880);scale=min(maxw/img.width,maxh/img.height);size=(round(img.width*scale),round(img.height*scale));img=img.resize(size,Image.Resampling.LANCZOS)
   x=(1920-size[0])//2;y=78+(880-size[1])//2;im.paste(img,(x,y))
   d.rectangle((0,975,1920,1080),fill='#17384b');bbox=d.textbbox((0,0),cap[3],font=subtitle);d.text(((1920-(bbox[2]-bbox[0]))//2,1002),cap[3],font=subtitle,fill='white')
   dest=composed/f'frame-{j:05d}.png';im.save(dest,compress_level=3)
   nexttime=raw[j+1]['elapsed_ms']/1000 if j+1<len(raw) else 88
   duration=max(.01,nexttime-elapsed)
   concat.extend(["file '"+dest.as_posix()+"'",'duration '+str(duration)])
   timeline.append({'frame':j,'source':f['file'],'elapsed_seconds':elapsed,'caption':cap[3],'detail_crop':zoom})
  concat.append("file '"+dest.as_posix()+"'")
  listing=run/'composition.ffconcat';listing.write_text('\n'.join(concat),encoding='utf-8')
  (run/'composition.json').write_text(json.dumps(timeline,ensure_ascii=False,indent=2),encoding='utf-8')
  out=ROOT/'deliverables/lab1A-demo.mp4';old=out.with_name(out.name+'.'+datetime.datetime.now().strftime('%Y%m%d-%H%M%S')+'.bak')
  if out.exists():shutil.copy2(out,old)
  execute('encode',[FF,'-y','-f','concat','-safe','0','-i',listing,'-r','24','-c:v','libx264','-preset','fast','-crf','21','-pix_fmt','yuv420p','-movflags','+faststart',out],timeout=180)
  probe=subprocess.run([str(FF.with_name('ffprobe.exe')),'-v','error','-show_entries','format=duration,size:stream=codec_name,width,height,r_frame_rate','-of','json',str(out)],capture_output=True,check=True);metadata=json.loads(probe.stdout)
  (run/'ffprobe.json').write_text(json.dumps(metadata,indent=2));execute('decode',[FF,'-v','error','-i',out,'-f','null','-'])
  keydir=run/('keyframes-'+uuid.uuid4().hex[:8]);keydir.mkdir();manifest['keyframes_dir']=keydir.name
  for sec in [4,16,22,33,40,46,59,67,75,82]:
   idx=min(range(len(raw)),key=lambda j:abs(raw[j]['elapsed_ms']/1000-sec));shutil.copy2(composed/f'frame-{idx:05d}.png',keydir/f'{sec:02d}s.png')
  manifest.update(outcome='pass',video_path=str(out),video_sha256=sha(out),ffprobe=metadata,frame_count=len(raw),captions=CAPTIONS,gui= {'sent':tour['sent'],'received':tour['received'],'captured':tour['captured']},independent_export='pass',form='Actual GUI widget renders and actual dialog/button/filter/field operations, with teaching captions and detail crops; no compilation-log segments.');save();print(json.dumps(manifest,ensure_ascii=False))

def main():
 run=ROOT/'evidence/runs'/('gui-tour-'+datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ')+'-'+uuid.uuid4().hex[:8]);run.mkdir(parents=True)
 work=ROOT/'build'/('tour-'+uuid.uuid4().hex[:8]);work.mkdir()
 cmake=f'''cmake_minimum_required(VERSION 3.20)
project(gui_tour LANGUAGES CXX)
set(CMAKE_CXX_STANDARD 17)
find_package(Qt5 5.15 REQUIRED COMPONENTS Widgets Network)
add_subdirectory("{ROOT.as_posix()}" app EXCLUDE_FROM_ALL)
add_executable(lab1_gui_tour "{(ROOT/'probes/recording/gui-tour.cpp').as_posix()}")
target_compile_options(lab1_gui_tour PRIVATE /utf-8 /W4)
target_link_libraries(lab1_gui_tour PRIVATE lab1_parser Qt5::Widgets Qt5::Network)
capture_target(lab1_gui_tour)
'''
 (work/'CMakeLists.txt').write_text(cmake,encoding='utf-8')
 env=os.environ.copy();env['PATH']=r'E:\Anaconda3\Library\bin;'+env['PATH'];env['QT_QPA_PLATFORM_PLUGIN_PATH']=r'E:\Anaconda3\Library\plugins\platforms';env['QT_QPA_PLATFORM']='windows'
 manifest={'run_id':run.name,'outcome':'incomplete','gui_source_sha256':sha(ROOT/'src/gui.cpp'),'harness_sha256':sha(ROOT/'probes/recording/gui-tour.cpp'),'script_sha256':sha(Path(__file__)),'production_gui_unchanged':True,'commands':[]}
 def save(): (run/'manifest.json').write_text(json.dumps(manifest,ensure_ascii=False,indent=2),encoding='utf-8')
 def execute(name,cmd,timeout=180):
  manifest['commands'].append({'name':name,'argv':[str(x) for x in cmd]});save()
  with (run/(name+'.log')).open('wb') as log:
   cp=subprocess.run([str(x) for x in cmd],env=env,cwd=ROOT,stdout=log,stderr=subprocess.STDOUT,timeout=timeout)
  manifest['commands'][-1]['exit_code']=cp.returncode;save()
  if cp.returncode:raise RuntimeError(name+' failed')
 try:
  execute('configure',['cmake','-S',work,'-B',work/'b','-G','Visual Studio 17 2022','-A','x64','-DCMAKE_PREFIX_PATH=E:/Anaconda3/Library','-DNPCAP_SDK_DIR='+str(ROOT/'.deps/npcap-sdk-1.17')])
  execute('build',['cmake','--build',work/'b','--config','Release','--target','lab1_gui_tour'])
  data=(ROOT/'fixtures/v2/ethernet.pcap').read_bytes();expected=json.loads((ROOT/'fixtures/v2/expected.json').read_text());selected=[f['number'] for f in expected['files']['ethernet.pcap']['frames'] if f['expected'].get('status')=='valid']
  records=[];pos=24;i=1
  while pos<len(data):
   n=struct.unpack_from('<I',data,pos+8)[0]
   if i in selected: records.append(data[pos:pos+16+n])
   pos+=16+n;i+=1
  assert len(records)==10
  sample=run/'protocol-demo.pcap';sample.write_bytes(data[:24]+b''.join(records))
  manifest['sample']={'source':'fixtures/v2/ethernet.pcap','source_sha256':hashlib.sha256(data).hexdigest(),'source_frames':selected,'sha256':sha(sample),'count':len(records)};save()
  execute('gui',[work/'b/Release/lab1_gui_tour.exe',run,sample],timeout=120)
  tour=json.loads((run/'tour.json').read_text(encoding='utf-8'));assert tour['outcome']=='pass'
  check=subprocess.run([r'E:\APP\Wireshark\tshark.exe','-r',str(run/'live-export.pcap'),'-T','fields','-e','udp.payload'],capture_output=True,check=True)
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
 manifest['recomposition']={'timestamp':stamp,'script_sha256':sha(Path(__file__)),'raw_tour_sha256':sha(run/'tour.json'),'purpose':'Refine two captions and the detail crop; reuse the same actual GUI frames.'}
 def save():(run/'manifest.json').write_text(json.dumps(manifest,ensure_ascii=False,indent=2),encoding='utf-8')
 def execute(name,cmd,timeout=180):
  with (run/('recompose-'+name+'-'+stamp+'.log')).open('wb') as log:
   cp=subprocess.run([str(x) for x in cmd],stdout=log,stderr=subprocess.STDOUT,timeout=timeout)
  manifest['commands'].append({'name':'recompose-'+name,'argv':[str(x) for x in cmd],'exit_code':cp.returncode});save()
  if cp.returncode:raise RuntimeError(name+' failed')
 compose(run,tour,manifest,execute,save)
if __name__=='__main__':
 if len(sys.argv)==3 and sys.argv[1]=='--recompose':recompose(sys.argv[2])
 else:main()
