import datetime,json,os,subprocess,time,uuid
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
run=ROOT/'evidence/runs'/('visual-'+datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ')+'-'+uuid.uuid4().hex[:8]);run.mkdir(parents=True)
env=os.environ.copy()
if env.get('LAB1_QT_ROOT'):
    qt=Path(env['LAB1_QT_ROOT']).resolve()
    env['PATH']=str(qt/'bin')+os.pathsep+env['PATH']
    env['QT_QPA_PLATFORM_PLUGIN_PATH']=str(qt/'plugins/platforms')
exe=Path(env.get('LAB1_BUILD_DIR',ROOT/'build')).resolve()/'Release/lab1_sniffer.exe';results=[]
for name,options in [('live',['--live-demo',run/'live','--record-frames',run/'frames','--auto-exit','7000']),('normal',['--demo',ROOT/'fixtures/v2/ethernet.pcap','--screenshot',run/'normal.png','--auto-exit','3500']),('malformed',['--demo',ROOT/'fixtures/v2/ethernet.pcap','--screenshot',run/'malformed.png','--select-status','malformed','--auto-exit','3500']),('http',['--demo',ROOT/'fixtures/v2/ethernet.pcap','--screenshot',run/'http.png','--display-filter','HTTP','--auto-exit','3500']),('capacity',['--demo',ROOT/'fixtures/v2/load.pcap','--screenshot',run/'capacity.png','--auto-exit','6000'])]:
    start=time.perf_counter()
    with (run/(name+'.stdout.log')).open('wb') as out,(run/(name+'.stderr.log')).open('wb') as err:
        cp=subprocess.run([str(exe)]+[str(x) for x in options],env=env,stdout=out,stderr=err,timeout=25)
    results.append({'name':name,'exit_code':cp.returncode,'wall_seconds':time.perf_counter()-start})
    if cp.returncode:raise RuntimeError(name+' failed')
video=subprocess.run([env.get('LAB1_FFMPEG','ffmpeg'),'-y','-framerate','10','-i',str(run/'frames/frame-%05d.png'),'-vf','pad=ceil(iw/2)*2:ceil(ih/2)*2','-c:v','libx264','-pix_fmt','yuv420p',str(run/'automated-live-demo.mp4')],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
(run/'video.log').write_bytes(video.stderr)
meta=json.loads((run/'live/live-demo.json').read_text());assert meta['outcome']=='pass'
fields=subprocess.run([env.get('LAB1_TSHARK','tshark'),'-r',str(run/'live/live.pcap'),'-T','fields','-e','udp.payload'],capture_output=True,check=True).stdout.decode().splitlines();assert len(fields)==10 and all(x==meta['payload_hex'] for x in fields)
(run/'live/tshark-payloads.txt').write_text('\n'.join(fields))
cap=json.loads((run/'capacity.png.json').read_text());normal=json.loads((run/'normal.png.json').read_text());http=json.loads((run/'http.png.json').read_text())
# Actual properties are retained as an independent review input, not hidden if schema changes.
summary={'outcome':'pass' if video.returncode==0 else 'fail','runs':results,'live':meta,'capacity':cap,'normal':normal,'http':http,'video_exit':video.returncode,'video_kind':'actual application QWidget frame rendering with scripted operations; not human desktop recording; timestamps in frames.json'}
(run/'summary.json').write_text(json.dumps(summary,ensure_ascii=False,indent=2))
print(run)
