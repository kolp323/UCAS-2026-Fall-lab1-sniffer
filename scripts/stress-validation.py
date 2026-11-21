import json,subprocess,hashlib,csv,os
from pathlib import Path
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
r=Path(__file__).resolve().parents[1]/'evidence/runs/stress-20261120-105412'
s=json.loads((r/'summary.json').read_text());rows=[]
fig,axes=plt.subplots(1,2,figsize=(10,4))
for i,x in enumerate(s['runs']):
    assert x['counts_pass'] and x['responsiveness_pass'] and x['process_exit']==0
    packet_file=r/f'repeat-{i+1}/live.pcap'
    cp=subprocess.run([os.environ.get('LAB1_TSHARK','tshark'),'-r',str(packet_file),'-T','fields','-e','udp.payload'],capture_output=True,check=True)
    payloads=cp.stdout.decode().splitlines();assert len(payloads)==2000 and all(p==x['payload_hex'] for p in payloads)
    (r/f'export-check-{i+1}.txt').write_text(f'TShark: {len(payloads)} retained packets; all payloads equal controlled input. Full observed3000 not all retained.\n')
    trace=x['resource_trace']; t=[v['elapsed_ms']/1000 for v in trace]
    axes[0].plot(t,[v['retained'] for v in trace],label=f'Run {i+1} retained')
    axes[1].plot(t,[v['working_set_bytes']/1048576 for v in trace],label=f'Run {i+1}')
    assert all(v['retained']<=2000 and v['retained_raw_bytes']<=16777216 for v in trace)
    rows.append({'repeat':i+1,'sent':x['sent'],'captured':x['captured'],'retained':x['retained'],'evicted':x['evicted'],'stop_ms':x['stop_ms'],'max_heartbeat_gap_ms':x['max_capture_heartbeat_gap_ms'],'send_span_ms':x['last_send_elapsed_ms']-x['first_send_elapsed_ms'],'driver_drop':x['driver_dropped'],'pcap_sha256':hashlib.sha256(packet_file.read_bytes()).hexdigest()})
axes[0].axhline(2000,ls='--',color='gray',label='Retention cap');axes[0].set_ylabel('retained packets');axes[0].set_title('Bounded retained window')
axes[1].set_ylabel('working set (MiB)');axes[1].set_title('Measured process memory')
for a in axes:a.set_xlabel('elapsed seconds');a.legend(fontsize=8);a.spines[['top','right']].set_visible(False)
fig.suptitle('3 independent finite loopback runs | 3,000 datagrams each');fig.tight_layout(rect=[0,.06,1,.94]);fig.text(.05,.02,'50 datagrams per 30 ms nominal burst; stop measured after finite input ends. No unlimited-load claim.',fontsize=8);fig.savefig(r/'stress-resources.png',dpi=180);fig.savefig(r/'stress-resources.svg')
with (r/'measurements.csv').open('w',newline='') as f:w=csv.DictWriter(f,fieldnames=rows[0]);w.writeheader();w.writerows(rows)
(r/'independent-check.json').write_text(json.dumps({'outcome':'pass','retained_exports_tshark_checked':3,'declared_bounds_checked':True,'rows':rows,'source':'summary.json and each live.pcap','boundary':'Finite bursts only;2000 retained packet exports per run, not full3000 archive'},indent=2))
print(json.dumps(rows))
