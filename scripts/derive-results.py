import argparse,csv,json,hashlib
from pathlib import Path
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
p=argparse.ArgumentParser();p.add_argument('--run',required=True,type=Path);a=p.parse_args();run=a.run
rows=list(csv.DictReader((run/'measurements.csv').open()));formal=[r for r in rows if r['phase']=='formal']
fig,axes=plt.subplots(1,2,figsize=(10,4));fig.patch.set_facecolor('#f4f7fb')
for ax,key,title,unit,factor in [(axes[0],'wall_seconds','Offline full-process duration','seconds',1),(axes[1],'peak_sampled_rss_bytes','Sampled process peak memory','MiB',1/1048576)]:
    vals=[float(r[key])*factor for r in formal];ax.bar([1,2,3],vals,color=['#126b8a','#218da5','#61adba']);ax.set_xticks([1,2,3],['Run 1','Run 2','Run 3']);ax.set_title(title);ax.set_ylabel(unit);ax.spines[['top','right']].set_visible(False)
    for i,v in enumerate(vals):ax.text(i+1,v,f'{v:.3f}',ha='center',va='bottom',fontsize=9)
fig.suptitle('6,000 fixed packets per independent process | 3 formal runs');fig.tight_layout(rect=[0,.06,1,.93]);fig.text(.05,.02,'Includes startup and JSON output. Not live capture throughput. RSS sampled every 20 ms; peaks may be missed.',fontsize=8)
fig.savefig(run/'performance.png',dpi=180);fig.savefig(run/'performance.svg');plt.close(fig)
(run/'figure-provenance.json').write_text(json.dumps({'input':'measurements.csv','input_sha256':hashlib.sha256((run/'measurements.csv').read_bytes()).hexdigest(),'generator':'scripts/derive-results.py','formal_processes':3,'pilot_excluded_from_chart_but_preserved':True,'numeric_values':formal},indent=2))
print(run/'performance.png')
