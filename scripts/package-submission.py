"""Create the course-named unencrypted ZIP from committed source and reviewed media.
New output only; source history is included as a verified Git bundle.
"""
import argparse,datetime,hashlib,io,json,subprocess,uuid,zipfile
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
def digest(p): return hashlib.sha256(p.read_bytes()).hexdigest()
def main(a):
    for value in (a.name,a.student_id):
        if not value or any(c in value for c in '<>:"/\\|?*'):raise ValueError('Invalid filename identity')
    base=a.name+'_'+a.student_id
    top=base+'_EX1A'; src=top+'/'+base+'_ex1A_src/'
    dest=ROOT/'deliverables'/(top+'.zip')
    if dest.exists():raise FileExistsError('Refusing to overwrite '+str(dest))
    git=['git','-C',str(ROOT)]
    commit=subprocess.check_output(git+['rev-parse','HEAD']).decode().strip()
    implementation=subprocess.check_output(git+['rev-parse',a.implementation_commit+'^{commit}']).decode().strip()
    subprocess.run(git+['merge-base','--is-ancestor',implementation,commit],check=True)
    for run in a.evidence_run:
        if '/' in run or '\\' in run or run in ('.','..') or not (ROOT/'evidence/runs'/run).is_dir():
            raise ValueError("Invalid evidence run: "+run)
    if subprocess.check_output(git+['status','--porcelain','--untracked-files=no']).strip():raise RuntimeError('Commit tracked changes before packaging')
    scratch=ROOT/'build'/('pkg-'+uuid.uuid4().hex[:8]);scratch.mkdir(parents=True,exist_ok=False)
    bundle=scratch/'history.bundle'
    subprocess.run(git+['bundle','create',str(bundle),'--all'],check=True,capture_output=True)
    verify=subprocess.run(git+['bundle','verify',str(bundle)],capture_output=True,text=True,errors='replace')
    if verify.returncode:raise RuntimeError(verify.stderr)
    archive=subprocess.check_output(git+['archive','--format=zip','HEAD'])
    report=a.report.resolve();video=ROOT/'deliverables/lab1A-demo.mp4'
    for p in (report,video):
        if not p.is_file() or p.stat().st_size==0:raise FileNotFoundError(p)
    text=''.join(page.extract_text() for page in __import__('pypdf').PdfReader(str(report)).pages)
    if not all(x in text for x in (a.name,a.student_id,'kolp323')):raise RuntimeError('Report identity or repository missing')
    manifest={'created_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'source_commit':commit,'implementation_commit':implementation,'included_evidence_runs':a.evidence_run,'repository':'https://github.com/kolp323/UCAS-2026-Fall-lab1-sniffer','name':a.name,'student_id':a.student_id,'report_sha256':digest(report),'video_sha256':digest(video),'git_bundle_sha256':digest(bundle),'course_requirement':'PDF pages2-3: course-named source folder/report/video and unencrypted ZIP; PPT supplied separately','scope':'Prepared and checked; NOT uploaded to course website. Same-machine reproduction only.'}
    with zipfile.ZipFile(dest,'x',compression=zipfile.ZIP_DEFLATED,compresslevel=6) as z:
        with zipfile.ZipFile(io.BytesIO(archive)) as source:
            for item in source.infolist():
                if item.is_dir():
                    continue
                # The bundle preserves complete history, including older raw runs.
                # Keep only the requested runs in the checked-out ZIP snapshot.
                parts=item.filename.split('/')
                if parts[:2]==['evidence','runs'] and parts[2] not in a.evidence_run:
                    continue
                z.writestr(src+item.filename,source.read(item))
        z.write(bundle,src+'history.bundle')
        z.writestr(src+'submission-manifest.json',json.dumps(manifest,ensure_ascii=False,indent=2))
        authoring=ROOT/'deliverables/authoring'
        report_sources=[ROOT/'deliverables/lab1A-report.md',ROOT/'deliverables/README.md',
                        *sorted(authoring.glob('*')), *sorted((authoring/'figures').glob('*'))]
        for p in report_sources:
            if p.is_file() and not p.name.endswith('.bak'):
                z.write(p,src+'report-sources/'+p.relative_to(ROOT/'deliverables').as_posix())
        z.write(report,top+'/'+base+'_ex1A_report.pdf')
        z.write(video,top+'/'+base+'_ex1A_play.mp4')
    with zipfile.ZipFile(dest) as z:
        names=z.namelist();bad=z.testzip()
        assert bad is None and len(names)==len(set(names)) and all(not(i.flag_bits&1) for i in z.infolist())
        assert src+'src/gui.cpp' in names and src+'CMakeLists.txt' in names and src+'history.bundle' in names
        # Full real extraction uses Windows extended-length paths to preserve nested evidence.
        extracted=scratch/'extracted';extracted.mkdir()
        z.extractall('\\\\?\\'+str(extracted.resolve()))
        assert digest(extracted/top/(base+'_ex1A_report.pdf'))==digest(report)
        assert digest(extracted/top/(base+'_ex1A_play.mp4'))==digest(video)
    result={**manifest,'outcome':'pass','zip':str(dest),'zip_sha256':digest(dest),'zip_bytes':dest.stat().st_size,'entries':len(names),'crc_check':'pass','encryption':False,'full_extraction':'pass','extraction_path':str(extracted),'git_bundle_verify':verify.stdout+verify.stderr}
    check=dest.with_suffix('.validation.json');check.write_text(json.dumps(result,ensure_ascii=False,indent=2),encoding='utf-8')
    print(json.dumps(result,ensure_ascii=False))
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--name',required=True);p.add_argument('--student-id',required=True);p.add_argument('--implementation-commit',default='HEAD');p.add_argument('--report',type=Path,default=ROOT/'deliverables/lab1A-report.pdf');p.add_argument('--evidence-run',action='append',default=[]);main(p.parse_args())
