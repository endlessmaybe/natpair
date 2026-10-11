import hashlib,json,pathlib,subprocess
r=pathlib.Path(__file__).parent;exe=r/'dist-mesh/NATPairMesh/NATPairMesh.exe'
digest=hashlib.sha256(exe.read_bytes()).hexdigest()
for flags,name in ((['--self-check'],'binary-driver-check'),(['--tail-check','--target','100.124.84.17'],'binary-tail-check')):
    file=r/(name+'.json')
    process=subprocess.run([str(exe),*flags,'--result',str(file)],timeout=50,creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
    report=json.loads(file.read_text(encoding='utf8'));assert process.returncode==0 and report['passed'],report
    report['exe_sha256']=digest;file.write_text(json.dumps(report,ensure_ascii=False,indent=2),encoding='utf8')
    print(json.dumps({'check':name,'passed':True,'version':report['version']}),flush=True)
