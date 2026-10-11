import hashlib,json,pathlib,secrets,subprocess,zipfile
from test_v114 import udp_service
r=pathlib.Path(__file__).parent;exe=r/'dist-mesh/NATPairMesh/NATPairMesh.exe'
service,_=udp_service();service.service.admit=lambda ip:True;service.service.mesh_window=3
cfg=service.cfg|{'scoped_peer_firewall':False,'live_egress_discovery':False}
path=r/'binary-star-config.json';path.write_text(json.dumps(cfg),encoding='utf8');code=secrets.token_hex(16);processes=[];results=[]
try:
    for i in range(3):
        output=r/f'binary-star-{i}.zip';role='host' if i==0 else 'player'
        processes.append(subprocess.Popen([str(exe),'--cli','--udp-only','--config',str(path),'--name',role+'-'+str(i),'--code',code,'--duration','20','--coexist','--star-role',role,'--game-port','41234','--result',str(output)],creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0)))
    for i,p in enumerate(processes):
        p.wait(timeout=40);assert p.returncode==0
        with zipfile.ZipFile(r/f'binary-star-{i}.zip') as archive:s=json.loads(archive.read('summary.json'))
        pairs=list(s['pairs'].values())+s.get('pair_history',[]);expected=2 if i==0 else 1
        results.append({'member':i,'role':s['result']['role'],'pairs':len(pairs),'passed':len(pairs)==expected and all(x['result']['udp_direct_verified'] for x in pairs) and not any(e['event']=='error' for e in s['events']),
            'first_seconds':[x['result']['seconds_to_first_udp'] for x in pairs]})
    report={'passed':all(x['passed'] for x in results),'exe_sha256':hashlib.sha256(exe.read_bytes()).hexdigest(),'members':3,'authenticated_star_edges':2,'leaf_leaf_engines':0,'results':results,'scope':'actual Windows EXE, real UDP loopback; no real Minecraft game launched'}
    (r/'binary-star-check.json').write_text(json.dumps(report,indent=2),encoding='utf8');print(json.dumps(report));assert report['passed']
finally:
    for p in processes:
        if p.poll() is None:p.terminate();p.wait(5)
    service.stop()
