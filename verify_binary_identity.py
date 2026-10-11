import hashlib,json,pathlib,secrets,subprocess,time,zipfile
from test_v114 import udp_service
r=pathlib.Path(__file__).parent;exe=r/'dist-mesh/NATPairMesh/NATPairMesh.exe'
service,protocol=udp_service();service.service.admit=lambda ip:True
cfg=service.cfg|{'tail_metadata_only':True,'scoped_peer_firewall':False,'live_egress_discovery':False}
(r/'binary-identity-config.json').write_text(json.dumps(cfg),encoding='utf8');code=secrets.token_hex(16)
processes=[];profiles={};results=[]
try:
 for i in range(2):processes.append(subprocess.Popen([str(exe),'--cli','--udp-only','--config',str(r/'binary-identity-config.json'),'--code',code,'--name','identity-'+str(i),'--duration','14','--result',str(r/('binary-identity-'+str(i)+'.zip'))],creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0)))
 deadline=time.monotonic()+30
 while any(p.poll() is None for p in processes) and time.monotonic()<deadline:
  for room in list(service.service.rooms.values()):
   for m in list(room.values()):
    if m.get('multi_protocol') and (m.get('profile') or {}).get('tail',{}).get('tail_ip'):profiles[m['id']]=dict(m['profile'])
  time.sleep(.1)
 for i,p in enumerate(processes):
  p.wait(timeout=8)
  with zipfile.ZipFile(r/('binary-identity-'+str(i)+'.zip')) as z:s=json.loads(z.read('summary.json'))
  outcomes=list(s['pairs'].values())+s.get('pair_history',[])
  results.append({'returncode':p.returncode,'own':s['result']['tail_manager']['own'],'first_udp':[v['result']['seconds_to_first_udp'] for v in outcomes],
                 'udp_authenticated':len(outcomes)==1 and outcomes[0]['result']['udp_probe_acks']>=3,'errors':[e for e in s['events'] if e['event']=='error']})
 report={'passed':len(profiles)==2 and all(x['returncode']==0 and x['udp_authenticated'] and x['own'].get('tail_ip') and not x['errors'] for x in results),'exe_sha256':hashlib.sha256(exe.read_bytes()).hexdigest(),
         'published_tailscale_identities':len(profiles),'checks':results,'scope':'two actual Windows EXE processes publish real native Tailscale metadata and authenticate loopback UDP; not native multi-PC proxy authentication'}
 (r/'binary-identity-check.json').write_text(json.dumps(report,ensure_ascii=False,indent=2),encoding='utf8');print(json.dumps(report,ensure_ascii=False));assert report['passed']
finally:
 for p in processes:
  if p.poll() is None:p.terminate();p.wait(10)
 service.stop()
