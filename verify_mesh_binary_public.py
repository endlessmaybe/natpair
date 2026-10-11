import argparse,hashlib,json,pathlib,secrets,subprocess,time,zipfile
args=argparse.ArgumentParser();args.add_argument('--unlimited',action='store_true');args.add_argument('--coexist',action='store_true');args.add_argument('--star',action='store_true');args=args.parse_args()
r=pathlib.Path(__file__).parent;exe=r/'dist-mesh/NATPairMesh/NATPairMesh.exe';code=secrets.token_hex(16)
ssh=['ssh','-o','BatchMode=yes','-o','ConnectTimeout=12','-o','StrictHostKeyChecking=yes','-i','C:/Users/whb/.ssh/id_ed25519_loaiqyku','root@204.152.206.124']
cfg=json.loads((r/'config.json').read_text(encoding='utf8'));cfg.update(scoped_peer_firewall=False,live_egress_discovery=False)
(r/'binary-public-config.json').write_text(json.dumps(cfg),encoding='utf8')
limit=['--coexist'] if args.coexist else [] if args.unlimited else ['--new-combinations-per-second','1000']
remote_args=['python3','-B','public_debug_runner.py','--cli','--udp-only','--config','/opt/natpair-mesh-v120/server-config.json','--name','Public-binary-check','--code',code,'--duration','36','--result','public-binary-remote-'+code+'.zip']+limit+(['--star-role','host','--game-port','41234'] if args.star else [])
launch="import subprocess,pathlib,json; r=pathlib.Path('/opt/natpair-mesh-v120/check-runtime'); log=(r/'public-binary-console-"+code+".log').open('w'); p=subprocess.Popen("+repr(remote_args)+",cwd=r,stdout=log,stderr=log,start_new_session=True); print(json.dumps({'pid':p.pid}))"
remote=subprocess.run(ssh+['python3 -B -'],input=launch,text=True,capture_output=True,timeout=25,check=True)
pid=json.loads(remote.stdout)['pid'];remote_rc=None
try:
        result=r/'binary-public-result.zip';process=subprocess.run([str(exe),'--cli','--udp-only','--config',str(r/'binary-public-config.json'),'--name','Windows-binary-check','--code',code,'--duration','25','--result',str(result)]+limit+(['--star-role','player'] if args.star else []),creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0),timeout=45)
        with zipfile.ZipFile(result) as archive:summary=json.loads(archive.read('summary.json'))
        deadline=time.monotonic()+35
        while time.monotonic()<deadline:
            poll="import pathlib; p=pathlib.Path('/opt/natpair-mesh-v120/check-runtime/public-binary-exit-"+code+".json'); print(p.read_text() if p.exists() else '{}')"
            status=subprocess.run(ssh+['python3 -B -'],input=poll,text=True,capture_output=True,timeout=20,check=True)
            exit_record=json.loads(status.stdout)
            if 'returncode' in exit_record:remote_rc=exit_record['returncode'];break
            time.sleep(1)
        assert remote_rc is not None,'remote runner has not finished; inspect stacks'
        scp=['scp','-o','BatchMode=yes','-o','ConnectTimeout=12','-o','StrictHostKeyChecking=yes','-i','C:/Users/whb/.ssh/id_ed25519_loaiqyku']
        remote_zip=r/'binary-public-remote-result.zip'
        subprocess.run(scp+['root@204.152.206.124:/opt/natpair-mesh-v120/check-runtime/public-binary-remote-'+code+'.zip',str(remote_zip)],check=True,timeout=30)
        with zipfile.ZipFile(remote_zip) as archive:remote_summary=json.loads(archive.read('summary.json'))
        def outcomes(s):return [p['result'] for p in list(s['pairs'].values())+s.get('pair_history',[])]
        pair_results=outcomes(summary);remote_results=outcomes(remote_summary)
        report={'passed':process.returncode==remote_rc==0 and len(pair_results)==len(remote_results)==1 and all(p['udp_direct_verified'] and p['udp_probe_acks']>=3 for p in pair_results+remote_results),
                'exe_sha256':hashlib.sha256(exe.read_bytes()).hexdigest(),'first_udp_seconds':[p['seconds_to_first_udp'] for p in pair_results],
                'authenticated_acks':[p['udp_probe_acks'] for p in pair_results],'control_reconnects':[p['control_reconnects'] for p in pair_results],
                'remote_first_udp_seconds':[p['seconds_to_first_udp'] for p in remote_results],
                'remote_authenticated_acks':[p['udp_probe_acks'] for p in remote_results],
                'remote_clean_exit':remote_rc==0,'new_combinations_limit':None if args.unlimited or args.coexist else 1000,
                'coexist_guard':summary['result']['coexist_guard'],'scope':'actual Windows EXE to own public IPv4 server; not a two-NAT4 or high-load Bifrost survival test'}
        if args.coexist:report['passed']=report['passed'] and report['coexist_guard']['enabled']
        if args.star:
            report['topology']='star';report['host_role']=remote_summary['result']['role'];report['player_role']=summary['result']['role'];report['game_port']=summary['result']['mc_game_port']
            report['passed']=report['passed'] and report['host_role']=='host' and report['player_role']=='player' and report['game_port']==41234
        (r/('binary-star-public-check.json' if args.star else 'binary-mesh-public-check.json')).write_text(json.dumps(report,indent=2),encoding='utf8');print(json.dumps(report),flush=True);assert report['passed']
finally:
    if remote_rc is None:
        cleanup="import pathlib,os,signal; p=pathlib.Path('/proc/"+str(pid)+"/cmdline'); cmd=p.read_bytes() if p.exists() else b'';\nif b'public_debug_runner.py' in cmd and "+repr(code.encode())+" in cmd:os.kill("+str(pid)+",signal.SIGTERM)"
        subprocess.run(ssh+['python3 -B -'],input=cleanup,text=True,capture_output=True,timeout=20)
