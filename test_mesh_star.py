import copy,json,pathlib,secrets,socket,threading,time,unittest
from unittest.mock import MagicMock,patch
from meshapp import MC_MODE,mode_settings,defaults
from meshclient import MultiClient,PairClient
from meshplan import MeshPlanner,pair_key
from session import SessionRunner
from test_mesh import member,FakeTailManager
from test_v114 import udp_service,until
from wire import unpack

ROOT=pathlib.Path(__file__).parent
def stars(n=8):
    result={m['id']:m for m in map(member,range(n))}
    for i,m in enumerate(result.values()):
        m.update(topology='star',role='host' if i==0 else 'player',name=str(i),game_port=41234)
        m['profile']['tail']={'tail_ip':f'100.99.0.{i+1}'}
    return result

class StarPlannerTests(unittest.TestCase):
    def test_eight_star_has_seven_edges_and_rotates_without_leaf_tasks(self):
        members=stars();host=next(iter(members));planner=MeshPlanner(2);seen=set();now=100
        for _ in range(16):
            for m in members.values():m['last']=now
            snap=planner.snapshot(members,now);self.assertEqual(snap['possible_pairs'],7)
            self.assertEqual(len(snap['tasks']),1)
            for t in snap['tasks']:
                self.assertIn(host,t['members']);seen.add(t['pair'])
                for ident in t['members']:members[ident]['profile']['prepared_tasks']=[t['id']]
            self.assertEqual(planner.snapshot(members,now+.1)['tasks'][0]['state'],'go');now+=2.2
        self.assertEqual(len(seen),7)
        self.assertEqual(snap['host_tail_ip'],'100.99.0.1');self.assertEqual(snap['game_port'],41234)
    def test_native_ipv6_skips_only_its_host_edge(self):
        m=stars(4);h,a,b,c=m.values()
        h['profile']['links'][a['id']]={'peer_generation':a['profile']['generation'],'native_verified':True,'native_route':'ipv6'}
        snap=MeshPlanner().snapshot(m,100)
        self.assertEqual(snap['completed_pairs'],1);self.assertEqual(snap['possible_pairs'],3)
        self.assertNotIn(a['id'],snap['tasks'][0]['members']);self.assertIn(h['id'],snap['tasks'][0]['members'])
    def test_no_host_and_departed_host_wait_without_tasks(self):
        m=stars(3);host=m.pop(next(iter(m)));planner=MeshPlanner()
        snap=planner.snapshot(m,100);self.assertEqual(snap['possible_pairs'],0);self.assertEqual(snap['tasks'],[])
        m[host['id']]=host;self.assertEqual(len(planner.snapshot(m,100)['tasks']),1)
        m.pop(host['id']);planner.leave(host['id'],host['profile']['generation'])
        snap=planner.snapshot(m,101);self.assertEqual(snap['tasks'],[]);self.assertIsNone(snap['host_id'])
    def test_single_pending_task_renewal_retains_token_but_stale_member_does_not(self):
        m=stars(2);p=MeshPlanner(2);t=p.snapshot(m,100)['tasks'][0]
        for v in m.values():v['profile']['prepared_tasks']=[t['id']]
        self.assertEqual(p.snapshot(m,100.1)['tasks'][0]['state'],'go')
        for v in m.values():v['last']=103
        new=p.snapshot(m,103)['tasks'][0];self.assertEqual(t['id'],new['id']);self.assertGreater(new['remaining_seconds'],1)
        next(iter(m.values()))['last']=70;self.assertEqual(p.snapshot(m,104)['tasks'],[])
    def test_full_mesh_single_edge_renewal_and_generation_invalidates_token(self):
        m=stars(2)
        for v in m.values():v['topology']='full_mesh'
        p=MeshPlanner(1);t=p.snapshot(m,100)['tasks'][0]
        for v in m.values():v['profile']['prepared_tasks']=[t['id']]
        p.snapshot(m,100.1);self.assertEqual(p.snapshot(m,102)['tasks'][0]['id'],t['id'])
        next(iter(m.values()))['profile']['generation']='e'*32
        self.assertNotEqual(p.snapshot(m,103)['tasks'][0]['id'],t['id'])

class StarAdmissionTests(unittest.TestCase):
    def test_players_first_single_host_mixed_mode_and_role_spoof_rejected(self):
        service,protocol=udp_service();room='a'*64
        def join(n,role='player',topology='star',port=25565,profile=None):
            return protocol.sync(bytes([n])*16,{'k':'sync','room':room,'id':f'{n:032x}','resume':f'{n+20:032x}','run':1,'name':str(n),'multi_protocol':1,
                'topology':topology,'role':role,'game_port':port,'profile':profile or {'generation':f'{n+40:032x}'}})
        try:
            self.assertEqual(join(1)['mesh']['tasks'],[])
            self.assertIsNone(join(2)['mesh']['host_id'])
            self.assertEqual(join(3,'host',port=43210)['mesh']['game_port'],43210)
            before=set(service.service.rooms[room]);self.assertIn('已有房主',join(4,'host')['error'])
            self.assertEqual(set(service.service.rooms[room]),before)
            self.assertIn('不能混用',join(5,topology='full_mesh')['error'])
            self.assertIn('切换房主',join(1,'host')['error'])
            snap=join(1,profile={'generation':f'{41:032x}','role':'host','game_port':11111})
            self.assertEqual(snap['mesh']['host_id'],f'{3:032x}');self.assertEqual(snap['mesh']['game_port'],43210)
            self.assertEqual(service.service.rooms[room][f'{1:032x}']['role'],'player')
            self.assertIn('invalid_room_mode',join(6,port=0)['error'])
            self.assertEqual(len(service.service.rooms[room]),3)
        finally:service.stop()
    def test_host_leave_allows_new_host_and_port(self):
        service,p=udp_service();room='a'*64
        obj={'k':'sync','room':room,'id':'b'*32,'resume':'c'*32,'name':'host','run':1,'multi_protocol':1,'topology':'star','role':'host','game_port':25565,'profile':{'generation':'d'*32}}
        try:
            p.sync(b'1'*16,obj);p.sync(b'2'*16,{**obj,'id':'e'*32,'resume':'f'*32,'role':'player'})
            p.sync(b'1'*16,{**obj,'k':'leave'})
            snap=p.sync(b'3'*16,{**obj,'run':2,'game_port':45678,'profile':{'generation':'1'*32}})
            self.assertEqual(snap['mesh']['host_generation'],'1'*32);self.assertEqual(snap['mesh']['game_port'],45678)
        finally:service.stop()
    def test_mc_configuration_requires_tail_and_actual_valid_port(self):
        self.assertEqual(mode_settings(MC_MODE,'房主','41234'),{'tailscale_bridge':True,'mesh_topology':'star','mesh_role':'host','mc_game_port':41234})
        self.assertEqual(mode_settings(MC_MODE)['mesh_role'],'player')
        for port in ('x','0','65536'):
            with self.assertRaises(ValueError):mode_settings(MC_MODE,'房主',port)

class CandidateRetryTests(unittest.TestCase):
    def make(self,limit=1):
        o=MultiClient({'mesh_coexist_guard':True,'_guard_scope':secrets.token_hex(8),'coexist_footprint_limit':limit},'AA'*16,'retry');o.mux=MagicMock()
        p={'id':'b'*32,'name':'peer','udp':[['127.0.0.1',1234]],'profile':{'generation':'c'*32}}
        c=PairClient(o,p,o.pair_code(p),{'public_only':False,'unlimited_search':True});s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.bind(('127.0.0.1',0));c.udp=[s]
        return o,p,c,s
    def test_saturated_budget_retries_real_authenticated_existing_packet_and_retains_cursor(self):
        o,p,c,s=self.make();receiver=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);receiver.bind(('127.0.0.1',0));receiver.settimeout(1)
        target=receiver.getsockname();p['udp']=[list(target)]
        try:
            self.assertTrue(c.trace_probe(s,target,p,time.monotonic(),'test'));receiver.recvfrom(4096)
            before=c.schedule.position;fresh_before=o.coexist_guard.fresh_combinations;unique_before=o.combinations.total;time.sleep(.01)
            self.assertFalse(c.trace_probe(s,('127.0.0.1',target[1]+1 if target[1]<65535 else 1),p,time.monotonic(),'full_scan'))
            packet,origin=receiver.recvfrom(4096);decoded=unpack(c.key,packet)
            self.assertEqual(decoded['k'],'probe');self.assertEqual(decoded['to'],p['id']);self.assertEqual(origin[1],s.getsockname()[1])
            self.assertEqual(c.schedule.position,before);self.assertEqual(o.coexist_guard.fresh_combinations,fresh_before);self.assertEqual(o.combinations.total,unique_before)
            self.assertEqual(c.stats['coexist_candidate_retries'],1)
            for _ in range(20):c.trace_probe(s,('127.0.0.1',1),p,time.monotonic(),'full_scan')
            self.assertEqual(c.stats['coexist_candidate_retries'],1)
        finally:s.close();receiver.close();c.journal.close()
    def test_pool_bounded_so_non_pool_mappings_can_age_out(self):
        o,p,c,s=self.make(256)
        try:
            for port in range(1,151):
                self.assertTrue(c.trace_probe(s,('127.0.0.1',port),p,time.monotonic(),'authenticated_reply'))
            self.assertEqual(len(c.guard_candidates),128);self.assertEqual(len(o.coexist_guard.touched),150)
            now=time.monotonic()
            with o.coexist_guard.lock:
                for key in list(o.coexist_guard.touched)[:22]:o.coexist_guard.touched[key]=now-181
                o.coexist_guard._expire(now)
            self.assertEqual(len(o.coexist_guard.touched),128)
            time.sleep(.006);self.assertTrue(c.trace_probe(s,('127.0.0.1',200),p,time.monotonic(),'full_scan'))
        finally:s.close();c.journal.close()
    def test_closed_expired_or_other_ip_candidates_never_retried(self):
        o,p,c,s=self.make();target=('127.0.0.1',1234)
        try:
            c.guard_candidates[(s,target)]=time.monotonic()
            self.assertFalse(c.retry_guard_candidates(p,time.monotonic()))
            o.coexist_guard.commit(s.getsockname()[1],target,time.monotonic(),priority=True)
            wrong={**p,'udp':[['127.0.0.2',1234]]};self.assertFalse(c.retry_guard_candidates(wrong,time.monotonic()))
            s.close();self.assertFalse(c.retry_guard_candidates(p,time.monotonic()))
        finally:s.close();c.journal.close()

class StarIntegrationTests(unittest.TestCase):
    def test_four_real_udp_star_stop_rejoin_and_host_departure(self):
        service,_=udp_service();service.service.admit=lambda ip:True;service.service.mesh_window=3
        cfg=defaults(service.cfg)|{'mesh_topology':'star','tailscale_bridge':False,'scoped_peer_firewall':False,'live_egress_discovery':False,'packet_journal_dir':None,'new_combinations_per_second':1000}
        controllers=[];clients=[];code=secrets.token_hex(16)
        def start(role,name):
            runner=SessionRunner(lambda e:None,factory=MultiClient);controllers.append(runner);c=runner.start(cfg|{'mesh_role':role,'mc_game_port':41234},code,name);clients.append(c);return c
        def connected():
            return len(clients[0].pairs)==3 and all(len(c.pairs)==1 for c in clients[1:]) and all(p['client'].stats['udp_probe_acks']>=2 for c in clients for p in c.pairs.values())
        try:
            h=start('host','host');a=start('player','a');b=start('player','b');d=start('player','d')
            self.assertTrue(until(connected,35));self.assertTrue(all(c.mesh['possible_pairs']==3 for c in clients));saved=h.pairs[a.id]['client']
            self.assertTrue(all(set(c.pairs)=={h.id} for c in clients[1:]));self.assertEqual(h.status()['mc_game_port'],41234)
            controllers[2].stop();controllers[2].thread.join(10);self.assertTrue(until(lambda:b.id not in h.pairs));self.assertIs(h.pairs[a.id]['client'],saved)
            old=b.generation;b=controllers[2].start(cfg|{'mesh_role':'player'},code,'b-again');clients[2]=b
            self.assertNotEqual(b.generation,old);self.assertTrue(until(connected,30));self.assertIs(h.pairs[a.id]['client'],saved)
            controllers[0].stop();controllers[0].thread.join(10);self.assertTrue(until(lambda:all(not c.pairs and not c.tasks and not c.mesh.get('host_id') for c in clients[1:]),10))
            h=controllers[0].start(cfg|{'mesh_role':'host','mc_game_port':41235},code,'host-again');clients[0]=h
            self.assertTrue(until(connected,30));self.assertTrue(until(lambda:all(c.mesh.get('game_port')==41235 for c in clients)))
            self.assertFalse(any(e['event']=='error' for c in clients for e in c.logs))
            (ROOT/'mesh-star-check.json').write_text(json.dumps({'passed':True,'members':4,'real_authenticated_edges':3,'leaf_leaf_engines':0,'player_stop_rejoin_preserved_other_edge':True,'host_leave_wait_and_rejoin':True,'scope':'real UDP loopback authentication; no Minecraft game or two-NAT4 proof'},indent=2),encoding='utf8')
        finally:
            for s in controllers:s.stop()
            for s in controllers:s.thread.join(15)
            service.stop()
    def test_native_ipv6_star_edge_skipped_and_two_other_proxies_isolated(self):
        service,_=udp_service();service.service.admit=lambda ip:True;service.service.mesh_window=3
        cfg=defaults(service.cfg)|{'mesh_topology':'star','tailscale_bridge':True,'scoped_peer_firewall':False,'live_egress_discovery':False,'packet_journal_dir':None,'new_combinations_per_second':1000}
        FakeTailManager.instances={};FakeTailManager.counter=0;controllers=[];clients=[]
        try:
            with patch('meshclient.TailManager',FakeTailManager),patch('meshclient.is_admin',return_value=True),patch('client.is_admin',return_value=True),patch('meshclient.driver_check',return_value={'passed':True}),patch('client.driver_check',return_value={'passed':True}):
                code=secrets.token_hex(16)
                for i in range(4):
                    s=SessionRunner(lambda e:None,factory=MultiClient);controllers.append(s);clients.append(s.start(cfg|{'mesh_role':'host' if i==0 else 'player'},code,'star-'+str(i)))
                    self.assertTrue(until(lambda:len(FakeTailManager.instances)==i+1))
                h,a,b,c=clients
                self.assertTrue(until(lambda:len(h.pairs)==2 and not a.pairs and all(len(x.pairs)==1 and x.pairs[h.id]['client'].tail.enabled for x in (b,c)),35))
                self.assertEqual(set(h.pairs),{b.id,c.id});self.assertEqual(set(b.tail.targets),{h.tail.own['tail_ip']})
                self.assertEqual(b.status()['mc_connect_address'],h.tail.own['tail_ip']+':25565')
                from transport import DataTransport
                # Send distinct synthetic WireGuard payloads toward each native
                # endpoint and verify they land only at the designated player.
                payloads=[b'\x04\0\0\0'+bytes([n])*28 for n in (11,22)]
                for x,payload in zip((b,c),payloads):h.pairs[x.id]['client'].tail.outbound.put((payload,'tailscale_local_proxy'))
                self.assertTrue(until(lambda:any(p==payloads[0] for p,_ in b.tail.received) and any(p==payloads[1] for p,_ in c.tail.received),8))
                self.assertFalse(any(p==payloads[1] for p,_ in b.tail.received));self.assertFalse(any(p==payloads[0] for p,_ in c.tail.received))
                (ROOT/'mesh-star-tail-check.json').write_text(json.dumps({'passed':True,'native_ipv6_edge_skipped':True,'leaf_leaf_targets':0,'isolated_proxy_deliveries':2,'scope':'real UDP/AEAD; synthetic native Tailscale data, not real game authentication'},indent=2),encoding='utf8')
        finally:
            for s in controllers:s.stop()
            for s in controllers:s.thread.join(18)
            service.stop()

if __name__=='__main__':unittest.main()
