import collections,copy,hashlib,itertools,json,pathlib,queue,secrets,socket,threading,time,unittest
from unittest.mock import MagicMock,patch
from meshplan import MeshPlanner,pair_key
from meshclient import MultiClient,PairClient
from meshtail import CaptureHub,native_route
from combinations import CombinationLimit
from session import SessionRunner
from test_v114 import udp_service,until
from meshapp import defaults
from tailbridge import parse_ipv4_udp

ROOT=pathlib.Path(__file__).parent
def member(n,now=100):
    return {'id':f'{n:032x}','last':now,'profile':{'generation':f'{n+100:032x}','links':{},'prepared_tasks':[]}}

class PlannerTests(unittest.TestCase):
    def test_stale_room_member_keeps_seat_but_receives_no_new_scan_task(self):
        a,b=map(member,range(2));a['last']=70;b['last']=100
        planner=MeshPlanner();snapshot=planner.snapshot({m['id']:m for m in (a,b)},100)
        self.assertEqual(len(snapshot['members']),2);self.assertEqual(len(snapshot['fresh_members']),1);self.assertEqual(snapshot['tasks'],[])
    def test_eight_all_28_pairs_are_fairly_covered_and_no_node_double_scheduled(self):
        members={m['id']:m for m in map(member,range(8))};p=MeshPlanner(2);seen=set()
        now=100
        for _ in range(30):
            for m in members.values():m['last']=now
            snapshot=p.snapshot(members,now);busy=[]
            for task in snapshot['tasks']:
                busy+=task['members'];seen.add(task['pair'])
                for ident in task['members']:members[ident]['profile']['prepared_tasks']=[task['id']]
            self.assertEqual(len(busy),len(set(busy)))
            snapshot=p.snapshot(members,now+.1)
            self.assertTrue(all(t['state']=='go' for t in snapshot['tasks']));now+=2.2
        self.assertEqual(len(seen),28)
    def test_success_native_ipv6_and_restart_invalidate_only_related_pairs(self):
        a,b,c,d=map(member,range(4));members={m['id']:m for m in (a,b,c,d)};p=MeshPlanner()
        a['profile']['links'][b['id']]={'peer_generation':b['profile']['generation'],'native_verified':True,'native_route':'ipv6'}
        first=p.snapshot(members,100);self.assertNotIn(pair_key(a['id'],b['id']),p.active)
        cd=pair_key(c['id'],d['id'])
        if cd not in p.active:
            p=MeshPlanner();p.active[cd]={'id':'f'*32,'members':[c['id'],d['id']],'pair':cd,'generations':{c['id']:c['profile']['generation'],d['id']:d['profile']['generation']},'state':'go','until':220,'serial':1}
        token=p.active[cd]['id'];a['profile']['generation']='e'*32;p.snapshot(members,101)
        self.assertEqual(p.active[cd]['id'],token)
    def test_prepare_requires_both_exact_task_acks_and_stale_session_report_rejected(self):
        a,b=map(member,range(2));members={a['id']:a,b['id']:b};p=MeshPlanner();t=p.snapshot(members,100)['tasks'][0]
        a['profile']['prepared_tasks']=[t['id']];self.assertEqual(p.snapshot(members,101)['tasks'][0]['state'],'prepare')
        b['profile']['prepared_tasks']=[t['id']];self.assertEqual(p.snapshot(members,102)['tasks'][0]['state'],'go')
        a['profile']['links'][b['id']]={'peer_generation':'wrong','native_verified':True,'native_route':'ipv6'}
        self.assertEqual(p.snapshot(members,103)['completed_pairs'],0)
    def test_single_waiter_and_mixed_ipv6_derp_are_per_pair(self):
        a,b,c=map(member,range(3));p=MeshPlanner();self.assertEqual(p.snapshot({a['id']:a},100)['tasks'],[])
        a['profile']['links'][b['id']]={'peer_generation':b['profile']['generation'],'native_verified':True,'native_route':'ipv6'}
        snap=p.snapshot({m['id']:m for m in (a,b,c)},100)
        self.assertEqual(snap['completed_pairs'],1);self.assertEqual(len(snap['tasks']),1)

def ip_packet(source,target,payload):
    import struct
    return b'\x45\x00'+struct.pack('!H',28+len(payload))+b'\x00\x00\x00\x00\x40\x11\x00\x00'+socket.inet_aton(source[0])+socket.inet_aton(target[0])+struct.pack('!HHHH',source[1],target[1],len(payload)+8,0)+payload

class SharedTailTests(unittest.TestCase):
    def test_live_summary_does_not_hold_root_lock_while_waiting_for_worker(self):
        owner=MultiClient({},'AA'*16,'a');workers=[]
        def status():
            t=threading.Thread(target=lambda:owner.log('worker_export_check'),daemon=True);workers.append(t);t.start();t.join(1)
            self.assertFalse(t.is_alive(),'export must not block probe event workers');return {}
        owner.status=status
        try:self.assertEqual(owner.summary()['pair_history'],[])
        finally:
            for t in workers:t.join(2)
    def test_retired_pair_success_is_preserved_in_bounded_history(self):
        owner=MultiClient({},'AA'*16,'a');owner.status=lambda:{}
        c=MagicMock();c.id='e'*32;c.pair_token='f'*32;c.summary.return_value={'result':{'udp_direct_verified':True,'udp_probe_acks':9},'events':[{'event':'udp_direct_verified'},{'event':'status'}]}
        thread=MagicMock();thread.is_alive.return_value=False
        owner.pairs['b']={'client':c,'thread':thread,'generation':'c'*32}
        owner.retire_pair('b','explicit_leave');owner.collect_retired()
        self.assertEqual(owner.pairs,{});self.assertEqual(owner.retired,[])
        h=owner.summary()['pair_history'];self.assertEqual(len(h),1);self.assertEqual(h[0]['result']['udp_probe_acks'],9)
        self.assertEqual(h[0]['events'],[{'event':'udp_direct_verified'}]);self.assertEqual(owner.pair_history.maxlen,56)
    def test_usable_tail_is_not_labeled_connecting_while_proxy_evidence_pending(self):
        owner=MultiClient({},'AA'*16,'a');peer={'id':'b'*32,'name':'b','profile':{'generation':'c'*32,'tail':{'tail_ip':'100.99.0.2'}}};owner.peers={peer['id']:peer}
        sock=MagicMock();sock.fileno.return_value=20;c=MagicMock();c.stop.is_set.return_value=False;c.direct_path=(sock,('1.1.1.1',1234));c.last_direct_ack=time.monotonic()
        c.stats={};c.actual_rates.return_value={};c.first_udp_at=None;c.active_elapsed=1;c.tail_bridge_error=None
        owner.pairs[peer['id']]={'client':c,'joined_at':time.monotonic()};owner.tail=MagicMock()
        for route in ('natpair_proxy','derp'):
            owner.tail.route_health.return_value={'native_verified':True,'route':route,'proxy_verified':False}
            state=owner.rows()[0]['state'];self.assertNotIn('接入中',state);self.assertTrue('已可用' in state or '经 DERP' in state)
    def test_absent_coordinator_peer_is_retained_only_while_authenticated_path_live(self):
        from wire import room_keys
        owner=MultiClient({},'AA'*16,'a',member_id='a'*32);peer={'id':'b'*32,'name':'b','profile':{'generation':'c'*32}}
        owner.peers={peer['id']:peer};c=MagicMock();c.stop.is_set.return_value=False;c.direct_path=True;c.last_direct_ack=time.monotonic()
        owner.pairs[peer['id']]={'client':c,'generation':'c'*32,'thread':MagicMock()}
        frame={'k':'peers','peers':[],'mesh':{'protocol':1,'members':[owner.id],'tasks':[],'departures':{}}}
        owner.accept(frame);self.assertIn(peer['id'],owner.peers);self.assertTrue(owner.peers[peer['id']]['coordinator_stale'])
        frame['mesh']['departures']={peer['id']:{'generation':'c'*32}};owner.accept(frame)
        self.assertNotIn(peer['id'],owner.peers);c.stop.set.assert_called_once()
    def test_disk_write_failure_disables_journal_without_disabling_udp_or_cleanup(self):
        from journal import PacketJournal
        journal=PacketJournal(ROOT/'disk-failure-test','a'*32);real=journal.file;real.close()
        bad=MagicMock();bad.write.side_effect=OSError('disk full');bad.close.side_effect=OSError('disk full');journal.file=bad
        first=journal.record(direction='tx',kind='probe',accepted=True)
        second=journal.record(direction='rx',kind='ack',accepted=True)
        self.assertLess(first['journal_seq'],second['journal_seq']);self.assertEqual(journal.error,'disk full');self.assertIsNone(journal.file)
        journal.proof(first,second,{});journal.close()
    def test_global_1000_limit_is_atomic_across_three_pair_threads(self):
        owner=MultiClient({'new_combinations_per_second':1000},'AA'*16,'a',member_id='a'*32);owner.mux=MagicMock()
        peers=[{'id':f'{n:032x}','udp':[['127.0.0.1',1234]],'profile':{'generation':f'{n+20:032x}'}} for n in (1,2,3)]
        engines=[PairClient(owner,p,owner.pair_code(p),{'public_only':False,'unlimited_search':True}) for p in peers]
        sockets=[];counts=[];barrier=threading.Barrier(3)
        def send(i):
            c=engines[i];s=sockets[i];barrier.wait();success=0
            with patch.object(c,'send_udp',return_value=True):
                for port in range(1,701):success+=c.trace_probe(s,('127.0.0.1',port),peers[i],100,'test') is not False
            counts.append(success)
        try:
            for c in engines:
                s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.bind(('127.0.0.1',0));sockets.append(s);c.udp=[s]
            threads=[threading.Thread(target=send,args=(i,)) for i in range(3)]
            for t in threads:t.start()
            for t in threads:t.join(3)
            self.assertEqual(sum(counts),1000);self.assertEqual(owner.combinations.total,1000)
        finally:
            for s in sockets:s.close()
    def test_business_queue_yields_dense_search_without_adding_a_rate_limit(self):
        owner=MultiClient({},'AA'*16,'a');owner.tasks['b']={'id':'c'*32,'state':'go','generations':{'b':'d'*32},'local_until':time.monotonic()+60}
        client=MagicMock();client.direct_path=True;client.tail.enabled=True;client.tail_frames=[];client.tail.outbound=queue.Queue()
        owner.pairs['x']={'client':client};owner.native_direct=lambda peer:False
        self.assertTrue(owner.dense_allowed('b','d'*32));client.tail.outbound.put(b'payload')
        self.assertFalse(owner.dense_allowed('b','d'*32));client.tail.outbound.get_nowait()
        self.assertTrue(owner.dense_allowed('b','d'*32));self.assertIsNone(owner.combinations.limit)
    def test_shared_capture_routes_full_endpoint_and_drops_ambiguous_destination(self):
        capture=MagicMock();capture.recv.side_effect=OSError('closed')
        hub=CaptureHub(threading.Event(),lambda *a,**k:None);hub.capture=capture;hub.port=41641
        a=hub.subscribe('a',41641,[('1.1.1.1',11)]);b=hub.subscribe('b',41641,[('1.1.1.1',12)])
        packet=ip_packet(('192.168.1.1',41641),('1.1.1.1',11),b'x'*78);hub.dispatch(packet)
        self.assertEqual(a.queue.get_nowait(),packet);self.assertTrue(b.queue.empty())
        c=hub.subscribe('c',41641,[('1.1.1.1',11)]);hub.dispatch(packet)
        self.assertTrue(a.queue.empty());self.assertTrue(c.queue.empty());self.assertEqual(hub.ambiguous,1)
        c.close();hub.dispatch(packet);self.assertFalse(a.queue.empty());b.close();self.assertFalse(a.closed)
        hub.close();capture.close.assert_called_once()
    def test_native_route_does_not_confuse_overlay_ipv6_or_local_proxy(self):
        self.assertEqual(native_route('[2409:8a34::1]:41641'),'ipv6')
        self.assertEqual(native_route('[fd7a:115c:a1e0::1]:41641'),'unknown')
        self.assertEqual(native_route('192.168.31.195:58001',['192.168.31.195:58001']),'natpair_proxy')
        self.assertEqual(native_route(''),'derp')
    def test_closed_subscription_cannot_remove_replacement(self):
        hub=CaptureHub(threading.Event(),lambda *a,**k:None);hub.capture=MagicMock();hub.port=41641
        first=hub.subscribe('a',41641,[('1.1.1.1',1)]);second=hub.subscribe('a',41641,[('1.1.1.1',2)]);first.close()
        self.assertIs(hub.subscriptions['a'],second);hub.close()
    def test_pair_firewall_and_transport_ids_are_unique_and_data_not_room_wide(self):
        owner=MultiClient({},'AA'*16,'a',member_id='a'*32);owner.mux=MagicMock()
        peers=[{'id':f'{n:032x}','profile':{'generation':f'{n+20:032x}'}} for n in (1,2)]
        engines=[PairClient(owner,p,owner.pair_code(p),{}) for p in peers]
        self.assertNotEqual(engines[0].id,engines[1].id);self.assertNotEqual(engines[0].key,engines[1].key)
        self.assertIs(engines[0].combination_limit,engines[1].combination_limit)

class QueueCapture:
    def __init__(self):self.closed=threading.Event()
    def recv(self):
        self.closed.wait();raise OSError('closed')
    def close(self):self.closed.set()

class FakeTailManager:
    instances={};counter=0
    def __init__(self,stop,emit,bridge):
        self.stop=stop;self.emit=emit;self.index=FakeTailManager.counter;FakeTailManager.counter+=1
        self.own={'node_key':'node-'+str(self.index),'tail_ip':'100.99.0.'+str(self.index+1)};self.error=None;self.proxies={}
        self.hub=CaptureHub(stop,emit,factory=lambda p:QueueCapture());self.received=[];self.targets={}
        self.native=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);self.native.bind(('127.0.0.1',0));self.native.settimeout(.05)
        self.thread=threading.Thread(target=self.run,daemon=True);FakeTailManager.instances[self.own['tail_ip']]=self
    def start(self):self.thread.start()
    def run(self):
        while not self.stop.is_set():
            try:payload,origin=self.native.recvfrom(65535)
            except socket.timeout:continue
            except OSError:return
            self.received.append((payload,origin))
            if self.index==2:self.native.sendto(payload,origin)
    def set_targets(self,targets):self.targets=dict(targets)
    def register_proxy(self,target,tail):self.proxies[target]=tail
    def unregister_proxy(self,target,tail):
        if self.proxies.get(target) is tail:self.proxies.pop(target,None)
    def read_metadata(self,target,**kwargs):
        other=self.instances[target]
        return {'node_key':self.own['node_key'],'expected_peer_key':other.own['node_key'],'disco_key':'discokey:'+str(self.index+1)*64,
            'expected_peer_disco_key':'discokey:'+str(other.index+1)*64,'udp_port':self.native.getsockname()[1],
            'tail_ips':[self.own['tail_ip']],'peer_tail_ip':target,'peer_endpoints':[['8.8.8.'+str(other.index+1),41641]]}
    def route_health(self,target):
        other=self.instances.get(target);v6=bool(other and {self.index,other.index}=={0,1})
        return {'native_verified':v6,'route':'ipv6' if v6 else 'derp','checked_at':time.monotonic()}
    def close(self):self.hub.close();self.native.close();self.thread.join(2)

class MultiBridgeIntegrationTests(unittest.TestCase):
    def test_mixed_ipv6_pair_skipped_and_two_proxies_share_native_socket_without_cross_delivery(self):
        service,protocol=udp_service();service.service.admit=lambda ip:True;service.service.mesh_window=5
        cfg=defaults(service.cfg);cfg.update(tailscale_bridge=True,scoped_peer_firewall=False,live_egress_discovery=False,
                                            packet_journal_dir=str(ROOT/'mesh-tail-test-evidence'),new_combinations_per_second=1000)
        FakeTailManager.instances={};FakeTailManager.counter=0;controllers=[];clients=[]
        try:
            with patch('meshclient.TailManager',FakeTailManager),patch('meshclient.is_admin',return_value=True),patch('client.is_admin',return_value=True),patch('meshclient.driver_check',return_value={'passed':True}),patch('client.driver_check',return_value={'passed':True}):
                code=secrets.token_hex(16)
                for i in range(3):
                    s=SessionRunner(lambda e:None,factory=MultiClient);controllers.append(s);clients.append(s.start(cfg,code,'tail-'+str(i)))
                    self.assertTrue(until(lambda:len(FakeTailManager.instances)==i+1))
                a,b,c=clients
                self.assertTrue(until(lambda:len(c.pairs)==2 and all(x['client'].tail and x['client'].tail.enabled for x in c.pairs.values()) and len(a.pairs)==len(b.pairs)==1,30))
                self.assertNotIn(b.id,a.pairs);self.assertNotIn(a.id,b.pairs)
                ca=a.pairs[c.id]['client'];cb=b.pairs[c.id]['client']
                self.assertEqual([x['native_route'] for x in a.rows() if x['id']==b.id],['ipv6'])
                payload_a=b'\x04\x00\x00\x00'+b'A'*28;payload_b=b'\x04\x00\x00\x00'+b'B'*28
                ca.tail.outbound.put((payload_a,'tailscale_local_proxy'));cb.tail.outbound.put((payload_b,'tailscale_local_proxy'))
                self.assertTrue(until(lambda:any(p==payload_a for p,_ in a.tail.received) and any(p==payload_b for p,_ in b.tail.received),8))
                self.assertFalse(any(p==payload_b for p,_ in a.tail.received));self.assertFalse(any(p==payload_a for p,_ in b.tail.received))
                received=dict(c.tail.received)
                self.assertEqual(received[payload_a],c.pairs[a.id]['client'].tail.socket.getsockname())
                self.assertEqual(received[payload_b],c.pairs[b.id]['client'].tail.socket.getsockname())
                self.assertNotEqual(received[payload_a],received[payload_b]);self.assertEqual(c.tail.hub.opened,1)
                (ROOT/'mesh-mixed-tail-check.json').write_text(json.dumps({'passed':True,'native_ipv6_pair_auxiliary_engines':0,'shared_native_udp_socket':True,'isolated_proxy_roundtrips':2,'shared_capture_handles':c.tail.hub.opened,'scope':'real UDP and AEAD transport; synthetic native Tailscale payloads, no native Tailscale authentication'}),encoding='utf8')
        finally:
            for s in controllers:s.stop()
            for s in controllers:
                if s.thread:s.thread.join(18)
            service.stop()

class MeshIntegrationTests(unittest.TestCase):
    def test_twenty_solo_restart_cycles_retire_sids_and_late_packets_cannot_rejoin(self):
        from roomudp import Codec
        service,protocol,cfg=self.make_service();cfg['packet_journal_dir']=None;controller=SessionRunner(lambda e:None,factory=MultiClient);code=secrets.token_hex(16)
        try:
            for cycle in range(20):
                c=controller.start(cfg,code,'solo');self.assertTrue(until(lambda:c.connected,5))
                state=copy.deepcopy(c.control.state);sid=c.control.sid;sequence=c.control.sequence
                controller.stop();controller.thread.join(5);self.assertFalse(controller.running());self.assertTrue(until(lambda:not service.service.rooms,3))
                self.assertNotIn(sid,protocol.latest)
                test_socket=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
                try:
                    for packet in Codec(cfg['access']).encode(sid,sequence+100,{**state,'k':'sync','room_wire':3},compress=True):test_socket.sendto(packet,('127.0.0.1',cfg['room_udp_port']))
                    time.sleep(.03);self.assertFalse(service.service.rooms)
                finally:test_socket.close()
            self.assertEqual(len(protocol.latest),0)
        finally:controller.stop();controller.thread.join(10);service.stop()
    def make_service(self):
        service,protocol=udp_service();service.service.admit=lambda ip:True;service.service.mesh_window=5
        cfg=defaults(service.cfg);cfg.update(tailscale_bridge=False,scoped_peer_firewall=False,live_egress_discovery=False,packet_journal_dir=str(ROOT/'mesh-test-evidence'),new_combinations_per_second=1000)
        return service,protocol,cfg
    def start_clients(self,count,cfg,code):
        controllers=[SessionRunner(lambda e:None,factory=MultiClient) for _ in range(count)]
        clients=[s.start(cfg,code,'member-'+str(i)) for i,s in enumerate(controllers)];return controllers,clients
    def all_connected(self,clients):
        return all(len(c.pairs)==len(clients)-1 and all(p['client'].direct_path and p['client'].stats['udp_probe_acks']>=2 for p in c.pairs.values()) for c in clients)
    def stop_all(self,controllers,service):
        for s in controllers:s.stop()
        for s in controllers:
            if s.thread:s.thread.join(15)
        service.stop()
    def test_three_real_udp_pairs_and_stop_rejoin_preserves_unrelated_channel(self):
        service,protocol,cfg=self.make_service();code=secrets.token_hex(16);controllers,clients=self.start_clients(3,cfg,code)
        try:
            if not until(lambda:self.all_connected(clients),30):
                (ROOT/'mesh-three-failure.json').write_text(json.dumps([c.summary() for c in clients],ensure_ascii=False,indent=2),encoding='utf8')
                self.fail('three-node full mesh not connected; inspect mesh-three-failure.json')
            a,b,c=clients;ab=a.pairs[b.id]['client'];ab_port=ab.udp[0].getsockname()[1];ab_session=ab.data_session;old_generation=c.generation
            self.assertTrue(all((len(x.mesh['members'])==3 and x.mesh['possible_pairs']==3) for x in clients))
            self.assertEqual(len({x.mux.socket.getsockname()[1] for x in clients}),3)
            controllers[2].stop();self.assertTrue(until(lambda:not controllers[2].running()))
            self.assertTrue(until(lambda:len(a.peers)==1 and len(b.peers)==1));self.assertIs(a.pairs[b.id]['client'],ab);self.assertTrue(ab.direct_path)
            self.assertTrue(until(lambda:any(h['peer_id']==c.id and h['result']['udp_direct_verified'] for h in a.pair_history)))
            fresh=controllers[2].start(cfg,code,'member-2');clients[2]=fresh
            self.assertNotEqual(old_generation,fresh.generation)
            self.assertTrue(until(lambda:self.all_connected(clients),30))
            self.assertIs(a.pairs[b.id]['client'],ab);self.assertEqual(ab.data_session,ab_session);self.assertEqual(ab.udp[0].getsockname()[1],ab_port)
            self.assertTrue(all(not any(e['event']=='error' for e in x.logs) for x in clients))
            self.assertTrue(all(x.directory and list(x.directory.glob('first-success-*.json')) for x in clients))
            (ROOT/'mesh-three-check.json').write_text(json.dumps({'passed':True,'real_authenticated_pairs':3,'stop_rejoin_affected_pairs_only':True,'rows':[x.rows() for x in clients]},ensure_ascii=False,indent=2),encoding='utf8')
        finally:self.stop_all(controllers,service)
    def test_solo_wait_and_lost_room_snapshots_do_not_reconnect_or_drop_verified_pairs(self):
        service,protocol,cfg=self.make_service();code=secrets.token_hex(16);controllers,clients=self.start_clients(1,cfg,code)
        try:
            self.assertTrue(until(lambda:clients[0].connected));original=clients[0].control;udpport=clients[0].mux.socket.getsockname()[1]
            time.sleep(.7);self.assertEqual(clients[0].pairs,{})
            more,others=self.start_clients(1,cfg,code);controllers+=more;clients+=others
            self.assertTrue(until(lambda:self.all_connected(clients),20))
            with patch.object(protocol,'datagram_received',return_value=None):
                time.sleep(2);self.assertTrue(self.all_connected(clients));self.assertIs(clients[0].control,original)
                self.assertEqual(clients[0].mux.socket.getsockname()[1],udpport)
            self.assertTrue(until(lambda:time.monotonic()-clients[0].last_snapshot<1))
        finally:self.stop_all(controllers,service)
    def test_eight_members_28_authenticated_pairs(self):
        service,protocol,cfg=self.make_service();controllers,clients=self.start_clients(8,cfg,secrets.token_hex(16))
        try:
            if not until(lambda:self.all_connected(clients),90):
                (ROOT/'mesh-eight-failure.json').write_text(json.dumps([x.summary() for x in clients],ensure_ascii=False,indent=2),encoding='utf8')
                self.fail('eight-member full mesh not connected; inspect mesh-eight-failure.json')
            self.assertTrue(all(len(c.rows())==7 for c in clients))
            self.assertTrue(all(len(c.status()['active_dense_peers'])<=1 for c in clients))
            self.assertTrue(all(not any(e['event']=='error' for e in c.logs) for c in clients))
            (ROOT/'mesh-eight-check.json').write_text(json.dumps({'passed':True,'members':8,'real_authenticated_pairs':28,'source':'real UDP loopback, not NAT4 simulation','seconds':max(time.monotonic()-c.started_at for c in clients),'rows':[c.rows() for c in clients]},ensure_ascii=False,indent=2),encoding='utf8')
        finally:self.stop_all(controllers,service)

if __name__=='__main__':unittest.main()
