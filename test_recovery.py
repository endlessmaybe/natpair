import asyncio,hashlib,json,secrets,socket,threading,time,unittest
from unittest.mock import patch
from discovery import LiveDiscovery,PairClock
from strategy import mapping_stable,Coordination
from wire import pack,unpack
from server import LabServer
from client import LabClient
from measure import Measurements
from test_lab import Service

def stable_profile():
    trials=[]
    for ip in ('162.159.207.0','54.65.63.244'):
        trials.append({'before':{'endpoint':['36.249.212.32',4534]},'other_ip':{'endpoint':['36.249.212.32',4534]},'after':{'endpoint':['36.249.212.32',4534]},'other_server':{'ip':ip}})
    return {'port_pattern':{'validated':True,'step':0},'cross_ip_mapping':{'classification':'same_for_tested_destination_ips','trials':trials},'same_ip_filtering':'undetermined','allocation_prediction':{'validated':False},'strategy_protocol':1}

class RecoveryTests(unittest.TestCase):
    def test_closing_ssl_writer_is_an_expected_connection_error(self):
        class ClosedWriter:
            def is_closing(self):return True
            def write(self,data):raise AssertionError('closed writer must not be written')
        service=LabServer(secrets.token_hex(32))
        async def check():
            with self.assertRaises(ConnectionError):await service.send({'writer':ClosedWriter(),'lock':asyncio.Lock()},{'k':'notice'})
        asyncio.run(check())
    def test_active_timer_pauses_and_gap_timeout_is_explicit(self):
        c=PairClock(100,300,60);c.step(0,False);c.step(10,True)
        self.assertEqual(c.step(30,True)[1],20)
        self.assertEqual(c.step(32,False)[1],20)
        self.assertEqual(c.step(70,False)[1],20)
        self.assertEqual(c.step(71,True)[1],20)
        self.assertEqual(c.step(81,True)[1],30)
        c.step(83,False);self.assertTrue(c.step(143,False)[2]);self.assertEqual(c.reason,'peer_or_control_gap_timeout')
    def test_stable_mapping_beats_failed_allocation_and_retains_roles(self):
        a,b=Coordination('11'*16,10),Coordination('22'*16,10)
        pa={'strategy_protocol':1};pb=stable_profile()
        self.assertTrue(mapping_stable(pb));self.assertIsNone(pb['allocation_prediction'].get('step'))
        for start in (0,12,24,36):
            a.step({'id':b.id,'profile':pb},pa,start);pa['punch_coord']=dict(a.record)
            b.step({'id':a.id,'profile':pa},pb,start+.1);pb['punch_coord']=dict(b.record)
            a.step({'id':b.id,'profile':pb},pa,start+1);pa['punch_coord']=dict(a.record)
            b.step({'id':a.id,'profile':pa},pb,start+1.1);pb['punch_coord']=dict(b.record)
            self.assertEqual((a.role,b.role),('anchor','scan'));self.assertEqual(a.mode,'tested_stable_mapping_mixed')
        pb['cross_ip_mapping']['trials'][1]['after']=None;self.assertFalse(mapping_stable(pb))
    def test_peer_epoch_resets_stale_round(self):
        c=Coordination('22'*16);c.peer_id='11'*16;c.round=9;c.remote_epoch='aa'*16
        profile={'strategy_protocol':1,'punch_epoch':'bb'*16,'punch_coord':{'protocol':1,'token':'cc'*16,'state':'prepare','round':0,'leader_role':'anchor'}}
        changed,role=c.step({'id':'11'*16,'profile':profile},{},100)
        self.assertTrue(changed);self.assertEqual(c.round,0);self.assertEqual(role,'synchronizing')
    def test_server_epoch_discards_measurement_mapping_and_late_packets(self):
        service=LabServer(secrets.token_hex(32),False);ticket=secrets.token_hex(32);ticket_id=hashlib.sha256(bytes.fromhex(ticket)).hexdigest()
        member={'id':'aa'*16,'name':'x','ticket':ticket,'observed':{},'last':time.monotonic(),'epoch':'11'*16,'stage':'measurement','prepared':False,'version':'0.9.4-lab','tcp':[],'tcp_active':[],'udp':[],'profile':{}}
        service.tickets[ticket_id]=member
        class Sender:
            def sendto(self,*args):pass
        service.udp=[Sender()]*8
        old={'k':'observe','n':secrets.token_hex(16),'slot':7,'epoch':'11'*16,'ticket_id':ticket_id}
        service.udp_receive(pack(bytes.fromhex(ticket),old),('127.0.0.1',3333),0)
        self.assertEqual(len(service.observations(member)),1)
        member.update(epoch='22'*16,stage='main',prepared=True)
        self.assertEqual(service.peer_snapshot(member)['udp'],[])
        service.udp_receive(pack(bytes.fromhex(ticket),old),('127.0.0.1',4444),0)
        self.assertEqual(service.observations(member),[])
        new={**old,'epoch':'22'*16,'slot':0,'n':secrets.token_hex(16)}
        service.udp_receive(pack(bytes.fromhex(ticket),new),('127.0.0.1',5555),0)
        self.assertEqual(service.peer_snapshot(member)['udp'],[['127.0.0.1',5555]])
    def test_repeated_baseline_requires_new_observation(self):
        d=LiveDiscovery(False);d.set_ticket(secrets.token_hex(32));s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
        try:
            s.bind(('127.0.0.1',0));d.attach(0,s);request=unpack(bytes.fromhex(d.ticket),d.request(0,100))
            d.accept([{'slot':0,'epoch':d.epoch,'nonce':request['n'],'age_seconds':1,'endpoint':['127.0.0.1',1234]}],'tls',101)
            self.assertIsNotNone(d.slot_endpoint(0,101));d.invalidate(0);self.assertIsNone(d.slot_endpoint(0,101))
            epoch=d.new_epoch();self.assertNotEqual(epoch,request['epoch']);self.assertEqual(d.endpoints(101),[])
        finally:s.close()
    def test_tls_disconnect_reconnects_without_replacing_source_sockets(self):
        service=Service();service.cfg.update(duration=18,peer_gap_seconds=15)
        clients=[LabClient(service.cfg,secrets.token_hex(16),'placeholder')]
        code=secrets.token_hex(16);clients=[LabClient(service.cfg,code,n) for n in ('a','b')]
        threads=[threading.Thread(target=c.run) for c in clients]
        profile={'same_ip_filtering':'undetermined','cross_ip_filtering':'undetermined','port_pattern':{'validated':False}}
        try:
            with patch.object(Measurements,'run',side_effect=lambda:dict(profile)),patch.object(LabClient,'receive_udp',return_value=None):
                for t in threads:t.start()
                deadline=time.monotonic()+12
                while time.monotonic()<deadline and not all(c.paired_started and c.stats['udp_probe_tx']>5 for c in clients):time.sleep(.1)
                self.assertTrue(all(c.paired_started for c in clients))
                ports=[[s.getsockname()[1] for s in c.udp] for c in clients];cursor=sum(c.schedule.position for c in clients)
                async def disconnect():
                    for room in list(service.service.rooms.values()):
                        if clients[0].id in room:room[clients[0].id]['writer'].close()
                asyncio.run_coroutine_threadsafe(disconnect(),service.loop).result(2)
                deadline=time.monotonic()+10
                while time.monotonic()<deadline and not (clients[0].control_reconnects and all(c.connected.is_set() for c in clients) and sum(c.schedule.position for c in clients)>cursor+10):time.sleep(.1)
                self.assertEqual(clients[0].control_reconnects,1)
                self.assertEqual([[s.getsockname()[1] for s in c.udp] for c in clients],ports)
                self.assertGreater(sum(c.schedule.position for c in clients),cursor+10)
                self.assertEqual(sum(len(r) for r in service.service.rooms.values()),2)
                self.assertTrue(any(e['event']=='testing_paused' for c in clients for e in c.logs))
                for c in clients:self.assertFalse([e for e in c.logs if e['event']=='error'],c.logs)
                for t in threads:t.join(30);self.assertFalse(t.is_alive())
                for c in clients:self.assertEqual(c.logs[-1]['event'],'finished')
        finally:
            for c in clients:c.stop.set()
            for t in threads:
                if t.ident:t.join(5)
            service.stop()

    def test_same_identity_replaces_half_open_control_without_old_cleanup_removing_new(self):
        from net import tls_connect
        service=Service();channels=[];ident=secrets.token_hex(16);resume=secrets.token_hex(16)
        def join(token):
            channel,_=tls_connect(service.cfg,'127.0.0.1',0);channels.append(channel)
            channel.sendall(json.dumps({'access':service.access,'room':'aa'*32,'id':ident,'name':'resume','resume':token,'version':'0.9.4-lab'}).encode()+b'\n')
            return json.loads(channel.makefile('rb').readline())
        try:
            first=join(resume);second=join(resume);self.assertNotEqual(first['observer_ticket'],second['observer_ticket'])
            time.sleep(.2)
            async def current():return service.service.rooms['aa'*32][ident]['ticket']
            self.assertEqual(asyncio.run_coroutine_threadsafe(current(),service.loop).result(2),second['observer_ticket'])
            self.assertIn('error',join(secrets.token_hex(16)))
            self.assertEqual(asyncio.run_coroutine_threadsafe(current(),service.loop).result(2),second['observer_ticket'])
        finally:
            for channel in channels:channel.close()
            service.stop()

    def test_verified_udp_keepalive_survives_brief_control_loss(self):
        service=Service();service.cfg.update(duration=14,peer_gap_seconds=15)
        code=secrets.token_hex(16);clients=[LabClient(service.cfg,code,n) for n in ('a','b')]
        threads=[threading.Thread(target=c.run) for c in clients]
        profile={'same_ip_filtering':'undetermined','cross_ip_filtering':'undetermined','port_pattern':{'validated':False}}
        try:
            with patch.object(Measurements,'run',side_effect=lambda:dict(profile)):
                for t in threads:t.start()
                deadline=time.monotonic()+10
                while time.monotonic()<deadline and not all(c.stats['udp_probe_acks']>=4 for c in clients):time.sleep(.1)
                self.assertTrue(all(c.udp_direct for c in clients))
                before=clients[0].stats['udp_probe_acks']
                async def disconnect():
                    for room in list(service.service.rooms.values()):
                        if clients[0].id in room:room[clients[0].id]['writer'].close()
                asyncio.run_coroutine_threadsafe(disconnect(),service.loop).result(2)
                deadline=time.monotonic()+6
                while time.monotonic()<deadline and not (clients[0].control_reconnects and clients[0].stats['udp_probe_acks']>=before+4):time.sleep(.1)
                self.assertEqual(clients[0].control_reconnects,1)
                self.assertGreaterEqual(clients[0].stats['udp_probe_acks'],before+4)
                for c in clients:self.assertFalse([e for e in c.logs if e['event']=='udp_path_expired'],c.logs)
                for t in threads:t.join(25);self.assertFalse(t.is_alive())
                for c in clients:self.assertEqual(c.logs[-1]['event'],'finished')
        finally:
            for c in clients:c.stop.set()
            for t in threads:
                if t.ident:t.join(5)
            service.stop()

if __name__=='__main__':unittest.main(verbosity=2)
