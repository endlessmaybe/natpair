import time
import unittest
from strategy import allocation_model,Coordination,PortSchedule

def samples(ports):return [{'local_port':40000+i,'endpoint':['1.2.3.4',p] if p else None} for i,p in enumerate(ports)]

class StrategyTests(unittest.TestCase):
    def test_coordinated_roles_reach_actual_send_loop_without_false_success(self):
        import secrets,threading
        from unittest.mock import patch
        from test_lab import Service
        from client import LabClient
        from measure import Measurements
        service=Service();code=secrets.token_hex(16)
        clients=[LabClient(service.cfg,code,n) for n in ('a','b')]
        profile={'same_ip_filtering':'undetermined','cross_ip_filtering':'undetermined','port_pattern':{'validated':False}}
        threads=[threading.Thread(target=c.run) for c in clients]
        try:
            with patch.object(Measurements,'run',side_effect=lambda:dict(profile)),patch.object(LabClient,'receive_udp',return_value=None):
                for t in threads:t.start()
                for t in threads:t.join(25);self.assertFalse(t.is_alive())
            roles=[]
            for c in clients:
                self.assertFalse([e for e in c.logs if e['event']=='error'],c.logs)
                actual=[e['role'] for e in c.logs if e['event']=='coordination' and e['role'] in ('anchor','scan')]
                self.assertTrue(actual,c.logs);roles.append(actual[-1])
                self.assertFalse(c.udp_direct);self.assertLessEqual(len(c.budget.targets),128)
            self.assertEqual(set(roles),{'anchor','scan'})
            scanner=next(c for c,role in zip(clients,roles) if role=='scan')
            self.assertGreater(scanner.schedule.position,20)
            self.assertGreater(scanner.stats['udp_unique_targets'],20)
        finally:
            for c in clients:c.stop.set()
            for t in threads:
                if t.ident:t.join(5)
            service.stop()
    def test_prediction_requires_nonzero_training_and_unseen_holdout(self):
        for ports in (list(range(30000,30008)),list(range(30008,30000,-1))):
            self.assertTrue(allocation_model(samples(ports))['validated'])
        for ports in ([30000]*8,[1,2,3,4,5,6,100,101],[10,11,12,13,14,15,None,17],[10,20,19,30,31,40,41,42]):
            self.assertFalse(allocation_model(samples(ports))['validated'])
    def test_changing_public_ip_cannot_validate(self):
        data=samples(range(30000,30008));data[-1]['endpoint'][0]='5.6.7.8'
        self.assertFalse(allocation_model(data)['validated'])
    def pair(self,model=None):
        a,b=Coordination('11'*16,10),Coordination('22'*16,10)
        pa={'strategy_protocol':1};pb={'strategy_protocol':1}
        if model:pb['allocation_prediction']={'validated':True,'step':1}
        def exchange(now):
            ca,ra=a.step({'id':b.id,'profile':pb},pa,now)
            if ca:pa['punch_coord']=dict(a.record)
            cb,rb=b.step({'id':a.id,'profile':pa},pb,now+.1)
            if cb:pb['punch_coord']=dict(b.record)
            return ra,rb
        return a,b,pa,pb,exchange
    def test_handshake_no_scan_before_matching_ack(self):
        a,b,pa,pb,exchange=self.pair()
        self.assertEqual(exchange(100),('synchronizing','synchronizing'))
        self.assertEqual(exchange(101),('anchor','scan'))
        a.step({'id':b.id,'profile':{'strategy_protocol':1,'punch_coord':{'state':'ack','token':'ff'*16}}},pa,112)
        self.assertIsNone(a.role)
    def test_mixed_model_assigns_unvalidated_side_anchor(self):
        a,b,pa,pb,exchange=self.pair(True);exchange(100)
        self.assertEqual(exchange(101),('anchor','scan'));self.assertEqual(a.mode,'mixed_observer_prediction')
    def test_two_validated_models_select_duplex_pool(self):
        a,b,pa,pb,exchange=self.pair(True);pa['allocation_prediction']={'validated':True,'step':-1}
        exchange(100);self.assertEqual(exchange(101),('duplex','duplex'))
        s=PortSchedule(b'key','a');peer={'udp':[['1.2.3.4',30000]],'profile':pb};slots=set()
        for _ in range(8):
            slot,target,scan=s.choice('duplex',0,peer,8);slots.add(slot);s.sent('duplex',scan)
        self.assertEqual(len(slots),8);self.assertEqual(s.position,0)
    def test_round_changes_require_new_handshake(self):
        a,b,pa,pb,exchange=self.pair();exchange(100);exchange(101)
        self.assertEqual(exchange(112),('synchronizing','synchronizing'))
        self.assertEqual(exchange(113),('scan','anchor'));self.assertEqual(a.round,1)
    def test_incompatible_peer_never_gets_scan_role(self):
        a=Coordination('11'*16);self.assertEqual(a.step({'id':'22'*16,'profile':{}},{},1),(False,'incompatible'))
    def test_all_ports_permutation_and_resume(self):
        s=PortSchedule(b'key','a');ports={1+(s.start+i*s.stride)%65535 for i in range(65535)}
        self.assertEqual(len(ports),65535);self.assertNotIn(0,ports)
        peer={'udp':[['1.2.3.4',12345]],'profile':{}}
        s.sent('scan',False);first=s.choice('scan',0,peer,8)
        self.assertEqual(first,s.choice('scan',0,peer,8));self.assertEqual(s.position,0)
        s.sent('scan',True);self.assertEqual(s.position,1)
        s.choice('anchor',1,peer,8);s.choice('scan',2,peer,8);self.assertEqual(s.position,1)
    def test_anchor_target_and_scan_source_remain_fixed(self):
        s=PortSchedule(b'key','a');peer={'udp':[['1.2.3.4',12345]],'profile':{}}
        targets=set();slots=set()
        for _ in range(16):
            slot,target,scan=s.choice('anchor',0,peer,8);targets.add(target);slots.add(slot);s.sent('anchor',scan)
        self.assertEqual(len(targets),1);self.assertEqual(len(slots),8)
        for _ in range(20):
            slot,target,scan=s.choice('scan',1,peer,8);self.assertEqual(slot,0);s.sent('scan',scan)
    def test_anchor_uses_correlated_scanner_slot_zero(self):
        s=PortSchedule(b'key','a')
        peer={'udp':[['1.2.3.4',2222],['1.2.3.4',1111]],'profile':{'source_zero_observer_endpoint':['1.2.3.4',1111]}}
        self.assertEqual(s.choice('anchor',0,peer,8)[1],('1.2.3.4',1111))
        peer['profile']['source_zero_observer_endpoint']=['5.6.7.8',9999]
        self.assertEqual(s.choice('anchor',1,peer,8)[1],('1.2.3.4',2222))
    def test_live_direct_path_accepts_peer_without_observer(self):
        import secrets,socket
        from client import LabClient
        from wire import pack
        a=LabClient({'public_only':False},'ABCD'*8,'a');s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.bind(('127.0.0.1',0))
        try:
            ident='22'*16;a.peer={'id':ident,'udp':[]};a.direct_path=(s,('127.0.0.1',12345))
            nonce=secrets.token_hex(16);a.pending[nonce]=(s,('127.0.0.1',12345),time.monotonic())
            a.receive_udp(s,pack(a.key,{'k':'ack','from':ident,'to':a.id,'n':nonce}),('127.0.0.1',12345))
            self.assertTrue(a.udp_direct);self.assertTrue(a.summary()['result']['udp_direct_live'])
        finally:s.close()
        self.assertFalse(a.summary()['result']['udp_direct_live'])
    def test_socket_replacement_invalidates_previous_observation(self):
        import secrets,socket
        from discovery import LiveDiscovery
        from wire import unpack
        d=LiveDiscovery(False);d.set_ticket(secrets.token_hex(32))
        a,b=socket.socket(socket.AF_INET,socket.SOCK_DGRAM),socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
        try:
            a.bind(('127.0.0.1',0));b.bind(('127.0.0.1',0));d.attach(0,a)
            obj=unpack(bytes.fromhex(d.ticket),d.request(0,100))
            record={'slot':0,'endpoint':['127.0.0.1',3456],'nonce':obj['n'],'age_seconds':1,'epoch':d.epoch}
            d.accept([record],'server_observed_tls',101);self.assertIsNotNone(d.slot_endpoint(0,101))
            d.attach(0,b);self.assertIsNone(d.slot_endpoint(0,101))
            d.accept([record],'server_observed_tls',102);self.assertIsNone(d.slot_endpoint(0,102))
        finally:a.close();b.close()
    def test_source_prediction_via_tls_when_udp_responses_are_blocked(self):
        import secrets,threading
        from unittest.mock import patch
        from test_lab import Service
        from client import LabClient
        from measure import Measurements
        service=Service();service.service.test_drop_registered_responses=True
        client=LabClient(service.cfg,secrets.token_hex(16),'prediction-test')
        def only_allocation(m):
            return {'same_ip_filtering':'undetermined','port_pattern':{'validated':False},'allocation_prediction':m.source_allocation()}
        try:
            with patch.object(Measurements,'run',only_allocation):client.run(measure_only=True)
            self.assertFalse([e for e in client.logs if e['event']=='error'],client.logs)
            model=client.profile['allocation_prediction'];self.assertTrue(model['validated'],model)
            self.assertEqual(len(model['samples']),8)
            self.assertTrue(all(s['observation_source']=='correlated_tls_observation' for s in model['samples']))
            self.assertFalse(client.udp_direct)
        finally:client.stop.set();service.stop()

if __name__=='__main__':unittest.main(verbosity=2)
