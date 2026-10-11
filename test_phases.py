import json,pathlib,secrets,threading,time,unittest,zipfile
from unittest.mock import patch
from accelerator import MixedSearch,phased_choice
from client import LabClient,Budget
from evidence import export_evidence
from measure import Measurements
from strategy import Coordination,PortSchedule
from test_lab import Service

ROOT=pathlib.Path(__file__).parent/'test-assets/phases'

class PhaseTests(unittest.TestCase):
    def test_both_ends_negotiate_all_phases_and_reverse_stable_roles(self):
        a,b=Coordination('11'*16,10),Coordination('22'*16,10)
        pa={'strategy_protocol':1,'search_phase_protocol':1};pb=dict(pa)
        phases=[];roles=[]
        def exchange(now):
            changed,_=a.step({'id':b.id,'profile':pb},pa,now)
            if changed:pa['punch_coord']=dict(a.record)
            changed,_=b.step({'id':a.id,'profile':pa},pb,now+.01)
            if changed:pb['punch_coord']=dict(b.record)
        for i in range(6):
            exchange(100+i*12);exchange(101+i*12)
            self.assertEqual(a.phase,b.phase);phases.append(a.phase);roles.append((a.role,b.role))
        self.assertEqual(phases,['nearby','original','stable_pair','range','original','stable_pair'])
        self.assertEqual(roles[2],('anchor','scan'));self.assertEqual(roles[5],('scan','anchor'))
    def test_original_and_stable_anchor_are_not_overridden_by_nearby(self):
        peer={'udp':[['1.1.1.1',4308],['1.1.1.1',4309]],'profile':{'source_zero_observer_endpoint':['1.1.1.1',4308]}}
        coord=Coordination('11'*16);coord.role='anchor';coord.round=2;coord.phase='stable_pair'
        search=MixedSearch();schedule=PortSchedule(b'key','a');choices=[]
        for i in range(100):
            choice=phased_choice(coord,search,schedule,peer,8,100+i/20);choices.append(choice);schedule.sent(coord.role,False)
        self.assertEqual(set(choices),{(0,('1.1.1.1',4308),'fixed_target')});self.assertEqual(search.nearby.cursor,0)
        coord.phase='original';coord.round=4;slots=set()
        for i in range(8):
            slot,target,lane=phased_choice(coord,search,schedule,peer,8,200+i/20)
            self.assertEqual((target,lane),(('1.1.1.1',4308),'fixed_target'));slots.add(slot);schedule.sent(coord.role,False)
        self.assertEqual(len(slots),8)
    def test_old_peer_does_not_silently_enter_new_phase(self):
        a=Coordination('11'*16);p={'strategy_protocol':1,'search_phase_protocol':1}
        a.step({'id':'22'*16,'profile':{'strategy_protocol':1}},p,100)
        self.assertIsNone(a.phase);self.assertNotIn('phase_protocol',a.record)
    def test_range_phase_expands_beyond_old_64_port_window_and_resumes(self):
        search=MixedSearch();coord=Coordination('11'*16);coord.phase='range';coord.round=3;coord.role='scan'
        peer={'udp':[['1.1.1.1',4308]],'profile':{}}
        first=phased_choice(coord,search,PortSchedule(b'key','a'),peer,8,100)
        self.assertEqual(first,(0,('1.1.1.1',3284),'observed_range'))
        self.assertEqual(first,phased_choice(coord,search,None,peer,8,101))
        search.dense.sent();coord.round=9
        self.assertEqual(phased_choice(coord,search,None,peer,8,200)[1],('1.1.1.1',212))
        coord.round=3
        self.assertEqual(phased_choice(coord,search,None,peer,8,201)[1],('1.1.1.1',3285))
    def test_budget_stall_reason_and_unsent_scan_resume(self):
        budget=Budget();budget.at=100;budget.targets={i:100 for i in range(128)}
        self.assertEqual(budget.reason(('new',1),101),'new_socket_target_limit')
        self.assertIsNone(budget.reason(0,101));self.assertEqual(budget.reason(0,100.01),'packet_rate_limit')
        schedule=PortSchedule(b'key','a');peer={'udp':[['1.1.1.1',4308]]}
        schedule.sent('scan',False);choice=schedule.choice('scan',0,peer,8)
        self.assertFalse(budget.admit(('new',1),101));self.assertEqual(choice,schedule.choice('scan',0,peer,8))
        self.assertTrue(budget.admit(('new',1),116));schedule.sent('scan',True);self.assertEqual(schedule.position,1)
    def test_running_zip_compression_does_not_hold_packet_writer_lock(self):
        ROOT.mkdir(parents=True,exist_ok=True)
        c=LabClient({'packet_journal_dir':str(ROOT)},secrets.token_hex(16),'export')
        original=zipfile.ZipFile.writestr;checks=[]
        def writing(archive,*args,**kwargs):
            acquired=c.journal.lock.acquire(blocking=False);checks.append(acquired)
            if acquired:c.journal.lock.release()
            self.assertTrue(acquired,'compression blocks packet/keepalive writer')
            c.journal.record(direction='event',event='during_compression')
            return original(archive,*args,**kwargs)
        try:
            with patch.object(zipfile.ZipFile,'writestr',writing):export_evidence(c,ROOT/'live-export.zip')
            self.assertTrue(checks)
            with zipfile.ZipFile(ROOT/'live-export.zip') as z:
                for name in z.namelist():
                    if name.endswith('.jsonl'):
                        for line in z.read(name).splitlines():json.loads(line)
        finally:c.journal.close()
    def test_real_send_loop_preserves_original_phase_and_fixed_source_anchor(self):
        service=Service();code=secrets.token_hex(16)
        cfg={**service.cfg,'fast_start':True,'nearby_priority':True,'phased_search':True,'coordinated_scan':True,
            'coordination_window_seconds':.4,'duration':20,'lab_sockets':8,'packet_journal_dir':str(ROOT)}
        clients=[LabClient(cfg,code,str(i)) for i in range(2)];threads=[threading.Thread(target=c.run) for c in clients]
        sent=[];original=LabClient.trace_probe
        def trace(c,s,target,peer,now,lane,**fields):
            sent.append((c.id,c.coord.phase,c.coord.role,c.udp.index(s),target,lane))
            return original(c,s,target,peer,now,lane,**fields)
        try:
            with patch.object(LabClient,'receive_udp',return_value=None),patch.object(LabClient,'trace_probe',trace):
                for t in threads:t.start()
                deadline=time.monotonic()+18
                while time.monotonic()<deadline and not any(p[1]=='stable_pair' and p[2]=='anchor' and p[5]=='fixed_target' for p in sent):time.sleep(.02)
                self.assertTrue(any(p[1]=='original' and p[2]=='scan' and p[5]=='full_scan' for p in sent),sent[-15:])
                anchors=[p for p in sent if p[1]=='stable_pair' and p[2]=='anchor' and p[5]=='fixed_target']
                self.assertTrue(anchors,sent[-15:]);self.assertEqual({p[3] for p in anchors},{0})
                self.assertFalse([p for p in sent if p[1] in ('original','stable_pair') and p[5] in ('nearby_matrix','observed_range')])
        finally:
            for c in clients:c.stop.set()
            for t in threads:
                if t.ident:t.join(10);self.assertFalse(t.is_alive())
            service.stop()
    def test_failed_tcp_mapping_is_retried_without_waiting_for_udp(self):
        service=Service();cfg={**service.cfg,'fast_start':True,'tcp_mapping_retry':True,'duration':10}
        c=LabClient(cfg,secrets.token_hex(16),'retry');original=c.prepare_tcp;calls=[]
        def prepare(m,listener,refresh=False):
            original(m,listener,refresh)
            if c.tcp_prepare_generation==1:c.last_tcp_refresh=time.monotonic()-31
        def observe(m,port,local_port=0):
            calls.append(port)
            if c.tcp_prepare_generation==1:return {'error':'synthetic timeout','stage':'read_observation','local_port':local_port}
            return {'endpoint':['127.0.0.1',local_port],'local_port':local_port,'stage':'complete'}
        t=threading.Thread(target=c.run)
        try:
            with patch.object(c,'prepare_tcp',prepare),patch.object(Measurements,'tcp_observe',observe):
                t.start();deadline=time.monotonic()+5
                while time.monotonic()<deadline and not c.own_tcp_active:time.sleep(.01)
                self.assertTrue(c.own_tcp_active,c.logs);self.assertEqual(c.tcp_prepare_generation,2)
                self.assertEqual(calls,[service.cfg['lab_udp_base']]*2+[service.cfg['lab_udp_base']+1]*2)
                self.assertFalse(c.udp_direct);self.assertTrue(any(e['event']=='tcp_mapping_retry' for e in c.logs))
        finally:
            c.stop.set()
            if t.ident:t.join(10);self.assertFalse(t.is_alive())
            service.stop()
