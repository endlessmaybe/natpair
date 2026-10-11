import datetime,json,pathlib,secrets,threading,time,unittest
from unittest.mock import patch
from client import LabClient,Budget
from protection import ConnectionGuard,offer,negotiated
from coexist import Coexistence
from accelerator import FastSearch
from test_lab import Service

ROOT=pathlib.Path(__file__).parent

class CoexistTests(unittest.TestCase):
    def line(self,stamp,message):
        return datetime.datetime.fromtimestamp(stamp,datetime.timezone.utc).isoformat()+'|pid=1|tid=2|'+message
    def test_single_transient_only_pauses_five_seconds(self):
        c=Coexistence(True);c.signal(self.line(1000,'runtime-mihomo-readback-transient-unhealthy'),100,1000)
        self.assertTrue(c.snapshot(104)['pause']);self.assertFalse(c.snapshot(105)['pause']);self.assertTrue(c.snapshot(105)['recovering'])
    def test_persistent_failure_pauses_and_deduplicates(self):
        c=Coexistence(True)
        for n in range(3):c.signal(self.line(1000+n,'runtime-mihomo-readback-transient-unhealthy'),100+n,1000+n)
        self.assertEqual(c.until,192);c.signal(self.line(1002,'runtime-mihomo-readback-transient-unhealthy'),180,1080)
        self.assertEqual(c.until,192)
    def test_stale_signal_does_not_restart_old_cooldown(self):
        c=Coexistence(True);c.signal(self.line(900,'runtime-connect-failed'),100,1000)
        self.assertFalse(c.snapshot(100)['pause']);c.signal(self.line(995,'runtime-connect-failed'),100,1000)
        self.assertEqual(c.until,185)
    def test_reader_partial_rotation_and_missing_file(self):
        folder=ROOT/'test-assets'/secrets.token_hex(8);folder.mkdir(parents=True);p=folder/'trace.log';c=Coexistence(True,p)
        c.poll(100,1000);self.assertEqual(c.status,'trace_not_available')
        line=self.line(1000,'runtime-connect-failed')
        p.write_text(line[:25],encoding='utf-8');c.poll(100,1000);self.assertFalse(c.snapshot(100)['pause'])
        with p.open('a',encoding='utf-8') as f:f.write(line[25:]+'\n')
        c.poll(100,1000);self.assertTrue(c.snapshot(100)['pause'])
        p.replace(folder/'trace.old');p.write_text(self.line(1010,'command-start action=disconnect')+'\n',encoding='utf-8');c.poll(110,1010)
        self.assertEqual(c.until,200);self.assertEqual(c.snapshot(110)['last_signal'],'command-start action=disconnect')
    def test_known_observer_not_starved_by_short_new_target_cap(self):
        b=Budget(80,16,True);observer=('observer',123)
        self.assertTrue(b.admit(observer,100))
        for n in range(16):self.assertTrue(b.admit(('peer',n),116+n*.15))
        self.assertFalse(b.admit(observer,120));self.assertTrue(b.admit(observer,120,maintenance=True))
        self.assertFalse(b.admit(('observer',456),121,maintenance=True))
    def test_pause_preserves_authentication_and_known_observer(self):
        b=Budget(80,16,True);self.assertTrue(b.admit('observer',100));b.pause=True
        self.assertFalse(b.admit('new',101));self.assertFalse(b.admit('observer',101))
        self.assertTrue(b.admit('observer',101,maintenance=True));self.assertTrue(b.admit('reverse_authenticated',102,authenticated=True))
    def test_new_target_pacing_keeps_existing_path_unthrottled(self):
        b=Budget(80,48,True);b.pressure.spacing=.25
        self.assertTrue(b.admit('a',100));self.assertFalse(b.admit('b',100.1));self.assertTrue(b.admit('a',100.1));self.assertTrue(b.admit('b',100.25))
    def test_brief_candidate_gap_never_causes_thirty_second_wait(self):
        g=ConnectionGuard();self.assertFalse(g.step(100,True,True));self.assertTrue(g.step(100.5,True,True))
        self.assertFalse(g.step(110,False,True));self.assertFalse(g.step(111,True,True));self.assertTrue(g.step(111.5,True,True))
        self.assertEqual(g.cooldown_until,0)
    def test_real_control_failure_and_long_gap_still_cool_down(self):
        for control in (False,True):
            g=ConnectionGuard();g.step(100,True,True);g.step(101,True,True);g.step(110,False,control);g.step(119,False,control)
            self.assertFalse(g.step(120,True,True));self.assertTrue(g.step(130,True,True))
    def test_room_count_unknown_when_stale_instead_of_false_solo(self):
        c=LabClient({},secrets.token_hex(16),'room');self.assertIsNone(c.room_members(100))
        c.connected.set();c.last_snapshot=99;c.room_peer_ids=[];self.assertEqual(c.room_members(100),1)
        c.room_peer_ids=['peer'];self.assertEqual(c.room_members(100),2);self.assertIsNone(c.room_members(108))
        c.connected.clear();self.assertIsNone(c.room_members(100))
    def test_peer_pause_is_fresh_and_authenticated_channel_scoped(self):
        c=LabClient({'protected_search':True},secrets.token_hex(16),'pause');c.last_snapshot=100
        c.update_coexistence({'profile':{'coexist_pause':True}},101);self.assertTrue(c.budget.pause)
        c.update_coexistence({'profile':{'coexist_pause':True}},109);self.assertFalse(c.budget.pause)
    def test_monitor_unavailable_falls_back_and_is_visible(self):
        cfg={'protected_search':True,'bifrost_coexist':True};c=LabClient(cfg,secrets.token_hex(16),'unobserved');c.coexist.status='trace_unreadable'
        c.negotiate_protection({'profile':{'protected_search':offer(cfg)}});c.update_coexistence(None,100)
        self.assertEqual(c.coexist_state['monitor'],'trace_unreadable');self.assertEqual(c.budget.interval,.05)
        self.assertGreaterEqual(c.budget.pressure.spacing,.5)
    def test_continuous_scan_priority_retains_fresh_and_full_progress(self):
        f=FastSearch();f.continuous_priority=True;p={'udp':[['1.1.1.1',27155]],'profile':{}}
        lanes=[]
        for n in range(8):
            choice=f.protected_choice(p,8,'scan',100+n);lanes.append(choice[2]);f.sent(choice[2])
        self.assertEqual(lanes.count('center_scan'),6);self.assertEqual(lanes.count('fresh_center_scan'),2)
        self.assertEqual(f.scan_position,6)
    def test_coexist_policy_negotiates_limits_without_clearing_ledger(self):
        cfg={'protected_search':True,'bifrost_coexist':True};a=offer(cfg);b=offer({**cfg,'probe_rate':20})
        p=negotiated(a,b);self.assertEqual(p,negotiated(b,a));self.assertEqual(p['rate'],20);self.assertEqual(p['new180'],192);self.assertEqual(p['burst'],2);self.assertEqual(p['new_spacing_ms'],250)
    def test_production_no_public_tcp_even_with_old_peer_candidates(self):
        service=Service();folder=ROOT/'test-assets'/secrets.token_hex(8);folder.mkdir(parents=True);trace=folder/'trace.log';trace.write_text('',encoding='utf-8')
        cfg={**service.cfg,'protected_search':True,'bifrost_coexist':True,'bifrost_trace_path':str(trace),'raw_tcp_experiment':False,'efficient_search':True,'fast_start':True,'coordinated_scan':True,'production_mode':True}
        clients=[LabClient(cfg,secrets.token_hex(16),'unused')]
        code=secrets.token_hex(16);clients=[LabClient(cfg,code,n) for n in ('a','b')];threads=[threading.Thread(target=c.run) for c in clients]
        try:
            for t in threads:t.start()
            deadline=time.monotonic()+10
            while time.monotonic()<deadline and not all(c.stats['udp_probe_acks']>=3 for c in clients):time.sleep(.03)
            self.assertTrue(all(c.udp_direct for c in clients))
            before=[c.stats['udp_probe_acks'] for c in clients]
            now=time.time();trace.write_text(self.line(now,'runtime-connect-failed')+'\n',encoding='utf-8')
            deadline=time.monotonic()+4
            while time.monotonic()<deadline and not all(c.budget.pause and c.stats['udp_probe_acks']>n for c,n in zip(clients,before)):time.sleep(.03)
            self.assertTrue(all(c.budget.pause for c in clients));self.assertTrue(all(c.stats['udp_probe_acks']>n for c,n in zip(clients,before)))
            for c in clients:
                self.assertEqual(c.room_members(),2);self.assertEqual(c.stats['tcp_attempts'],0);self.assertIsNone(c.tcp_listener);self.assertIsNone(c.tcp_executor)
                self.assertFalse([e for e in c.logs if e['event'] in ('tcp_prepared','tcp_attempt_started','udp_path_expired','error')])
        finally:
            for c in clients:c.stop.set()
            for t in threads:
                if t.ident:t.join(15);self.assertFalse(t.is_alive())
            service.stop()

if __name__=='__main__':unittest.main()
