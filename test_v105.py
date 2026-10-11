import json,secrets,threading,time,unittest
from types import SimpleNamespace
from unittest.mock import patch
from client import Budget,LabClient
from protection import MappingPressure,ConnectionGuard,offer,negotiated
from accelerator import FastSearch
from test_lab import Service
from test_tail import native_responses
import test_v103

class ProtectionTests(unittest.TestCase):
    def test_different_strengths_negotiate_identical_smaller_limits(self):
        a=offer({'probe_rate':240,'probe_new_targets':2048});b=offer({'probe_rate':120,'probe_new_targets':48})
        self.assertEqual(negotiated(a,b),negotiated(b,a));self.assertEqual(negotiated(a,b)['rate'],80);self.assertEqual(negotiated(a,b)['new15'],48)
        self.assertEqual(negotiated(a,offer({'probe_rate':20}))['rate'],20)
    def test_old_peer_keeps_local_protection_and_lower_rate(self):
        self.assertEqual(negotiated(offer({}),None)['rate'],20);self.assertFalse(negotiated(offer({}),{})['peer_supported'])
    def test_long_mapping_cap_survives_short_window_rollover(self):
        b=Budget(80,64,True);b.pressure.limit=4
        for i in range(4):self.assertTrue(b.admit(i,100+i*.2))
        self.assertFalse(b.admit(5,116));self.assertEqual(b.reason(5,116),'long_mapping_pressure_limit')
        self.assertTrue(b.admit(0,116));self.assertFalse(b.admit(5,279));self.assertTrue(b.admit(5,281))
        self.assertLessEqual(len(b.pressure.targets),4)
    def test_new_mapping_burst_does_not_limit_existing_keepalive(self):
        b=Budget(80,64,True)
        for i in range(8):self.assertTrue(b.admit(i,100+i*.013))
        self.assertFalse(b.admit(9,100.2));self.assertEqual(b.reason(9,100.2),'new_mapping_burst_limit')
        self.assertTrue(b.admit(0,100.22));self.assertTrue(b.admit(9,101.3))
    def test_authenticated_reply_is_not_stranded_by_mapping_limit(self):
        b=Budget(80,64,True);b.pressure.limit=1;self.assertTrue(b.admit(1,100))
        self.assertTrue(b.admit(2,101,authenticated=True));self.assertLessEqual(len(b.pressure.targets),1)
    def test_renegotiation_never_clears_accumulated_pressure(self):
        c=LabClient({'protected_search':True},secrets.token_hex(16),'safe');c.budget.admit('live',100)
        c.negotiate_protection({'profile':{'protected_search':offer({'probe_rate':20})}})
        self.assertIn('live',c.budget.pressure.targets);self.assertAlmostEqual(c.budget.interval,.05)
    def test_outage_pauses_then_cools_down_after_recovery(self):
        g=ConnectionGuard();self.assertFalse(g.step(100,True));self.assertTrue(g.step(102,True))
        self.assertFalse(g.step(103,False));self.assertFalse(g.step(110,True));self.assertEqual(g.reason,'connection_recovery_cooldown');self.assertTrue(g.step(134,True))
    def test_observer_stops_without_control_and_is_bounded_after_reconnect(self):
        c=LabClient({'protected_search':True},secrets.token_hex(16),'observer');c.udp=[None]*8
        self.assertIsNone(c.protected_observer_slot(100));c.connected.set();slots=[]
        for n in range(8):
            slot=c.protected_observer_slot(100+n*.5);slots.append(slot);c.observer_last[slot]=100+n*.5
            self.assertIsNone(c.protected_observer_slot(100+n*.5+.1))
        self.assertEqual(slots,list(range(8)));c.connected.clear();self.assertIsNone(c.protected_observer_slot(110))
    def peer(self,port):return {'udp':[['1.1.1.1',port]],'profile':{'source_zero_observer_endpoint':['1.1.1.1',port]}}
    def test_anchor_never_runs_center_scan_in_protected_mode(self):
        f=FastSearch()
        for i in range(100):
            item=f.protected_choice(self.peer(27155),8,'anchor',100+i)
            self.assertEqual(item[2],'fast_anchor');f.sent(item[2])
        self.assertEqual(f.scan_position,0)
    def test_changed_observer_refreshes_near_search_without_resetting_global_scan(self):
        f=FastSearch()
        for i in range(12):
            item=f.protected_choice(self.peer(27155),8,'scan',100+i);f.sent(item[2])
        position=f.scan_position;f.tick=0
        item=f.protected_choice(self.peer(28155),8,'scan',140)
        self.assertEqual(item,(0,('1.1.1.1',28155),'fresh_center_scan'));self.assertEqual(f.scan_position,position)
        self.assertIsNone(f.protected_choice(self.peer(28155),8,'synchronizing',150))
    def test_actual_peerapi_success_output_is_accepted(self):
        c=test_v103.HealthTests().client();c.cfg={'tail_tcp_check':True};status=test_v103.HealthTests().status()
        with patch('client.command',side_effect=native_responses(c,['pong',status,RuntimeError('TSMP timeout'),status,'hit peerapi of 100.1.1.2 (node.example.) at http://100.1.1.2:1234 in 19ms',status])),patch('client.read_metadata',return_value={}):c.native_check()
        self.assertTrue(c.native_verified);self.assertTrue(c.native_health['tcp_business_verified'])
    def test_real_clients_different_rate_negotiate_and_direct(self):
        service=Service();code=secrets.token_hex(16);cfg={**service.cfg,'protected_search':True,'fast_center_search':True,'fast_start':True,'coordinated_scan':True,'duration':10}
        a=LabClient({**cfg,'probe_rate':240,'probe_new_targets':64},code,'a');b=LabClient({**cfg,'probe_rate':20,'probe_new_targets':32},code,'b')
        threads=[threading.Thread(target=c.run) for c in (a,b)]
        try:
            for t in threads:t.start()
            deadline=time.monotonic()+8
            while time.monotonic()<deadline and not all(c.udp_direct for c in (a,b)):time.sleep(.02)
            self.assertTrue(a.udp_direct and b.udp_direct)
            self.assertEqual(a.protection_policy,b.protection_policy);self.assertEqual(a.protection_policy['rate'],20)
            self.assertTrue(all(c.budget.pressure for c in (a,b)))
        finally:
            for c in (a,b):c.stop.set()
            for t in threads:
                if t.ident:t.join(10);self.assertFalse(t.is_alive())
            service.stop()
    def test_protected_connection_recovery_keeps_existing_udp_alive(self):
        import asyncio
        service=Service();code=secrets.token_hex(16);cfg={**service.cfg,'protected_search':True,'fast_start':True,'coordinated_scan':True,'production_mode':True}
        clients=[LabClient(cfg,code,n) for n in ('a','b')];threads=[threading.Thread(target=c.run) for c in clients]
        try:
            for t in threads:t.start()
            deadline=time.monotonic()+8
            while time.monotonic()<deadline and not all(c.stats['udp_probe_acks']>=2 for c in clients):time.sleep(.03)
            self.assertTrue(all(c.udp_direct for c in clients));before=clients[0].stats['udp_probe_acks'];epoch=clients[0].profile['punch_epoch']
            async def disconnect():
                for room in service.service.rooms.values():
                    if clients[0].id in room:room[clients[0].id]['writer'].close()
            asyncio.run_coroutine_threadsafe(disconnect(),service.loop).result(2)
            deadline=time.monotonic()+8
            while time.monotonic()<deadline and not (clients[0].control_reconnects and clients[0].stats['udp_probe_acks']>=before+4):time.sleep(.03)
            self.assertGreaterEqual(clients[0].control_reconnects,1);self.assertGreaterEqual(clients[0].stats['udp_probe_acks'],before+4)
            self.assertEqual(clients[0].profile['punch_epoch'],epoch)
            self.assertFalse([e for c in clients for e in c.logs if e['event']=='udp_path_expired'])
        finally:
            for c in clients:c.stop.set()
            for t in threads:
                if t.ident:t.join(10);self.assertFalse(t.is_alive())
            service.stop()

if __name__=='__main__':unittest.main()
