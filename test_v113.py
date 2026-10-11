import json,pathlib,secrets,tempfile,threading,time,unittest
from unittest.mock import patch
from client import LabClient
from test_lab import Service
from tailbridge import driver_check
from health import native_label

class Repair113Tests(unittest.TestCase):
    def test_solo_delayed_snapshots_resume_on_same_connection_and_ticket(self):
        service=Service();c=LabClient({**service.cfg,'fast_start':True,'raw_tcp_experiment':False,
            'production_mode':True,'unlimited_search':True,'control_reply_timeout':.2,'control_stall_timeout':3},secrets.token_hex(16),'solo')
        original=service.service.send;blackhole=threading.Event()
        async def send(member,obj):
            if blackhole.is_set() and obj.get('k')=='peers':return
            await original(member,obj)
        thread=threading.Thread(target=c.run)
        try:
            with patch.object(service.service,'send',side_effect=send):
                thread.start();deadline=time.monotonic()+8
                while time.monotonic()<deadline and c.last_confirmed_room_members!=1:time.sleep(.02)
                self.assertEqual(c.last_confirmed_room_members,1)
                channel=c.control;ticket=c.discovery.ticket;blackhole.set();time.sleep(1)
                self.assertEqual(c.control_failures,0);self.assertIs(c.control,channel)
                self.assertGreater(c.control_soft_timeouts,0);self.assertEqual(c.stats['udp_probe_tx'],0)
                self.assertEqual(c.discovery.ticket,ticket)
                blackhole.clear();deadline=time.monotonic()+4
                while time.monotonic()<deadline and c.control_health['state']!='application_verified':time.sleep(.02)
                self.assertEqual(c.control_health['state'],'application_verified')
                self.assertIs(c.control,channel);self.assertEqual(c.control_reconnects,0)
                self.assertTrue(any(e['event']=='control_reply_resumed' for e in c.logs))
        finally:
            c.stop.set();thread.join(5);service.stop()

    def test_unresponsive_coordinator_eventually_recovers_not_infinite_soft_wait(self):
        service=Service();c=LabClient({**service.cfg,'fast_start':True,'raw_tcp_experiment':False,
            'production_mode':True,'unlimited_search':True,'control_reply_timeout':.2,'control_stall_timeout':.7},secrets.token_hex(16),'hard-timeout')
        original=service.service.send;blackhole=threading.Event()
        async def send(member,obj):
            if blackhole.is_set() and obj.get('k')=='peers':return
            await original(member,obj)
        thread=threading.Thread(target=c.run)
        try:
            with patch.object(service.service,'send',side_effect=send):
                thread.start();deadline=time.monotonic()+8
                while time.monotonic()<deadline and c.last_confirmed_room_members!=1:time.sleep(.02)
                blackhole.set();deadline=time.monotonic()+4
                while time.monotonic()<deadline and c.control_failures<1:time.sleep(.02)
                self.assertGreaterEqual(c.control_failures,1)
                blackhole.clear();deadline=time.monotonic()+8
                while time.monotonic()<deadline and c.control_reconnects<1:time.sleep(.02)
                self.assertGreaterEqual(c.control_reconnects,1);self.assertFalse(c.stop.is_set())
                self.assertEqual(c.stats['udp_probe_tx'],0)
        finally:
            c.stop.set();thread.join(5);service.stop()

    def test_unanswered_peer_udp_does_not_reconnect_room(self):
        service=Service();cfg={**service.cfg,'fast_start':True,'raw_tcp_experiment':False,'unlimited_search':True,
            'production_mode':True,'coordinated_scan':True,'control_reply_timeout':.3,'control_stall_timeout':2}
        code=secrets.token_hex(16);clients=[LabClient(cfg,code,str(i)) for i in range(2)]
        threads=[threading.Thread(target=c.run) for c in clients]
        try:
            with patch.object(LabClient,'receive_udp',return_value=None):
                for t in threads:t.start()
                deadline=time.monotonic()+10
                while time.monotonic()<deadline and not all(c.stats['udp_probe_tx']>100 for c in clients):time.sleep(.03)
                self.assertTrue(all(c.stats['udp_probe_tx']>100 for c in clients))
                time.sleep(2)
                for c in clients:
                    self.assertFalse(c.udp_direct);self.assertEqual(c.stats['udp_probe_acks'],0)
                    self.assertEqual(c.control_failures,0);self.assertEqual(c.control_reconnects,0)
                    self.assertIsNone(c.budget.rate_limit)
        finally:
            for c in clients:c.stop.set()
            for t in threads:t.join(5)
            service.stop()

    def test_missing_driver_reports_actionable_error_before_room_join(self):
        with tempfile.TemporaryDirectory(dir=r'H:\CodexTemp\tmp') as d:
            with self.assertRaisesRegex(RuntimeError,'组件缺失'):driver_check(pathlib.Path(d))
        c=LabClient({'tailscale_bridge':True,'bind':'127.0.0.1','if_index':0,'unlimited_search':True},secrets.token_hex(16),'missing')
        with patch('client.is_admin',return_value=True),patch('client.driver_check',side_effect=RuntimeError('组件缺失')):
            c.run()
        self.assertTrue(any(e['event']=='error' and '组件缺失' in e['message'] for e in c.logs))
        self.assertEqual(c.stats['udp_probe_tx'],0);self.assertIsNone(c.control)

    def test_dll_error_cannot_be_labelled_as_tail_connecting(self):
        self.assertIn('接入失败',native_label({'udp_direct_live':True,'tail_bridge_error':'missing DLL'}))
        self.assertIn('DERP',native_label({'udp_direct_live':True,'tail_bridge_error':'missing DLL','tail_native_verified':True,'tail_health':{'route':'derp'}}))

if __name__=='__main__':unittest.main(verbosity=2)
