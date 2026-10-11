import secrets,time,unittest
from unittest.mock import patch
from client import LabClient
from protection import offer,negotiated

class RestoreTests(unittest.TestCase):
    def test_restored_profile_matches_successful_v105_exactly(self):
        cfg={'restore_v105_budget':True,'bifrost_coexist':True,'probe_rate':80,'probe_new_targets':48}
        a=offer(cfg);b=offer({'probe_rate':80,'probe_new_targets':48})
        self.assertEqual(a,b)
        self.assertEqual((a['rate'],a['new15'],a['new180'],a['burst'],a['window'],a['new_spacing_ms']),(80,48,256,8,180,0))
    def test_no_monitor_does_not_silently_restore_v106_throttle(self):
        cfg={'restore_v105_budget':True,'protected_search':True,'bifrost_coexist':True,'probe_new_targets':48}
        c=LabClient(cfg,secrets.token_hex(16),'restore');c.coexist.status='trace_not_available';c.negotiate_protection({'profile':{'protected_search':offer(cfg)}})
        c.update_coexistence(None,100)
        self.assertEqual(c.budget.interval,1/80);self.assertEqual(c.budget.pressure.spacing,0);self.assertEqual(c.budget.pressure.limit,256);self.assertEqual(c.budget.pressure.burst,8)
        self.assertFalse(c.fast_search.continuous_priority)
    def test_v106_peer_still_negotiates_lower_limit_honestly(self):
        restored=offer({'restore_v105_budget':True,'bifrost_coexist':True,'probe_new_targets':48});old=offer({'bifrost_coexist':True,'probe_new_targets':48})
        p=negotiated(restored,old);self.assertEqual(p['new180'],192);self.assertEqual(p['burst'],2);self.assertEqual(p['new_spacing_ms'],250)
    def test_fault_feedback_still_pauses_and_recovery_is_visible(self):
        cfg={'restore_v105_budget':True,'protected_search':True,'bifrost_coexist':True};c=LabClient(cfg,secrets.token_hex(16),'fault')
        c.coexist.status='trace_monitoring';c.coexist.until=110;c.coexist.recovery_until=120
        c.update_coexistence(None,100);self.assertTrue(c.budget.pause)
        c.update_coexistence(None,111);self.assertFalse(c.budget.pause);self.assertTrue(c.coexist_state['recovering']);self.assertEqual(c.budget.interval,.05)
    def test_actual_rate_distinguishes_observer_repeat_and_new_combination(self):
        c=LabClient({},secrets.token_hex(16),'rates');c.started_at=100
        class Sock:
            def getsockname(self):return ('127.0.0.1',1234)
        s=Sock()
        for n in range(10):
            with patch('client.time.monotonic',return_value=100+n):c.trace_packet(s,b'x','tx',('1.1.1.1',1000),kind='probe')
        with patch('client.time.monotonic',return_value=109):c.trace_packet(s,b'x','tx',('1.1.1.1',2000),kind='observer')
        rates=c.actual_rates(109.9)
        self.assertAlmostEqual(rates['peer_probe_tx_pps'],1.01);self.assertAlmostEqual(rates['observer_tx_pps'],.1);self.assertAlmostEqual(rates['new_udp_combinations_pps'],.2)
        rates=c.actual_rates(120);self.assertEqual(rates['peer_probe_tx_pps'],0);self.assertEqual(rates['observer_tx_pps'],0);self.assertEqual(rates['new_udp_combinations_pps'],0)
    def test_original_eight_new_targets_possible_within_one_second(self):
        cfg={'restore_v105_budget':True,'protected_search':True,'bifrost_coexist':True};c=LabClient(cfg,secrets.token_hex(16),'original');c.negotiate_protection({'profile':{'protected_search':offer(cfg)}})
        for i in range(8):self.assertTrue(c.budget.admit(('target',i),100+i*.05))
        self.assertFalse(c.budget.admit(('target',8),100.8));self.assertTrue(c.budget.admit(('target',8),101.1))

if __name__=='__main__':unittest.main()
