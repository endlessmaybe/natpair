from test_tail import native_responses
import json,secrets,threading,time,unittest
from types import SimpleNamespace
from unittest.mock import patch
from accelerator import FastSearch
from client import LabClient,Budget
from discovery import PairClock
from firewall import PeerFirewall
from measure import Measurements
from test_lab import Service

class FastTests(unittest.TestCase):
    def peer(self,port=27155):return {'udp':[['112.49.193.186',port]],'profile':{'source_zero_observer_endpoint':['112.49.193.186',port]}}
    def test_logged_winning_port_is_covered_from_source_zero_under_two_seconds(self):
        lane=FastSearch();found=None
        for i in range(240):
            slot,target,kind=lane.choice(self.peer(),8,'scan')
            if (slot,target)==(0,('112.49.193.186',27196)):found=i/120;break
            lane.sent(kind)
        self.assertIsNotNone(found);self.assertLess(found,2)
    def test_center_scan_covers_every_port_once_and_then_next_source(self):
        lane=FastSearch();ports=[]
        for i in range(65535):
            # Force scanner tick without advancing anchor or denial state.
            lane.tick=0;slot,target,kind=lane.choice(self.peer(1),8,'scan');ports.append(target[1]);lane.sent(kind)
            self.assertEqual(slot,0)
        self.assertEqual(set(ports),set(range(1,65536)));self.assertEqual(lane.choice(self.peer(1),8,'scan')[0],1)
    def test_denied_choice_does_not_advance_and_refresh_keeps_progress(self):
        lane=FastSearch();one=lane.choice(self.peer(),8,'scan');self.assertEqual(lane.choice(self.peer(),8,'scan'),one)
        lane.sent(one[2]);self.assertEqual(lane.scan_position,1)
        self.assertEqual(lane.choice(self.peer(27156),8,'scan')[1],('112.49.193.186',27156))
        self.assertEqual(lane.scan_position,1)
    def test_anchor_covers_all_local_sources_and_selected_peer_only(self):
        lane=FastSearch();sources=set();targets=set()
        for i in range(64):
            lane.tick=0;slot,target,kind=lane.choice(self.peer(),8,'anchor');sources.add(slot);targets.add(target);lane.sent(kind)
        self.assertEqual(sources,set(range(8)));self.assertTrue(all(ip=='112.49.193.186' for ip,port in targets))
        self.assertIsNone(lane.choice({'udp':[['127.0.0.1',1234]]},8,'scan'))
    def test_aggressive_budget_enforces_rate_and_target_limits(self):
        budget=Budget(120,1024)
        for i in range(1024):self.assertTrue(budget.admit(i,100+i*.009))
        now=100+1024*.009;self.assertFalse(budget.admit('new',now));self.assertEqual(budget.reason('new',now),'new_socket_target_limit')
        self.assertTrue(budget.admit('authenticated_peer',now,authenticated=True))
        self.assertLessEqual(len(budget.targets),1024)
        self.assertFalse(budget.admit('new',now+.001));self.assertTrue(budget.admit('new',116))
        self.assertEqual(Budget(9999,9999).max_new,2048);self.assertAlmostEqual(Budget(9999).interval,1/240)

class WaitAndTCPTests(unittest.TestCase):
    def test_current_summary_cannot_use_historical_forwarding_counts(self):
        c=LabClient({},secrets.token_hex(16),'summary');c.tail=SimpleNamespace(stats={'tail_tx_wg_datagrams':100,'tail_rx_wg_datagrams':100,'tail_tx_datagrams':100},snapshot=lambda:{})
        self.assertTrue(c.summary()['result']['business_forwarding_ever']);self.assertFalse(c.summary()['result']['business_forwarding'])
        c.direct_path=(SimpleNamespace(fileno=lambda:5),('1.1.1.1',1234));c.last_direct_ack=time.monotonic();c.native_proxy_verified=True
        self.assertTrue(c.summary()['result']['business_forwarding'])
        c.direct_path[0].fileno=lambda:-1
        self.assertFalse(c.summary()['result']['business_forwarding'])
    def native_fixture(self,address):
        from test_v103 import HealthTests
        c=HealthTests().client();c.direct_path=None
        return c,HealthTests().status(address)
    def test_native_direct_is_usable_before_natpair_hole(self):
        from health import native_label
        c,status=self.native_fixture('36.249.212.18:41641')
        with patch('client.command',side_effect=native_responses(c,['pong',status,'pong via TSMP',status])),patch('client.read_metadata',return_value={}):c.native_check()
        self.assertTrue(c.native_verified);self.assertFalse(c.native_proxy_verified)
        self.assertEqual(c.native_health['route'],'native_reported_direct');self.assertIsNotNone(c.first_native_at)
        self.assertEqual(native_label({'udp_direct_live':False,'tail_native_verified':True,'tail_health':c.native_health}),'已可用，Tailscale 报告直连')
    def test_working_derp_is_available_but_not_reported_as_direct(self):
        from health import native_label
        c,status=self.native_fixture('')
        with patch('client.command',side_effect=native_responses(c,['pong via DERP',status,'pong via TSMP',status])),patch('client.read_metadata',return_value={}):c.native_check()
        self.assertTrue(c.native_verified);self.assertIsNone(c.first_native_at);self.assertIsNotNone(c.first_tail_usable_at)
        self.assertEqual(c.native_health['route'],'derp');self.assertIn('中继',native_label({'tail_native_verified':True,'tail_health':c.native_health}))
    def test_ipv6_native_direct_does_not_require_our_ipv4_proxy(self):
        c,status=self.native_fixture('[2409:8a34::1234]:41641')
        with patch('client.command',side_effect=native_responses(c,['pong',status,'pong via TSMP',status])),patch('client.read_metadata',return_value={}):c.native_check()
        self.assertTrue(c.native_verified);self.assertEqual(c.native_health['route'],'native_reported_direct')
    def test_no_direct_path_checker_still_runs_and_avoids_parallel_checks(self):
        c=LabClient({},secrets.token_hex(16),'native');c.tail=SimpleNamespace();c.native_check=lambda:None
        worker=SimpleNamespace(start=lambda:None,is_alive=lambda:True)
        with patch('client.threading.Thread',return_value=worker) as thread:
            c.service_native_check(100);c.service_native_check(200)
        thread.assert_called_once();self.assertIsNone(c.direct_path)
    def test_plain_discovery_pong_alone_never_claims_data_or_direct(self):
        from health import native_label
        c,status=self.native_fixture('36.249.212.18:41641')
        with patch('client.command',side_effect=native_responses(c,['pong',status,RuntimeError('TSMP timeout'),status])),patch('client.read_metadata',return_value={}):c.native_check()
        self.assertFalse(c.native_verified);self.assertFalse(c.native_proxy_verified);self.assertIsNone(c.first_native_at)
        self.assertNotIn('已可用',native_label({'tail_native_verified':False,'tail_health':c.native_health}))
    def test_http_data_success_after_endpoint_change_preserves_availability(self):
        from test_v103 import HealthTests
        c,status=self.native_fixture('36.249.212.18:41641');c.cfg={'tail_tcp_check':True}
        final=HealthTests().status('36.249.212.18:12345')
        with patch('client.command',side_effect=native_responses(c,['pong',status,RuntimeError('TSMP timeout'),status,'pong via peerapi',final])),patch('client.read_metadata',return_value={}):c.native_check()
        self.assertTrue(c.native_verified);self.assertTrue(c.native_health['tcp_business_verified']);self.assertFalse(c.native_proxy_verified)
        self.assertEqual(c.native_health['route'],'path_changed');self.assertIsNone(c.first_native_at)
    def test_actual_native_traffic_keeps_usable_when_diagnostic_pings_are_blocked(self):
        c,status=self.native_fixture('36.249.212.18:41641');c.cfg={'tail_tcp_check':True}
        final=json.loads(status);final['Peer']['p'].update(TxBytes=10000,RxBytes=11000)
        with patch('client.command',side_effect=native_responses(c,['pong',status,RuntimeError('TSMP blocked'),status,RuntimeError('HTTP blocked'),json.dumps(final)])),patch('client.read_metadata',return_value={}):c.native_check()
        self.assertTrue(c.native_verified);self.assertFalse(c.native_proxy_verified)
        self.assertEqual(c.native_health['data_evidence'],'recent_bidirectional_native_traffic');self.assertEqual(c.native_health['native_data_delta'],[9600,10500])
    def test_only_outbound_counter_growth_cannot_prove_native_availability(self):
        c,status=self.native_fixture('36.249.212.18:41641');final=json.loads(status);final['Peer']['p']['TxBytes']=10000
        with patch('client.command',side_effect=native_responses(c,['pong',status,RuntimeError('no reply'),json.dumps(final)])),patch('client.read_metadata',return_value={}):c.native_check()
        self.assertFalse(c.native_verified);self.assertIsNone(c.first_native_at)
    def test_historical_proxy_counts_cannot_prove_current_tsmp_path(self):
        from test_v103 import HealthTests
        c=HealthTests().client();status=HealthTests().status()
        with patch('client.command',side_effect=native_responses(c,['pong',status,'pong',status],advance=False)),patch('client.read_metadata',return_value={}):c.native_check()
        self.assertTrue(c.native_verified);self.assertFalse(c.native_proxy_verified);self.assertEqual(c.native_health['route'],'proxy_unconfirmed')
        self.assertEqual(c.native_health['proxy_data_delta'],[0,0])
    def test_native_http_can_verify_data_when_tsmp_times_out(self):
        from test_v103 import HealthTests
        c=HealthTests().client();c.cfg={'tail_tcp_check':True};status=HealthTests().status()
        with patch('client.command',side_effect=native_responses(c,['pong',status,RuntimeError('no reply'),status,'pong via peerapi',status])),patch('client.read_metadata',return_value={}):c.native_check()
        self.assertTrue(c.native_verified);self.assertTrue(c.native_health['tcp_business_verified'])
        self.assertEqual(c.native_health['proxy_data_delta'],[1,1])
    def test_native_tcp_check_is_separate_from_public_tcp_experiment(self):
        from test_v103 import HealthTests
        from health import native_label
        c=HealthTests().client();c.cfg={'tail_tcp_check':True}
        status=HealthTests().status()
        with patch('client.command',side_effect=native_responses(c,['pong',status,'pong',status,'pong via peerapi',status])),patch('client.read_metadata',return_value={}):c.native_check()
        self.assertTrue(c.native_verified);self.assertTrue(c.native_health['tcp_business_verified'])
        self.assertIn('TCP 检查通过',native_label({'udp_direct_live':True,'tail_native_verified':True,'tail_health':c.native_health}))
        with patch('client.command',side_effect=native_responses(c,['pong',status,'pong',status,RuntimeError('HTTP timeout'),status])),patch('client.read_metadata',return_value={}):c.native_check()
        self.assertTrue(c.native_verified);self.assertFalse(c.native_health['tcp_business_verified'])
    def test_initial_server_wait_survives_30_seconds_and_can_be_cancelled(self):
        c=LabClient({'wait_unlimited':True},secrets.token_hex(16),'wait');times=iter([100,131,141])
        waits=iter([False,False,True])
        c.joined=SimpleNamespace(wait=lambda _:next(waits))
        with patch('client.time.monotonic',side_effect=lambda:next(times)):
            self.assertTrue(c.wait_for_coordination())
        self.assertFalse(c.stop.is_set());self.assertTrue(any(e['event']=='waiting_for_server' for e in c.logs))
        c.stop.set();self.assertFalse(c.wait_for_coordination())
    def test_single_member_clock_never_expires_until_effective_time_runs(self):
        clock=PairClock(180,float('inf'),float('inf'))
        for now in (0,31,301,3601):self.assertFalse(clock.step(now,False)[2])
        self.assertEqual(clock.elapsed,0);self.assertIsNone(clock.started)
        self.assertTrue(clock.step(4000,True)[0]);self.assertFalse(clock.step(4100,True)[2]);self.assertTrue(clock.step(4180,True)[2])
    def test_tcp_neighbor_guesses_are_bounded_and_not_udp_ports(self):
        c=LabClient({'tcp_neighbor_candidates':True},secrets.token_hex(16),'tcp');c.own_tcp_active=[['1.1.1.1',34000]]
        choices=[c.tcp_candidate(i) for i in range(12)]
        self.assertEqual(choices[0],['1.1.1.1',34000]);self.assertIn(['1.1.1.1',33992],choices)
        self.assertTrue(all(ip=='1.1.1.1' and 1<=p<=65535 for ip,p in choices))
        c.own_tcp_active=[['1.1.1.1',1]];self.assertEqual(c.tcp_candidate(2),['1.1.1.1',1])
    def test_scoped_tcp_allow_refreshes_only_its_two_ports_and_cleans_up(self):
        scripts=[];g=PeerFirewall('44'*16,'192.168.31.195',[41000,41001],lambda *a,**kw:None,scripts.append,program='H:/Apps/NATPairTail.exe',protocol='TCP')
        g.update(['36.249.212.18']);g.thread.join(2)
        self.assertIn('-Protocol TCP',scripts[0]);self.assertIn('-LocalPort 41000,41001',scripts[0]);self.assertIn("-RemoteAddress '36.249.212.18'",scripts[0])
        g.update_ports([41000,41002]);g.update(['36.249.212.18']);g.thread.join(2)
        self.assertIn('-LocalPort 41000,41002',scripts[1]);g.close();self.assertIn('Remove-NetFirewallRule',scripts[-1]);self.assertNotIn('*',scripts[-1])
    def test_tcp_refresh_uses_new_source_and_publishes_consistent_candidate(self):
        c=LabClient({'tcp_rotate_source':True,'tcp_mapping_retry':True,'bind':'127.0.0.1'},secrets.token_hex(16),'tcp')
        c.bind='127.0.0.1';c.index=0;c.active_port=1;c.profile={};c.publish_profile=lambda:None;c.direct_path=True
        m=SimpleNamespace(base=20000,tcp_observe=lambda port,local:{'endpoint':['1.1.1.1',30000+local%1000],'local_port':local,'stage':'complete'})
        listener=SimpleNamespace(getsockname=lambda:('127.0.0.1',20001))
        c.prepare_tcp(m,listener,True)
        self.assertNotEqual(c.active_port,1);self.assertTrue(c.profile['tcp_offer_ready']);self.assertEqual(c.tcp_candidates_at>0,True)

    def test_real_send_loop_uses_fast_center_and_preserves_legacy_lanes(self):
        service=Service();cfg={**service.cfg,'fast_start':True,'nearby_priority':True,'candidate_pool_priority':True,'phased_search':True,'coordinated_scan':True,
            'coordination_window_seconds':.4,'duration':20,'lab_sockets':8,'fast_center_search':True,'probe_rate':120,'probe_new_targets':1024}
        clients=[LabClient(cfg,secrets.token_hex(16),'a')]
        clients.append(LabClient(cfg,'ABCD'*8,'b'));clients[1].room=clients[0].room;clients[1].key=clients[0].key
        threads=[threading.Thread(target=c.run) for c in clients]
        try:
            with patch.object(LabClient,'receive_udp',return_value=None):
                for t in threads:t.start()
                deadline=time.monotonic()+10
                while time.monotonic()<deadline:
                    lanes={k for c in clients for k,v in c.lane_sent.items() if v}
                    if {'center_scan','fast_anchor'}<=lanes and lanes&{'full_scan','observed_range'}:break
                    time.sleep(.02)
                self.assertTrue({'center_scan','fast_anchor'}<=lanes,lanes);self.assertTrue(lanes&{'full_scan','observed_range'},lanes)
                self.assertTrue(all(not c.udp_direct for c in clients))
        finally:
            for c in clients:c.stop.set()
            for t in threads:
                if t.ident:t.join(10);self.assertFalse(t.is_alive())
            service.stop()
    def test_production_wait_survives_peer_diagnostic_completion(self):
        service=Service();code=secrets.token_hex(16);cfg={**service.cfg,'fast_start':True,'wait_unlimited':True}
        a=LabClient({**cfg,'production_mode':True},code,'production');b=LabClient(cfg,code,'diagnostic')
        threads=[threading.Thread(target=c.run) for c in (a,b)]
        try:
            for t in threads:t.start()
            threads[1].join(16);self.assertFalse(threads[1].is_alive());self.assertTrue(b.paired_started)
            deadline=time.monotonic()+2
            while not a.peer_completed and time.monotonic()<deadline:time.sleep(.02)
            self.assertTrue(a.peer_completed);self.assertTrue(threads[0].is_alive());self.assertFalse(a.stop.is_set())
        finally:
            for c in (a,b):c.stop.set()
            for t in threads:
                if t.ident:t.join(10)
            service.stop()

if __name__=='__main__':unittest.main()
