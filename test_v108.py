import json,pathlib,secrets,threading,time,unittest
from unittest.mock import patch
from client import LabClient,Budget
from measure import Measurements
from protection import offer
from accelerator import FastSearch
from test_lab import Service

ROOT=pathlib.Path(__file__).parent
class UnlimitedTests(unittest.TestCase):
    def test_unlimited_nearby_matrix_expands_after_all_sources(self):
        f=FastSearch();f.unlimited=True;peer={'udp':[['1.1.1.1',30000]],'profile':{}}
        pairs=[]
        for i in range(4000):
            choice=f.protected_choice(peer,8,'scan',100,True)
            if choice[2]=='fresh_center_scan':pairs.append(choice[:2])
            f.sent(choice[2])
        self.assertEqual(len(pairs),len(set(pairs)))
        self.assertEqual({slot for slot,_ in pairs[:257*8]},set(range(8)))
        self.assertTrue(any(abs(target[1]-30000)>128 for _,target in pairs))
    def test_every_port_and_every_local_source_admitted_at_same_time(self):
        b=Budget(rate=20,max_new=16,protected=True,unlimited=True);b.pause=True
        for slot in range(8):
            for port in range(1,65536):self.assertTrue(b.admit((slot,('1.1.1.1',port)),100))
        self.assertEqual(b.sent,8*65535);self.assertEqual(b.denied,0)
        self.assertIsNone(b.reason(('new',65536),100));self.assertIsNone(b.pressure)
        self.assertEqual(b.targets,{});self.assertIsNone(b.rate_limit)

    def test_remote_or_local_bifrost_feedback_cannot_add_limits(self):
        c=LabClient({'unlimited_search':True,'protected_search':True,'bifrost_coexist':True},secrets.token_hex(16),'u')
        c.coexist.until=1000;c.coexist.recovery_until=2000;c.last_snapshot=100
        peer={'profile':{'protected_search':offer({'probe_rate':20}),'coexist_pause':True}}
        c.negotiate_protection(peer);c.update_coexistence(peer,101)
        self.assertFalse(c.coexist.enabled);self.assertFalse(c.budget.pause);self.assertFalse(c.remote_pause)
        self.assertIsNone(c.protection_policy);self.assertEqual(c.budget.interval,0)
        self.assertTrue(c.summary()['result']['unlimited_search'])

    def test_send_buffer_full_is_not_counted_as_success(self):
        c=LabClient({'unlimited_search':True},secrets.token_hex(16),'u')
        class Sock:
            def getsockname(self):return ('127.0.0.1',40000)
            def sendto(self,*args):raise BlockingIOError(10055,'test send buffer full')
        s=Sock();self.assertFalse(c.trace_probe(s,('127.0.0.1',1234),{'id':'11'*16},100,'full_scan'))
        self.assertEqual(c.stats['udp_probe_tx'],0);self.assertEqual(c.stats['udp_send_backpressure'],1)
        self.assertEqual(c.pending,{})

    def test_continuous_scheduler_advances_without_a_live_peer_packet(self):
        # Intercept peer probes before sendto. Observer/control traffic stays
        # on an isolated loopback fixture; no public port scan or stress test.
        service=Service();code=secrets.token_hex(16)
        cfg={**service.cfg,'unlimited_search':True,'fast_center_search':True,'phased_search':True,
             'nearby_priority':True,'candidate_pool_priority':True,'immediate_challenge':True,
             'raw_tcp_experiment':False,'tcp_udp_assist':False,'duration':3,'lab_sockets':8}
        clients=[LabClient(cfg,code,n) for n in ('a','b')];threads=[threading.Thread(target=c.run) for c in clients]
        visited={c.id:set() for c in clients}
        def trace(c,s,target,peer,now,lane,**fields):
            visited[c.id].add((s.fileno(),target));c.stats['udp_probe_tx']+=1
            c.trace_packet(s,b'fake','tx',target,kind='probe',lane=lane);return True
        profile={'port_pattern':{'validated':False},'same_ip_filtering':'undetermined','cross_ip_filtering':'undetermined','scope':'simulated_no_peer_reply'}
        try:
            with patch.object(Measurements,'run',return_value=profile),patch.object(LabClient,'trace_probe',trace):
                for t in threads:t.start()
                for t in threads:t.join(15);self.assertFalse(t.is_alive())
            rows=[]
            for c in clients:
                self.assertFalse([e for e in c.logs if e['event']=='error'],c.summary())
                self.assertGreater(c.stats['udp_probe_tx'],1000)
                self.assertEqual(c.budget.denied,0);self.assertEqual(dict(c.search_stalls),{})
                self.assertEqual(c.stats['tcp_attempts'],0);self.assertFalse(c.udp_direct)
                self.assertEqual(c.room_members(),None) # stopped, no stale count
                rows.append({'probes':c.stats['udp_probe_tx'],'unique_combinations':len(visited[c.id]),
                             'active_seconds':c.active_elapsed,'lanes':dict(c.lane_sent),
                             'rates':c.actual_rates()})
            self.assertGreater(max(r['unique_combinations'] for r in rows),1000)
            (ROOT/'scheduler-benchmark.json').write_text(json.dumps({'passed':True,'scope':'simulated sends; loopback control/observer only, not physical-network throughput','clients':rows},indent=2),encoding='utf-8')
        finally:
            for c in clients:c.stop.set()
            for t in threads:
                if t.ident:t.join(5)
            service.stop()

if __name__=='__main__':unittest.main()
