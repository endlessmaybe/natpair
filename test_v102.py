from test_tail import native_responses
import collections,json,queue,secrets,socket,struct,time,unittest
from unittest.mock import patch
from types import SimpleNamespace
from accelerator import CandidatePriority
from firewall import LocalProxyFirewall
from tailbridge import TailBridge
from journal import NullJournal
from test_tail import FakeCapture

class NewTests(unittest.TestCase):
    def test_exact_candidates_prioritizes_correlated_slots_and_covers_matrix(self):
        peer={'udp':[['1.1.1.1',1000+i] for i in range(8)]}
        lane=CandidatePriority();choices=[]
        for i in range(64):
            item=lane.choice(peer,8,100+i*.51)
            self.assertIsNotNone(item)
            choices.append(item);lane.sent()
        self.assertEqual(choices[:2],[(0,('1.1.1.1',1000),'priority_candidates'),(0,('1.1.1.1',1001),'priority_candidates')])
        self.assertEqual(len(set((s,t) for s,t,_ in choices)),64)
        self.assertEqual({s for s,t,_ in choices},set(range(8)))
        self.assertTrue(all(t in [tuple(p) for p in peer['udp']] for s,t,_ in choices))

    def test_exact_candidates_rate_and_cursor_only_advance_on_send(self):
        lane=CandidatePriority();peer={'udp':[['1.1.1.1',1000]]}
        first=lane.choice(peer,2,100)
        self.assertIsNone(lane.choice(peer,2,100.2))
        self.assertEqual(lane.choice(peer,2,100.6),first)
        lane.sent();self.assertNotEqual(lane.choice(peer,2,101.2),first)
        peer['udp']=[['1.1.1.1',2000]]
        self.assertEqual(lane.choice(peer,2,101.8)[1],('1.1.1.1',2000))

    def test_exact_candidates_never_use_nonpublic_or_invalid_endpoints(self):
        lane=CandidatePriority()
        self.assertIsNone(lane.choice({'udp':[['127.0.0.1',1000],['1.1.1.1',0]]},8,100))

    def test_logged_minus_two_candidate_is_prioritized_from_source_three(self):
        lane=CandidatePriority();peer={'udp':[['112.49.193.186',27234],['112.49.193.186',27283]]}
        targets=[*peer['udp'],['112.49.193.186',27281],['9.9.9.9',8888]]
        self.assertEqual(lane.choice(peer,8,100,True,targets),(3,('112.49.193.186',27281),'priority_candidates'))
        lane.sent()
        second=lane.choice(peer,8,101,True,targets)
        self.assertEqual(second,(0,('112.49.193.186',27234),'priority_candidates'))
        self.assertNotIn((3,('9.9.9.9',8888)),lane.choices)

    def test_lan_proxy_readiness_uses_actual_bound_address(self):
        from client import LabClient
        c=object.__new__(LabClient);c.stop=SimpleNamespace(is_set=lambda:False);c.profile={};c.native_verified=False;c.first_native_at=None
        c.tail=SimpleNamespace(metadata={'peer_tail_ip':'100.1.1.2','expected_peer_key':'nodekey:peer'},
            socket=SimpleNamespace(getsockname=lambda:('192.168.31.195',50000)),
            stats={'tail_tx_wg_datagrams':1,'tail_rx_wg_datagrams':1},refresh=lambda _:False)
        rows=[];c.log=lambda e,**kw:rows.append((e,kw))
        status=json.dumps({'Peer':{'peer':{'PublicKey':'nodekey:peer','CurAddr':'192.168.31.195:50000'}}})
        with patch('client.command',side_effect=native_responses(c,['pong',status,'pong',status])),patch('client.read_metadata',return_value={}):c.native_check()
        self.assertTrue(c.native_verified)
        self.assertEqual(rows[0][1]['expected_proxy'],'192.168.31.195:50000')

    def test_missing_local_native_response_is_explicit(self):
        from client import LabClient
        c=object.__new__(LabClient);c.stop=SimpleNamespace(is_set=lambda:False);c.profile={};c.native_verified=False;c.first_native_at=None
        c.tail=SimpleNamespace(metadata={'peer_tail_ip':'100.1.1.2','expected_peer_key':'nodekey:peer'},socket=SimpleNamespace(getsockname=lambda:('192.168.31.195',50000)),
            stats={'tail_tx_wg_datagrams':0,'tail_rx_wg_datagrams':0,'tail_rx_disco_datagrams':3,'tail_local_return_datagrams':0},refresh=lambda _:False)
        rows=[];c.log=lambda e,**kw:rows.append((e,kw))
        status=json.dumps({'Peer':{'peer':{'PublicKey':'nodekey:peer','CurAddr':''}}})
        with patch('client.command',side_effect=native_responses(c,['pong DERP',status])),patch('client.read_metadata',return_value={}):c.native_check()
        self.assertFalse(c.native_verified)
        self.assertEqual(rows[0][1]['diagnosis'],'no_local_native_reply')

    def test_local_allow_rules_are_exact_and_refresh_both_ports(self):
        scripts=[];events=[]
        guard=LocalProxyFirewall('33'*16,'192.168.31.195',50000,lambda e,**kw:events.append(e),lambda s:scripts.append(s),program='H:/Apps/NATPairTail.exe')
        guard.update(41641);guard.thread.join(2)
        self.assertEqual(len(scripts),1)
        self.assertIn("-RemoteAddress '192.168.31.195'",scripts[0])
        self.assertIn('-LocalPort 50000 -RemotePort 41641',scripts[0])
        self.assertIn('-LocalPort 41641 -RemotePort 50000',scripts[0])
        self.assertIn('-Program $native[0]',scripts[0])
        self.assertNotIn('-RemoteAddress Any',scripts[0])
        guard.update(41642);guard.thread.join(2)
        self.assertIn('-LocalPort 50000 -RemotePort 41642',scripts[1])
        guard.close();self.assertIn('Remove-NetFirewallRule',scripts[-1]);self.assertNotIn('*',scripts[-1])
        self.assertEqual(events[-1],'tail_local_firewall_cleanup')

    def test_local_partial_failure_still_cleans_exact_names(self):
        scripts=[]
        def runner(script):
            scripts.append(script)
            if len(scripts)==1:raise TimeoutError('synthetic partial create')
        guard=LocalProxyFirewall('44'*16,'192.168.31.195',50000,lambda *a,**kw:None,runner)
        guard.update(41641);guard.thread.join(2);guard.close()
        self.assertEqual(len(scripts),2)
        self.assertNotIn('*',scripts[-1]);self.assertIn('NATPairTail-LocalNative-'+'44'*16,scripts[-1])

    def test_local_proxy_rejects_wrong_port_and_counts_real_return(self):
        native=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);native.bind(('127.0.0.1',0));self.addCleanup(native.close)
        other=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);other.bind(('127.0.0.1',0));self.addCleanup(other.close)
        meta={'udp_port':native.getsockname()[1]}
        bridge=TailBridge(meta,lambda *a,**kw:None,NullJournal(),FakeCapture,bind_ip='127.0.0.1');self.addCleanup(bridge.close)
        payload=struct.pack('<I',4)+secrets.token_bytes(28)
        other.sendto(payload,bridge.socket.getsockname());native.sendto(payload,bridge.socket.getsockname())
        time.sleep(.01);bridge.poll()
        self.assertEqual(bridge.stats['tail_local_return_datagrams'],1)
        self.assertEqual(bridge.stats['tail_local_source_rejected'],1)
        self.assertEqual(bridge.outbound.get_nowait()[0],payload)

if __name__=='__main__':unittest.main()
