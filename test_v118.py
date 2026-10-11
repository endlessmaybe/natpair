import asyncio,copy,json,secrets,socket,threading,time,unittest
from unittest.mock import patch,MagicMock
from client import LabClient
from combinations import CombinationLimit
from strategy import Coordination
from modes import MODE_TAIL,MODE_UDP,MODE_UDP_SYNC,configure_mode
from test_v114 import udp_service,until
from test_v115 import Reflector

def profile(ips):
    return {'multi_exit_protocol':1,'strategy_protocol':1,'coordination_protocol':2,
            'probe_public_ips':ips,'transport_session':'c'*32,'punch_epoch':'d'*32}

def peer(ips):
    p=profile(ips);p['exit_observations']={'observations':[
        {'endpoint':[ip,58238+i*51],'age_seconds':1} for i,ip in enumerate(ips)]}
    return {'id':'b'*32,'udp':[[ips[0],64915]],'profile':p,'prepared':True,'version':'0.9.4-lab'}

class Combinations118Tests(unittest.TestCase):
    def test_1000_rolling_limit_repeats_are_free_and_source_ip_count_separately(self):
        b=CombinationLimit(1000)
        for p in range(1,1001):self.assertTrue(b.allows(1234,('1.1.1.1',p),100));b.sent(1234,('1.1.1.1',p),100)
        self.assertFalse(b.allows(1234,('1.1.1.1',1001),100.999))
        self.assertTrue(b.allows(1234,('1.1.1.1',1),100.999))
        self.assertFalse(b.allows(1235,('1.1.1.1',1),100.999));self.assertFalse(b.allows(1234,('8.8.8.8',1),100.999))
        self.assertTrue(b.allows(1234,('1.1.1.1',1001),101));self.assertEqual(b.total,1000)
    def test_limit_uses_successful_sends_not_candidate_selection(self):
        c=LabClient({'new_combinations_per_second':1,'public_only':False},'AA'*16,'a')
        s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.bind(('127.0.0.1',0));c.udp=[s];p=peer(['127.0.0.1'])
        try:
            with patch.object(c,'send_udp',return_value=False):self.assertFalse(c.trace_probe(s,('127.0.0.1',1),p,100,'test'))
            self.assertEqual(c.combination_limit.total,0)
            with patch.object(c,'send_udp',return_value=True) as send:
                self.assertTrue(c.trace_probe(s,('127.0.0.1',1),p,100,'test'))
                self.assertFalse(c.trace_probe(s,('127.0.0.1',2),p,100.5,'test'))
                self.assertTrue(c.trace_probe(s,('127.0.0.1',1),p,100.5,'test'));self.assertEqual(send.call_count,2)
            self.assertEqual(c.combination_limit.total,1)
        finally:s.close()
    def test_unlimited_default_has_no_packet_or_combination_cap(self):
        b=CombinationLimit()
        for p in range(1,65536):self.assertTrue(b.allows(1234,('1.1.1.1',p),100));b.sent(1234,('1.1.1.1',p),100)
        self.assertTrue(b.allows(1235,('1.1.1.1',1),100));self.assertEqual(b.total,65535)

class LeaseAndMode118Tests(unittest.TestCase):
    def leased(self):
        c=LabClient({'unlimited_search':True,'verified_peer_lease_seconds':90,'preflight_exchange':True},'AA'*16,'a')
        p=peer(['1.1.1.1']);c.cached_search_peer=p;c.cached_search_at=100;c.last_snapshot=100
        c.exchange_verified=True;c.exchange_peer_session=(p['id'],p['profile']['transport_session']);c.coord.role='scan'
        return c,p
    def test_verified_session_continues_through_short_control_gap(self):
        c,p=self.leased();self.assertEqual(c.search_peer(p,120),(p,False));self.assertTrue(c.peer_lease_active)
        self.assertEqual(c.search_peer(p,191),(p,True));self.assertFalse(c.peer_lease_active)
    def test_unverified_session_cannot_get_active_lease(self):
        c,p=self.leased();c.exchange_verified=False;self.assertEqual(c.search_peer(p,120),(p,True));self.assertFalse(c.peer_lease_active)
    def test_empty_room_and_restarted_peer_never_use_old_lease(self):
        c,p=self.leased();c.connected.set();c.last_snapshot=118
        self.assertEqual(c.search_peer(None,120),(None,False));self.assertFalse(c.peer_lease_active)
        replacement=copy.deepcopy(p);replacement['profile']['transport_session']='e'*32;c.last_snapshot=100
        self.assertEqual(c.search_peer(replacement,120),(replacement,False));self.assertFalse(c.peer_lease_active)
    def test_udp_firewall_independent_of_tailscale_and_truthful_without_admin(self):
        cfg=configure_mode({},MODE_UDP);c=LabClient(cfg,'AA'*16,'a');c.bind='192.168.1.2'
        c.udp=[MagicMock()];c.udp[0].getsockname.return_value=(c.bind,1234)
        with patch('client.is_admin',return_value=True),patch('client.PeerFirewall') as fw:
            c.configure_probe_firewall();fw.assert_called_once();self.assertIs(c.firewall,fw.return_value);self.assertIsNone(c.tail)
        c.firewall=None
        with patch('client.is_admin',return_value=False),patch('client.PeerFirewall') as fw:
            c.configure_probe_firewall();fw.assert_not_called();self.assertEqual(c.probe_firewall_state['status'],'administrator_required')
    def test_sync_only_retains_metadata_without_enabling_proxy_or_raw_tcp(self):
        cfg=configure_mode({'peer_tail_ip':'100.1.1.2','run_continuously':True},MODE_UDP_SYNC)
        self.assertTrue(cfg['tail_metadata_only']);self.assertTrue(cfg['peer_sync_overlay']);self.assertTrue(cfg['udp_only']);self.assertTrue(cfg['production_mode'])
        self.assertFalse(cfg['tailscale_bridge']);self.assertFalse(cfg['tail_tcp_check']);self.assertFalse(cfg['raw_tcp_experiment'])
        self.assertEqual(cfg['peer_tail_ip'],'100.1.1.2')
        pure=configure_mode(cfg,MODE_UDP);self.assertFalse(pure['tail_metadata_only']);self.assertFalse(pure['peer_sync_overlay'])
    def test_real_udp_sync_mode_authenticates_without_native_driver_or_proxy(self):
        service,protocol=udp_service();cs=[];ts=[]
        try:
            configs=[configure_mode({**service.cfg,'peer_tail_ip':'100.1.1.'+str(2-i),
                'live_egress_discovery':False,'preflight_exchange':True,
                'new_combinations_per_second':1000},MODE_UDP_SYNC) for i in range(2)]
            code=secrets.token_hex(16);cs=[LabClient(cfg,code,str(i)) for i,cfg in enumerate(configs)]
            with patch('client.read_metadata',return_value={'tail_ips':[],'peer_endpoints':[]}),patch('client.driver_check',side_effect=AssertionError('must not load driver')),patch('client.TailBridge',side_effect=AssertionError('must not proxy')),patch('client.is_admin',return_value=False):
                ts=[threading.Thread(target=c.run) for c in cs]
                for t in ts:t.start()
                self.assertTrue(until(lambda:all(c.direct_path for c in cs)),[c.logs[-2:] for c in cs])
                self.assertTrue(all(c.exchange_verified for c in cs));self.assertTrue(all(c.tail is None for c in cs))
                self.assertTrue(all(c.control_failures==0 for c in cs));self.assertFalse(any(e['event']=='error' for c in cs for e in c.logs))
                for c in cs:c.stop.set()
                for t in ts:t.join(8);self.assertFalse(t.is_alive())
        finally:
            for c in cs:c.stop.set()
            for t in ts:t.join(8)
            service.stop()

if __name__=='__main__':unittest.main()
