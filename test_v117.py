import json,queue,secrets,socket,threading,time,unittest
from unittest.mock import patch
from bridgecheck import Capture,Journal,ResourceError
from modes import MODE_TAIL,MODE_UDP,configure_mode
from tailbridge import TailBridge,DISCO,read_metadata
import test_tail
from test_tail import ip_packet
from test_v114 import udp_service,until
from client import LabClient

class Disco117Tests(unittest.TestCase):
    def bridge(self):
        n=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);n.bind(('127.0.0.1',0));n.settimeout(.3);self.addCleanup(n.close)
        m={'node_key':'nodekey:a','expected_peer_key':'nodekey:b','disco_key':'discokey:'+'11'*32,
            'expected_peer_disco_key':'discokey:'+'33'*32,'udp_port':n.getsockname()[1],
            'peer_tail_ip':'100.1.1.2','peer_endpoints':[['1.1.1.1',41641]]}
        j=Journal();events=[];b=TailBridge(m,lambda e,**kw:events.append((e,kw)),j,Capture)
        self.addCleanup(b.close);b.bind_peer({'node_key':'nodekey:b','expected_peer_key':'nodekey:a','disco_key':'discokey:'+'22'*32});b.start()
        return b,n,j,events
    def test_native_reply_current_key_passes_stale_remote_self_snapshot(self):
        b,n,j,e=self.bridge();p=DISCO+bytes.fromhex('33'*32)+secrets.token_bytes(40)
        self.assertTrue(b.deliver(p));self.assertEqual(n.recvfrom(65535)[0],p)
        self.assertTrue(j.rows[-1]['disco_local_snapshot_matches']);self.assertFalse(j.rows[-1]['disco_peer_snapshot_matches'])
        self.assertEqual(b.peer['disco_key'],'discokey:'+'22'*32);self.assertEqual(b.stats['tail_rx_wg_datagrams'],0)
    def test_unknown_public_header_is_advisory_never_adopted_or_marked_authenticated(self):
        b,n,j,e=self.bridge();p=DISCO+bytes.fromhex('44'*32)+secrets.token_bytes(40)
        before=dict(b.metadata)
        self.assertTrue(b.deliver(p));self.assertEqual(n.recvfrom(65535)[0],p)
        self.assertEqual(b.metadata,before);self.assertEqual(b.peer['disco_key'],'discokey:'+'22'*32)
        self.assertEqual(j.rows[-1]['disco_authentication'],'native_tailscale')
        self.assertFalse(j.rows[-1]['disco_local_snapshot_matches']);self.assertEqual(b.stats['tail_rx_wg_datagrams'],0)
    def test_capture_runtime_key_change_retains_source_and_target_scope(self):
        b,n,j,e=self.bridge();p=DISCO+bytes.fromhex('55'*32)+secrets.token_bytes(40)
        b.capture.q.put(ip_packet(p,source=('127.0.0.1',b.metadata['udp_port']+1)))
        b.capture.q.put(ip_packet(p,source=('127.0.0.1',b.metadata['udp_port']),target=('1.1.1.2',41641)))
        b.capture.q.put(ip_packet(p,source=('127.0.0.1',b.metadata['udp_port'])))
        self.assertEqual(b.next_outbound() if not b.outbound.empty() else b.outbound.get(timeout=1),(p,'bootstrap_copy'))
        self.assertEqual(b.stats['bootstrap_scope_rejected'],2)
        self.assertEqual(j.rows[-1]['disco_sender_key'],'discokey:'+'55'*32)
        self.assertEqual(b.metadata['disco_key'],'discokey:'+'11'*32)
    def test_metadata_records_local_peer_table_disco_without_substituting_node_identity(self):
        own={'Key':'nodekey:a','DiscoKey':'discokey:'+'11'*32}
        peer={'Key':'nodekey:b','DiscoKey':'discokey:'+'33'*32,'Addresses':['100.1.1.2/32']}
        with patch('tailbridge.command',side_effect=[json.dumps({'BackendState':'Running'}),json.dumps({'SelfNode':own,'Peers':[peer]})]):
            m=read_metadata('100.1.1.2',port=41641)
        self.assertEqual(m['expected_peer_disco_key'],peer['DiscoKey']);self.assertEqual(m['expected_peer_key'],'nodekey:b')
    def test_full_authenticated_clients_stale_keys_and_passive_driver(self):
        test_tail.TailTests.run_native_tunnel_case(self,passive_peer=True,stale_disco=True)
    def test_selected_node_mismatch_still_cannot_bind(self):
        b,n,j,e=self.bridge()
        with self.assertRaises(RuntimeError):b.bind_peer({'node_key':'nodekey:other','expected_peer_key':'nodekey:a'})
    def test_no_bound_identity_or_malformed_packet_still_rejected(self):
        b,n,j,e=self.bridge();p=DISCO+bytes.fromhex('44'*32)+secrets.token_bytes(40)
        b.peer=None;self.assertFalse(b.deliver(p));self.assertEqual(j.rows[-1]['reason'],'peer_identity_not_bound')
        self.assertFalse(b.deliver(b'garbage'));self.assertEqual(j.rows[-1]['reason'],'unsupported_native_packet')

class UDPMode117Tests(unittest.TestCase):
    def test_udp_mode_disables_all_tailscale_paths_with_dirty_inherited_config(self):
        cfg={'tailscale_bridge':True,'peer_sync_overlay':True,'control_tail_host':'100.1.1.1',
            'control_transports':['tail','system'],'peer_tail_ip':'100.1.1.2','peer_sync_host':'100.1.1.3','scoped_peer_firewall':True}
        r=configure_mode(cfg,MODE_UDP)
        for k in ('tailscale_bridge','peer_sync_overlay','tail_tcp_check','raw_tcp_experiment','tcp_udp_assist'):self.assertFalse(r[k],k)
        self.assertTrue(r['scoped_peer_firewall'])
        self.assertEqual(r['control_transports'],['system','physical']);self.assertEqual(r['control_tail_host'],'');self.assertEqual(r['peer_tail_ip'],'')
        self.assertTrue(cfg['tailscale_bridge'])
    def test_tail_mode_preserves_selected_node_and_overlay(self):
        cfg={'peer_tail_ip':'100.1.1.2','peer_sync_overlay':True,'control_tail_host':'100.1.1.1'}
        r=configure_mode(cfg,MODE_TAIL);self.assertTrue(r['tailscale_bridge']);self.assertTrue(r['tail_tcp_check']);self.assertEqual(r['peer_tail_ip'],cfg['peer_tail_ip'])
    def test_continuous_udp_mode_does_not_end_on_diagnostic_clock(self):
        self.assertTrue(configure_mode({'run_continuously':True},MODE_UDP)['production_mode'])
        self.assertFalse(configure_mode({'run_continuously':True},MODE_UDP,measure_only=True)['production_mode'])
    def test_real_room_and_udp_authentication_without_tailscale_commands_or_admin(self):
        service,protocol=udp_service();clients=[];threads=[]
        try:
            cfg=configure_mode({**service.cfg,'tailscale_bridge':True,'peer_sync_overlay':True,'control_tail_host':'100.1.1.1',
                'live_egress_discovery':False,'packet_journal_dir':None,'duration':30,'bind':'127.0.0.1'},MODE_UDP)
            code=secrets.token_hex(16);clients=[LabClient(cfg,code,str(i)) for i in range(2)]
            with patch('client.read_metadata',side_effect=AssertionError('UDP-only must not read Tailscale')),patch('client.command',side_effect=AssertionError('UDP-only must not run Tailscale CLI')),patch('client.is_admin',return_value=False),patch('client.driver_check',side_effect=AssertionError('UDP-only must not load driver')):
                threads=[threading.Thread(target=c.run) for c in clients]
                for t in threads:t.start()
                self.assertTrue(until(lambda:all(c.direct_path for c in clients)),[c.summary()['result']['finish_reason'] for c in clients])
                self.assertTrue(all(c.tail is None and c.peer_sync is None and c.firewall is None for c in clients))
                self.assertTrue(all(c.summary()['result']['seconds_to_first_udp'] is not None for c in clients))
                self.assertTrue(all(c.summary()['result']['control_failures']==0 for c in clients))
                for c in clients:c.stop.set()
                for t in threads:t.join(8);self.assertFalse(t.is_alive())
                self.assertFalse(any(e['event']=='error' for c in clients for e in c.logs))
        finally:
            for c in clients:c.stop.set()
            for t in threads:
                if t.ident:t.join(8)
            service.stop()

if __name__=='__main__':unittest.main()
