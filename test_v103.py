from test_tail import native_responses
import json,queue,secrets,socket,struct,threading,time,unittest
from types import SimpleNamespace
from unittest.mock import patch
from client import LabClient
from tailbridge import TailBridge,DISCO
from journal import NullJournal
from test_tail import FakeCapture,ip_packet
from health import native_label

class HealthTests(unittest.TestCase):
    def client(self):
        c=object.__new__(LabClient);c.stop=threading.Event();c.profile={};c.native_verified=False;c.first_native_at=None
        c.tail=SimpleNamespace(metadata={'peer_tail_ip':'100.1.1.2','expected_peer_key':'nodekey:peer'},
            socket=SimpleNamespace(getsockname=lambda:('192.168.31.195',58141)),
            stats={'tail_tx_wg_datagrams':414,'tail_rx_wg_datagrams':529},refresh=lambda m:False)
        c.rows=[];c.log=lambda event,**fields:c.rows.append((event,fields))
        return c
    def status(self,address='192.168.31.195:58141'):
        return json.dumps({'Peer':{'p':{'PublicKey':'nodekey:peer','CurAddr':address,'RxBytes':500,'TxBytes':400}}})
    def test_tsmp_timeout_keeps_discovery_and_endpoint_and_refreshes_metadata(self):
        c=self.client();c.first_native_at=1
        with patch('client.command',side_effect=native_responses(c,['pong in 19ms',self.status(),RuntimeError('no reply'),self.status()])),patch('client.read_metadata',return_value={}) as refresh:
            c.native_check();refresh.assert_called_once()
        self.assertFalse(c.native_verified);self.assertEqual(c.native_health['state'],'validation_timeout')
        self.assertTrue(c.native_health['discovery_ok']);self.assertTrue(c.native_health['using_proxy'])
        self.assertEqual(c.native_health['errors']['tsmp'],'no reply');self.assertEqual(c.first_native_at,1)
        label=native_label({'udp_direct_live':True,'tail_native_verified':False,'tail_health':c.native_health,'seconds_to_first_native_tailscale':67})
        self.assertEqual(label,'曾成功，当前数据验证超时')
    def test_discovery_timeout_does_not_prevent_real_data_verification(self):
        c=self.client()
        with patch('client.command',side_effect=native_responses(c,[RuntimeError('no reply'),self.status(),'pong via TSMP',self.status()])),patch('client.read_metadata',return_value={}):c.native_check()
        self.assertTrue(c.native_verified);self.assertEqual(c.native_health['state'],'data_verified')
    def test_metadata_error_does_not_erase_successful_data_check(self):
        c=self.client()
        with patch('client.command',side_effect=native_responses(c,['pong',self.status(),'pong',self.status()])),patch('client.read_metadata',side_effect=RuntimeError('netmap busy')):c.native_check()
        self.assertTrue(c.native_verified);self.assertEqual(c.rows[-1][0],'tail_metadata_refresh_error')
    def test_endpoint_switch_preserves_data_reply_but_cannot_prove_proxy(self):
        c=self.client()
        with patch('client.command',side_effect=native_responses(c,['pong',self.status(),'pong',self.status('10.102.41.158:41641')])),patch('client.read_metadata',return_value={}):c.native_check()
        self.assertTrue(c.native_verified);self.assertFalse(c.native_proxy_verified);self.assertEqual(c.native_health['route'],'path_changed')
    def test_status_failure_is_explicit_and_metadata_still_refreshes(self):
        c=self.client()
        with patch('client.command',side_effect=native_responses(c,['pong',RuntimeError('status failed')])),patch('client.read_metadata',return_value={}) as refresh:c.native_check();refresh.assert_called_once()
        self.assertEqual(c.native_health['state'],'status_unavailable');self.assertFalse(c.native_verified)
    def test_ui_never_claims_usable_on_discovery_alone_or_old_success(self):
        for state in ('validation_timeout','other_endpoint','status_unavailable','discovery_only','waiting','data_verified'):
            label=native_label({'udp_direct_live':True,'tail_native_verified':False,'seconds_to_first_native_tailscale':4000,'tail_health':{'state':state,'discovery_ok':True}})
            self.assertNotIn('数据通路已验证',label);self.assertNotEqual(label,'接入中')
        self.assertIn('已可用',native_label({'udp_direct_live':False,'udp_direct_verified':True,'tail_native_verified':True}))

class BootstrapTests(unittest.TestCase):
    def bridge(self):
        native=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);native.bind(('127.0.0.1',0));self.addCleanup(native.close)
        metadata={'udp_port':native.getsockname()[1],'node_key':'nodekey:a','expected_peer_key':'nodekey:b','disco_key':'discokey:'+'11'*32,
            'peer_endpoints':[['1.1.1.1',41641]],'peer_tail_ip':'100.1.1.2'}
        events=[];b=TailBridge(metadata,lambda e,**kw:events.append((e,kw)),NullJournal(),FakeCapture)
        self.addCleanup(b.close);b.bind_peer({'node_key':'nodekey:b','expected_peer_key':'nodekey:a','disco_key':'discokey:'+'22'*32})
        b.start();return b,native,events
    def test_actual_native_reply_stops_bootstrap_and_discards_queued_copies(self):
        b,native,events=self.bridge();disco=DISCO+bytes.fromhex('11'*32)+secrets.token_bytes(40)
        b.queue(disco,'bootstrap_copy')
        payload=struct.pack('<I',4)+secrets.token_bytes(28);native.sendto(payload,b.socket.getsockname());time.sleep(.01);b.poll()
        self.assertTrue(b.bootstrap_stopped.is_set());self.assertEqual(b.next_outbound(),(payload,'tailscale_local_proxy'))
        with self.assertRaises(queue.Empty):b.next_outbound()
        b.queue(disco,'bootstrap_copy')
        with self.assertRaises(queue.Empty):b.next_outbound()
        self.assertEqual(len(events),2)
    def test_native_return_does_not_break_bidirectional_proxy(self):
        b,native,events=self.bridge();native.settimeout(1)
        own=DISCO+bytes.fromhex('11'*32)+secrets.token_bytes(40)
        remote=DISCO+bytes.fromhex('22'*32)+secrets.token_bytes(40)
        native.sendto(own,b.socket.getsockname());time.sleep(.01);b.poll()
        self.assertTrue(b.deliver(remote));self.assertEqual(native.recvfrom(65535)[0],remote)
        self.assertEqual(b.next_outbound(),(own,'tailscale_local_proxy'))
    def test_other_local_sender_cannot_stop_bootstrap(self):
        b,native,events=self.bridge();other=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);other.bind(('127.0.0.1',0));self.addCleanup(other.close)
        other.sendto(struct.pack('<I',4)+secrets.token_bytes(28),b.socket.getsockname());time.sleep(.01);b.poll()
        self.assertFalse(b.bootstrap_stopped.is_set());self.assertEqual(b.stats['tail_local_source_rejected'],1)
    def test_endpoint_refresh_never_rearms_bootstrap_but_native_identity_change_does(self):
        b,native,events=self.bridge();b.stop_bootstrap('test')
        b.refresh({**b.metadata,'peer_endpoints':[['1.1.1.1',42000]]});self.assertTrue(b.bootstrap_stopped.is_set())
        b.refresh({**b.metadata,'disco_key':'discokey:'+'33'*32});self.assertFalse(b.bootstrap_stopped.is_set())
    def test_capture_suppresses_other_candidates_after_native_return(self):
        b,native,events=self.bridge();b.stop_bootstrap('test')
        packet=ip_packet(DISCO+bytes.fromhex('11'*32)+secrets.token_bytes(40),source=(b.local_ip,b.metadata['udp_port']));b.capture.q.put(packet)
        deadline=time.monotonic()+1
        while b.stats['bootstrap_suppressed']==0 and time.monotonic()<deadline:time.sleep(.01)
        self.assertEqual(b.stats['bootstrap_copies'],0);self.assertEqual(b.stats['bootstrap_suppressed'],1)
        with self.assertRaises(queue.Empty):b.next_outbound()

if __name__=='__main__':unittest.main()
