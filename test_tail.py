import ctypes,hashlib,json,pathlib,queue,secrets,socket,struct,threading,time,unittest
from unittest.mock import patch
from types import SimpleNamespace
from client import LabClient
from test_lab import Service
from transport import DataTransport,MAX_DATAGRAM,FlowBudget
from tailbridge import TailBridge,DISCO,payload_kind,parse_ipv4_udp
ROOT=pathlib.Path(__file__).parent/'test-assets'/'tail'

def native_responses(client,results,advance=True):
    replies=iter(results)
    def call(args,**kwargs):
        value=next(replies)
        if isinstance(value,Exception):raise value
        if advance and ('--tsmp' in args or '--peerapi' in args) and 'pong' in value.lower():
            if all(client.tail.stats.get(k,0) for k in ('tail_tx_wg_datagrams','tail_rx_wg_datagrams')):
                for key in ('tail_tx_wg_datagrams','tail_rx_wg_datagrams'):client.tail.stats[key]+=1
        return value
    return call

class FakeCapture:
    def __init__(self,*args):self.q=queue.Queue()
    def recv(self):
        data=self.q.get()
        if data is None:raise OSError('closed')
        return data
    def close(self):self.q.put(None)

def ip_packet(payload,source=('192.168.1.2',41641),target=('1.1.1.1',41641)):
    total=28+len(payload)
    header=struct.pack('!BBHHHBBH4s4s',0x45,0,total,1,0,64,17,0,socket.inet_aton(source[0]),socket.inet_aton(target[0]))
    return header+struct.pack('!4H',source[1],target[1],8+len(payload),0)+payload

class TailTests(unittest.TestCase):
    def check_native_readiness(self,after_address,tx=1,rx=1):
        from journal import NullJournal
        c=object.__new__(LabClient);c.stop=threading.Event();c.profile={};c.native_verified=False;c.first_native_at=None
        c.tail=SimpleNamespace(metadata={'peer_tail_ip':'100.1.1.2','expected_peer_key':'nodekey:peer'},
            socket=SimpleNamespace(getsockname=lambda:('127.0.0.1',38080)),
            stats={'tail_tx_wg_datagrams':tx,'tail_rx_wg_datagrams':rx},refresh=lambda m:False)
        events=[];c.log=lambda event,**fields:events.append((event,fields))
        def status(address):return json.dumps({'Peer':{'peer':{'PublicKey':'nodekey:peer','CurAddr':address}}})
        with patch('client.command',side_effect=native_responses(c,['pong',status('127.0.0.1:38080'),'pong',status(after_address)])),patch('client.read_metadata',return_value={}):
            c.native_check()
        return c,events
    def test_native_proxy_proof_requires_proxy_after_wireguard_ping(self):
        c,events=self.check_native_readiness('1.1.1.1:41641')
        self.assertTrue(c.native_verified);self.assertFalse(c.native_proxy_verified);self.assertIsNone(c.first_native_at)
        c,events=self.check_native_readiness('127.0.0.1:38080')
        self.assertTrue(c.native_verified);self.assertIsNotNone(c.first_native_at)
    def test_native_data_reply_with_missing_proxy_counts_does_not_prove_proxy(self):
        for tx,rx in ((0,1),(1,0),(0,0)):
            c,events=self.check_native_readiness('127.0.0.1:38080',tx,rx)
            self.assertTrue(c.native_verified);self.assertFalse(c.native_proxy_verified);self.assertIsNone(c.first_native_at)
    def transport_pair(self):
        root=secrets.token_bytes(32);a,sa,b,sb=[secrets.token_hex(16) for _ in range(4)]
        return DataTransport(root,a,sa,b,sb),DataTransport(root,b,sb,a,sa)
    def test_encrypted_fragments_reassemble_out_of_order(self):
        for size in (1,1280,1440,4096,65507):
            a,b=self.transport_pair();payload=secrets.token_bytes(size);frames=a.encode(payload)
            self.assertTrue(all(len(f)<=MAX_DATAGRAM for f in frames));result=None
            for frame in reversed(frames):result=b.decode(frame) or result
            self.assertEqual(result,payload);self.assertEqual(b.dropped,0)
            self.assertIsNone(b.decode(frames[0]));self.assertEqual(b.dropped,1)
    def test_tamper_or_wrong_session_is_rejected(self):
        a,b=self.transport_pair();frame=a.encode(b'payload')[0]
        changed=frame[:-1]+bytes([frame[-1]^1]);self.assertIsNone(b.decode(changed));self.assertEqual(b.dropped,1)
        c,d=self.transport_pair();self.assertIsNone(d.decode(frame));self.assertEqual(d.dropped,1)
        self.assertEqual(b.decode(frame),b'payload')
    def test_incomplete_fragments_expire_and_have_bounded_memory(self):
        a,b=self.transport_pair();frames=a.encode(b'x'*2000);self.assertIsNone(b.decode(frames[0],100))
        b.decode(a.encode(b'single')[0],104);self.assertEqual(len(b.parts),0)
    def test_parser_rejects_fragmented_ip_and_non_native_payloads(self):
        p=DISCO+b'a'*32+b'b'*40;parsed=parse_ipv4_udp(ip_packet(p));self.assertEqual(parsed[2],p)
        fragment=bytearray(ip_packet(p));fragment[6:8]=struct.pack('!H',0x2000);self.assertIsNone(parse_ipv4_udp(bytes(fragment)))
        self.assertIsNone(payload_kind(b'ordinary UDP payload'));self.assertEqual(payload_kind(struct.pack('<I',4)+b'x'*1276),'wireguard_data')
    def test_flow_budget_is_separate_from_probe_budget(self):
        b=FlowBudget(rate=100,burst=100);at=b.at;self.assertTrue(b.admit(100,at));self.assertFalse(b.admit(1,at));self.assertTrue(b.admit(50,at+.5))
    def test_tailbridge_rejects_wrong_peer_identity(self):
        meta={'node_key':'nodekey:a','expected_peer_key':'nodekey:b','disco_key':'discokey:'+'11'*32,'udp_port':41641,'peer_endpoints':[['1.1.1.1',41641]],'peer_tail_ip':'100.1.1.1'}
        from journal import NullJournal
        bridge=TailBridge(meta,lambda *a,**k:None,NullJournal(),FakeCapture);self.addCleanup(bridge.close)
        with self.assertRaises(RuntimeError):bridge.bind_peer({'node_key':'nodekey:c','expected_peer_key':'nodekey:a'})
    def run_native_tunnel_case(self,local_ip='127.0.0.1',passive_peer=False,stale_disco=False):
        service=Service();native=[];clients=[];threads=[];code=secrets.token_hex(16)
        for _ in range(2):
            s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.bind((local_ip,0));s.settimeout(2);native.append(s)
        metas=[]
        for i in range(2):
            metas.append({'node_key':'nodekey:'+str(i+1)*64,'disco_key':'discokey:'+str(i+3)*64,
                'expected_peer_key':'nodekey:'+str(2-i)*64,'udp_port':native[i].getsockname()[1],
                'peer_tail_ip':'100.1.1.'+str(2-i),'tail_ips':['100.1.1.'+str(i+1)],'peer_endpoints':[['1.1.1.1',41641]]})
        def metadata(target,**kwargs):return dict(metas[0 if target=='100.1.1.2' else 1])
        cfg={**service.cfg,'bind':local_ip,'tailscale_bridge':True,'production_mode':True,'fast_start':True,'nearby_priority':True,
            'immediate_challenge':True,'tcp_udp_assist':True,'packet_journal_dir':str(ROOT)}
        clients=[LabClient({**cfg,'peer_tail_ip':metas[i]['peer_tail_ip']},code,str(i)) for i in range(2)]
        threads=[threading.Thread(target=c.run) for c in clients]
        def capture(port,endpoints):
            if passive_peer and port==metas[1]['udp_port']:
                from bridgecheck import ResourceError
                raise ResourceError('injected capture failure 1450')
            return FakeCapture(port,endpoints)
        try:
            with patch('client.is_admin',return_value=True),patch('client.read_metadata',side_effect=metadata),patch('tailbridge.WinSniffer',capture),patch('driverdiag.collect',return_value={'synthetic_test':True}),patch.object(LabClient,'native_check',lambda self:None):
                for t in threads:t.start()
                deadline=time.monotonic()+6
                while time.monotonic()<deadline and not all(c.tail and c.tail.enabled and c.direct_path for c in clients):time.sleep(.01)
                self.assertTrue(all(c.tail and c.tail.enabled for c in clients),[c.summary() for c in clients])
                for c in clients:c.tcp_direct=False
                # Force two independently verified directional paths. The
                # receiver must authenticate data from the peer's alternate
                # source without replacing its pinned outgoing path.
                clients[1].direct_path=(clients[1].udp[1],clients[0].udp[0].getsockname())
                # Capture bootstrap discovery using synthetic public headers;
                # actual Tailscale crypto authentication remains untested here.
                discovery=DISCO+bytes.fromhex('77'*32 if stale_disco else metas[0]['disco_key'].split(':')[1])+secrets.token_bytes(40)
                clients[0].tail.capture.q.put(ip_packet(discovery,source=(local_ip,metas[0]["udp_port"])));received,_=native[1].recvfrom(65535);self.assertEqual(received,discovery)
                if stale_disco:
                    reply=DISCO+bytes.fromhex('88'*32)+secrets.token_bytes(40)
                    native[1].sendto(reply,clients[1].tail.socket.getsockname())
                    received,_=native[0].recvfrom(65535);self.assertEqual(received,reply)
                    self.assertEqual(clients[0].tail.stats['tail_peer_disco_snapshot_mismatches'],1)
                    self.assertEqual(clients[1].tail.stats['tail_local_disco_snapshot_mismatches'],1)
                    self.assertNotEqual(clients[0].tail.peer['disco_key'],'discokey:'+'88'*32)
                if passive_peer:
                    self.assertIsNone(clients[1].tail.capture);self.assertIsNone(clients[1].tail_bridge_error)
                    self.assertEqual(clients[1].tail.capture_failures,1)
                for i,size in ((0,1280),(1,1440)):
                    payload=struct.pack('<I',4)+secrets.token_bytes(size-4)
                    native[i].sendto(payload,clients[i].tail.socket.getsockname());received,source=native[1-i].recvfrom(65535)
                    self.assertEqual(received,payload);self.assertEqual(source,clients[1-i].tail.socket.getsockname())
                # sendto can deliver to the test receiver before the sender's
                # next statement publishes its counters on another thread.
                deadline=time.monotonic()+1
                while time.monotonic()<deadline and not all(c.tail.stats['tail_tx_datagrams'] and c.tail.stats['tail_rx_datagrams'] for c in clients):time.sleep(.01)
                self.assertTrue(all(c.tail.stats['tail_tx_datagrams'] and c.tail.stats['tail_rx_datagrams'] for c in clients))
                self.assertTrue(all(not c.native_verified for c in clients))
                self.assertTrue(all(c.summary()['profile']['transport_session']!=c.session for c in clients))
                ROOT.mkdir(parents=True,exist_ok=True)
                (ROOT/'forwarding-test.json').write_text(json.dumps({'passed':True,'scope':'real outer UDP + AEAD + loopback proxies, synthetic native UDP endpoints and fake capture; not native Tailscale authentication','results':[c.summary()['result'] for c in clients]},indent=2),encoding='utf-8')
        finally:
            for c in clients:c.stop.set()
            for t in threads:
                if t.ident:t.join(10);self.assertFalse(t.is_alive())
            for s in native:s.close()
            service.stop()
    def test_udp_tunnel_forwards_synthetic_native_datagrams_before_tcp(self):
        self.run_native_tunnel_case()
    def test_udp_tunnel_uses_explicit_nondefault_local_proxy_address(self):
        self.run_native_tunnel_case('127.0.0.2')
    def test_udp_coordinated_tcp_round_uses_the_reserved_tcp_source(self):
        service=Service();code=secrets.token_hex(16);cfg={**service.cfg,'fast_start':True,'nearby_priority':True,'immediate_challenge':True,'tcp_udp_assist':True,'packet_journal_dir':str(ROOT)}
        clients=[LabClient(cfg,code,str(i)) for i in range(2)];threads=[threading.Thread(target=c.run) for c in clients];calls=[];lock=threading.Lock()
        def task(c,target,peer,source_port,mode='listener_connect'):
            c.stats['tcp_attempts']+=1
            if mode=='udp_coordinated_simultaneous_open':
                with lock:calls.append({'id':c.id,'source_port':source_port,'reserved_port':c.active_port,'at':time.monotonic(),'udp_already_verified':bool(c.direct_path)})
                c.tcp_direct=True
        try:
            with patch.object(LabClient,'tcp_task',task):
                for t in threads:t.start()
                deadline=time.monotonic()+8
                while time.monotonic()<deadline and len(calls)<2:time.sleep(.01)
                self.assertEqual(len(calls),2,[c.summary() for c in clients])
                self.assertTrue(all(x['source_port']==x['reserved_port'] and x['udp_already_verified'] for x in calls))
                self.assertLess(abs(calls[0]['at']-calls[1]['at']),.5)
        finally:
            for c in clients:c.stop.set()
            for t in threads:
                if t.ident:t.join(8);self.assertFalse(t.is_alive())
            service.stop()
