import hashlib,json,pathlib,secrets,socket,time,unittest,threading
from unittest.mock import patch
from accelerator import MixedSearch
from test_lab import Service
from measure import Measurements
from client import LabClient
from wire import pack,unpack
from journal import PacketJournal
from evidence import export_evidence,analyze
ROOT=pathlib.Path(__file__).parent/'test-assets'/'trace'

class TraceTests(unittest.TestCase):
    def pair(self):
        code=secrets.token_hex(16);cfg={'public_only':False,'packet_journal_dir':str(ROOT)}
        a,b=[LabClient(cfg,code,n) for n in ('a','b')]
        for c in (a,b):
            s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.bind(('127.0.0.1',0));s.settimeout(1);c.udp=[s];c.stage='main'
        for c,p in ((a,b),(b,a)):c.peer={'id':p.id,'udp':[list(p.udp[0].getsockname())]}
        self.addCleanup(lambda:[(c.udp[0].close(),c.journal.close()) for c in (a,b)])
        return a,b
    def deliver(self,a,b,lane='candidate_pool',target=None):
        a.trace_probe(a.udp[0],target or b.udp[0].getsockname(),a.peer,time.monotonic(),lane)
        data,source=b.udp[0].recvfrom(4096);b.receive_udp(b.udp[0],data,source)
        s,target,ack=b.replies.popleft();s.sendto(ack,target);obj=unpack(b.key,ack)
        b.trace_packet(s,ack,'tx',target,kind='ack',nonce=obj['n'],sender=b.id,receiver=a.id,accepted=True,
            probe_sha256=obj['probe_sha256'],observed_by_peer=obj['seen_from'])
        data,source=a.udp[0].recvfrom(4096);a.receive_udp(a.udp[0],data,source)
        return ack
    def test_four_packet_chain_identifies_exact_lane(self):
        for lane in ('full_scan','fixed_target','candidate_pool','scan_budget_keepalive'):
            a,b=self.pair();self.deliver(a,b,lane);self.deliver(b,a,'fixed_target')
            p=ROOT/(secrets.token_hex(8)+'.zip');q=ROOT/(secrets.token_hex(8)+'.zip');export_evidence(a,p);export_evidence(b,q)
            r=analyze([p,q]);self.assertTrue(r['all_hits_uniquely_correlated'],r)
            own=next(h for h in r['first_hits'] if h['actor']==a.id);self.assertEqual(own['lane'],lane)
            self.assertEqual(own['probe_target'],list(b.udp[0].getsockname()));self.assertEqual(own['source_slot'],0)
    def test_one_side_is_insufficient_for_complete_chain(self):
        a,b=self.pair();self.deliver(a,b);r=analyze([a.journal.directory])
        self.assertTrue(r['first_hits'][0]['local_evidence_valid']);self.assertFalse(r['all_hits_uniquely_correlated'])
    def test_wrong_digest_does_not_verify(self):
        a,b=self.pair();a.trace_probe(a.udp[0],b.udp[0].getsockname(),a.peer,time.monotonic(),'full_scan')
        nonce=next(iter(a.pending));ack=pack(a.key,{'k':'ack','from':b.id,'to':a.id,'n':nonce,'probe_sha256':'0'*64})
        a.receive_udp(a.udp[0],ack,b.udp[0].getsockname());self.assertFalse(a.udp_direct);self.assertIsNone(a.journal.proof_path)
        self.assertEqual(a.journal.recent[-1]['reason'],'probe_digest_mismatch')
    def test_duplicate_and_wrong_socket_cannot_be_first_hit(self):
        a,b=self.pair();a.trace_probe(a.udp[0],b.udp[0].getsockname(),a.peer,time.monotonic(),'full_scan')
        nonce=next(iter(a.pending));wrong=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);wrong.bind(('127.0.0.1',0));self.addCleanup(wrong.close)
        ack=pack(a.key,{'k':'ack','from':b.id,'to':a.id,'n':nonce})
        a.receive_udp(wrong,ack,b.udp[0].getsockname());self.assertFalse(a.udp_direct)
        self.assertEqual(a.journal.recent[-1]['reason'],'wrong_receive_socket')
    def test_expired_probe_cannot_verify(self):
        a,b=self.pair();a.trace_probe(a.udp[0],b.udp[0].getsockname(),a.peer,time.monotonic()-6,'full_scan')
        nonce=next(iter(a.pending));ack=pack(a.key,{'k':'ack','from':b.id,'to':a.id,'n':nonce})
        a.receive_udp(a.udp[0],ack,b.udp[0].getsockname());self.assertFalse(a.udp_direct)
    def test_invalid_hmac_recorded_as_rejected(self):
        a,b=self.pair();a.receive_udp(a.udp[0],b'wrong authentication',b.udp[0].getsockname())
        self.assertFalse(a.udp_direct);self.assertEqual(a.journal.recent[-1]['reason'],'invalid_authentication')
    def test_first_proof_survives_rotation_and_second_hit(self):
        a,b=self.pair();self.deliver(a,b);path=pathlib.Path(a.journal.proof_path);before=path.read_bytes()
        a.journal.limit=180;a.journal.segments=2
        for i in range(20):a.journal.record(direction='event',padding='x'*100,number=i)
        self.deliver(a,b);self.assertEqual(path.read_bytes(),before)
        self.assertLessEqual(len(list(a.journal.directory.glob('packets-*.jsonl'))),2)
        a.journal.flush();b.journal.flush()
        self.assertTrue(analyze([a.journal.directory,b.journal.directory])['all_hits_uniquely_correlated'])
    def test_return_source_may_differ_from_sent_target(self):
        a,b=self.pair();sent=('127.0.0.1',12345);s=a.udp[0];a.trace_probe(s,sent,a.peer,time.monotonic(),'candidate_pool')
        nonce=next(iter(a.pending));tx=a.pending[nonce][3]
        # Emulate a NAT which accepts at the tested target but replies with a
        # different public source. The proof must retain both endpoints.
        ack=pack(a.key,{'k':'ack','from':b.id,'to':a.id,'n':nonce,'probe_sha256':tx['sha256'],'seen_from':list(s.getsockname())})
        a.receive_udp(s,ack,b.udp[0].getsockname());proof=json.loads(pathlib.Path(a.journal.proof_path).read_text(encoding='utf-8'))
        self.assertEqual(proof['tx']['remote'],list(sent));self.assertNotEqual(proof['rx']['remote'],list(sent))
    def test_metadata_does_not_store_room_secret_or_payload(self):
        a,b=self.pair();self.deliver(a,b);export_evidence(a,ROOT/'redaction.zip')
        for f in a.journal.directory.iterdir():
            text=f.read_text(encoding='utf-8');self.assertNotIn(a.key.hex(),text);self.assertNotIn('"payload"',text)
    def test_nearby_prioritized_and_original_lane_always_retained(self):
        search=MixedSearch();peer={'udp':[['1.1.1.1',27529],['1.1.1.1',27579]]}
        early=[];later=[]
        for n in range(20):
            choice=search.choice(peer,8,100);lane=choice[2] if choice else 'full_scan';early.append(lane);search.sent(lane)
        self.assertEqual(early.count('nearby_matrix'),16);self.assertEqual(early.count('full_scan'),4)
        for n in range(20):
            choice=search.choice(peer,8,230);lane=choice[2] if choice else 'full_scan';later.append(lane);search.sent(lane)
        self.assertEqual(later.count('nearby_matrix'),12);self.assertEqual(later.count('observed_range'),4);self.assertEqual(later.count('full_scan'),4)
        # Exact observed addresses and +2 candidates are tried across every
        # local source; no 35-second sync state is required.
        found=False
        for n in range(1000):
            choice=search.choice(peer,8,110);lane=choice[2] if choice else 'full_scan'
            if choice and choice[:2]==(2,('1.1.1.1',27581)):found=True;break
            search.sent(lane)
        self.assertTrue(found)
    def test_empty_budget_keeps_search_cursor_on_unsent_candidate(self):
        search=MixedSearch();peer={'udp':[['1.1.1.1',27579]]}
        before=search.choice(peer,8,100)
        # Budget keepalive is an actual sent packet, but the rejected nearby
        # target must not be counted as tested or advance the nearby cursor.
        search.sent('search_budget_keepalive');self.assertEqual(search.nearby.cursor,0)
        after=search.choice(peer,8,101);self.assertEqual(before,after)
    def test_fast_udp_does_not_wait_for_slow_tcp_or_full_measurements(self):
        service=Service();code=secrets.token_hex(16)
        cfg={**service.cfg,'packet_journal_dir':str(ROOT),'fast_start':True,'nearby_priority':True,'immediate_challenge':True,'duration':10}
        a,b=[LabClient(cfg,code,n) for n in ('a','b')];clients=[a,b];threads=[threading.Thread(target=c.run) for c in clients]
        tcp_finish=[];release_tcp=threading.Event()
        def slow_tcp(m,*args,**kwargs):
            while not release_tcp.wait(.02):
                if m.stop.is_set():return {'error':'stopped'}
            tcp_finish.append(time.monotonic());return {'error':'synthetic_slow_tcp_mapping'}
        start=time.monotonic()
        try:
            with patch.object(Measurements,'tcp_observe',slow_tcp):
                for t in threads:t.start()
                deadline=time.monotonic()+6
                while time.monotonic()<deadline and not all(c.udp_direct for c in clients):time.sleep(.01)
                self.assertTrue(all(c.udp_direct for c in clients),[c.summary() for c in clients])
                # Hold TCP until UDP really succeeds, rather than using a
                # wall-clock race with a 2-second sleep under Windows load.
                elapsed=time.monotonic()-start;self.assertLess(elapsed,6.0);self.assertFalse(tcp_finish)
                release_tcp.set()
                for c in clients:
                    self.assertEqual(c.profile['port_pattern']['reason'],'not_measured_in_fast_start')
                    self.assertTrue(c.journal.proof_path)
                paths=[]
                for c in clients:
                    p=ROOT/(secrets.token_hex(8)+'.zip');export_evidence(c,p);paths.append(p)
                result=analyze(paths);self.assertTrue(result['all_hits_uniquely_correlated'],result)
                (ROOT/'fast-establishment-test.json').write_text(json.dumps({'seconds':round(elapsed,3),'scope':'loopback with TCP delayed; not NAT4 field performance','evidence':result},indent=2),encoding='utf-8')
        finally:
            release_tcp.set()
            for c in clients:c.stop.set()
            for t in threads:t.join(8);self.assertFalse(t.is_alive())
            service.stop()
