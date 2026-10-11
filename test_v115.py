import asyncio,collections,json,pathlib,secrets,socket,struct,threading,time,unittest,zlib
from unittest.mock import patch
from client import LabClient
from egress import LiveEgress,ExitExplorer,extra_candidates
from roomudp import Codec,RoomUDPServer
from session import SessionRunner
from strategy import Coordination
from test_v114 import udp_service,until
from wire import COOKIE,pack

class Reflector(asyncio.DatagramProtocol):
    def __init__(self,ip):self.ip=ip;self.count=0
    def connection_made(self,t):self.transport=t
    def datagram_received(self,data,addr):
        if len(data)!=20 or data[4:8]!=struct.pack('!I',COOKIE):return
        self.count+=1;ip=bytes(a^b for a,b in zip(socket.inet_aton(self.ip),struct.pack('!I',COOKIE)))
        body=struct.pack('!HHBBH',0x20,8,0,1,addr[1]^(COOKIE>>16))+ip
        self.transport.sendto(struct.pack('!HHI',0x101,len(body),COOKIE)+data[8:20]+body,addr)

class V115Tests(unittest.TestCase):
    def test_remote_ack_receipt_requires_real_sent_packet_and_current_sessions(self):
        c=LabClient({'public_only':False},'AA'*16,'a');c.profile={};sock=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);sock.bind(('127.0.0.1',0));c.udp=[sock]
        now=time.monotonic();nonce=secrets.token_hex(16);peer={'id':'b'*32,'profile':{'transport_session':'c'*32}}
        receipt={'nonce':nonce,'probe_sha256':'d'*64,'ack_sha256':'e'*64,'sender_session':'c'*32,'receiver_session':c.data_session};peer['profile']['udp_path_receipt']=receipt
        try:
            self.assertFalse(c.apply_path_receipt(peer,now));c.reply_proofs[nonce]=(sock,('127.0.0.2',45000),'e'*64,'d'*64,now)
            receipt['receiver_session']='f'*32;self.assertFalse(c.apply_path_receipt(peer,now))
            receipt['receiver_session']=c.data_session;receipt['ack_sha256']='0'*64;self.assertFalse(c.apply_path_receipt(peer,now))
            receipt['ack_sha256']='e'*64;self.assertTrue(c.apply_path_receipt(peer,now));self.assertEqual(c.direct_path,(sock,('127.0.0.2',45000)));self.assertEqual(c.stats['udp_path_receipts'],1)
            saved=c.last_direct_ack;self.assertFalse(c.apply_path_receipt(peer,now+1));self.assertEqual(c.last_direct_ack,saved)
            c.reply_proofs[nonce]=(sock,('127.0.0.2',45000),'e'*64,'d'*64,now-9);self.assertFalse(c.apply_path_receipt(peer,now))
        finally:sock.close()
    def test_authenticated_alternative_recovers_and_preserves_outbound_target(self):
        from wire import unpack
        c=LabClient({'public_only':False,'unlimited_search':True},'AA'*16,'a');c.profile={}
        sockets=[]
        for _ in range(3):
            sock=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);sock.bind(('127.0.0.1',0));sock.settimeout(1);sockets.append(sock)
        s,old,sink=sockets;c.udp=[s];c.peer={'id':'b'*32,'udp':[list(old.getsockname()),list(sink.getsockname())]};c.direct_path=(s,old.getsockname());c.udp_direct=True;c.last_direct_ack=time.monotonic()-2
        try:
            c.trace_probe(s,sink.getsockname(),c.peer,time.monotonic(),'candidate_pool');raw=sink.recvfrom(2048)[0];obj=unpack(c.key,raw)
            reply=pack(c.key,{'k':'ack','from':c.peer['id'],'to':c.id,'n':obj['n'],'probe_sha256':__import__('hashlib').sha256(raw).hexdigest()})
            c.receive_udp(s,reply,old.getsockname())
            self.assertEqual(c.direct_path,(s,sink.getsockname()));self.assertEqual(c.last_direct_peer_source,old.getsockname());self.assertEqual(c.stats['udp_probe_acks'],1)
            saved=c.last_direct_ack;c.receive_udp(s,reply,old.getsockname());self.assertEqual(c.last_direct_ack,saved)
        finally:[sock.close() for sock in sockets]
    def test_reserved_live_path_socket_is_not_used_for_other_reflectors(self):
        sockets=[]
        for _ in range(2):
            sock=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);sock.bind(('127.0.0.1',0));sockets.append(sock)
        stop=threading.Event();observer=LiveEgress({'public_only':False,'egress_stun_servers':[]},sockets,'127.0.0.1',0,stop,lambda *a,**k:None)
        sent=[]
        try:
            observer.thread.join(2);observer.servers=[('127.0.0.2',3478)];observer.started=time.monotonic()-5
            observer.tick(time.monotonic(),lambda sock,*args:sent.append(sock) or True,lambda *a,**k:None,sockets[0])
            self.assertEqual(sent,[sockets[1]])
            observer.last_send=0;observer.at.clear()
            observer.tick(time.monotonic(),lambda sock,*args:sent.append(sock) or True,lambda *a,**k:None,None)
            self.assertIn(sockets[0],sent)
        finally:stop.set();observer.close();[sock.close() for sock in sockets]
    def test_unlimited_receive_burst_replies_without_waiting_for_outer_scan_loop(self):
        from wire import unpack
        c=LabClient({'public_only':False,'unlimited_search':True},'AA'*16,'a');s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.bind(('127.0.0.1',0));sink=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);sink.bind(('127.0.0.1',0));sink.settimeout(1)
        c.udp=[s];c.peer={'id':'b'*32,'udp':[list(sink.getsockname())]}
        try:
            for _ in range(300):
                nonce=secrets.token_hex(16);c.receive_udp(s,pack(c.key,{'k':'probe','from':c.peer['id'],'to':c.id,'n':nonce}),sink.getsockname())
                obj=unpack(c.key,sink.recvfrom(2048)[0]);self.assertEqual((obj['k'],obj['n']),('ack',nonce));self.assertFalse(c.replies)
            self.assertEqual(c.stats['udp_probe_rx'],300)
        finally:s.close();sink.close()
    def test_reverse_verification_is_sent_while_ack_backlog_remains(self):
        from wire import unpack
        c=LabClient({'public_only':False,'unlimited_search':True},'AA'*16,'a')
        s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.bind(('127.0.0.1',0));sink=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);sink.bind(('127.0.0.1',0));sink.settimeout(1)
        c.udp=[s];peer={'id':'b'*32,'udp':[list(sink.getsockname())]};target=sink.getsockname()
        try:
            for _ in range(10):c.replies.append((s,target,pack(c.key,{'k':'ack','from':c.id,'to':peer['id'],'n':secrets.token_hex(16)})))
            c.challenges.append((s,target,{'nonce':secrets.token_hex(16),'sha256':'f'*64}))
            c.service_peer_control(peer,time.monotonic())
            kinds=[unpack(c.key,sink.recvfrom(2048)[0])['k'] for _ in range(2)]
            self.assertEqual(kinds,['ack','probe']);self.assertEqual(len(c.replies),9);self.assertFalse(c.challenges);self.assertEqual(c.stats['udp_probe_tx'],1)
        finally:s.close();sink.close()
    def test_initial_exchange_requires_ack_of_this_run_and_resets_for_new_peer_session(self):
        c=LabClient({'preflight_exchange':True},'AA'*16,'a');c.profile={};c.own_udp=[['112.49.193.186',12345]]
        peer={'id':'b'*32,'prepared':True,'udp':[['112.111.24.193',35007]],'profile':{'transport_session':'c'*32,'initial_exchange':{'token':'d'*32}}}
        self.assertFalse(c.initial_exchange(peer,True));self.assertEqual(c.stats['udp_probe_tx'],0)
        peer['profile']['initial_exchange'].update(ack=c.exchange_token,peer_session='e'*32)
        self.assertFalse(c.initial_exchange(peer,True))
        peer['profile']['initial_exchange']['peer_session']=c.data_session
        self.assertFalse(c.initial_exchange(peer,False));self.assertTrue(c.initial_exchange(peer,True))
        peer['profile']['transport_session']='f'*32;peer['profile']['initial_exchange']={'token':'1'*32}
        self.assertFalse(c.initial_exchange(peer,True))
    def test_peer_sync_rejects_previous_run_and_other_tail_sender(self):
        from peersync import PeerSync
        key=secrets.token_hex(32);sid=secrets.token_hex(16);stop=threading.Event()
        a=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);a.bind(('127.0.0.1',0));target=a.getsockname()
        expected=['b'*32,sid,'a'*32]
        sync=PeerSync(key,secrets.token_hex(16),('127.0.0.1',0),target,lambda:None,lambda:tuple(expected),stop,lambda *a,**k:None)
        obj={'k':'peer_sync','id':'b'*32,'to':'a'*32,'prepared':True,'udp':[['112.111.24.193',35007]],'version':'0.9.4-lab','profile':{'transport_session':sid}}
        try:
            packet=Codec(key).encode(bytes.fromhex(sid),1,obj,True)[0]
            sync.accept(packet,('127.0.0.2',target[1]));self.assertIsNone(sync.fresh())
            sync.accept(packet,target);self.assertIsNotNone(sync.fresh())
            expected[1]=secrets.token_hex(16);self.assertIsNone(sync.fresh())
            sync.accept(packet,target);self.assertIsNone(sync.fresh());self.assertGreater(sync.stats['rejected'],0)
        finally:stop.set();sync.close();a.close()
    def test_overlay_keeps_current_pair_coordinated_through_room_blackhole(self):
        service,protocol=udp_service();runners=[SessionRunner(lambda e:None) for _ in range(2)];ports=[]
        for _ in range(2):
            s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.bind(('127.0.0.1',0));ports.append(s.getsockname()[1]);s.close()
        cfg={**service.cfg,'peer_sync_overlay':True,'preflight_exchange':True,'coordinated_scan_v2':True,'multi_exit_search':True,'coordination_window_seconds':2}
        original=protocol.datagram_received;drop=threading.Event()
        try:
            code=secrets.token_hex(16)
            clients=[runners[i].start({**cfg,'peer_sync_bind':'127.0.0.1','peer_sync_host':'127.0.0.1','peer_sync_port':ports[i],'peer_sync_remote_port':ports[1-i]},code,str(i)) for i in range(2)]
            self.assertTrue(until(lambda:all(c.exchange_verified and c.peer_sync.fresh() for c in clients),12))
            self.assertTrue(until(lambda:all(c.udp_direct for c in clients),12))
            for c in clients:
                events=[e['event'] for e in c.logs];self.assertLess(events.index('initial_exchange_verified'),events.index('testing'))
            with patch.object(protocol,'datagram_received',side_effect=lambda data,addr:None if drop.is_set() else original(data,addr)):
                drop.set();time.sleep(10)
                for c in clients:
                    self.assertGreater(time.monotonic()-c.last_snapshot,8);self.assertFalse(c.cached_search_active)
                    self.assertTrue(c.peer_sync.fresh());self.assertEqual(c.room_members(),2);self.assertEqual(c.control_reconnects,0)
                    self.assertTrue(c.exchange_verified);self.assertGreater(c.stats['udp_probe_acks'],10)
        finally:
            for s in runners:s.stop()
            for s in runners:
                if s.thread:s.thread.join(10)
            self.assertTrue(all(not c.peer_sync.thread.is_alive() and c.peer_sync.socket.fileno()<0 for c in clients))
            service.stop()
    def test_compressed_snapshot_roundtrip_and_old_framing_compatibility(self):
        key=secrets.token_hex(32);a=Codec(key);b=Codec(key,True);sid=secrets.token_bytes(16)
        payload={'profile':{'body':'mapping '*1000},'peers':[{'id':secrets.token_hex(16)}]}
        plain=a.encode(sid,1,payload);compressed=a.encode(sid,2,payload,True)
        self.assertGreater(len(plain),5);self.assertEqual(len(compressed),1)
        out=None
        for p in reversed(plain):out=b.decode(p,('127.0.0.1',1)) or out
        self.assertEqual(out[2],payload);self.assertEqual(b.decode(compressed[0],('127.0.0.1',1))[2],payload)
    def test_decoder_rejects_inflation_bomb(self):
        key=secrets.token_hex(32);a=Codec(key);b=Codec(key,True);sid=secrets.token_bytes(16)
        original=json.dumps
        # Supply authenticated wire bytes through the legacy framing to test
        # the post-authentication decompression bound, not random invalid data.
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        from roomudp import HEADER,MAGIC
        raw=b'\0Z1'+zlib.compress(b'x'*1000000);header=HEADER.pack(MAGIC,sid,1,0,1);nonce=secrets.token_bytes(12)
        packet=header+nonce+AESGCM(a.key(sid,False)).encrypt(nonce,raw,header)
        self.assertIsNone(b.decode(packet,('127.0.0.1',1)))
    def test_extra_candidates_preserve_observations_and_do_not_use_native_port(self):
        peer={'udp':[['112.111.24.193',35007]],'profile':{'exit_observations':{'observations':[{'endpoint':['112.111.24.189',41000],'age_seconds':1,'slot':0},{'endpoint':['112.111.24.199',44000],'age_seconds':99}]}}}
        result=extra_candidates(peer,[['112.111.24.197',41641],['26.216.68.189',41641]])
        self.assertIn((('112.111.24.189',41000),'same_socket_stun_observed'),result)
        self.assertIn((('112.111.24.197',35007),'candidate_ip_observed_port_hypothesis'),result)
        self.assertFalse(any(ep[0] in ('112.111.24.199','26.216.68.189') or ep[1]==41641 for ep,reason in result))
    def test_full_port_explorer_covers_each_extra_ip_without_reset(self):
        peer={'udp':[['127.0.0.1',35007]],'profile':{}};search=ExitExplorer();coverage=collections.defaultdict(set)
        for _ in range(65535*8):
            choice=search.choice(peer,2,[['127.0.0.2',41641],['127.0.0.3',41641]],False)
            slot,target,lane,ip,why=choice
            if lane=='exit_ip_full_scan':coverage[ip].add(target[1])
            search.sent(lane,ip)
        self.assertEqual({k:len(v) for k,v in coverage.items()},{'127.0.0.2':65535,'127.0.0.3':65535})
    def test_new_authenticated_ip_is_received_but_wrong_identity_is_rejected(self):
        c=LabClient({'public_only':False,'multi_exit_search':True},'AA'*16,'a');s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.bind(('127.0.0.1',0));c.udp=[s]
        peer={'id':'b'*32,'udp':[['127.0.0.1',20000]]};c.peer=peer
        try:
            bad=pack(c.key,{'k':'probe','from':'c'*32,'to':c.id,'n':secrets.token_hex(16)})
            c.receive_udp(s,bad,('127.0.0.2',30000));self.assertEqual(c.stats['udp_probe_rx'],0)
            good=pack(c.key,{'k':'probe','from':peer['id'],'to':c.id,'n':secrets.token_hex(16)})
            c.cfg['preflight_exchange']=True;c.receive_udp(s,good,('127.0.0.2',30000));self.assertEqual(c.stats['udp_probe_rx'],0);self.assertEqual(len(c.replies),0)
            c.exchange_verified=True
            c.receive_udp(s,good,('127.0.0.2',30000));self.assertEqual(c.stats['udp_probe_rx'],1);self.assertIn('127.0.0.2',c.extra_ips_seen);self.assertEqual(len(c.replies),1)
        finally:s.close()
    def test_v2_round_does_not_expire_before_running_confirmation(self):
        mine={'strategy_protocol':1,'punch_epoch':'a'*32,'coordination_protocol':2,'search_phase_protocol':1};other={'id':'b'*32,'profile':{'strategy_protocol':1,'punch_epoch':'b'*32,'coordination_protocol':2,'search_phase_protocol':1}}
        co=Coordination('a'*32,2);co.step(other,mine,0);token=co.record['token'];other['profile']['punch_coord']={'state':'ack','token':token,'round':0};co.step(other,mine,1)
        co.step(other,mine,10);self.assertEqual(co.round,0);self.assertEqual(co.role,'anchor')
        other['profile']['punch_coord']={'state':'running','token':token,'round':0};co.step(other,mine,11);self.assertEqual(co.round,1)
    def test_live_actual_sockets_measure_two_reflectors_and_pair(self):
        service,protocol=udp_service();runners=[SessionRunner(lambda e:None) for _ in range(2)]
        async def listen():
            result=[]
            for ip in ['127.0.0.1','127.0.0.2']:
                transport,p=await service.loop.create_datagram_endpoint(lambda ip=ip:Reflector(ip),local_addr=(ip,0));service.listeners.append(transport);result.append([ip,transport.get_extra_info('sockname')[1]])
            return result
        servers=asyncio.run_coroutine_threadsafe(listen(),service.loop).result(3)
        cfg={**service.cfg,'live_egress_discovery':True,'egress_stun_servers':servers,'multi_exit_search':True,'coordinated_scan_v2':True}
        try:
            code=secrets.token_hex(16);clients=[s.start(cfg,code,str(i)) for i,s in enumerate(runners)]
            self.assertTrue(until(lambda:all(c.udp_direct and c.stats['udp_probe_acks']>=3 for c in clients),15))
            for c in clients:
                records=c.egress.snapshot(time.monotonic())['observations'];self.assertEqual(len(records),len(c.udp)*2)
                self.assertEqual({r['reflector'][0] for r in records},{'127.0.0.1','127.0.0.2'})
                for r in records:self.assertEqual(r['local_port'],c.udp[r['slot']].getsockname()[1])
                self.assertFalse(c.egress.snapshot(time.monotonic())['peer_mapping_verified']);self.assertEqual(c.control_failures,0)
        finally:
            for s in runners:s.stop()
            for s in runners:
                if s.thread:s.thread.join(10)
            service.stop()
    def test_missing_reflector_is_bounded_and_peer_scan_starts(self):
        service,protocol=udp_service();runners=[SessionRunner(lambda e:None) for _ in range(2)];cfg={**service.cfg,'live_egress_discovery':True,'egress_stun_servers':[['127.0.0.2',9]],'coordinated_scan_v2':True}
        try:
            code=secrets.token_hex(16);clients=[s.start(cfg,code,str(i)) for i,s in enumerate(runners)]
            self.assertTrue(until(lambda:all(c.udp_direct for c in clients),15))
            self.assertTrue(all(c.prepared and not c.exit_discovery_pending for c in clients));self.assertTrue(all(c.egress.received==0 for c in clients))
        finally:
            for s in runners:s.stop()
            for s in runners:
                if s.thread:s.thread.join(10)
            service.stop()

if __name__=='__main__':unittest.main(verbosity=2)
