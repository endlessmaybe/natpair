import asyncio,datetime,hashlib,json,pathlib,secrets,socket,struct,threading,time,unittest
from unittest.mock import patch
from cryptography import x509
from cryptography.hazmat.primitives import hashes,serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from client import LabClient,Budget
from measure import Measurements
from server import LabServer,start
from wire import pack,unpack,pattern,room_keys,parse_stun,COOKIE,endpoint
from discovery import LiveDiscovery,PairClock

ROOT=pathlib.Path(__file__).parent
class Service:
    def __init__(self):
        assets=ROOT/'test-assets'/secrets.token_hex(8);assets.mkdir(parents=True,exist_ok=True)
        key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
        subject=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'localhost')]);now=datetime.datetime.now(datetime.timezone.utc)
        cert=x509.CertificateBuilder().subject_name(subject).issuer_name(subject).public_key(key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(now-datetime.timedelta(days=1)).not_valid_after(now+datetime.timedelta(days=1)).sign(key,hashes.SHA256())
        self.cert=assets/'cert.pem';self.keyfile=assets/'key.pem'
        self.cert.write_bytes(cert.public_bytes(serialization.Encoding.PEM));self.keyfile.write_bytes(key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
        self.access=secrets.token_hex(32);self.service=LabServer(self.access,public=False);self.loop=asyncio.new_event_loop();self.ready=threading.Event();self.error=None
        self.unhandled=[];self.loop.set_exception_handler(lambda loop,context:self.unhandled.append(context))
        self.cfg={'host':'127.0.0.1','access':self.access,'pin':hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest(),'public_only':False,'stun_hosts':[],'bind':'127.0.0.1','if_index':0,'duration':10,'lab_sockets':2}
        self.thread=threading.Thread(target=self.run,daemon=True);self.thread.start();assert self.ready.wait(10)
        if self.error:raise self.error
    def run(self):
        asyncio.set_event_loop(self.loop)
        async def begin():
            for _ in range(30):
                # Avoid consecutive Windows ephemeral ports left in TIME_WAIT
                # by previous reflection tests; isolate the listener range.
                base=20000+secrets.randbelow(24000)
                if base>65520:continue
                try:
                    self.listeners=await start(self.service,'127.0.0.1',base,base+9,str(self.cert),str(self.keyfile))
                    self.cfg.update(lab_udp_base=base,lab_control_port=base+9);return
                except OSError:self.service.udp=[]
            raise RuntimeError('No free observer range')
        try:self.loop.run_until_complete(begin())
        except Exception as e:self.error=e
        self.ready.set()
        if not self.error:self.loop.run_forever()
    def stop(self):
        async def close():
            for m in list(self.service.rooms.values()):
                for client in list(m.values()):client['writer'].close()
            for listener in self.listeners:listener.close()
            await asyncio.sleep(.1)
        asyncio.run_coroutine_threadsafe(close(),self.loop).result(10);self.loop.call_soon_threadsafe(self.loop.stop);self.thread.join(10);self.loop.close()
        assert not self.unhandled,self.unhandled

class Tests(unittest.TestCase):
    def test_zero_step_still_adds_neighbors(self):
        c=LabClient({'public_only':False},'ABCD'*8,'a',lambda _:None)
        peer={'udp':[['127.0.0.1',4894+i] for i in range(8)],'profile':{'port_pattern':{'validated':True,'step':0}}}
        targets=c.targets(peer);self.assertIn(('127.0.0.1',4892),targets);self.assertIn(('127.0.0.1',4893),targets)
        self.assertIn(('127.0.0.1',4902),targets);self.assertIn(('127.0.0.1',4905),targets)
        self.assertGreater(len(targets),8);self.assertLessEqual(len(targets),24)
    def test_bracketed_cross_ip_mapping(self):
        class DummySocket:
            def getsockname(self):return ('127.0.0.1',12345)
            def close(self):pass
        cfg={'access':secrets.token_hex(32),'host':'127.0.0.1','stun_hosts':['example.invalid']}
        m=Measurements(cfg,'127.0.0.1',0,threading.Event(),lambda _:None)
        for before,after,alternate,expected in [(100,100,200,'different_between_destination_ips'),(100,100,100,'same_for_tested_destination_ips'),(100,101,200,'undetermined'),(None,100,200,'undetermined')]:
            replies=[{'endpoint':['1.1.1.1',v]} if v else None for v in (before,after)]
            with patch('measure.public_dns',return_value='8.8.8.8'),patch.object(m,'socket',return_value=DummySocket()),patch.object(m,'query',side_effect=replies),patch.object(m,'binding_on_socket',return_value={'endpoint':['1.1.1.1',alternate]}):
                r=m.cross_ip_mapping();self.assertEqual(r['classification'],expected);self.assertEqual(r['trials'][0]['local_port'],12345)
    def test_tcp_reflection_reports_failure_stage(self):
        cfg={'access':secrets.token_hex(32),'host':'127.0.0.1'};m=Measurements(cfg,'127.0.0.1',0,threading.Event(),lambda _:None)
        class FakeSocket:
            def settimeout(self,*a):pass
            def getsockname(self):return ('127.0.0.1',12345)
            def connect(self,*a):pass
            def sendall(self,*a):pass
            def makefile(self,*a):raise TimeoutError('read stalled')
            def close(self):pass
        with patch('measure.raw_socket',return_value=FakeSocket()):
            result=m.tcp_observe(123);self.assertEqual(result['stage'],'read_observation');self.assertEqual(result['local_port'],12345)
    def test_timer_waits_for_both(self):
        c=PairClock(180,300)
        self.assertEqual(c.step(100,False),(False,0,False));self.assertEqual(c.step(240,True),(True,0,False))
        self.assertEqual(c.step(300,True),(False,60,False));self.assertEqual(c.step(420,True),(False,180,True))
        c=PairClock(180,300);c.step(100,False);self.assertTrue(c.step(400,False)[2]);self.assertIsNone(c.started)
    def test_live_discovery_correlation_and_expiry(self):
        d=LiveDiscovery(False);d.set_ticket(secrets.token_hex(32));s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.bind(('127.0.0.1',0));d.attach(0,s)
        try:
            obj=unpack(bytes.fromhex(d.ticket),d.request(0,100));record={'slot':0,'endpoint':['127.0.0.1',3456],'nonce':obj['n'],'age_seconds':1,'epoch':d.epoch}
            self.assertEqual(len(d.accept([record],'server_observed_tls',101)),1);self.assertEqual(d.endpoints(101),[['127.0.0.1',3456]])
            d.accept([{**record,'nonce':'00'*16}],'server_observed_tls',102);self.assertEqual(d.rejected,1)
            d.accept([{**record,'slot':1}],'server_observed_tls',102);self.assertEqual(d.rejected,2)
            self.assertEqual(d.endpoints(116),[]);d.accept([record],'server_observed_tls',116);self.assertEqual(d.rejected,3)
            self.assertFalse(LabClient({},'ABCD'*8,'a',lambda e:None).udp_direct)
        finally:s.close()
    def test_server_does_not_trust_claimed_ticket(self):
        access=secrets.token_hex(32);service=LabServer(access,False);ticket=secrets.token_hex(32);ticket_id=hashlib.sha256(bytes.fromhex(ticket)).hexdigest()
        member={'ticket':ticket,'observed':{},'epoch':'33'*16,'last':time.monotonic()};service.tickets[ticket_id]=member
        class Sender:
            def sendto(self,*args):pass
        service.udp=[Sender(),Sender()]
        obj={'k':'observe','n':secrets.token_hex(16),'slot':0,'epoch':member['epoch'],'ticket_id':ticket_id}
        service.udp_receive(pack(bytes.fromhex(access),obj),('127.0.0.1',3333),0);self.assertFalse(member['observed'])
        service.udp_receive(pack(bytes.fromhex(ticket),obj),('127.0.0.1',3333),0);self.assertEqual(member['observed'][0]['endpoint'],['127.0.0.1',3333])
        member['last']=time.monotonic()-31;member['observed'].clear();service.udp_receive(pack(bytes.fromhex(ticket),obj),('127.0.0.1',4444),0);self.assertFalse(member['observed'])
    def test_tls_discovery_when_all_observer_udp_replies_drop(self):
        service=Service();service.service.test_drop_observer_responses=True
        profile={'same_ip_filtering':'undetermined','cross_ip_filtering':'undetermined','port_pattern':{'validated':False},'scope':'loopback_fault_injection'}
        clients=[LabClient(service.cfg,secrets.token_hex(16),'a',lambda e:None)]
        code=secrets.token_hex(16);clients=[LabClient(service.cfg,code,n,lambda e:None) for n in ('a','b')]
        threads=[threading.Thread(target=c.run) for c in clients]
        try:
            with patch.object(Measurements,'run',return_value=profile):
                threads[0].start();time.sleep(2);threads[1].start()
                for t in threads:t.join(25);self.assertFalse(t.is_alive())
            for c in clients:
                self.assertTrue(c.udp_direct,c.summary());self.assertTrue(c.tcp_direct,c.summary());self.assertGreater(c.stats['udp_probe_acks'],3,c.summary())
                self.assertGreater(c.stats['udp_probe_tx'],0);self.assertGreater(c.stats['observer_tls_reports'],0)
                self.assertEqual(c.stats['observer_udp_replies'],0);self.assertEqual(c.stats['tcp_local_errors'],0)
                testing=next(e for e in c.logs if e['event']=='testing');self.assertTrue(testing['own_candidates'] and testing['peer_candidates'])
        finally:
            for c in clients:c.stop.set()
            for t in threads:
                if t.ident:t.join(5)
            service.stop()
    def test_slow_tcp_has_no_concurrent_outbound_reuse(self):
        service=Service();service.cfg['tcp_simultaneous_enabled']=False;code=secrets.token_hex(16);clients=[LabClient(service.cfg,code,n,lambda e:None) for n in ('a','b')]
        threads=[threading.Thread(target=c.run) for c in clients];active={c.id:0 for c in clients};peak=dict(active);lock=threading.Lock()
        original=LabClient.tcp_task
        def task(client,*args):
            with lock:active[client.id]+=1;peak[client.id]=max(peak[client.id],active[client.id])
            try:return original(client,*args)
            finally:
                with lock:active[client.id]-=1
        def slow_echo(*args):time.sleep(1.6)
        profile={'same_ip_filtering':'undetermined','cross_ip_filtering':'undetermined','port_pattern':{'validated':False},'scope':'loopback_slow_tcp_fault_injection'}
        try:
            with patch.object(Measurements,'run',return_value=profile),patch.object(LabClient,'tcp_task',task),patch.object(LabClient,'tcp_exchange',slow_echo):
                for t in threads:t.start()
                for t in threads:t.join(25);self.assertFalse(t.is_alive())
            for c in clients:
                self.assertEqual(peak[c.id],1);self.assertEqual(c.stats['tcp_local_errors'],0,c.summary());self.assertGreater(c.stats['tcp_attempts'],2)
                self.assertFalse(c.tcp_direct);self.assertTrue(c.udp_direct)
        finally:
            for c in clients:c.stop.set()
            for t in threads:
                if t.ident:t.join(5)
            service.stop()
    def test_simultaneous_local_conflict_backs_off_without_network_failure(self):
        c=LabClient({},'ABCD'*8,'a',lambda _:None);c.bind='127.0.0.1';c.index=0
        class RejectSocket:
            def settimeout(self,*a):pass
            def getsockname(self):return ('127.0.0.1',12345)
            def connect(self,*a):raise OSError(98,'Address already in use')
            def close(self):pass
        at=time.monotonic()
        with patch('client.raw_socket',return_value=RejectSocket()):c.tcp_task(('127.0.0.1',23456),{'id':'11'*16},12345,'simultaneous_open')
        self.assertEqual(c.stats['tcp_network_attempts'],0);self.assertEqual(c.stats['tcp_local_errors'],1)
        self.assertGreaterEqual(c.tcp_active_disabled_until,at+9);self.assertFalse(c.tcp_direct)
    def test_authenticated_frames(self):
        key=b'k';frame=pack(key,{'k':'probe'});self.assertEqual(unpack(key,frame),{'k':'probe'})
        self.assertIsNone(unpack(b'other',frame));self.assertIsNone(unpack(key,frame[:-1]+b'!'))
    def test_invalid_frames(self):
        for frame in (b'',b'NPL9',b'NPL9'+b'x'*4000):self.assertIsNone(unpack(b'k',frame))
        with self.assertRaises(ValueError):pack(b'k',{'s':'x'*4000})
    def test_endpoint_limits(self):
        for ep in (['127.0.0.1',10],['::1',10],['1.1.1.1',True],['1.1.1.1',65536],None):self.assertIsNone(endpoint(ep))
        self.assertEqual(endpoint(['1.1.1.1',10]),('1.1.1.1',10))
    def test_holdout(self):
        self.assertTrue(pattern(list(range(100,108)))['validated']);self.assertTrue(pattern([100]*8)['validated'])
        self.assertFalse(pattern([100,101,102,103,104,105,110,111])['validated'])
        self.assertFalse(pattern([100,101,None,103,104,105,106,107])['validated'])
        self.assertFalse(pattern([100,102,101,103,104,105,106,107])['validated'])
    def test_room_keys(self):
        self.assertEqual(room_keys('abcd-'*8),room_keys('ABCD'*8))
        with self.assertRaises(ValueError):room_keys('short')
    def test_stun_parse(self):
        tx=secrets.token_bytes(12);ip=socket.inet_aton('1.2.3.4');encoded=bytes(a^b for a,b in zip(ip,struct.pack('!I',COOKIE)))
        body=struct.pack('!HHBBH',0x20,8,0,1,1234^(COOKIE>>16))+encoded
        body+=struct.pack('!HHBBH',0x802c,8,0,1,3479)+socket.inet_aton('5.6.7.8')
        data=struct.pack('!HHI',0x101,len(body),COOKIE)+tx+body
        self.assertEqual(parse_stun(data,tx)['mapped'],('1.2.3.4',1234));self.assertEqual(parse_stun(data,tx)['other'],('5.6.7.8',3479))
        self.assertIsNone(parse_stun(data,bytes(12)));self.assertIsNone(parse_stun(data[:-1],tx))
    def test_budget(self):
        b=Budget();self.assertTrue(b.admit(1,1));self.assertFalse(b.admit(2,1.01))
        for i in range(1,128):self.assertTrue(b.admit(i+1,1+i*.051))
        self.assertFalse(b.admit(200,8));self.assertTrue(b.admit(200,17))
    def test_udp_false_ack(self):
        a=LabClient({'public_only':False},'ABCD'*8,'a',lambda e:None);b=LabClient({'public_only':False},'ABCD'*8,'b',lambda e:None)
        a.peer={'id':b.id,'udp':[['127.0.0.1',10]]};s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.bind(('127.0.0.1',0))
        try:
            nonce=secrets.token_hex(16);frame=pack(a.key,{'k':'ack','from':b.id,'to':a.id,'n':nonce})
            a.receive_udp(s,frame,('127.0.0.1',10));self.assertFalse(a.udp_direct)
            nonce=secrets.token_hex(16);a.pending[nonce]=(s,('127.0.0.1',10),time.monotonic())
            frame=pack(a.key,{'k':'ack','from':b.id,'to':a.id,'n':nonce});a.receive_udp(s,frame,('127.0.0.1',11));self.assertTrue(a.udp_direct)
            a.receive_udp(s,frame,('127.0.0.1',11));self.assertEqual(a.stats['udp_probe_acks'],1)
        finally:s.close()
    def test_ack_queue_priority(self):
        a=LabClient({'public_only':False},'ABCD'*8,'a',lambda e:None);b=LabClient({'public_only':False},'ABCD'*8,'b',lambda e:None)
        a.peer={'id':b.id,'udp':[['127.0.0.1',10]]};s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
        try:
            a.budget.at=time.monotonic();a.receive_udp(s,pack(a.key,{'k':'probe','from':b.id,'to':a.id,'n':secrets.token_hex(16)}),('127.0.0.1',10))
            self.assertEqual(len(a.replies),1);self.assertFalse(a.udp_direct)
        finally:s.close()
    def test_control_candidates_are_not_direct(self):
        a=LabClient({'public_only':False},'ABCD'*8,'a',lambda e:None)
        a.peer={'id':'11'*16,'udp':[['127.0.0.1',10000]],'tcp':[['127.0.0.1',10001]],'profile':{'port_pattern':{'validated':True,'step':1}}}
        self.assertLessEqual(len(a.targets(a.peer)),24)
        self.assertFalse(a.summary()['result']['udp_direct_verified']);self.assertFalse(a.summary()['result']['tcp_direct_verified'])
    def test_tcp_echo_and_simultaneous_active(self):
        for simultaneous in (False,True):
            a=LabClient({},'ABCD'*8,'a',lambda e:None);b=LabClient({},'ABCD'*8,'b',lambda e:None)
            x,y=socket.socketpair();errors=[]
            def worker():
                try:b.tcp_exchange(y,simultaneous,{'id':a.id})
                except Exception as e:errors.append(e)
            thread=threading.Thread(target=worker);thread.start()
            try:a.tcp_exchange(x,True,{'id':b.id});thread.join(5);self.assertFalse(errors);self.assertTrue(a.tcp_direct and b.tcp_direct)
            finally:x.close();y.close();thread.join(3)
    def test_observers_and_pair(self):
        service=Service()
        try:
            m=Measurements(service.cfg,'127.0.0.1',0,threading.Event(),lambda _:None);s=m.socket()
            try:
                baseline=m.query(s,m.base);self.assertIsNotNone(baseline)
                self.assertIsNotNone(m.query(s,m.base,'cross'));self.assertEqual(m.tcp_observe(m.base)['endpoint'][0],'127.0.0.1')
            finally:s.close()
            code=secrets.token_hex(16);clients=[LabClient(service.cfg,code,n,lambda _:None) for n in ('a','b')]
            threads=[threading.Thread(target=c.run) for c in clients]
            for t in threads:t.start()
            for t in threads:t.join(30);self.assertFalse(t.is_alive())
            for c in clients:
                self.assertFalse([e for e in c.logs if e['event']=='error'],c.logs)
                self.assertTrue(c.udp_direct,c.summary());self.assertTrue(c.tcp_direct,c.summary());self.assertGreater(c.stats['udp_probe_acks'],3,c.summary())
        finally:service.stop()

if __name__=='__main__':unittest.main(verbosity=2)
