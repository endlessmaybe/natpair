import json,pathlib,secrets,socket,threading,time,unittest
from types import SimpleNamespace
from unittest.mock import patch
from client import LabClient
from net import tls_connect,raw_socket
from tailbridge import read_metadata
from test_lab import Service
from wire import pack

ROOT=pathlib.Path(__file__).parent
class OnceBlocked:
    def __init__(self):self.calls=[];self.once=True
    def fileno(self):return 123
    def getsockname(self):return ('127.0.0.1',23456)
    def sendto(self,data,target):
        self.calls.append((data,target))
        if self.once:self.once=False;raise BlockingIOError(10035,'injected would block')
        return len(data)

class RetryTests(unittest.TestCase):
    def client(self):
        c=LabClient({'unlimited_search':True},secrets.token_hex(16),'retry');s=OnceBlocked();c.udp=[s];return c,s
    def test_observer_retries_exact_nonce_without_crashing_or_false_counter(self):
        c,s=self.client();c.discovery.set_ticket(secrets.token_hex(32));c.discovery.attach(0,s);m=SimpleNamespace(host='127.0.0.1',base=30000)
        self.assertFalse(c.send_observer(m,0,100));self.assertEqual(c.stats['observer_requests'],0)
        self.assertTrue(c.send_observer(m,0,100.01));self.assertEqual(c.stats['observer_requests'],1)
        self.assertEqual(s.calls[0],s.calls[1]);self.assertEqual(len(c.discovery.pending),1)
        self.assertEqual(c.observer_retries,{})
    def test_observer_ticket_change_discards_stale_retry(self):
        c,s=self.client();c.discovery.set_ticket(secrets.token_hex(32));c.discovery.attach(0,s);m=SimpleNamespace(host='127.0.0.1',base=30000)
        c.send_observer(m,0,100);c.discovery.set_ticket(secrets.token_hex(32));self.assertTrue(c.send_observer(m,0,100.1));self.assertNotEqual(s.calls[0][0],s.calls[1][0])
    def test_ack_remains_queued_until_send_acceptance(self):
        c,s=self.client();packet=pack(c.key,{'k':'ack','n':secrets.token_hex(16),'from':c.id,'to':'11'*16});c.replies.append((s,('127.0.0.1',30000),packet))
        self.assertFalse(c.send_reply(100));self.assertEqual(len(c.replies),1)
        self.assertTrue(c.send_reply(100.01));self.assertEqual(len(c.replies),0);self.assertEqual(s.calls[0],s.calls[1])
    def test_reverse_challenge_not_lost_on_would_block(self):
        c,s=self.client();c.challenges.append((s,('127.0.0.1',30000),{'nonce':'22'*16,'sha256':'33'*32,'journal_seq':1}))
        self.assertFalse(c.send_challenge({'id':'11'*16},100));self.assertEqual(len(c.challenges),1);self.assertEqual(c.stats['udp_probe_tx'],0)
        self.assertTrue(c.send_challenge({'id':'11'*16},100.01));self.assertEqual(len(c.challenges),0);self.assertEqual(c.stats['udp_probe_tx'],1)
    def test_fatal_socket_error_not_hidden(self):
        c,s=self.client();s.sendto=lambda *args:(_ for _ in ()).throw(OSError(10049,'invalid address'))
        with self.assertRaises(OSError):c.send_udp(s,b'x',('127.0.0.1',30000),100,'observer')
    def test_backpressure_yield_does_not_reintroduce_packet_or_target_budgets(self):
        c,s=self.client();c.send_udp(s,b'x',('127.0.0.1',1),100,'probe')
        self.assertFalse(c.send_udp(s,b'x',('127.0.0.1',2),100.0005,'probe'));self.assertEqual(len(s.calls),1)
        self.assertTrue(c.send_udp(s,b'x',('127.0.0.1',2),100.002,'probe'))
        self.assertTrue(c.send_udp(s,b'x',('127.0.0.1',3),100.002,'probe'))
        self.assertEqual(c.budget.interval,0);self.assertIsNone(c.budget.pressure)
    def test_two_endpoints_survive_observer_probe_and_ack_blocking(self):
        service=Service();cfg={**service.cfg,'unlimited_search':True,'fast_start':True,'immediate_challenge':True,'fast_center_search':True,'raw_tcp_experiment':False}
        code=secrets.token_hex(16);clients=[LabClient(cfg,code,n) for n in ('a','b')];threads=[threading.Thread(target=c.run) for c in clients];faults=[]
        class FaultSocket:
            def __init__(self,s):self.s=s;self.seen=set()
            def __getattr__(self,n):return getattr(self.s,n)
            def sendto(self,data,target):
                kind=json.loads(data[4:-32]).get('k') if data.startswith(b'NPL9') else 'cipher'
                if kind in ('observe','probe','ack') and kind not in self.seen:
                    self.seen.add(kind);faults.append(kind);raise BlockingIOError(10035,'injected '+kind)
                return self.s.sendto(data,target)
        def factory(kind,*args,**kwargs):
            s=raw_socket(kind,*args,**kwargs);return FaultSocket(s) if kind==socket.SOCK_DGRAM else s
        try:
            with patch('measure.raw_socket',side_effect=factory):
                for t in threads:t.start()
                for t in threads:t.join(20);self.assertFalse(t.is_alive())
            for c in clients:
                self.assertTrue(c.udp_direct,c.summary());self.assertGreater(c.stats['udp_probe_acks'],3)
                self.assertGreater(c.stats.get('udp_send_backpressure',0),0)
                self.assertFalse([e for e in c.logs if e['event']=='error'],c.summary())
                self.assertEqual(c.stats['tcp_attempts'],0)
            self.assertEqual(set(faults),{'observe','probe','ack'})
            (ROOT/'retry-integration-check.json').write_text(json.dumps({'passed':True,'scope':'two real loopback UDP endpoints with injected WSAEWOULDBLOCK for observer/probe/ack','fault_kinds':faults,'clients':[{'acks':c.stats['udp_probe_acks'],'backpressure':c.stats.get('udp_send_backpressure',0)} for c in clients]},indent=2),encoding='utf-8')
        finally:
            for c in clients:c.stop.set()
            for t in threads:
                if t.ident:t.join(5)
            service.stop()

class ControlTests(unittest.TestCase):
    def test_stalled_physical_route_does_not_delay_working_system_route(self):
        service=Service();closed=threading.Event();events=[]
        class Blocked:
            def settimeout(self,*args):pass
            def connect(self,*args):closed.wait(6);raise TimeoutError('physical stalled')
            def close(self):closed.set()
        channel=None;at=time.monotonic()
        try:
            with patch('net.raw_socket',return_value=Blocked()):channel,route=tls_connect(service.cfg,'127.0.0.1',0,emit=lambda **x:events.append(x))
            self.assertEqual(route,'system');self.assertLess(time.monotonic()-at,2);self.assertTrue(closed.wait(1))
            self.assertTrue(any(x['stage']=='connected' and x['route']=='system' for x in events))
        finally:
            if channel:channel.close()
            service.stop()
    def test_bad_pin_never_returns_a_connection(self):
        service=Service()
        try:
            with self.assertRaises(RuntimeError):tls_connect({**service.cfg,'pin':'00'*32},'127.0.0.1',0)
        finally:service.stop()
    def test_pre_cancelled_connection_does_not_open_socket(self):
        done=threading.Event();done.set()
        with patch('net.raw_socket') as factory:
            with self.assertRaises(OSError):tls_connect({'host':'invalid','pin':'00'*32},'127.0.0.1',0,stop=done)
            factory.assert_not_called()

class MetadataTests(unittest.TestCase):
    def metadata(self,ports,preferred):
        status={'BackendState':'Running'};netmap={'SelfNode':{'Key':'nodekey:local','DiscoKey':'discokey:local'},'Peers':[{'Addresses':['100.1.1.2/32'],'Key':'nodekey:peer','Endpoints':['1.1.1.1:1234']}]}
        with patch('tailbridge.command',side_effect=[json.dumps(status),json.dumps(netmap)]),patch('tailbridge.run_command',return_value=json.dumps(ports)):
            return read_metadata('100.1.1.2',preferred_port=preferred)
    def test_refresh_reuses_only_still_owned_previous_listener(self):
        self.assertEqual(self.metadata([41641,55555],41641)['udp_port'],41641)
        self.assertEqual(self.metadata([55555],41641)['udp_port'],55555)
    def test_ambiguous_unverified_listener_is_not_guessed(self):
        with self.assertRaises(RuntimeError):self.metadata([41641,55555],None)
        with self.assertRaises(RuntimeError):self.metadata([41641,55555],1234)

if __name__=='__main__':unittest.main()
