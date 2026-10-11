import asyncio
import json
import secrets
import ssl
import threading
import time
import unittest
from unittest.mock import patch

from client import LabClient
from controlstream import ControlStream
from net import tls_connect
from test_lab import Service


class Recovery112Tests(unittest.TestCase):
    def test_confirmed_empty_room_does_not_probe_previous_member(self):
        c=LabClient({'unlimited_search':True},secrets.token_hex(16),'empty')
        old={'id':'11'*16,'version':'0.9.4-lab','prepared':True,'udp':[['1.2.3.4',1234]]}
        c.cached_search_peer=old;c.cached_search_at=99
        c.connected.set();c.last_snapshot=100
        self.assertEqual(c.search_peer(None,101),(None,False))
        new={'id':'22'*16,'prepared':False}
        self.assertEqual(c.search_peer(new,101),(new,False))
        # A lost coordinator is distinct from a freshly confirmed empty room.
        c.connected.clear()
        self.assertEqual(c.search_peer(None,102),(old,True))

    def test_control_recovery_reuses_sockets_and_does_not_advance_scan(self):
        import socket
        c=LabClient({'unlimited_search':True,'public_only':False},secrets.token_hex(16),'recovery')
        sockets=[socket.socket(socket.AF_INET,socket.SOCK_DGRAM) for _ in range(2)]
        for s in sockets:s.bind(('127.0.0.1',0))
        c.udp=sockets
        peer={'id':'11'*16,'udp':[['127.0.0.1',30001],['127.0.0.1',30002]],'profile':{}}
        c.schedule.position=4321;c.fast_search.scan_position=1234
        try:
            pairs=set()
            for _ in range(500):
                s,target=c.recovery_choice(peer);pairs.add((s.fileno(),target));c.recovery_cursor+=1
            self.assertEqual(len(pairs),2)
            self.assertEqual(c.schedule.position,4321);self.assertEqual(c.fast_search.scan_position,1234)
            self.assertEqual(c.budget.interval,0);self.assertEqual(c.budget.denied,0)
        finally:
            for s in sockets:s.close()

    def test_real_send_loop_advances_rounds_without_local_slot_zero_observation(self):
        service=Service()
        cfg={**service.cfg,'production_mode':True,'unlimited_search':True,'fast_start':True,
             'fast_center_search':True,'coordinated_scan':True,'phased_search':True,
             'coordination_window_seconds':1,'raw_tcp_experiment':False}
        code=secrets.token_hex(16);clients=[LabClient(cfg,code,str(i)) for i in range(2)]
        threads=[threading.Thread(target=c.run) for c in clients]
        try:
            with patch.object(clients[0].discovery,'slot_endpoint',return_value=None),patch.object(LabClient,'receive_udp',return_value=None):
                for t in threads:t.start()
                deadline=time.monotonic()+12
                while time.monotonic()<deadline and not all(c.coord.round>=2 for c in clients):time.sleep(.02)
                self.assertTrue(all(c.coord.round>=2 for c in clients),[c.summary() for c in clients])
                self.assertFalse(clients[0].cached_search_active)
                self.assertTrue(all(c.stats['udp_probe_tx']>100 for c in clients))
        finally:
            for c in clients:c.stop.set()
            for t in threads:t.join(6)
            service.stop()

    def test_observer_expiry_does_not_freeze_fresh_coordination(self):
        c=LabClient({'unlimited_search':True},secrets.token_hex(16),'expiry')
        peer={'id':'11'*16,'version':'0.9.4-lab','prepared':True,'udp':[['1.2.3.4',1234]],'profile':{}}
        c.cached_search_peer={**peer,'udp':[['1.2.3.4',1111]]}
        c.cached_search_at=1;c.connected.set();c.last_snapshot=100
        self.assertEqual(c.search_peer(peer,101,False),(peer,False))
        c.connected.clear()
        self.assertEqual(c.search_peer(None,102,False),(c.cached_search_peer,True))

    def test_overlay_control_fallback_uses_same_pinned_service_and_room(self):
        service=Service();stream=None;stop=threading.Event()
        async def extra():
            context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(service.cert,service.keyfile)
            return await asyncio.start_server(service.service.control,'127.0.0.2',service.cfg['lab_control_port'],ssl=context,limit=32768)
        listener=asyncio.run_coroutine_threadsafe(extra(),service.loop).result(3)
        try:
            cfg={**service.cfg,'control_tail_host':'127.0.0.2','control_transports':['tail'],
                 'control_preflight':True}
            raw,route=tls_connect(cfg,'127.0.0.1',0,stop=stop)
            self.assertEqual(route,'tail');self.assertFalse(service.service.rooms)
            stream=ControlStream(raw)
            stream.sendall(json.dumps({'access':service.access,'room':secrets.token_hex(32),
                'id':secrets.token_hex(16),'resume':secrets.token_hex(16),'name':'fallback','version':'0.9.4-lab'}).encode()+b'\n')
            self.assertEqual(json.loads(stream.readline(stop,3))['k'],'joined')
            stream.sendall(b'{"k":"poll"}\n')
            self.assertEqual(json.loads(stream.readline(stop,3))['k'],'peers')
            with self.assertRaisesRegex(RuntimeError,'指纹'):
                tls_connect({**cfg,'pin':'00'*32},'127.0.0.1',0,stop=stop)
        finally:
            if stream:stream.close()
            listener.close();service.stop()

    def test_repeated_stop_restart_after_initial_control_failure_still_sends_and_authenticates(self):
        service=Service();checks=[]
        try:
            for cycle in range(5):
                cfg={**service.cfg,'production_mode':True,'unlimited_search':True,'fast_start':True,
                     'immediate_challenge':True,'fast_center_search':True,'raw_tcp_experiment':False}
                code=secrets.token_hex(16);clients=[LabClient(cfg,code,str(i)) for i in range(2)]
                threads=[threading.Thread(target=c.run) for c in clients]
                original=tls_connect;failures=[0]
                def flaky(*args,**kwargs):
                    if failures[0]<2:
                        failures[0]+=1;raise TimeoutError('initial injected failure')
                    return original(*args,**kwargs)
                try:
                    with patch('client.tls_connect',side_effect=flaky):
                        for t in threads:t.start()
                        deadline=time.monotonic()+12
                        while time.monotonic()<deadline and not all(c.udp_direct and c.stats['udp_probe_acks']>=3 for c in clients):time.sleep(.02)
                        self.assertTrue(all(c.udp_direct for c in clients),[c.summary() for c in clients])
                        self.assertTrue(all(c.stats['udp_probe_acks']>=3 for c in clients))
                        self.assertTrue(all(c.budget.interval==0 and c.budget.pressure is None for c in clients))
                finally:
                    for c in clients:c.stop.set()
                    for t in threads:t.join(6)
                self.assertFalse(any(t.is_alive() for t in threads))
                self.assertTrue(all(not [e for e in c.logs if e['event']=='error'] for c in clients))
                self.assertTrue(all(all(s.fileno()<0 for s in c.udp) for c in clients))
                checks.append({'cycle':cycle,'probe_tx':[c.stats['udp_probe_tx'] for c in clients],
                    'acks':[c.stats['udp_probe_acks'] for c in clients]})
            from pathlib import Path
            Path(__file__).with_name('repeat-recovery-check.json').write_text(json.dumps({'passed':True,'cycles':checks},indent=2),encoding='utf8')
        finally:service.stop()


if __name__=='__main__':unittest.main(verbosity=2)
