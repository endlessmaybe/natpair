import asyncio
import copy
import json
import secrets
import socket
import threading
import time
import unittest
from unittest.mock import patch

from client import LabClient
from controlstream import ControlStream
from net import tls_connect
from test_lab import Service


class Recovery110Tests(unittest.TestCase):
    def test_intentional_stop_is_not_reported_as_a_connection_failure(self):
        c=LabClient({'unlimited_search':True,'access':secrets.token_hex(32)},secrets.token_hex(16),'stop')
        c.bind='127.0.0.1';c.index=0
        class Stream:
            def sendall(self,data):pass
            def readline(self,*args,**kwargs):
                c.stop.set();raise OSError(10038,'socket closed during requested stop')
            def shutdown(self,*args):pass
            def close(self):pass
        with patch('client.tls_connect',return_value=(object(),'system')),patch('client.ControlStream',return_value=Stream()):c.control_read()
        self.assertEqual(c.control_failures,0)
        self.assertEqual(c.control_health['state'],'stopped')
        self.assertFalse([e for e in c.logs if e['event'] in ('error','control_error','control_path_failed')])

    def test_unknown_peer_never_starts_scanning(self):
        c=LabClient({'unlimited_search':True},secrets.token_hex(16),'unknown')
        self.assertEqual(c.search_peer(None,100), (None,False))
        self.assertIsNone(c.budget.pressure)
        self.assertEqual(c.budget.interval,0)

    def test_stale_control_and_observer_do_not_stop_known_peer_unlimited_search(self):
        c=LabClient({'unlimited_search':True},secrets.token_hex(16),'known')
        peer={'id':'aa'*16,'version':'0.9.4-lab','prepared':True,'udp':[['1.2.3.4',1234]],'profile':{}}
        c.cached_search_peer=copy.deepcopy(peer);c.cached_search_at=1
        # No hidden eight-second, 120-second or long-running packet cutoff.
        self.assertEqual(c.search_peer(None,86400,False), (peer,True))
        c.peer_completed=True
        self.assertEqual(c.search_peer(None,86401,False), (None,False))

    def test_fresh_peer_replaces_cached_candidates(self):
        c=LabClient({'unlimited_search':True},secrets.token_hex(16),'fresh')
        peer={'id':'aa'*16,'version':'0.9.4-lab','prepared':True,'udp':[['1.2.3.4',1234]],'profile':{}}
        c.cached_search_peer={**peer,'udp':[['4.3.2.1',4321]]};c.cached_search_at=1
        c.connected.set();c.last_snapshot=100
        self.assertEqual(c.search_peer(peer,101), (peer,False))

    def test_tls_writer_producers_never_touch_the_socket(self):
        class Socket:
            def setblocking(self,value):pass
            def send(self,*args):raise AssertionError('producer touched TLS socket')
            def close(self):pass
        stream=ControlStream(Socket())
        threads=[threading.Thread(target=lambda: [stream.sendall(b'{"k":"poll"}\n') for _ in range(1000)]) for _ in range(4)]
        for t in threads:t.start()
        for t in threads:t.join(2);self.assertFalse(t.is_alive())
        self.assertEqual(len(stream.queue),1)
        self.assertEqual(stream.stats['tx_bytes'],0)
        stream.close()

    def test_delayed_initial_join_replies_recover_without_tailscale(self):
        service=Service();client=LabClient({**service.cfg,'fast_start':True,'raw_tcp_experiment':False,
            'unlimited_search':True,'control_reply_timeout':.6},secrets.token_hex(16),'initial-recovery')
        original=service.service.send;drops=[]
        async def send(member,obj):
            if obj.get('k')=='joined' and len(drops)<2:
                drops.append(member['id']);return
            await original(member,obj)
        thread=threading.Thread(target=client.run)
        try:
            with patch.object(service.service,'send',side_effect=send):
                thread.start();deadline=time.monotonic()+12
                while time.monotonic()<deadline and not client.control_health.get('state')=='application_verified':time.sleep(.05)
                self.assertEqual(len(drops),2)
                self.assertEqual(client.control_health['state'],'application_verified',client.logs)
                self.assertGreaterEqual(client.control_failures,2)
                self.assertFalse([e for e in client.logs if e['event']=='error'])
                self.assertEqual(client.stats['udp_probe_tx'],0)
        finally:
            client.stop.set();thread.join(5);service.stop()
        self.assertFalse(thread.is_alive())

    def test_control_blackhole_keeps_sending_then_recovers_repeated_disconnects(self):
        service=Service();cfg={**service.cfg,'fast_start':True,'raw_tcp_experiment':False,
            'unlimited_search':True,'fast_center_search':True,'immediate_challenge':True,
            'coordinated_scan':True,'production_mode':True,'control_reply_timeout':3}
        code=secrets.token_hex(16);clients=[LabClient(cfg,code,name) for name in ('a','b')]
        threads=[threading.Thread(target=c.run) for c in clients]
        original=service.service.send;blackhole=threading.Event()
        async def send(member,obj):
            if blackhole.is_set() and obj.get('k')=='peers':return
            await original(member,obj)
        try:
            with patch.object(service.service,'send',side_effect=send),patch.object(LabClient,'receive_udp',return_value=None):
                for t in threads:t.start()
                deadline=time.monotonic()+12
                while time.monotonic()<deadline and not all(c.stats['udp_probe_tx']>100 for c in clients):time.sleep(.1)
                self.assertTrue(all(c.stats['udp_probe_tx']>100 for c in clients),[c.logs for c in clients])
                ports=[[s.getsockname()[1] for s in c.udp] for c in clients]
                blackhole.set();time.sleep(9)
                before=[c.stats['udp_probe_tx'] for c in clients];time.sleep(2)
                # Missing control is now a contact/recovery state, not an
                # unlimited scan against stale candidates. Normal scans still
                # have no packet or combination budget.
                self.assertTrue(all(1<=c.stats['udp_probe_tx']-n<=8 for c,n in zip(clients,before)))
                self.assertTrue(all(c.cached_search_active for c in clients))
                blackhole.clear()
                deadline=time.monotonic()+15
                while time.monotonic()<deadline and not all(c.connected.is_set() and not c.cached_search_active and c.control_health['state']=='application_verified' for c in clients):time.sleep(.1)
                self.assertTrue(all(c.connected.is_set() and not c.cached_search_active for c in clients))
                for cycle in range(3):
                    old=clients[0].control_reconnects;before=clients[0].stats['udp_probe_tx']
                    async def disconnect():
                        for room in list(service.service.rooms.values()):
                            if clients[0].id in room:room[clients[0].id]['writer'].close()
                    asyncio.run_coroutine_threadsafe(disconnect(),service.loop).result(3)
                    deadline=time.monotonic()+18
                    while time.monotonic()<deadline and not (clients[0].control_reconnects>old and clients[0].control_health['state']=='application_verified'):time.sleep(.1)
                    self.assertGreater(clients[0].control_reconnects,old)
                    self.assertGreater(clients[0].stats['udp_probe_tx'],before)
                self.assertEqual([[s.getsockname()[1] for s in c.udp] for c in clients],ports)
                for c in clients:
                    self.assertEqual(c.budget.interval,0)
                    self.assertIsNone(c.budget.pressure)
                    self.assertFalse([e for e in c.logs if e['event']=='error'])
        finally:
            blackhole.clear()
            for c in clients:c.stop.set()
            for t in threads:
                if t.ident:t.join(5)
            service.stop()
        self.assertTrue(all(not t.is_alive() for t in threads))

    def test_tls_line_survives_fragmentation_and_is_cancellable(self):
        service=Service();channel=None;stop=threading.Event()
        try:
            raw,_=tls_connect(service.cfg,'127.0.0.1',0);channel=ControlStream(raw)
            ident=secrets.token_hex(16)
            channel.sendall(json.dumps({'access':service.access,'room':'ab'*32,'id':ident,
                'resume':secrets.token_hex(16),'name':'fragment','version':'0.9.4-lab'}).encode()+b'\n')
            self.assertEqual(json.loads(channel.readline(stop,2))['k'],'joined')
            async def fragmented():
                member=service.service.rooms['ab'*32][ident]
                async with member['lock']:
                    for part in (b'{"k":',b'"fragment",',b'"ok":true}\n'):
                        member['writer'].write(part);await member['writer'].drain();await asyncio.sleep(.05)
            future=asyncio.run_coroutine_threadsafe(fragmented(),service.loop)
            self.assertEqual(json.loads(channel.readline(stop,2)),{'k':'fragment','ok':True});future.result(2)
            self.assertEqual(channel.stats['rx_frames'],2)
            stop.set()
            with self.assertRaises(OSError):channel.readline(stop,30)
        finally:
            if channel:channel.close()
            service.stop()

if __name__=='__main__':unittest.main(verbosity=2)
