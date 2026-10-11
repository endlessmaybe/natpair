import asyncio
import json
import secrets
import socket
import ssl
import threading
import time
import unittest
from unittest.mock import patch
from client import LabClient
from controlstream import ControlStream
from controludp import ReliableState, encode, decode, udp_tls_connect
from controludp_server import UDPControlServer, TLSControlProxy
from net import tls_connect
from test_lab import Service


class UDPService:
    def __init__(self, service):
        self.service = service
        async def begin():
            server = UDPControlServer(service.access, ('127.0.0.1', service.cfg['lab_control_port']))
            transport, _ = await service.loop.create_datagram_endpoint(lambda: server, local_addr=('127.0.0.1', 0))
            return server, transport.get_extra_info('sockname')[1]
        self.server, self.port = asyncio.run_coroutine_threadsafe(begin(), service.loop).result(3)
        self.cfg = {**service.cfg, 'control_udp_port': self.port, '_control_route_order': ['udp']}

    def stop(self):
        asyncio.run_coroutine_threadsafe(self.server.stop(), self.service.loop).result(3)


class Recovery111Tests(unittest.TestCase):
    def test_preflight_candidates_do_not_join_rooms_and_winner_completes_join(self):
        service = Service();stop = threading.Event();stream = None
        proxy = TLSControlProxy(service.access, ('127.0.0.1', service.cfg['lab_control_port']), service.cfg['pin'])
        async def begin():
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(service.cert, service.keyfile)
            listener = await asyncio.start_server(proxy.handle, '127.0.0.1', 0, ssl=context, limit=32768)
            port = listener.sockets[0].getsockname()[1]
            udp = UDPControlServer(service.access, ('127.0.0.1', port))
            transport, _ = await service.loop.create_datagram_endpoint(lambda: udp, local_addr=('127.0.0.1', 0))
            return listener, port, udp, transport.get_extra_info('sockname')[1]
        listener, port, udp, udp_port = asyncio.run_coroutine_threadsafe(begin(), service.loop).result(3)
        try:
            for route in ('system', 'udp'):
                cfg = {**service.cfg, 'lab_control_port': port, 'control_udp_port': udp_port,
                       'control_preflight': True, 'control_transports': [route]}
                events=[]
                raw, winner = tls_connect(cfg, '127.0.0.1', 0, emit=lambda **e: events.append(e), stop=stop)
                self.assertEqual(winner, route)
                self.assertTrue(any(e['stage'] == 'application_ready' for e in events))
                self.assertFalse(service.service.rooms)
                stream = ControlStream(raw)
                stream.sendall(json.dumps({'access': service.access, 'room': secrets.token_hex(32),
                    'id': secrets.token_hex(16), 'resume': secrets.token_hex(16), 'name': 'preflight',
                    'version': '0.9.4-lab'}).encode() + b'\n')
                self.assertEqual(json.loads(stream.readline(stop, 3))['k'], 'joined')
                stream.sendall(b'{"k":"poll"}\n')
                self.assertEqual(json.loads(stream.readline(stop, 3))['k'], 'peers')
                stream.close();stream = None
                deadline = time.monotonic() + 3
                while service.service.rooms and time.monotonic() < deadline:time.sleep(.02)
        finally:
            if stream:stream.close()
            async def end():
                await udp.stop();await proxy.stop();listener.close();await listener.wait_closed()
            asyncio.run_coroutine_threadsafe(end(), service.loop).result(3)
            service.stop()

    def test_join_confirmation_starts_observation_before_first_room_snapshot(self):
        service = Service()
        cfg = {**service.cfg, 'fast_start': True, 'raw_tcp_experiment': False,
               'unlimited_search': True, 'production_mode': True, 'control_reply_timeout': 4}
        client = LabClient(cfg, secrets.token_hex(16), 'initial-prepare')
        original = service.service.send
        async def send(member, obj):
            if obj.get('k') != 'peers':await original(member, obj)
        thread = threading.Thread(target=client.run)
        try:
            with patch.object(service.service, 'send', side_effect=send):
                thread.start();deadline = time.monotonic() + 3
                while time.monotonic() < deadline and client.stats['observer_requests'] == 0:time.sleep(.02)
                self.assertTrue(client.joined.is_set())
                self.assertTrue(client.prepared)
                self.assertGreater(client.stats['observer_requests'], 0)
                self.assertEqual(client.control_health['application_replies'], 0)
                self.assertEqual(client.stats['udp_probe_tx'], 0)
        finally:
            client.stop.set();thread.join(5);service.stop()

    def test_fragment_loss_reorder_duplicates_ack_loss_and_invalid_auth(self):
        root = secrets.token_bytes(32);ident = secrets.token_bytes(16)
        client = ReliableState(root, ident);server = ReliableState(root, ident, True)
        payloads = [secrets.token_bytes(63000), b'next-frame']
        for payload in payloads:client.queue(payload)
        wire = [];acks = [];result = bytearray()
        for step in range(20):client.tick(wire.append, 1 + step * .001)
        for packet in reversed(wire[1:]):result.extend(server.receive(packet, acks.append, 1))
        self.assertEqual(result, b'')
        self.assertFalse(server.receive(wire[0][:-1] + bytes([wire[0][-1] ^ 1]), acks.append, 1))
        wire = []
        for step in range(20):client.tick(wire.append, 2 + step * .001)
        for packet in reversed(wire):result.extend(server.receive(packet, acks.append, 2))
        self.assertEqual(result, b''.join(payloads))
        # Drop the entire first ACK batch; duplicate stream data must not replay.
        wire = []
        for step in range(20):client.tick(wire.append, 4 + step * .001)
        acks = []
        for packet in wire:self.assertFalse(server.receive(packet, acks.append, 4))
        for packet in acks:client.receive(packet, lambda p: None, 4)
        self.assertEqual(len(client.outgoing), 0)
        self.assertGreater(client.stats['retransmissions'], 0)

    def test_udp_pinned_tls_join_large_profile_and_both_room_members(self):
        service = Service();udp = UDPService(service);streams = [];stop = threading.Event()
        try:
            room = secrets.token_hex(32)
            for name in ('a', 'b'):
                raw = udp_tls_connect(udp.cfg, '127.0.0.1', 0, stop)
                stream = ControlStream(raw);streams.append(stream)
                stream.sendall(json.dumps({'access': service.access, 'room': room, 'id': secrets.token_hex(16),
                    'resume': secrets.token_hex(16), 'name': name, 'version': '0.9.4-lab'}).encode() + b'\n')
                self.assertEqual(json.loads(stream.readline(stop, 3))['k'], 'joined')
                stream.sendall(json.dumps({'k': 'profile', 'profile': {'padding': 'x' * 21000}}).encode() + b'\n')
                self.assertEqual(json.loads(stream.readline(stop, 3))['k'], 'peers')
            for stream in streams:
                stream.sendall(b'{"k":"poll"}\n')
                reply = json.loads(stream.readline(stop, 3))
                self.assertEqual(len(reply['peers']), 1)
                self.assertEqual(len(reply['peers'][0]['profile']['padding']), 21000)
                self.assertGreater(stream.channel.transport_stats()['acked_messages'], 0)
            wrong = {**udp.cfg, 'pin': '00' * 32}
            with self.assertRaisesRegex(RuntimeError, '指纹'):
                udp_tls_connect(wrong, '127.0.0.1', 0, stop)
        finally:
            for stream in streams:stream.close()
            udp.stop();service.stop()

    def test_client_udp_only_late_peer_restart_and_unlimited_probes(self):
        service = Service();udp = UDPService(service)
        cfg = {**udp.cfg, 'fast_start': True, 'raw_tcp_experiment': False, 'unlimited_search': True,
               'production_mode': True, 'control_reply_timeout': 4}
        code = secrets.token_hex(16);clients = [LabClient(cfg, code, name) for name in ('a', 'b')]
        threads = [threading.Thread(target=c.run) for c in clients]
        original = udp_tls_connect
        # Force TCP candidates to fail, so this proves UDP coordination alone.
        def connect(cfg, bind, index, emit=None, stop=None):
            return original(cfg, bind, index, stop), 'udp'
        try:
            with patch('client.tls_connect', side_effect=connect), patch.object(LabClient, 'receive_udp', return_value=None):
                threads[0].start()
                deadline = time.monotonic() + 8
                while time.monotonic() < deadline and clients[0].room_members() != 1:time.sleep(.05)
                self.assertEqual(clients[0].room_members(), 1)
                self.assertEqual(clients[0].stats['udp_probe_tx'], 0)
                threads[1].start()
                deadline = time.monotonic() + 15
                while time.monotonic() < deadline and not all(c.stats['udp_probe_tx'] > 100 for c in clients):time.sleep(.05)
                self.assertTrue(all(c.stats['udp_probe_tx'] > 100 for c in clients))
                ports = [[s.getsockname()[1] for s in c.udp] for c in clients]
                before = [c.stats['udp_probe_tx'] for c in clients]
                async def disconnect():
                    for session in list(udp.server.sessions.values()):session['task'].cancel()
                asyncio.run_coroutine_threadsafe(disconnect(), service.loop).result(3)
                deadline = time.monotonic() + 12
                while time.monotonic() < deadline and not all(c.control_reconnects >= 1 for c in clients):time.sleep(.05)
                self.assertTrue(all(c.control_reconnects >= 1 for c in clients))
                self.assertTrue(all(c.stats['udp_probe_tx'] > n for c, n in zip(clients, before)))
                self.assertEqual([[s.getsockname()[1] for s in c.udp] for c in clients], ports)
                self.assertTrue(all(c.budget.interval == 0 and c.budget.pressure is None for c in clients))
                self.assertFalse([e for c in clients for e in c.logs if e['event'] == 'error'])
        finally:
            for c in clients:c.stop.set()
            for t in threads:
                if t.ident:t.join(5)
            udp.stop();service.stop()
        self.assertTrue(all(not t.is_alive() for t in threads))


if __name__ == '__main__':unittest.main(verbosity=2)
