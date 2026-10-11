"""Authenticated UDP to local TCP bridge; the original TLS remains end to end."""
import argparse
import asyncio
import json
import pathlib
import socket
import signal
import ssl
import hashlib
import secrets
import time
from controludp import ReliableState, decode, MAGIC


class UDPControlServer(asyncio.DatagramProtocol):
    def __init__(self, access, backend):
        self.root = bytes.fromhex(access)
        self.backend = backend
        self.sessions = {}
        self.tasks = set()
        self.stats = {'created': 0, 'closed': 0, 'rejected': 0}
        self.maintenance = None

    def connection_made(self, transport):
        self.transport = transport
        transport.get_extra_info('socket').setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1048576)
        self.maintenance = asyncio.create_task(self.tick())

    def spawn(self, coro):
        task = asyncio.create_task(coro)
        self.tasks.add(task)
        task.add_done_callback(self.tasks.discard)
        return task

    def datagram_received(self, data, addr):
        if not data.startswith(MAGIC) or len(data) < 20:
            return
        ident = data[4:20]
        session = self.sessions.get(ident)
        if session is None:
            state = ReliableState(self.root, ident, server=True)
            obj = decode(state.rx_key, data)
            # Only the first sequenced stream message creates a backend socket.
            if obj is None or obj[1] != 1 or obj[2] != 1 or len(self.sessions) >= 128:
                self.stats['rejected'] += 1
                return
            session = {'state': state, 'addr': addr, 'at': time.monotonic(),
                       'buffer': bytearray(), 'writer': None, 'wakeup': asyncio.Event()}
            self.sessions[ident] = session
            self.stats['created'] += 1
            print(json.dumps({'event': 'udp_control_open', 'session': ident.hex()[:8]}), flush=True)
            session['task'] = self.spawn(self.bridge(ident, session))
        if session['addr'] != addr:
            print(json.dumps({'event': 'udp_control_address_changed', 'session': ident.hex()[:8]}), flush=True)
            return
        state = session['state']
        if decode(state.rx_key, data) is None:
            return
        session['at'] = time.monotonic()
        session['buffer'].extend(state.receive(data, lambda packet: self.transport.sendto(packet, addr)))
        if len(session['buffer']) > 262144:
            state.closed = True
        session['wakeup'].set()

    async def bridge(self, ident, session):
        writer = None
        async def upload():
            while not session['state'].closed:
                session['wakeup'].clear()
                if session['buffer']:
                    data = bytes(session['buffer'])
                    session['buffer'].clear()
                    writer.write(data)
                    await asyncio.wait_for(writer.drain(), 5)
                await session['wakeup'].wait()

        async def download(reader):
            while not session['state'].closed:
                if len(session['state'].outgoing) >= 32:
                    await asyncio.sleep(.02)
                    continue
                data = await reader.read(16000)
                if not data:
                    return
                session['state'].queue(data)
                session['state'].tick(lambda packet: self.transport.sendto(packet, session['addr']))

        workers = []
        try:
            reader, writer = await asyncio.wait_for(asyncio.open_connection(*self.backend), 5)
            session['writer'] = writer
            workers = [asyncio.create_task(upload()), asyncio.create_task(download(reader))]
            done, _ = await asyncio.wait(workers, return_when=asyncio.FIRST_COMPLETED)
            for task in done:
                task.result()
        except (OSError, asyncio.TimeoutError) as exc:
            print(json.dumps({'event': 'udp_control_backend_error', 'message': str(exc)}), flush=True)
        finally:
            for task in workers:
                task.cancel()
            if workers:
                await asyncio.gather(*workers, return_exceptions=True)
            if writer:
                writer.close()
            if self.sessions.get(ident) is session:
                self.sessions.pop(ident, None)
            self.stats['closed'] += 1
            print(json.dumps({'event': 'udp_control_close', 'session': ident.hex()[:8], 'stats': session['state'].stats,
                              'unacked': len(session['state'].outgoing), 'rx_sequence': session['state'].rx_seq}), flush=True)
            session['state'].closed = True
            from controludp import encode
            self.transport.sendto(encode(session['state'].tx_key, ident, 3, 0), session['addr'])

    async def tick(self):
        while True:
            await asyncio.sleep(.05)
            now = time.monotonic()
            for ident, session in list(self.sessions.items()):
                if session['state'].closed or now - session['at'] > 60:
                    session['task'].cancel()
                    continue
                session['state'].tick(lambda packet, addr=session['addr']: self.transport.sendto(packet, addr))

    async def stop(self):
        if self.maintenance:
            self.maintenance.cancel()
        for task in list(self.tasks):
            task.cancel()
        await asyncio.gather(*list(self.tasks), return_exceptions=True)
        if self.maintenance:
            await asyncio.gather(self.maintenance, return_exceptions=True)
        self.transport.close()


async def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--config', required=True)
    parser.add_argument('--host', default='204.152.206.124')
    parser.add_argument('--port', type=int, default=39609)
    parser.add_argument('--backend-port', type=int, default=39610)
    parser.add_argument('--tls-port', type=int, default=39611)
    parser.add_argument('--cert', default='/opt/natpair/server.crt')
    parser.add_argument('--key', default='/opt/natpair/server.key')
    args = parser.parse_args()
    cfg = json.loads(pathlib.Path(args.config).read_text())
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(args.cert, args.key)
    pem = pathlib.Path(args.cert).read_text()
    fingerprint = hashlib.sha256(ssl.PEM_cert_to_DER_cert(pem)).hexdigest()
    proxy = TLSControlProxy(cfg['access'], (args.host, args.backend_port), fingerprint)
    tls_listener = await asyncio.start_server(proxy.handle, args.host, args.tls_port, ssl=context, limit=32768)
    service = UDPControlServer(cfg['access'], (args.host, args.tls_port))
    await asyncio.get_running_loop().create_datagram_endpoint(lambda: service, local_addr=(args.host, args.port))
    def snapshot():
        print(json.dumps({'event': 'udp_control_sessions', 'sessions': [
            {'id': ident.hex()[:8], 'stats': s['state'].stats, 'rx_sequence': s['state'].rx_seq,
             'outgoing_missing': {str(seq): sorted(v['missing']) for seq, v in s['state'].outgoing.items()},
             'incoming_fragments': {str(seq): {'count': v['count'], 'received': sorted(v['chunks'])}
                                    for seq, v in s['state'].parts.items()}}
            for ident, s in service.sessions.items()]}), flush=True)
    if hasattr(signal, 'SIGUSR1'):
        asyncio.get_running_loop().add_signal_handler(signal.SIGUSR1, snapshot)
    print('NATPair reliable UDP coordinator ready', flush=True)
    try:
        await asyncio.Event().wait()
    finally:
        await service.stop()
        tls_listener.close()
        await tls_listener.wait_closed()
        await proxy.stop()


class TLSControlProxy:
    """Authenticated preflight before any room joins; existing coordinator state."""
    def __init__(self, access, backend, pin):
        self.access = access
        self.backend = backend
        self.pin = pin
        self.active = set()

    async def handle(self, reader, writer):
        task = asyncio.current_task()
        backend_writer = None
        workers = []
        if len(self.active) >= 128:
            writer.close()
            return
        self.active.add(task)
        try:
            line = await asyncio.wait_for(reader.readline(), 10)
            obj = json.loads(line)
            if (obj.get('k') != 'control_health' or obj.get('access') != self.access
                    or not isinstance(obj.get('nonce'), str) or len(obj['nonce']) != 32
                    or not isinstance(obj.get('padding', ''), str) or len(obj.get('padding', '')) > 4096):
                return
            writer.write(json.dumps({'k': 'control_ready', 'nonce': obj['nonce'], 'padding': obj.get('padding','')}, separators=(',', ':')).encode() + b'\n')
            await asyncio.wait_for(writer.drain(), 5)
            # A losing candidate never joins a room. Connect the old coordinator
            # only after this generation is chosen and sends its JOIN.
            join = await asyncio.wait_for(reader.readline(), 10)
            if not join:
                return
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            backend_reader, backend_writer = await asyncio.wait_for(
                asyncio.open_connection(*self.backend, ssl=context, server_hostname=self.backend[0]), 5)
            certificate = backend_writer.get_extra_info('ssl_object').getpeercert(binary_form=True)
            if not secrets.compare_digest(hashlib.sha256(certificate).hexdigest(), self.pin):
                raise OSError('local_backend_certificate_mismatch')
            backend_writer.write(join)
            await asyncio.wait_for(backend_writer.drain(), 5)
            async def pipe(source, target):
                while True:
                    data = await source.read(16384)
                    if not data:
                        return
                    target.write(data)
                    await asyncio.wait_for(target.drain(), 10)
            workers = [asyncio.create_task(pipe(reader, backend_writer)),
                       asyncio.create_task(pipe(backend_reader, writer))]
            done, _ = await asyncio.wait(workers, return_when=asyncio.FIRST_COMPLETED)
            for future in done:
                future.result()
        except (ValueError, OSError, asyncio.TimeoutError) as exc:
            print(json.dumps({'event': 'control_proxy_closed', 'reason': type(exc).__name__}), flush=True)
        finally:
            for worker in workers:
                worker.cancel()
            if workers:
                await asyncio.gather(*workers, return_exceptions=True)
            if backend_writer:
                backend_writer.close()
            writer.close()
            self.active.discard(task)

    async def stop(self):
        tasks = list(self.active)
        for task in tasks:
            task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)


if __name__ == '__main__':
    asyncio.run(main())
