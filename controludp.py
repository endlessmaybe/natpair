"""Reliable, authenticated datagrams carrying the original pinned TLS stream.

Only coordinator bytes travel here. Peer probes keep their original sockets.
"""
import collections
import hashlib
import hmac
import secrets
import select
import socket
import ssl
import struct
import time

MAGIC = b'NPC1'
HEADER = struct.Struct('!4s16sBQHH')
CHUNK = 1000
WINDOW = 32


def encode(key, ident, kind, sequence, index=0, count=0, payload=b''):
    head = HEADER.pack(MAGIC, ident, kind, sequence, index, count)
    return head + payload + hmac.digest(key, head + payload, 'sha256')


def decode(key, data):
    if not HEADER.size + 32 <= len(data) <= HEADER.size + 32 + CHUNK:
        return None
    body, tag = data[:-32], data[-32:]
    if not hmac.compare_digest(tag, hmac.digest(key, body, 'sha256')):
        return None
    magic, ident, kind, seq, index, count = HEADER.unpack(body[:HEADER.size])
    payload = body[HEADER.size:]
    if magic != MAGIC or seq >= 2**63:
        return None
    if kind == 1:
        if not 1 <= count <= 66 or index >= count or not payload:
            return None
        if index < count - 1 and len(payload) != CHUNK:
            return None
    elif kind == 2:
        if payload or not 1 <= count <= 66 or index >= count:
            return None
    elif kind == 3:
        if payload or index or count:
            return None
    else:
        return None
    return ident, kind, seq, index, count, payload


class ReliableState:
    def __init__(self, root, ident, server=False):
        self.ident = ident
        def key(direction):
            return hmac.digest(root, b'NATPair-control-udp-v1\0' + ident + direction, 'sha256')
        self.tx_key = key(b'server' if server else b'client')
        self.rx_key = key(b'client' if server else b'server')
        self.tx_seq = 0
        self.rx_seq = 0
        self.outgoing = collections.OrderedDict()
        self.parts = {}
        self.completed = {}
        self.closed = False
        self.stats = {'wire_tx': 0, 'wire_rx': 0, 'retransmissions': 0, 'acked_messages': 0}

    def queue(self, payload):
        if self.closed:
            raise OSError('udp_control_closed')
        if not 1 <= len(payload) <= CHUNK * 66:
            raise ValueError('udp_control_message_size')
        if len(self.outgoing) >= WINDOW:
            raise BlockingIOError('udp_control_window_full')
        self.tx_seq += 1
        count = (len(payload) + CHUNK - 1) // CHUNK
        packets = [encode(self.tx_key, self.ident, 1, self.tx_seq, i, count,
                          payload[i * CHUNK:(i + 1) * CHUNK]) for i in range(count)]
        self.outgoing[self.tx_seq] = {'packets': packets, 'missing': set(range(count)), 'sent': {}, 'attempts': {}}
        return len(payload)

    def tick(self, send, now=None):
        now = time.monotonic() if now is None else now
        emitted = 0
        for seq, message in list(self.outgoing.items()):
            # Four fragments per pump prevent large coordinator frames from
            # being one socket-buffer burst. Peer probes never use this sender.
            for index in sorted(message['missing']):
                attempts = message['attempts'].get(index, 0)
                last = message['sent'].get(index)
                interval = min(2., .35 * 1.5 ** min(attempts, 6))
                if last is not None and now - last < interval:
                    continue
                try:
                    send(message['packets'][index])
                except BlockingIOError:
                    return
                self.stats['wire_tx'] += 1
                if attempts:
                    self.stats['retransmissions'] += 1
                message['sent'][index] = now
                message['attempts'][index] = attempts + 1
                emitted += 1
                if emitted == 4:
                    return
        # Accepted fragments have been acknowledged. Keep them until assembly
        # or session close; expiring them would lose acknowledged stream bytes.

    def receive(self, packet, send, now=None):
        obj = decode(self.rx_key, packet)
        if obj is None or obj[0] != self.ident:
            return b''
        now = time.monotonic() if now is None else now
        _, kind, seq, index, count, payload = obj
        self.stats['wire_rx'] += 1
        if kind == 2:
            message = self.outgoing.get(seq)
            if message is not None and len(message['packets']) == count:
                message['missing'].discard(index)
                if not message['missing']:
                    self.outgoing.pop(seq)
                    self.stats['acked_messages'] += 1
            return b''
        if kind == 3:
            self.closed = True
            return b''
        if seq == 0 or seq > self.rx_seq + WINDOW:
            return b''
        if seq <= self.rx_seq or seq in self.completed:
            try:
                send(encode(self.tx_key, self.ident, 2, seq, index, count))
            except BlockingIOError:
                pass
            return b''
        part = self.parts.setdefault(seq, {'at': now, 'count': count, 'chunks': {}})
        if part['count'] != count:
            return b''
        previous = part['chunks'].get(index)
        if previous is not None and previous != payload:
            return b''
        part['chunks'][index] = payload
        try:
            send(encode(self.tx_key, self.ident, 2, seq, index, count))
        except BlockingIOError:
            pass
        if len(part['chunks']) == count:
            self.parts.pop(seq, None)
            self.completed[seq] = b''.join(part['chunks'][i] for i in range(count))
        result = bytearray()
        while self.rx_seq + 1 in self.completed:
            self.rx_seq += 1
            result.extend(self.completed.pop(self.rx_seq))
        return bytes(result)


class UDPChannel:
    def __init__(self, sock, address, access):
        self.sock = sock
        self.address = address
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 262144)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 262144)
        self.sock.setblocking(False)
        self.state = ReliableState(bytes.fromhex(access), secrets.token_bytes(16))
        self.received = bytearray()

    def fileno(self):
        return self.sock.fileno()

    def _send(self, packet):
        self.sock.sendto(packet, self.address)

    def pump(self):
        if self.sock.fileno() < 0:
            raise OSError('udp_control_socket_closed')
        for _ in range(128):
            try:
                data, origin = self.sock.recvfrom(2048)
            except BlockingIOError:
                break
            if origin == self.address:
                self.received.extend(self.state.receive(data, self._send))
        self.state.tick(self._send)
        if self.state.closed:
            raise OSError('udp_control_remote_closed')

    def send(self, data):
        accepted = self.state.queue(data)
        self.state.tick(self._send)
        return accepted

    def recv(self, size):
        self.pump()
        if not self.received:
            raise BlockingIOError('udp_control_would_block')
        data = bytes(self.received[:size])
        del self.received[:size]
        return data

    def close(self):
        if self.sock.fileno() >= 0:
            try:
                self._send(encode(self.state.tx_key, self.state.ident, 3, 0))
            except OSError:
                pass
            self.sock.close()


class BIOChannel:
    """Socket facade for SSLObject; all TLS work has a single caller."""
    def __init__(self, channel, host):
        self.channel = channel
        self.incoming = ssl.MemoryBIO()
        self.outgoing = ssl.MemoryBIO()
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        self.tls = ctx.wrap_bio(self.incoming, self.outgoing, server_hostname=host)
        self.encrypted_pending = b''

    def fileno(self):
        return self.channel.fileno()

    def setblocking(self, value):
        if value:
            raise ValueError('BIO control requires one nonblocking owner')

    def _flush(self):
        if not self.encrypted_pending and self.outgoing.pending:
            self.encrypted_pending = self.outgoing.read(min(64000, self.outgoing.pending))
        while self.encrypted_pending:
            try:
                self.channel.send(self.encrypted_pending)
            except BlockingIOError:
                return
            self.encrypted_pending = b''
            if self.outgoing.pending:
                self.encrypted_pending = self.outgoing.read(min(64000, self.outgoing.pending))

    def _pump(self):
        self._flush()
        self.channel.pump()
        if self.channel.received:
            self.incoming.write(bytes(self.channel.received))
            self.channel.received.clear()

    def handshake(self, stop, timeout=8):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline and not (stop and stop.is_set()):
            self._pump()
            try:
                self.tls.do_handshake()
                self._flush()
                return
            except (ssl.SSLWantReadError, ssl.SSLWantWriteError):
                self._flush()
                select.select([self.channel], [], [], .03)
        raise TimeoutError('udp_control_tls_handshake_timeout')

    def getpeercert(self, binary_form=False):
        return self.tls.getpeercert(binary_form=binary_form)

    def getsockname(self):
        return self.channel.sock.getsockname()

    def getpeername(self):
        return self.channel.address

    def send(self, data):
        self._pump()
        if self.encrypted_pending or self.outgoing.pending:
            raise ssl.SSLWantWriteError('udp_control_transport_busy')
        size = self.tls.write(data)
        self._flush()
        return size

    def recv(self, size):
        self._pump()
        try:
            return self.tls.read(size)
        finally:
            self._flush()

    def pending(self):
        self._pump()
        # SSLObject.pending counts only decrypted bytes. Newly fed ciphertext
        # also needs a read attempt even when select has consumed all datagrams.
        return self.tls.pending() or self.incoming.pending

    def shutdown(self, how=socket.SHUT_RDWR):
        self.close()

    def close(self):
        self.channel.close()

    def transport_stats(self):
        state = self.channel.state
        return {**state.stats, 'connection_id': state.ident.hex()[:8], 'unacked_messages': len(state.outgoing),
                'rx_sequence': state.rx_seq,
                'outgoing_missing': {str(seq): sorted(v['missing']) for seq, v in state.outgoing.items()},
                'incoming_fragments': {str(seq): {'count': v['count'], 'received': sorted(v['chunks'])}
                                       for seq, v in state.parts.items()}}


def udp_tls_connect(cfg, bind, index, stop=None):
    from net import raw_socket
    sock = raw_socket(socket.SOCK_DGRAM, bind, index)
    channel = BIOChannel(UDPChannel(sock, (cfg['host'], cfg['control_udp_port']), cfg['access']), cfg['host'])
    try:
        channel.handshake(stop, cfg.get('control_udp_handshake_timeout', 8))
        fingerprint = hashlib.sha256(channel.getpeercert(binary_form=True)).hexdigest()
        if not secrets.compare_digest(fingerprint, cfg['pin'].lower()):
            raise RuntimeError('服务器证书指纹不匹配')
        return channel
    except BaseException:
        channel.close()
        raise
