"""A single TLS I/O owner; other threads enqueue complete control messages."""
import collections
import json
import select
import socket
import ssl
import threading
import time


class ControlStream:
    def __init__(self, channel):
        self.channel = channel
        channel.setblocking(False)
        self.lock = threading.Lock()
        self.queue = collections.deque()
        self.closed = False
        self.received = bytearray()
        self.pending = b''
        self.offset = 0
        self.write_needs_read = False
        self.read_needs_write = False
        self.owner = None
        self.idle = threading.Event()
        self.idle.set()
        self.stats = {'tx_frames':0, 'rx_frames':0, 'tx_bytes':0, 'rx_bytes':0, 'queue_peak':0}

    def sendall(self, data):
        kind = json.loads(data).get('k')
        with self.lock:
            if self.closed:
                raise OSError('control_stream_closed')
            # Superseded snapshots and duplicate polls need no replay after a stall.
            if kind in ('profile', 'poll'):
                self.queue = collections.deque((k, v) for k, v in self.queue if k != kind)
            if len(self.queue) >= 128:
                raise OSError('control_send_queue_full')
            self.queue.append((kind, bytes(data)))
            self.idle.clear()
            self.stats['queue_peak'] = max(self.stats['queue_peak'],len(self.queue))

    def readline(self, stop, timeout=30, limit=32768):
        owner = threading.get_ident()
        if self.owner is None:
            self.owner = owner
        if owner != self.owner:
            raise RuntimeError('TLS control I/O must have one owner')
        deadline = time.monotonic() + timeout
        while not stop.is_set():
            at = self.received.find(b'\n')
            if at >= 0:
                if at + 1 > limit:
                    raise ValueError('control_line_too_large')
                line = bytes(self.received[:at + 1])
                del self.received[:at + 1]
                self.stats['rx_frames'] += 1
                return line
            if len(self.received) >= limit:
                raise ValueError('control_line_too_large')
            with self.lock:
                if self.closed:
                    raise OSError('control_stream_closed')
                if not self.pending and self.queue:
                    _, self.pending = self.queue.popleft()
                    self.offset = 0
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError('control_application_reply_timeout')
            writable = bool(self.pending and not self.write_needs_read) or self.read_needs_write
            try:
                ready_read, ready_write, _ = select.select(
                    [self.channel], [self.channel] if writable else [], [], min(.05, remaining))
            except ValueError as exc:
                raise OSError('control_socket_closed_during_wait') from exc
            if self.pending and (ready_write or (self.write_needs_read and ready_read)):
                try:
                    sent = self.channel.send(self.pending[self.offset:])
                    if not sent:
                        raise OSError('control_write_eof')
                    self.offset += sent
                    self.stats['tx_bytes'] += sent
                    self.stats['last_send_at'] = time.monotonic()
                    self.write_needs_read = False
                    if self.offset == len(self.pending):
                        self.pending = b''
                        self.stats['tx_frames'] += 1
                        with self.lock:
                            if not self.queue:self.idle.set()
                except ssl.SSLWantReadError:
                    self.write_needs_read = True
                except (ssl.SSLWantWriteError, BlockingIOError):
                    self.write_needs_read = False
            try:
                has_pending = self.channel.pending()
            except ValueError as exc:
                raise OSError('control_socket_closed_during_receive') from exc
            if ready_read or has_pending or (self.read_needs_write and ready_write):
                try:
                    data = self.channel.recv(16384)
                    if not data:
                        raise OSError('control_read_eof')
                    self.received.extend(data)
                    self.stats['rx_bytes'] += len(data)
                    self.stats['last_receive_at'] = time.monotonic()
                    self.read_needs_write = False
                except (ssl.SSLWantReadError, BlockingIOError):
                    self.read_needs_write = False
                except ssl.SSLWantWriteError:
                    self.read_needs_write = True
        raise OSError('control_cancelled')

    def shutdown(self, how=socket.SHUT_RDWR):
        self.channel.shutdown(how)

    def snapshot(self):
        result = dict(self.stats)
        if hasattr(self.channel, 'transport_stats'):
            result['udp_transport'] = self.channel.transport_stats()
        return result

    def flush(self, timeout=.5):
        return self.idle.wait(timeout) and not self.closed

    def close(self):
        with self.lock:
            self.closed = True
            self.queue.clear()
            self.idle.set()
        self.channel.close()
