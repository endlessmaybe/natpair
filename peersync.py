"""Room-authenticated metadata over the selected Tailscale peer only.

This socket never sends IPv4 hole-punch probes or substitutes Tailscale's
native UDP port for an application's observed mapping.
"""
import ipaddress,json,select,socket,threading,time
from roomudp import Codec

def tail_ip(value):
    try:return ipaddress.ip_address(value) in ipaddress.ip_network('100.64.0.0/10')
    except ValueError:return False

class PeerSync:
    def __init__(self,key,sid,local,target,produce,expected,stop,emit):
        self.sid=bytes.fromhex(sid);self.target=tuple(target);self.produce=produce;self.expected=expected;self.stop=stop;self.emit=emit
        self.encoder=Codec(key);self.decoder=Codec(key,True);self.seq=0;self.last_seq={};self.last_peer=None;self.received_at=0;self.closed=False
        self.stats={'tx':0,'rx':0,'rejected':0,'duplicates':0,'send_errors':0,'protocol':'tailscale_room_authenticated_metadata_only'}
        self.socket=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
        try:
            self.socket.setsockopt(socket.SOL_SOCKET,socket.SO_RCVBUF,1024*1024);self.socket.bind(tuple(local));self.socket.setblocking(False)
        except Exception:self.socket.close();raise
        self.local=self.socket.getsockname();self.thread=threading.Thread(target=self.run,name='NATPair-peer-sync',daemon=True);self.thread.start()
    def send(self,leave=False):
        obj=self.produce()
        if not obj:return
        obj={**obj,'k':'peer_leave' if leave else 'peer_sync'};self.seq+=1
        packets=self.encoder.encode(self.sid,self.seq,obj,True)
        for _ in range(2 if len(packets)>1 or leave else 1):
            for packet in packets:
                try:self.socket.sendto(packet,self.target);self.stats['tx']+=1
                except OSError:self.stats['send_errors']+=1;return
    def accept(self,data,source):
        if tuple(source)!=self.target:self.stats['rejected']+=1;return
        result=self.decoder.decode(data,source)
        if not result:return
        sid,seq,obj=result;expected=self.expected();profile=obj.get('profile') or {}
        if not isinstance(profile,dict) or not expected:return
        peer_id,peer_session,my_id=expected
        if obj.get('id')!=peer_id or obj.get('to')!=my_id or sid.hex()!=peer_session or profile.get('transport_session')!=peer_session:
            self.stats['rejected']+=1;return
        if seq<=self.last_seq.get(sid,0):self.stats['duplicates']+=1;return
        if obj.get('k') not in ('peer_sync','peer_leave'):return
        self.last_seq={sid:seq};self.stats['rx']+=1
        if obj['k']=='peer_leave':self.last_peer=None;self.received_at=0;return
        if not isinstance(obj.get('udp'),list) or len(obj['udp'])>16:return
        self.last_peer={k:obj.get(k) for k in ('id','name','profile','udp','prepared','epoch','version')};self.received_at=time.monotonic()
    def fresh(self,now=None):
        now=time.monotonic() if now is None else now;expected=self.expected();peer=self.last_peer
        if not peer or not expected or now-self.received_at>=4:return None
        if peer['id']!=expected[0] or (peer.get('profile') or {}).get('transport_session')!=expected[1]:return None
        return peer
    def snapshot(self):
        return {**self.stats,'local':list(self.local),'target':list(self.target),'fresh':bool(self.fresh()),'reply_age_seconds':round(time.monotonic()-self.received_at,3) if self.received_at else None}
    def run(self):
        next_send=0
        while not self.stop.is_set() and not self.closed:
            try:
                now=time.monotonic()
                if now>=next_send:self.send();next_send=now+.5
                ready,_,_=select.select([self.socket],[],[],.05)
                if ready:
                    for _ in range(32):
                        try:data,source=self.socket.recvfrom(2048)
                        except BlockingIOError:break
                        self.accept(data,source)
            except (OSError,ValueError,RuntimeError,TypeError) as exc:
                # Windows UDP may report an ICMP port-unreachable after the
                # selected peer stops. Keep this socket; freshness expires
                # naturally and the next run is validated by its new session.
                if isinstance(exc,OSError) and getattr(exc,'winerror',None)==10054:continue
                if not self.closed and not self.stop.is_set():
                    self.emit('peer_sync_error',message=str(exc));self.stop.wait(.2)
    def close(self):
        if self.closed:return
        self.closed=True;self.thread.join(2)
        try:self.send(leave=True)
        except (OSError,ValueError,RuntimeError,TypeError):pass
        self.socket.close()
