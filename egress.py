"""Fresh STUN observations on the actual peer-probe sockets, never a peer mapping claim."""
import collections,ipaddress,secrets,socket,struct,threading,time
from wire import endpoint,stun_request,parse_stun
from net import raw_socket

def resolve(host,bind,index,stop):
    """Bounded physical IPv4 DNS. Does not change the user's DNS or VPN."""
    try:
        ip=ipaddress.IPv4Address(host)
        return str(ip)
    except ValueError:pass
    labels=host.encode('ascii').split(b'.')
    if any(not 0<len(x)<=63 for x in labels):raise ValueError('invalid DNS name')
    question=b''.join(bytes([len(x)])+x for x in labels)+b'\0'+struct.pack('!HH',1,1)
    def skip(data,at):
        for _ in range(128):
            if at>=len(data):raise ValueError('truncated DNS name')
            n=data[at];at+=1
            if not n:return at
            if n&0xc0==0xc0:
                if at>=len(data):raise ValueError('truncated DNS pointer')
                return at+1
            if n>63 or at+n>len(data):raise ValueError('invalid DNS label')
            at+=n
        raise ValueError('DNS name too long')
    for resolver in ('223.5.5.5','1.1.1.1'):
        if stop.is_set():return None
        s=raw_socket(socket.SOCK_DGRAM,bind,index);s.settimeout(.15)
        try:
            tx=secrets.randbelow(65536);s.sendto(struct.pack('!6H',tx,0x100,1,0,0,0)+question,(resolver,53));end=time.monotonic()+1.2
            while not stop.is_set() and time.monotonic()<end:
                try:data,source=s.recvfrom(4096)
                except socket.timeout:continue
                if source!=(resolver,53) or len(data)<12:continue
                ident,flags,qd,an,_,_=struct.unpack('!6H',data[:12])
                if ident!=tx or flags&15 or not flags&0x8000 or qd!=1 or an>64:continue
                at=skip(data,12)+4
                for _ in range(an):
                    at=skip(data,at)
                    if at+10>len(data):break
                    kind,cls,ttl,size=struct.unpack('!HHIH',data[at:at+10]);at+=10
                    if at+size>len(data):break
                    if kind==1 and cls==1 and size==4:return socket.inet_ntoa(data[at:at+4])
                    at+=size
        except (OSError,ValueError):pass
        finally:s.close()
    return None

class LiveEgress:
    def __init__(self,cfg,sockets,bind,index,stop,emit):
        self.cfg=cfg;self.sockets=sockets;self.stop=stop;self.emit=emit;self.servers=[];self.errors=[];self.pending={};self.records={};self.at={};self.started=time.monotonic();self.published=0.;self.dirty=False
        self.sent=0;self.received=0;self.rejected=0;self.cursor=0;self.last_send=0.;self.resolved=threading.Event()
        def discover():
            try:
                for value in cfg.get('egress_stun_servers',[]):
                    if stop.is_set():break
                    host,port=value
                    try:
                        ip=resolve(host,bind,index,stop)
                        if not ip or not endpoint((ip,port),cfg.get('public_only',True)):raise ValueError('no valid reflector IPv4')
                        if ip not in {p[0] for p in self.servers}:self.servers.append((ip,int(port)))
                    except (OSError,ValueError) as exc:self.errors.append({'host':host,'error':str(exc)})
            finally:self.resolved.set()
        self.thread=threading.Thread(target=discover,name='NATPair-egress-DNS',daemon=True);self.thread.start()
    def tick(self,now,send,trace,reserved_socket=None):
        self.pending={n:p for n,p in self.pending.items() if now-p[2]<4}
        self.records={k:v for k,v in self.records.items() if now-v['at']<60}
        spacing=.03 if now-self.started<4 else .15
        if now-self.last_send<spacing or not self.servers or not self.sockets:return
        choices=[(slot,server) for server in tuple(self.servers) for slot in range(len(self.sockets))]
        for offset in range(len(choices)):
            slot,server=choices[(self.cursor+offset)%len(choices)]
            if now-self.at.get((slot,server),-1e9)<(1 if now-self.started<4 else 20):continue
            sock=self.sockets[slot]
            if sock is reserved_socket:continue
            nonce=secrets.token_bytes(12);data=stun_request(nonce)
            if not send(sock,data,server,now,'egress_observer'):return
            self.pending[nonce]=(slot,server,now,sock);self.at[(slot,server)]=now;self.cursor+=offset+1;self.last_send=now;self.sent+=1
            trace(sock,data,'tx',server,kind='egress_stun',nonce=nonce.hex(),lane='egress_observer');return
    def receive(self,sock,data,source,now):
        if len(data)<20 or data[4:8]!=struct.pack('!I',0x2112a442):return False
        expected=self.pending.get(data[8:20])
        if not expected:return False
        slot,server,sent,original=expected
        if source!=server or sock is not original or now-sent>=4:self.rejected+=1;return False
        obj=parse_stun(data,data[8:20]);mapped=endpoint((obj or {}).get('mapped'),self.cfg.get('public_only',True))
        if not mapped:self.rejected+=1;return False
        self.pending.pop(data[8:20],None);old=self.records.get((slot,server));self.records[(slot,server)]={'slot':slot,'reflector':list(server),'endpoint':list(mapped),'at':now,'rtt_ms':round((now-sent)*1000,2),'local_port':sock.getsockname()[1]};self.received+=1;self.dirty=True
        if not old or old['endpoint']!=list(mapped):self.emit('egress_observation',slot=slot,local=list(sock.getsockname()),reflector=list(server),endpoint=list(mapped),scope='same_live_probe_socket_to_this_reflector_only',message='本轮探测套接字的实测公网出口；尚未证明对方方向的映射')
        return True
    def snapshot(self,now):
        records=[{k:v for k,v in r.items() if k!='at'}|{'age_seconds':round(now-r['at'],2)} for r in self.records.values() if now-r['at']<60]
        return {'scope':'live_probe_sockets_to_named_reflectors_only','observations':records,'reflector_ips':sorted({r['reflector'][0] for r in records}),'public_ipv4':sorted({r['endpoint'][0] for r in records}),'peer_mapping_verified':False,'sent':self.sent,'received':self.received,'dns_complete':self.resolved.is_set(),'dns_errors':list(self.errors)}
    def initial_complete(self,now):return now-self.started>=4 or self.resolved.is_set() and (not self.servers or all((slot,server) in self.records for server in self.servers for slot in range(len(self.sockets))))
    def close(self):self.thread.join(4)

def extra_candidates(peer,hints=(),public=True):
    """Source socket/reflector records are observed candidates, not proven peer endpoints."""
    base=list(dict.fromkeys(p for p in (endpoint(v,public) for v in peer.get('udp',[])[:16]) if p));base_ips={p[0] for p in base};records=(peer.get('profile') or {}).get('exit_observations') or {};extras=[]
    for r in records.get('observations',[])[:32]:
        if not isinstance(r,dict) or type(r.get('age_seconds')) not in (int,float) or not 0<=r['age_seconds']<40:continue
        ep=endpoint(r.get('endpoint'),public)
        if ep and ep not in base and ep not in extras:extras.append(ep)
    ips=list(dict.fromkeys([p[0] for p in extras]))
    for v in hints[:16]:
        p=endpoint(v,public)
        # Radmin virtual addresses sometimes appear in native endpoint lists.
        if p and not p[0].startswith('26.') and p[0] not in base_ips and p[0] not in ips:ips.append(p[0])
    result=[(ep,'same_socket_stun_observed') for ep in extras]
    for ip in ips[:6]:
        for _,port in base[:8]:
            ep=(ip,port)
            if ep not in base and all(x[0]!=ep for x in result):result.append((ep,'candidate_ip_observed_port_hypothesis'))
    return result[:64]

class ExitExplorer:
    def __init__(self):self.tick=0;self.near=0;self.positions=collections.defaultdict(int)
    def choice(self,peer,count,hints=(),public=True):
        candidates=extra_candidates(peer,hints,public)
        if not candidates or not count:return None
        if self.tick%4<3:
            ep,reason=candidates[self.near//count%len(candidates)];delta=(0,1,-1,2,-2)[self.near//(count*len(candidates))%5]
            port=ep[1]+delta
            if not 1<=port<=65535:port=ep[1]
            return self.near%count,(ep[0],port),'exit_ip_nearby',ep[0],reason
        ips=list(dict.fromkeys(ep[0] for ep,reason in candidates));ip=ips[self.tick//4%len(ips)];pos=self.positions[ip]
        return pos//65535%count,(ip,1+pos%65535),'exit_ip_full_scan',ip,'candidate_ip_full_port_search'
    def sent(self,lane,ip):
        self.tick+=1
        if lane=='exit_ip_nearby':self.near+=1
        else:self.positions[ip]+=1
