"""One read-only native capture and one metadata/data verifier per computer."""
import copy,ipaddress,json,queue,socket,threading,time,traceback
from tailbridge import WinSniffer,parse_ipv4_udp,read_metadata,command,native_udp_port

def native_route(address,proxies=()):
    if not address:return 'derp'
    if address in proxies:return 'natpair_proxy'
    try:
        host,port=address.rsplit(':',1);ip=ipaddress.ip_address(host.strip('[]'))
        if not 1<=int(port)<=65535 or ip.is_loopback or ip.is_unspecified or ip.is_multicast:return 'unknown'
        if ip.version==6 and ip in ipaddress.ip_network('fd7a:115c:a1e0::/48'):return 'unknown'
        return 'ipv6' if ip.version==6 else 'ipv4'
    except (ValueError,AttributeError):return 'unknown'

class Subscription:
    mode='shared_compact_disco';attempts=[]
    def __init__(self,hub,owner,port,endpoints):
        self.hub=hub;self.owner=owner;self.port=port;self.endpoints=set(map(tuple,endpoints));self.queue=queue.Queue(256);self.closed=False
    def recv(self):
        while not self.closed:
            try:packet=self.queue.get(timeout=.1)
            except queue.Empty:continue
            if isinstance(packet,Exception):raise packet
            return packet
        raise OSError('shared_capture_subscription_closed')
    def close(self):
        if self.closed:return
        self.closed=True
        with self.hub.lock:
            if self.hub.subscriptions.get(self.owner) is self:self.hub.subscriptions.pop(self.owner,None)

class CaptureHub:
    def __init__(self,stop,emit,factory=None):
        self.stop=stop;self.emit=emit;self.factory=factory or (lambda p:WinSniffer(p,[],compact_only=True));self.lock=threading.RLock()
        self.subscriptions={};self.capture=None;self.port=None;self.closed=False;self.thread=None;self.threads=[];self.ambiguous=0;self.delivered=0;self.opened=0;self.retry_at=0
    def subscribe(self,owner,port,endpoints):
        with self.lock:
            if self.closed:raise OSError('shared_capture_closed')
            if self.capture and self.port!=port:self._retire()
            if self.capture is None:
                if time.monotonic()<self.retry_at:raise OSError('共享发现监听等待重试；UDP 代理继续工作')
                try:self.capture=self.factory(port)
                except (OSError,RuntimeError):self.retry_at=time.monotonic()+30;raise
                self.port=port;self.opened+=1
                self.thread=threading.Thread(target=self.read,args=(self.capture,),name='NATPair-shared-disco',daemon=True);self.threads=[t for t in self.threads if t.is_alive()]+[self.thread];self.thread.start()
            old=self.subscriptions.get(owner)
            if old:old.closed=True
            sub=Subscription(self,owner,port,endpoints);self.subscriptions[owner]=sub;return sub
    def dispatch(self,packet):
        parsed=parse_ipv4_udp(packet)
        if not parsed:return
        source,target,payload=parsed
        with self.lock:
            matches=[s for s in self.subscriptions.values() if not s.closed and s.port==source[1] and target in s.endpoints]
            if len(matches)!=1:
                if len(matches)>1:
                    self.ambiguous+=1
                    if self.ambiguous==1:self.emit('capture_ambiguous',endpoint=list(target),message='完整目标地址同时属于多个节点，未转发该发现报文；等待唯一候选')
                return
            try:matches[0].queue.put_nowait(packet);self.delivered+=1
            except queue.Full:pass
    def read(self,capture):
        while not self.closed and not self.stop.is_set() and self.capture is capture:
            try:self.dispatch(capture.recv())
            except OSError as exc:
                with self.lock:
                    if self.capture is capture:
                        self.capture=None;self.retry_at=time.monotonic()+30;capture.close()
                        for s in self.subscriptions.values():
                            try:s.queue.put_nowait(OSError(str(exc)))
                            except queue.Full:pass
                return
    def _retire(self):
        capture=self.capture;self.capture=None
        if capture:capture.close()
        for s in self.subscriptions.values():s.closed=True
        self.subscriptions.clear()
    def close(self):
        with self.lock:self.closed=True;self._retire()
        for thread in self.threads:thread.join(3)
    def snapshot(self):
        with self.lock:return {'active_handle':self.capture is not None,'subscriptions':len(self.subscriptions),'handles_opened':self.opened,'ambiguous_dropped':self.ambiguous,'delivered':self.delivered}

class TailManager:
    def __init__(self,stop,emit,bridge):
        self.stop=stop;self.emit=emit;self.bridge=bridge;self.lock=threading.RLock();self.ready=threading.Event();self.thread=None
        self.status={};self.netmap={};self.port=None;self.own={};self.metadata={};self.metadata_errors={};self.health={};self.targets={};self.proxies={};self.last_refresh=0;self.last_port=0;self.cursor=0;self.error=None;self.error_type=None;self.last_failure=None;self.refresh_count=0
        self.hub=CaptureHub(stop,emit)
    def start(self):
        self.thread=threading.Thread(target=self.run,name='NATPair-tail-manager',daemon=True);self.thread.start()
    def set_targets(self,targets):
        with self.lock:self.targets=dict(targets)
    def register_proxy(self,target,tail):
        with self.lock:self.proxies[target]=tail
    def unregister_proxy(self,target,tail):
        with self.lock:
            if self.proxies.get(target) is tail:self.proxies.pop(target,None)
    def refresh(self):
        status=json.loads(command(['status','--json'],timeout=5,stop=self.stop));netmap=json.loads(command(['debug','netmap'],timeout=5,stop=self.stop))
        if status.get('BackendState')!='Running':raise RuntimeError('请先登录并连接 Tailscale')
        node=netmap.get('SelfNode') or {};tailips=[str(a).split('/')[0] for a in node.get('Addresses',[])]
        own={'node_key':node.get('Key'),'tail_ip':next((s for s in tailips if ':' not in s),'')}
        if not own['node_key'] or not own['tail_ip']:raise RuntimeError('本机 Tailscale 节点身份或 IPv4 地址尚未就绪')
        # Publish our identity independently of peer enumeration or a slow
        # Windows UDP-port query. A foreign/offline peer cannot blank it.
        with self.lock:self.status=status;self.netmap=netmap;self.own=own
        self.ready.set()
        with self.lock:targets=list(self.targets)
        known=[str(a).split('/')[0] for p in (netmap.get('Peers') or []) for a in (p.get('Addresses') or [])]
        # Query the daemon UDP port once per refresh, never once per peer.
        needport=self.bridge and (self.port is None or time.monotonic()-self.last_port>=15)
        if needport:
            port=native_udp_port(self.port,self.stop)
            with self.lock:self.port=port;self.last_port=time.monotonic()
        metas={};errors={}
        for target in targets:
            if target not in known:errors[target]='该房间成员的 Tailscale 地址尚未出现在当前网络';continue
            try:metas[target]=read_metadata(target,port=self.port if self.bridge else 1,stop=self.stop,snapshots=(status,netmap))
            except Exception as exc:errors[target]=type(exc).__name__+': '+str(exc)
        with self.lock:self.metadata=metas;self.metadata_errors=errors;self.error=None;self.error_type=None;self.refresh_count+=1
        self.last_refresh=time.monotonic()
    def read_metadata(self,target,**kwargs):
        with self.lock:
            meta=copy.deepcopy(self.metadata.get(target))
        if not meta:raise RuntimeError(self.metadata_errors.get(target) or self.error or '等待该房间成员的 Tailscale 节点与当前 UDP 端口同步')
        return meta
    def route_health(self,target):
        with self.lock:h=dict(self.health.get(target,{}))
        if time.monotonic()-h.get('checked_at',0)>30:h['native_verified']=False;h['stale']=True
        return h
    def verify(self,target):
        with self.lock:
            metadata=self.metadata.get(target);proxy=self.proxies.get(target);before_status=self.status
        if not metadata:return
        key=metadata['expected_peer_key'];before=next((p for p in before_status.get('Peer',{}).values() if p.get('PublicKey')==key),{})
        before_addr=before.get('CurAddr','');counts=[proxy.stats.get(k,0) if proxy else 0 for k in ('tail_tx_wg_datagrams','tail_rx_wg_datagrams')]
        try:
            pong=command(['ping','--tsmp','--c=1','--timeout=2s',target],timeout=4,stop=self.stop)
            after_status=json.loads(command(['status','--json'],timeout=4,stop=self.stop))
            after=next((p for p in after_status.get('Peer',{}).values() if p.get('PublicKey')==key),{})
            proxy_address=':'.join(map(str,proxy.socket.getsockname())) if proxy and not proxy.stop.is_set() else None
            route=native_route(after.get('CurAddr',''),[proxy_address] if proxy_address else [])
            stable=before_addr==after.get('CurAddr','');verified='pong' in pong.lower()
            proxy_verified=bool(verified and stable and route=='natpair_proxy' and proxy and all(proxy.stats.get(k,0)>n for k,n in zip(('tail_tx_wg_datagrams','tail_rx_wg_datagrams'),counts)))
            h={'native_verified':verified,'route':route if stable else 'path_changed','cur_addr':after.get('CurAddr',''),
               'proxy_verified':proxy_verified,'checked_at':time.monotonic(),'data_evidence':'tsmp' if verified else None,
               'state':'data_verified' if verified else 'validation_timeout','using_proxy':route=='natpair_proxy','tsmp':pong[-300:]}
            with self.lock:self.health[target]=h;self.status=after_status
        except Exception as exc:
            # A failed read is unknown; don't immediately tear down a proven
            # connection or turn a single delayed reply into a room restart.
            with self.lock:
                h=self.health.setdefault(target,{})
                h.update(error=str(exc),last_attempt=time.monotonic())
    def run(self):
        while not self.stop.is_set():
            try:
                if time.monotonic()-self.last_refresh>=5:self.refresh()
                with self.lock:targets=list(self.targets)
                if targets:
                    target=targets[self.cursor%len(targets)];self.cursor+=1
                    h=self.route_health(target)
                    interval=10 if h.get('native_verified') else 3
                    if time.monotonic()-max(h.get('checked_at',0),h.get('last_attempt',0))>=interval:self.verify(target)
            except Exception as exc:
                self.error=str(exc);self.error_type=type(exc).__name__;self.last_failure={'type':self.error_type,'message':self.error,'traceback':traceback.format_exc()}
                if not self.stop.is_set():self.emit('tail_manager_wait',message=str(exc),error_type=self.error_type,traceback=self.last_failure['traceback'])
                self.stop.wait(2)
            self.stop.wait(.15)
    def snapshot(self):
        with self.lock:return {'worker_alive':bool(self.thread and self.thread.is_alive()),'own':dict(self.own),'udp_port':self.port,
                'identity_ready':self.ready.is_set(),'refresh_count':self.refresh_count,'metadata_peers':list(self.metadata),
                'metadata_errors':dict(self.metadata_errors),'error':self.error,'error_type':self.error_type,'last_failure':copy.deepcopy(self.last_failure)}
    def close(self):
        self.hub.close()
        if self.thread:self.thread.join(12)
