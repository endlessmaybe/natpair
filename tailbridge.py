"""Sniff bootstrap Disco only; bridge native UDP using a local IPv4 endpoint.

WinDivert is opened SNIFF|RECV_ONLY. It never blocks, rewrites or injects an
original network packet. After native Disco authenticates the proxy, native
Tailscale selects that local UDP endpoint without daemon preference edits.
Production Windows bridges bind the physical LAN IPv4: a native UDP socket
bound to a physical interface cannot reliably send to 127.0.0.1 (10049).
"""
import ctypes,hashlib,ipaddress,json,os,pathlib,queue,socket,struct,subprocess,sys,threading,time
DISCO=b'TS\xf0\x9f\x92\xac'
BASE=pathlib.Path(sys.executable).parent if getattr(sys,'frozen',False) else pathlib.Path(__file__).parent

def load_driver(base=None):
    base=pathlib.Path(base) if base is not None else BASE
    locations=[base/'driver',base/'_internal'/'driver']
    if getattr(sys,'frozen',False):locations.append(pathlib.Path(sys._MEIPASS)/'driver')
    directory=next((p for p in locations if (p/'WinDivert.dll').is_file() and (p/'WinDivert64.sys').is_file()),None)
    if directory is None:
        raise RuntimeError('Tailscale 接入组件缺失：需要 WinDivert.dll 和 WinDivert64.sys。请完整解压新版安装包，不能只复制 EXE。')
    try:dll=ctypes.WinDLL(str(directory/'WinDivert.dll'),use_last_error=True)
    except OSError as exc:raise RuntimeError('Tailscale 接入组件加载失败：'+str(exc)) from exc
    return dll,directory

def driver_check(base=None):
    dll,directory=load_driver(base)
    compile_filter=dll.WinDivertHelperCompileFilter
    compile_filter.argtypes=[ctypes.c_char_p,ctypes.c_int,ctypes.c_void_p,ctypes.c_uint,ctypes.POINTER(ctypes.c_char_p),ctypes.POINTER(ctypes.c_uint)]
    compile_filter.restype=ctypes.c_bool
    error=ctypes.c_char_p();position=ctypes.c_uint()
    filters=[b'outbound and ip and udp',compact_filter(41641).encode(),
        ('outbound and ip and udp and udp.SrcPort == 41641 and ('+' or '.join(f'(ip.DstAddr == 112.49.193.186 and udp.DstPort == {p})' for p in (41641,27387,27388,27624,27625,27626,27627,27628))+')').encode()]
    for flt in filters:
        if not compile_filter(flt,0,None,0,ctypes.byref(error),ctypes.byref(position)):
            raise RuntimeError('WinDivert 过滤器校验失败：'+str(error.value))
    return {'passed':True,'directory':str(directory),'dll_sha256':hashlib.sha256((directory/'WinDivert.dll').read_bytes()).hexdigest(),
            'sys_sha256':hashlib.sha256((directory/'WinDivert64.sys').read_bytes()).hexdigest(),
            'filters_compiled':len(filters),'scope':'actual DLL load and native filter compilation; no driver handle or traffic capture opened'}
def run_command(args,timeout=12,stop=None):
    proc=subprocess.Popen(args,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,encoding='utf8',errors='replace',
        creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0));deadline=time.monotonic()+timeout
    try:
        while True:
            if stop and stop.is_set():raise InterruptedError('session_stopping')
            remaining=deadline-time.monotonic()
            if remaining<=0:raise subprocess.TimeoutExpired(args,timeout)
            try:out,err=proc.communicate(timeout=min(.1,remaining));break
            except subprocess.TimeoutExpired:continue
        if proc.returncode:raise RuntimeError(err.strip() or out.strip() or 'command failed')
        return out
    finally:
        if proc.poll() is None:proc.kill();proc.communicate()

def command(args,timeout=12,stop=None):return run_command(['tailscale',*args],timeout,stop)
def is_admin():return os.name=='nt' and bool(ctypes.windll.shell32.IsUserAnAdmin())
def payload_kind(payload):
    if payload.startswith(DISCO) and 78<=len(payload)<=65507:return 'disco'
    if len(payload)<4:return None
    typ=struct.unpack('<I',payload[:4])[0]
    if typ==1 and len(payload)==148:return 'wireguard_handshake'
    if typ==2 and len(payload)==92:return 'wireguard_handshake'
    if typ==3 and len(payload)==64:return 'wireguard_cookie'
    if typ==4 and len(payload)>=32 and len(payload)%16==0:return 'wireguard_data'
    return None
def parse_ipv4_udp(packet):
    if len(packet)<28 or packet[0]>>4!=4 or packet[9]!=17:return None
    ihl=(packet[0]&15)*4;total=struct.unpack('!H',packet[2:4])[0]
    if ihl<20 or total>len(packet) or total<ihl+8 or struct.unpack('!H',packet[6:8])[0]&0x3fff:return None
    source,dest=socket.inet_ntoa(packet[12:16]),socket.inet_ntoa(packet[16:20])
    sport,dport,length,_=struct.unpack('!4H',packet[ihl:ihl+8])
    if length<8 or ihl+length!=total:return None
    return (source,sport),(dest,dport),packet[ihl+8:total]
def split_endpoint(text):
    try:
        host,port=text.rsplit(':',1);ip=ipaddress.ip_address(host.strip('[]'));port=int(port)
        return (str(ip),port) if ip.version==4 and 1<=port<=65535 and not ip.is_unspecified and not ip.is_multicast and not ip.is_loopback else None
    except (ValueError,TypeError):return None

def native_udp_port(preferred_port=None,stop=None):
    if os.name!='nt':raise RuntimeError('本机原生 Tailscale UDP 端口自动查询仅支持 Windows')
    script="$ids=@(Get-Process tailscaled -ErrorAction SilentlyContinue).Id; @(Get-NetUDPEndpoint | Where-Object { $_.OwningProcess -in $ids -and $_.LocalAddress -in @('0.0.0.0','127.0.0.1') } | Select-Object -ExpandProperty LocalPort -Unique) | ConvertTo-Json -Compress"
    output=run_command(['powershell.exe','-NoProfile','-NonInteractive','-Command',script],12,stop)
    ports=json.loads(output);ports=ports if isinstance(ports,list) else [ports]
    ports=list(dict.fromkeys(p for p in ports if type(p) is int and 1<=p<=65535))
    if type(preferred_port) is int and preferred_port in ports:return preferred_port
    if len(ports)==1:return ports[0]
    raise RuntimeError('无法唯一确认本机 Tailscale UDP 端口，请导出记录')
def read_metadata(target,port=None,preferred_port=None,stop=None,snapshots=None):
    if snapshots:status,netmap=snapshots
    else:status=json.loads(command(['status','--json'],stop=stop));netmap=json.loads(command(['debug','netmap'],stop=stop))
    if status.get('BackendState')!='Running':raise RuntimeError('请先登录并连接 Tailscale')
    own=netmap.get('SelfNode') or {};peers=netmap.get('Peers') or []
    peer=next((p for p in peers if any(str(a).split('/')[0]==target for a in (p.get('Addresses') or []))),None)
    if not peer:raise RuntimeError('所选 Tailscale 对端不在当前网络')
    endpoints=[p for p in (split_endpoint(x) for x in (peer.get('Endpoints') or [])) if p][:16]
    if port is None and os.name=='nt':
        port=native_udp_port(preferred_port,stop)
    if type(port) is not int or not 1<=port<=65535:raise RuntimeError('Tailscale UDP 端口不可用')
    node=own.get('Key');disco=own.get('DiscoKey');expected=peer.get('Key')
    if not node or not disco or not expected:raise RuntimeError('Tailscale 节点身份或发现密钥不完整')
    return {'node_key':node,'disco_key':disco,'udp_port':port,'tail_ips':[str(a).split('/')[0] for a in own.get('Addresses',[])],
        'expected_peer_key':expected,'expected_peer_disco_key':peer.get('DiscoKey'),
        'peer_tail_ip':target,'peer_endpoints':[list(p) for p in endpoints]}

class WinSniffer:
    def __init__(self,local_port,endpoints,compact_only=False):
        if not endpoints and not compact_only:raise RuntimeError('对端暂时没有 IPv4 Tailscale 候选，等待对端上线并更新候选')
        self.dll,directory=load_driver();self.attempts=[];self.mode='exact_peer_endpoints'
        self.dll.WinDivertOpen.argtypes=[ctypes.c_char_p,ctypes.c_int,ctypes.c_short,ctypes.c_ulonglong];self.dll.WinDivertOpen.restype=ctypes.c_void_p
        self.dll.WinDivertRecv.argtypes=[ctypes.c_void_p,ctypes.c_void_p,ctypes.c_uint,ctypes.POINTER(ctypes.c_uint),ctypes.c_void_p];self.dll.WinDivertRecv.restype=ctypes.c_bool
        self.dll.WinDivertClose.argtypes=[ctypes.c_void_p];self.dll.WinDivertClose.restype=ctypes.c_bool
        # Ports/endpoints are parsed numeric values, never raw filter input.
        addresses=' or '.join(f'(ip.DstAddr == {ip} and udp.DstPort == {port})' for ip,port in endpoints)
        self.filter=f'outbound and ip and udp and udp.SrcPort == {local_port} and ({addresses})'
        exact=self.filter
        choices=[('compact_disco',compact_filter(local_port))] if compact_only else [('exact_peer_endpoints',exact),('compact_disco',compact_filter(local_port))]
        for mode,flt in choices:
            # A compact read-only alternative diagnoses filter-dependent failure;
            # it does not claim to cure a depleted WFP/kernel resource.
            self.mode=mode;self.filter=flt
            ctypes.set_last_error(0)
            self.handle=self.dll.WinDivertOpen(flt.encode(),0,30000,1|4)
            error=ctypes.get_last_error() if self.handle in (None,ctypes.c_void_p(-1).value) else 0
            self.attempts.append({'mode':mode,'filter':flt,'layer':0,'priority':30000,'flags':5,'winerror':error,'opened':not error and self.handle not in (None,ctypes.c_void_p(-1).value)})
            if self.attempts[-1]['opened']:break
            if mode=='exact_peer_endpoints' and error==1450:continue
            exc=ctypes.WinError(error);exc.capture_diagnostics={'attempts':self.attempts,'driver_directory':str(directory),
                'dll_sha256':hashlib.sha256((directory/'WinDivert.dll').read_bytes()).hexdigest(),
                'sys_sha256':hashlib.sha256((directory/'WinDivert64.sys').read_bytes()).hexdigest()}
            raise exc
    def recv(self):
        buf=ctypes.create_string_buffer(65535);address=ctypes.create_string_buffer(80);length=ctypes.c_uint()
        if not self.dll.WinDivertRecv(self.handle,buf,len(buf),ctypes.byref(length),address):raise ctypes.WinError(ctypes.get_last_error())
        return buf.raw[:length.value]
    def close(self):
        handle=self.handle;self.handle=None
        if handle:self.dll.WinDivertClose(handle)

def compact_filter(port):
    return f'outbound and ip and udp and udp.SrcPort == {port} and udp.PayloadLength >= 78 and udp.Payload32[0] == 0x5453f09f and udp.Payload16[2] == 0x92ac'

class TailBridge:
    def __init__(self,metadata,emit,journal,capture_factory=None,bind_ip='127.0.0.1'):
        self.metadata=metadata;self.emit=emit;self.journal=journal;self.capture_factory=capture_factory or WinSniffer
        address=ipaddress.ip_address(bind_ip)
        if address.version!=4 or address.is_unspecified or address.is_multicast:raise ValueError('本地代理需要明确的 IPv4 地址')
        self.local_ip=str(address)
        self.socket=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
        try:self.socket.bind((self.local_ip,0));self.socket.setblocking(False)
        except BaseException:self.socket.close();raise
        self.outbound=queue.Queue(maxsize=256);self.capture=None;self.thread=None;self.stop=threading.Event();self.peer=None;self.enabled=False;self.lifecycle=threading.RLock()
        self.bootstrap_stopped=threading.Event();self.disco_notices=set()
        self.capture_warning=None;self.capture_diagnostics={};self.capture_retry_at=0;self.capture_failures=0;self.diagnostic_thread=None;self.resource_diagnostics={}
        self.stats={'tail_tx_bytes':0,'tail_rx_bytes':0,'tail_tx_datagrams':0,'tail_rx_datagrams':0,'tail_tx_wg_datagrams':0,'tail_rx_wg_datagrams':0,'tail_drop':0,'bootstrap_copies':0,
            'tail_local_return_datagrams':0,'tail_tx_disco_datagrams':0,'tail_rx_disco_datagrams':0,'tail_local_source_rejected':0,
            'bootstrap_stopped':False,'bootstrap_suppressed':0}
    def stop_bootstrap(self,reason):
        with self.lifecycle:
            if self.bootstrap_stopped.is_set():return
            self.bootstrap_stopped.set();self.stats['bootstrap_stopped']=True
            self.emit('tail_bootstrap_stopped',reason=reason,proxy=list(self.socket.getsockname()),
                message='原生代理已产生返回报文，停止复制其他候选的发现探测，避免误选路径')
    def bind_peer(self,peer_metadata):
        if not peer_metadata or peer_metadata.get('node_key')!=self.metadata['expected_peer_key'] or peer_metadata.get('expected_peer_key')!=self.metadata['node_key']:
            raise RuntimeError('房间成员与选择的 Tailscale 节点不匹配，两边请选择彼此的 100.x 地址')
        self.peer=peer_metadata
    def disco_fields(self,payload,origin):
        if payload_kind(payload)!='disco':return {}
        sender='discokey:'+payload[6:38].hex()
        local=origin in ('bootstrap_copy','tailscale_local_proxy')
        cached=self.metadata.get('disco_key') if local else self.metadata.get('expected_peer_disco_key')
        reported=(self.peer or {}).get('expected_peer_disco_key') if local else (self.peer or {}).get('disco_key')
        fields={'disco_sender_key':sender,'disco_local_snapshot_key':cached,'disco_peer_snapshot_key':reported,
            'disco_local_snapshot_matches':sender==cached if cached else None,
            'disco_peer_snapshot_matches':sender==reported if reported else None,
            'disco_authentication':'native_tailscale','disco_origin':origin}
        # SelfNode and Peers are controller snapshots. magicsock's current
        # sender key can differ after a rotation / TSMP advertisement. A relay
        # cannot authenticate NaCl using public bytes: keep NodeKey/session
        # binding and deliver the unchanged ciphertext to native Tailscale.
        # Do not promote an observed header key to a trusted identity.
        if (cached and sender!=cached) or (reported and sender!=reported):
            name='tail_local_disco_snapshot_mismatches' if local else 'tail_peer_disco_snapshot_mismatches'
            self.stats[name]=self.stats.get(name,0)+1
            notice=(origin,sender,cached,reported)
            if notice not in self.disco_notices:
                if len(self.disco_notices)>=128:self.disco_notices.clear()
                self.disco_notices.add(notice)
                self.emit('tail_disco_snapshot_mismatch',**fields,
                    message='发现公钥与元数据快照不同；保留当前节点与隧道认证，将原始密文交给 Tailscale 校验')
        return fields
    def start(self):
        with self.lifecycle:self._start()
    def _start(self):
        if self.stop.is_set():raise RuntimeError('本轮接入已关闭，不能重新开启旧监听')
        if self.enabled:return
        if not self.peer:raise RuntimeError('Tailscale 对端尚未核对')
        # Native UDP forwarding needs the already bound UDP socket, not WinDivert.
        # One healthy peer can bootstrap the other through this passive proxy.
        self.enabled=True
        self.emit('tail_bridge_started',proxy=list(self.socket.getsockname()),native_destination=[self.local_ip,self.metadata['udp_port']],
            proxy_mode='physical_lan' if not ipaddress.ip_address(self.local_ip).is_loopback else 'loopback_test',
            sniff_only=True,peer_tail_ip=self.metadata['peer_tail_ip'])
        self.service_capture()
    def snapshot(self):
        return {'proxy_ready':self.enabled and not self.stop.is_set(),'capture_active':self.capture is not None,
            'capture_warning':self.capture_warning,'capture_failures':self.capture_failures,'capture_diagnostics':self.capture_diagnostics,
            'resource_diagnostics':self.resource_diagnostics,'bootstrap_stopped':self.bootstrap_stopped.is_set(),
            'mode':'native_proxy_return' if self.bootstrap_stopped.is_set() else 'active_bootstrap' if self.capture is not None else 'passive_bootstrap'}
    def _diagnose(self):
        from driverdiag import collect
        try:result=collect()
        except Exception as exc:result={'diagnostic_error':str(exc)}
        if not self.stop.is_set():self.resource_diagnostics=result;self.emit('tail_driver_resources',diagnostics=result)
    def service_capture(self,now=None):
        with self.lifecycle:
            now=time.monotonic() if now is None else now
            if self.stop.is_set() or not self.enabled or self.capture is not None or self.bootstrap_stopped.is_set() or now<self.capture_retry_at:return
            try:capture=self.capture_factory(self.metadata['udp_port'],[tuple(x) for x in self.metadata['peer_endpoints']])
            except (OSError,RuntimeError) as exc:
                self.capture_failures+=1;self.capture_retry_at=now+min(120,30*2**min(self.capture_failures-1,2))
                self.capture_warning=str(exc);self.capture_diagnostics=getattr(exc,'capture_diagnostics',{'winerror':getattr(exc,'winerror',None)})
                self.emit('tail_capture_unavailable',message='发现监听不可用，UDP 代理仍就绪，等待对端发现报文',
                    error=str(exc),winerror=getattr(exc,'winerror',None),diagnostics=self.capture_diagnostics,proxy_ready=True)
                if getattr(exc,'winerror',None)==1450 and self.diagnostic_thread is None:
                    self.diagnostic_thread=threading.Thread(target=self._diagnose,daemon=True);self.diagnostic_thread.start()
                return
            self.capture=capture;self.capture_warning=None;self.capture_diagnostics={'mode':getattr(capture,'mode','test_capture'),'attempts':getattr(capture,'attempts',[])}
            self.thread=threading.Thread(target=self._capture,args=(capture,),daemon=True);self.thread.start()
            # Preserve the existing successful start event. Log recovery/fallback separately.
            if self.capture_failures or getattr(capture,'mode',None)=='compact_disco':self.emit('tail_capture_recovered',diagnostics=self.capture_diagnostics)
    def _capture(self,capture):
        last=0
        while not self.stop.is_set():
            try:parsed=parse_ipv4_udp(capture.recv())
            except OSError as exc:
                active=self.capture is capture
                if self.capture is capture:
                    self.capture=None;capture.close()
                if active and not self.stop.is_set():
                    self.capture_warning=str(exc);self.capture_retry_at=time.monotonic()+30
                    self.emit('tail_capture_error',message='发现监听已停止，UDP 代理继续转发',error=str(exc),proxy_ready=self.enabled)
                return
            if not parsed:continue
            source,target,payload=parsed
            if source[1]!=self.metadata['udp_port'] or target not in {tuple(x) for x in self.metadata['peer_endpoints']}:
                self.stats['bootstrap_scope_rejected']=self.stats.get('bootstrap_scope_rejected',0)+1;continue
            # Only copy discovery packets, never duplicate ordinary WG data
            # or other traffic that happens to share the peer's public IP.
            if payload_kind(payload)!='disco':continue
            if self.bootstrap_stopped.is_set():
                self.stats['bootstrap_suppressed']+=1;continue
            now=time.monotonic()
            if now-last<.2:continue
            last=now
            self.journal.record(direction='bootstrap_copy',source=list(source),target=list(target),kind='disco',bytes=len(payload),sha256=hashlib.sha256(payload).hexdigest(),**self.disco_fields(payload,'bootstrap_copy'))
            self.queue(payload,'bootstrap_copy');self.stats['bootstrap_copies']+=1
    def queue(self,payload,origin):
        if origin=='bootstrap_copy' and self.bootstrap_stopped.is_set():return
        try:self.outbound.put_nowait((payload,origin))
        except queue.Full:self.stats['tail_drop']+=1
    def next_outbound(self):
        while True:
            payload,origin=self.outbound.get_nowait()
            if origin=='bootstrap_copy' and self.bootstrap_stopped.is_set():continue
            return payload,origin
    def poll(self):
        for _ in range(64):
            try:payload,source=self.socket.recvfrom(65535)
            except BlockingIOError:break
            except ConnectionResetError:continue
            if source!=(self.local_ip,self.metadata['udp_port']) or not payload_kind(payload):
                self.stats['tail_drop']+=1;self.stats['tail_local_source_rejected']+=1
                self.journal.record(direction='tail_local_rejected',source=list(source),bytes=len(payload),reason='native_source_or_packet_kind_mismatch')
                continue
            self.stats['tail_local_return_datagrams']+=1
            self.stop_bootstrap('native_proxy_return')
            self.journal.record(direction='tail_local_return',source=list(source),local=list(self.socket.getsockname()),kind=payload_kind(payload),bytes=len(payload),sha256=hashlib.sha256(payload).hexdigest(),**self.disco_fields(payload,'tailscale_local_proxy'))
            self.queue(payload,'tailscale_local_proxy')
    def deliver(self,payload):
        # Called only after client.receive_udp has verified the selected
        # actor, current transport session, AEAD and current UDP source path.
        # The daemon retains its known-peer lookup and NaCl/WG authentication.
        kind=payload_kind(payload)
        reason=None
        if not kind:reason='unsupported_native_packet'
        elif not self.enabled or self.stop.is_set():reason='local_proxy_not_ready'
        elif not self.peer:reason='peer_identity_not_bound'
        if reason:
            self.stats['tail_drop']+=1;self.stats['tail_deliver_rejected']=self.stats.get('tail_deliver_rejected',0)+1
            self.journal.record(direction='tail_deliver_rejected',reason=reason,kind=kind,bytes=len(payload),sha256=hashlib.sha256(payload).hexdigest());return False
        fields=self.disco_fields(payload,'authenticated_peer_tunnel')
        try:self.socket.sendto(payload,(self.local_ip,self.metadata['udp_port']))
        except OSError as exc:
            if not isinstance(exc,(BlockingIOError,ConnectionResetError)) and getattr(exc,'winerror',None) not in (10035,10055) and exc.errno not in (11,35,10035,10055):raise
            self.stats['tail_drop']+=1;self.stats['tail_local_send_backpressure']=self.stats.get('tail_local_send_backpressure',0)+1
            self.journal.record(direction='tail_deliver_rejected',reason='native_socket_backpressure',kind=kind,bytes=len(payload),sha256=hashlib.sha256(payload).hexdigest());return False
        self.stats['tail_rx_bytes']+=len(payload);self.stats['tail_rx_datagrams']+=1
        if kind=='wireguard_data':self.stats['tail_rx_wg_datagrams']+=1
        if kind=='disco':self.stats['tail_rx_disco_datagrams']+=1
        self.journal.record(direction='tail_deliver',kind=kind,source=list(self.socket.getsockname()),target=[self.local_ip,self.metadata['udp_port']],bytes=len(payload),sha256=hashlib.sha256(payload).hexdigest(),**fields)
        return True
    def refresh(self,metadata):
        with self.lifecycle:return self._refresh(metadata)
    def _refresh(self,metadata):
        if self.stop.is_set():return False
        if metadata['node_key']!=self.metadata['node_key'] or metadata['expected_peer_key']!=self.metadata['expected_peer_key']:
            raise RuntimeError('Tailscale 节点身份已改变，请重新选择对端并启动')
        changed=metadata!=self.metadata;native_changed=metadata['udp_port']!=self.metadata['udp_port'] or metadata['disco_key']!=self.metadata['disco_key']
        restart=native_changed or metadata['peer_endpoints']!=self.metadata['peer_endpoints']
        if native_changed:
            self.bootstrap_stopped.clear();self.stats['bootstrap_stopped']=False
        self.metadata=metadata
        if restart and self.enabled:
            capture=self.capture;self.capture=None
            if capture:capture.close()
            if self.thread:self.thread.join(2)
            # Endpoint refresh cannot postpone an already backed-off failed open.
            if native_changed or capture:self.capture_retry_at=0
            self.service_capture()
        return changed
    def close(self):
        with self.lifecycle:self._close()
    def _close(self):
        self.stop.set()
        if self.capture:self.capture.close()
        if self.thread:self.thread.join(2)
        if self.diagnostic_thread:self.diagnostic_thread.join(2)
        self.socket.close();self.enabled=False
