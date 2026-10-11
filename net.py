import hashlib
import json
import os
import secrets
import socket
import ssl
import struct
import subprocess
import queue
import threading
import time

def physical():
    if os.name!='nt':return '0.0.0.0',0
    script="$x=@(Get-NetAdapter -Physical | Where-Object Status -eq 'Up' | ForEach-Object { $i=$_; $c=Get-NetIPConfiguration -InterfaceIndex $i.ifIndex; if($c.IPv4DefaultGateway -and $c.IPv4Address){[pscustomobject]@{ip=$c.IPv4Address[0].IPAddress;index=$i.ifIndex;metric=(Get-NetIPInterface -InterfaceIndex $i.ifIndex -AddressFamily IPv4).InterfaceMetric}} }); $x | Sort-Object metric | ConvertTo-Json -Compress"
    r=subprocess.run(['powershell.exe','-NoProfile','-NonInteractive','-Command',script],capture_output=True,text=True,timeout=20,creationflags=subprocess.CREATE_NO_WINDOW)
    rows=json.loads(r.stdout)
    if isinstance(rows,dict):rows=[rows]
    if not rows:raise RuntimeError('没有可用物理网卡，请填写 LAN IPv4 和网卡索引')
    return rows[0]['ip'],int(rows[0]['index'])
def raw_socket(kind,bind,index=0,port=0,reuse=False):
    s=socket.socket(socket.AF_INET,kind)
    try:
        if reuse:s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
        if os.name=='nt' and index:s.setsockopt(socket.IPPROTO_IP,31,struct.pack('!I',index))
        if os.name=='nt' and kind==socket.SOCK_DGRAM:
            import ctypes
            winsock=ctypes.WinDLL('Ws2_32.dll')
            ioctl=winsock.WSAIoctl
            ioctl.argtypes=[ctypes.c_size_t,ctypes.c_uint32,ctypes.c_void_p,ctypes.c_uint32,
                            ctypes.c_void_p,ctypes.c_uint32,ctypes.POINTER(ctypes.c_uint32),
                            ctypes.c_void_p,ctypes.c_void_p]
            ioctl.restype=ctypes.c_int
            enabled=ctypes.c_uint32(0);returned=ctypes.c_uint32(0)
            if ioctl(s.fileno(),0x9800000C,ctypes.byref(enabled),4,None,0,ctypes.byref(returned),None,None)!=0:
                raise OSError(winsock.WSAGetLastError(),'UDP connection-reset option failed')
        s.bind((bind,port));return s
    except BaseException:s.close();raise

def public_dns(host,bind,index):
    """Bypass synthetic VPN DNS on an explicitly bound physical socket."""
    import ipaddress
    try:
        ip=socket.gethostbyname(host)
        if ipaddress.ip_address(ip).is_global:return ip
    except OSError:pass
    labels=host.encode('ascii').split(b'.')
    question=b''.join(bytes([len(x)])+x for x in labels)+b'\0'+struct.pack('!HH',1,1)
    for resolver in ('223.5.5.5','1.1.1.1'):
        s=raw_socket(socket.SOCK_DGRAM,bind,index)
        try:
            ident=secrets.randbelow(65536);s.settimeout(2)
            s.sendto(struct.pack('!6H',ident,0x100,1,0,0,0)+question,(resolver,53))
            data,origin=s.recvfrom(4096)
            if origin!=(resolver,53) or len(data)<12:continue
            tx,flags,qd,an,_,_=struct.unpack('!6H',data[:12])
            if tx!=ident or flags&15 or not flags&0x8000 or qd!=1 or an>64:continue
            def skip(offset):
                for _ in range(128):
                    if offset>=len(data):raise ValueError('DNS truncated')
                    size=data[offset];offset+=1
                    if size==0:return offset
                    if size&0xc0==0xc0:
                        if offset>=len(data):raise ValueError('DNS truncated')
                        return offset+1
                    if size>63 or offset+size>len(data):raise ValueError('DNS invalid label')
                    offset+=size
                raise ValueError('DNS name too long')
            at=skip(12)+4
            for _ in range(an):
                at=skip(at)
                if at+10>len(data):break
                typ,cls,ttl,size=struct.unpack('!HHIH',data[at:at+10]);at+=10
                if at+size>len(data):break
                if typ==1 and cls==1 and size==4:
                    ip=socket.inet_ntoa(data[at:at+size])
                    if ipaddress.ip_address(ip).is_global:return ip
                at+=size
        except (OSError,ValueError):pass
        finally:s.close()
    raise OSError('无法取得真实公网 DNS 地址；保持现有 VPN 设置')
def tls_connect(cfg,bind,index,emit=None,stop=None):
    """Race two pinned TLS routes; cancel and close the unselected socket.

    Only the winning connection joins a room. Neither route changes the
    physical binding of the UDP discovery or peer traversal sockets.
    """
    results=queue.Queue();done=threading.Event();lock=threading.Lock();sockets={}
    def progress(route,stage,started,**fields):
        if emit:emit(route=route,stage=stage,seconds=round(time.monotonic()-started,3),**fields)
    def cancelled():return done.is_set() or bool(stop and stop.is_set())
    class Cancel:
        def is_set(self):return cancelled()
    def preflight(channel,route,started):
        if not cfg.get('control_preflight'):return
        from controlstream import ControlStream
        nonce=secrets.token_hex(16);stream=ControlStream(channel)
        stream.sendall(json.dumps({'k':'control_health','access':cfg['access'],'nonce':nonce,'padding':'C'*256},separators=(',',':')).encode()+b'\n')
        reply=json.loads(stream.readline(Cancel(),float(cfg.get('control_preflight_timeout',3))))
        if reply.get('k')!='control_ready' or not secrets.compare_digest(str(reply.get('nonce','')),nonce) or reply.get('padding')!='C'*256:raise RuntimeError('协调路径认证回复不匹配')
        progress(route,'application_ready',started)

    def attempt(route,delay):
        s=None;started=time.monotonic()
        try:
            if done.wait(delay) or cancelled():return
            if route=='udp':
                from controludp import udp_tls_connect
                progress(route,'udp_tls_handshake',started)
                s=udp_tls_connect(cfg,bind,index,Cancel())
                preflight(s,route,started)
                with lock:
                    if cancelled():s.close();return
                    sockets[route]=s
                progress(route,'connected',started,local_endpoint=list(s.getsockname()),server_endpoint=list(s.getpeername()))
                results.put((route,s,None));return
            context=ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT);context.check_hostname=False;context.verify_mode=ssl.CERT_NONE
            context.minimum_version=ssl.TLSVersion.TLSv1_2
            s=raw_socket(socket.SOCK_STREAM,bind,index) if route=='physical' else socket.socket(socket.AF_INET,socket.SOCK_STREAM)
            with lock:
                if cancelled():s.close();return
                sockets[route]=s
            s.settimeout(5);progress(route,'tcp_connect',started)
            target_host=cfg.get('control_tail_host') if route=='tail' else cfg['host']
            s.connect((target_host,cfg.get('lab_control_port',39610)))
            with lock:
                if cancelled():s.close();return
                s=context.wrap_socket(s,server_hostname=cfg['host'],do_handshake_on_connect=False);sockets[route]=s
            progress(route,'tls_handshake',started);s.do_handshake()
            if not secrets.compare_digest(hashlib.sha256(s.getpeercert(binary_form=True)).hexdigest(),cfg['pin'].lower()):raise RuntimeError('服务器证书指纹不匹配')
            preflight(s,route,started)
            if cancelled():s.close();return
            progress(route,'connected',started,local_endpoint=list(s.getsockname()),server_endpoint=list(s.getpeername()));results.put((route,s,None))
        except Exception as exc:
            if s:s.close()
            if not cancelled():progress(route,'failed',started,message=str(exc));results.put((route,None,exc))
    supported=('udp','physical','system') if cfg.get('control_udp_port') else ('physical','system')
    if cfg.get('control_tail_host'):supported=(*supported,'tail')
    supported=tuple(r for r in cfg.get('control_transports',supported) if r in supported)
    if not supported:raise ValueError('没有可用的协调传输方式')
    preferred=cfg.get('_control_route_preference',supported[0])
    routes=tuple(sorted(supported,key=lambda r:r!=preferred))
    # A TLS handshake does not prove application replies work. Recovery may
    # temporarily exclude a route that repeatedly won TLS but lost room replies.
    requested=cfg.get('_control_route_order')
    if requested:
        routes=tuple(r for r in requested if r in supported) or routes
    workers=[]
    for i,route in enumerate(routes):
        worker=threading.Thread(target=attempt,args=(route,.15*i),name='NATPair-TLS-'+route,daemon=True);worker.start();workers.append(worker)
    errors=[];deadline=time.monotonic()+11;winner=None
    try:
        while len(errors)<len(routes) and time.monotonic()<deadline:
            if stop and stop.is_set():raise OSError('协调连接已取消')
            try:route,s,error=results.get(timeout=.1)
            except queue.Empty:continue
            if error is None:winner=s;return s,route
            if isinstance(error,RuntimeError):raise error
            errors.append(route+': '+str(error))
        raise OSError('协调 TLS 无法连接: '+('; '.join(errors) or '双路连接超时'))
    finally:
        done.set()
        with lock:
            for s in sockets.values():
                if s is not winner:
                    if hasattr(s,'shutdown'):
                        try:s.shutdown(socket.SHUT_RDWR)
                        except OSError:pass
                    s.close()
        for worker in workers:worker.join(1)
