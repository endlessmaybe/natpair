"""Session-scoped UDP ingress for this executable, local ports and peer IPs."""
import base64,ipaddress,json,os,pathlib,re,subprocess,sys,threading

def powershell(script):
    encoded=base64.b64encode(("$ErrorActionPreference='Stop'; [Console]::OutputEncoding=[System.Text.Encoding]::UTF8; "+script).encode('utf-16le')).decode('ascii')
    env={k:v for k,v in os.environ.items() if k.lower()!='psmodulepath'}
    p=subprocess.run(['powershell.exe','-NoProfile','-NonInteractive','-EncodedCommand',encoded],
        capture_output=True,text=True,encoding='utf-8',errors='replace',timeout=15,env=env,creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
    if p.returncode:raise RuntimeError(p.stderr.strip() or 'Firewall command failed')
    return json.loads(p.stdout) if p.stdout.strip() else None

def quote(value):return "'"+str(value).replace("'","''")+"'"

class PeerFirewall:
    def __init__(self,ident,local,ports,emit,runner=powershell,program=None,protocol='UDP',authenticated_any_source=False,overlay_scope=False):
        if not re.fullmatch('[0-9a-f]{32}',ident):raise ValueError('invalid session identifier')
        address=ipaddress.ip_address(local)
        if address.version!=4:raise ValueError('IPv4 required')
        ports=sorted(set(ports))
        if not 1<=len(ports)<=8 or any(type(p) is not int or not 1<=p<=65535 for p in ports):raise ValueError('invalid UDP port set')
        if protocol not in ('UDP','TCP'):raise ValueError('invalid firewall protocol')
        self.protocol=protocol;self.name=('NATPairTail-TCP-' if protocol=='TCP' else 'NATPairTail-')+ident;self.local=str(address);self.ports=ports;self.program=str(pathlib.Path(program or sys.executable).resolve())
        self.emit=emit;self.runner=runner;self.signature=None;self.thread=None;self.lock=threading.Lock();self.created=False;self.closed=False
        self.overlay_scope=overlay_scope
        self.authenticated_any_source=bool(authenticated_any_source and protocol=='UDP')
    def update_ports(self,ports):
        ports=sorted(set(ports))
        if not 1<=len(ports)<=8 or any(type(p) is not int or not 1<=p<=65535 for p in ports):raise ValueError('invalid local port set')
        if self.closed or ports==self.ports or (self.thread and self.thread.is_alive()):return
        with self.lock:self.ports=ports;self.signature=None
    def update(self,addresses):
        ips=tuple(sorted(set(str(ipaddress.ip_address(a)) for a in addresses if ipaddress.ip_address(a).version==4 and (ipaddress.ip_address(a).is_global or self.overlay_scope and ipaddress.ip_address(a) in ipaddress.ip_network('100.64.0.0/10')))))
        if not ips or self.closed or ips==self.signature or (self.thread and self.thread.is_alive()):return
        self.thread=threading.Thread(target=self._apply,args=(ips,),daemon=True);self.thread.start()
    def _apply(self,ips):
        with self.lock:
            if self.closed:return
            common=f'-Name {quote(self.name)} -Direction Inbound -Action Allow -Enabled True -Profile Any -Protocol {self.protocol} -Program {quote(self.program)} -LocalAddress {quote(self.local)} -LocalPort '+','.join(map(str,self.ports))+' -RemoteAddress '+('Any' if self.authenticated_any_source else ','.join(quote(ip) for ip in ips))
            script=f'$existing=Get-NetFirewallRule -Name {quote(self.name)} -ErrorAction SilentlyContinue; if($existing){{Set-NetFirewallRule {common} | Out-Null}}else{{New-NetFirewallRule {common} -DisplayName {quote(self.name)} | Out-Null}}; '
            script+="@{rule=(Get-NetFirewallRule -Name "+quote(self.name)+" | Select-Object Name,Enabled,Direction,Action);profiles=@(Get-NetFirewallProfile | Select-Object Name,Enabled,DefaultInboundAction,AllowInboundRules,AllowLocalFirewallRules)} | ConvertTo-Json -Depth 5 -Compress"
            try:
                # Mark intent before invoking so a command that creates a rule
                # and then times out still triggers exact-name cleanup.
                self.created=True;result=self.runner(script);self.signature=ips
                self.emit('firewall_peer_allow',program=self.program,local_address=self.local,local_ports=self.ports,peer_ipv4=list(ips),protocol=self.protocol,authenticated_discovery_any_source=self.authenticated_any_source,scope='this_executable_eight_local_udp_ports_authenticated_peer' if self.authenticated_any_source else 'this_executable_selected_peer_'+self.protocol.lower()+'_only',result=result)
            except Exception as exc:self.emit('firewall_error',message=str(exc),rule=self.name)
    def close(self):
        self.closed=True
        if self.thread:self.thread.join(16)
        with self.lock:
            if not self.created:return
            try:
                self.runner(f'Get-NetFirewallRule -Name {quote(self.name)} -ErrorAction SilentlyContinue | Remove-NetFirewallRule; @{{removed={quote(self.name)}}} | ConvertTo-Json -Compress')
                self.emit('firewall_peer_cleanup',rule=self.name);self.created=False
            except Exception as exc:self.emit('firewall_cleanup_error',message=str(exc),rule=self.name)

class LocalProxyFirewall:
    """Two exact local UDP flows; never expose the proxy to other LAN hosts."""
    def __init__(self,ident,local,proxy_port,emit,runner=powershell,program=None):
        if not re.fullmatch('[0-9a-f]{32}',ident):raise ValueError('invalid session identifier')
        ip=ipaddress.ip_address(local)
        if ip.version!=4 or ip.is_unspecified or ip.is_multicast:raise ValueError('explicit local IPv4 required')
        if type(proxy_port) is not int or not 1<=proxy_port<=65535:raise ValueError('invalid proxy port')
        self.names=['NATPairTail-LocalProxy-'+ident,'NATPairTail-LocalNative-'+ident]
        self.local=str(ip);self.proxy_port=proxy_port;self.program=str(pathlib.Path(program or sys.executable).resolve())
        self.emit=emit;self.runner=runner;self.thread=None;self.lock=threading.Lock();self.created=False;self.closed=False;self.native_port=None
    def update(self,native_port):
        if type(native_port) is not int or not 1<=native_port<=65535 or native_port==self.proxy_port:raise ValueError('invalid native port')
        if self.closed or native_port==self.native_port:return
        if self.thread and self.thread.is_alive():self.thread.join(16)
        if self.closed:return
        self.thread=threading.Thread(target=self._apply,args=(native_port,),daemon=True);self.thread.start()
    def _apply(self,native_port):
        with self.lock:
            if self.closed:return
            # Resolve the installed daemon program in PowerShell, never by a
            # user supplied path or a broad "any program" firewall exception.
            script="$native=@(Get-Process tailscaled -ErrorAction Stop | Select-Object -ExpandProperty Path -Unique); if($native.Count -ne 1 -or -not $native[0]){throw 'Cannot uniquely resolve native Tailscale executable'}; "
            common=f'-Direction Inbound -Action Allow -Enabled True -Profile Any -Protocol UDP -LocalAddress {quote(self.local)} -RemoteAddress {quote(self.local)} '
            for name,program,local_port,remote_port in ((self.names[0],quote(self.program),self.proxy_port,native_port),(self.names[1],'$native[0]',native_port,self.proxy_port)):
                rule=f'-Name {quote(name)} {common}-Program {program} -LocalPort {local_port} -RemotePort {remote_port}'
                script+=f'$existing=Get-NetFirewallRule -Name {quote(name)} -ErrorAction SilentlyContinue; if($existing){{Set-NetFirewallRule {rule} | Out-Null}}else{{New-NetFirewallRule {rule} -DisplayName {quote(name)} | Out-Null}}; '
            script+='@{native_program=$native[0];rules=@('+','.join(quote(n) for n in self.names)+')} | ConvertTo-Json -Compress'
            try:
                self.created=True;result=self.runner(script);self.native_port=native_port
                self.emit('tail_local_firewall',local_address=self.local,proxy_port=self.proxy_port,native_port=native_port,
                    scope='exact_local_host_and_two_udp_ports_only',result=result)
            except Exception as exc:self.emit('tail_local_firewall_error',message=str(exc),rules=self.names)
    def close(self):
        self.closed=True
        if self.thread:self.thread.join(16)
        with self.lock:
            if not self.created:return
            try:
                self.runner('Get-NetFirewallRule -Name '+','.join(quote(n) for n in self.names)+" -ErrorAction SilentlyContinue | Remove-NetFirewallRule; @{removed=$true} | ConvertTo-Json -Compress")
                self.created=False;self.emit('tail_local_firewall_cleanup',rules=self.names)
            except Exception as exc:self.emit('tail_local_firewall_cleanup_error',message=str(exc),rules=self.names)
