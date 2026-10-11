import base64
import ipaddress
import secrets
import socket
import time
from net import raw_socket,public_dns
from wire import pack,unpack,endpoint,pattern,stun_request,parse_stun
from strategy import allocation_model

class Measurements:
    def __init__(self,cfg,bind,index,stop,emit):
        self.cfg,self.bind,self.index,self.stop,self.emit=cfg,bind,index,stop,emit
        self.last_query=0
        self.key=bytes.fromhex(cfg['access']);self.host=socket.gethostbyname(cfg['host']);self.base=cfg.get('lab_udp_base',39601)
    def socket(self):return raw_socket(socket.SOCK_DGRAM,self.bind,self.index)
    def query(self,s,port,kind='observe',retries=3):
        token=secrets.token_hex(16);destination=(self.host,port)
        expected=(self.host,self.base+1) if kind=='cross' else destination
        request=pack(self.key,{'k':kind,'n':token})
        for _ in range(retries):
            if self.stop.is_set():return None
            if self.stop.wait(max(0,.1-(time.monotonic()-self.last_query))):return None
            at=time.monotonic();self.last_query=at;s.sendto(request,destination);deadline=at+1.5
            if hasattr(self,'trace_packet'):self.trace_packet(s,request,'tx',destination,kind='measurement_'+kind,nonce=token,lane='measurement')
            while time.monotonic()<deadline and not self.stop.is_set():
                s.settimeout(min(.2,max(.001,deadline-time.monotonic())))
                try:data,source=s.recvfrom(4096)
                except socket.timeout:continue
                except OSError:return None
                if hasattr(self,'trace_packet'):self.trace_packet(s,data,'rx',source,kind='measurement_reply')
                obj=unpack(self.key,data)
                if obj and obj.get('k')=='observed' and obj.get('n')==token and source==expected and obj.get('mode')==kind:
                    ep=endpoint(obj.get('endpoint'),public=self.cfg.get('public_only',True))
                    if ep:return {'endpoint':list(ep),'source':list(source),'rtt_ms':round((time.monotonic()-at)*1000,2)}
            if self.stop.wait(.5):return None
        return None
    def tcp_observe(self,port,local_port=0):
        s=None;stage='bind';started=time.monotonic();bound_port=None
        try:
            s=raw_socket(socket.SOCK_STREAM,self.bind,self.index,local_port,reuse=True);s.settimeout(min(8,max(1,float(self.cfg.get('tcp_observe_timeout',3)))))
            bound_port=s.getsockname()[1]
            if hasattr(self,'tcp_permission'):
                deadline=time.monotonic()+12
                while not self.tcp_permission(s,(self.host,port)):
                    if self.stop.wait(.1) or time.monotonic()>=deadline:return {'error':'protection_deferred','stage':'protection'}
            stage='connect';s.connect((self.host,port));nonce=secrets.token_hex(16);stage='send_request'
            s.sendall(base64.b64encode(pack(self.key,{'k':'tcp_observe','n':nonce}))+b'\n')
            stage='read_observation'
            with s.makefile('rb') as reader:line=reader.readline(4096).strip()
            obj=unpack(self.key,base64.b64decode(line,validate=True))
            ep=endpoint(obj.get('endpoint'),public=self.cfg.get('public_only',True)) if obj and obj.get('n')==nonce else None
            return {'endpoint':list(ep),'local_port':s.getsockname()[1],'stage':'complete'} if ep else {'error':'invalid_tcp_observation','stage':'parse_observation'}
        except (OSError,ValueError) as e:return {'error':str(e),'stage':stage,'local_port':bound_port,'elapsed_seconds':round(time.monotonic()-started,3)}
        finally:
            if s:s.close()
    def public_stun(self):
        results=[]
        for host in self.cfg.get('stun_hosts',['stun.cloudflare.com','global.stun.twilio.com']):
            if self.stop.is_set():break
            try:
                ip=public_dns(host,self.bind,self.index)
                if not ipaddress.ip_address(ip).is_global:raise ValueError('DNS returned non-public IPv4')
                address=(ip,3478);s=self.socket()
                try:
                    transaction=secrets.token_bytes(12);s.sendto(stun_request(transaction),address);s.settimeout(2)
                    data,source=s.recvfrom(4096);obj=parse_stun(data,transaction) if source==address else None
                    if not obj:raise ValueError('invalid or unexpected STUN response')
                    entry={'host':host,'server':list(address),**obj,'cross_ip_filtering':'undetermined'}
                    other=endpoint(obj.get('other'),True)
                    if other and other[0]!=ip:
                        # No contact with OTHER-ADDRESS before filtering test.
                        tx=secrets.token_bytes(12);s.sendto(stun_request(tx,6),address);deadline=time.monotonic()+2.5
                        while time.monotonic()<deadline:
                            s.settimeout(min(.2,max(.001,deadline-time.monotonic())))
                            try:d,origin=s.recvfrom(4096)
                            except socket.timeout:continue
                            if origin==other and parse_stun(d,tx):
                                entry['cross_ip_filtering']='alternate_ip_reply_received';break
                        if entry['cross_ip_filtering']=='undetermined':entry['reason']='alternate_reply_not_seen; not proof of strict filtering'
                    else:entry['reason']='server_does_not_advertise_alternate_ipv4'
                    results.append(entry)
                finally:s.close()
            except (OSError,ValueError) as e:results.append({'host':host,'error':str(e),'cross_ip_filtering':'undetermined'})
            self.stop.wait(.5)
        return results
    def binding_on_socket(self,s,address):
        for _ in range(2):
            if self.stop.is_set():return None
            transaction=secrets.token_bytes(12);sent=time.monotonic();s.sendto(stun_request(transaction),address)
            deadline=sent+1.5
            while time.monotonic()<deadline and not self.stop.is_set():
                s.settimeout(min(.2,max(.001,deadline-time.monotonic())))
                try:data,source=s.recvfrom(4096)
                except socket.timeout:continue
                except OSError:return None
                obj=parse_stun(data,transaction) if source==address else None
                mapped=endpoint((obj or {}).get('mapped'),self.cfg.get('public_only',True))
                if mapped:return {'endpoint':list(mapped),'source':list(source),'rtt_ms':round((time.monotonic()-sent)*1000,2)}
            if self.stop.wait(.3):return None
        return None
    def observed_baseline(self,s,port):
        registered=getattr(self,'registered_observer',None)
        return (registered(s,0,port) if registered else None) or self.query(s,port)
    def cross_ip_mapping(self):
        endpoints=[];dns_errors=[]
        for host in self.cfg.get('stun_hosts',['stun.cloudflare.com','global.stun.twilio.com']):
            if self.stop.is_set():break
            try:
                ip=public_dns(host,self.bind,self.index)
                if ip not in {self.host,*[e['ip'] for e in endpoints]}:endpoints.append({'host':host,'ip':ip})
            except (OSError,ValueError) as e:dns_errors.append({'host':host,'error':str(e)})
        trials=[]
        if not endpoints:return {'classification':'undetermined','trials':trials,'dns_errors':dns_errors,'reason':'no_distinct_stun_ip_available'}
        for observer in endpoints[:2]:
            if self.stop.is_set():break
            s=self.socket()
            try:
                before=self.observed_baseline(s,self.base);alternate=self.binding_on_socket(s,(observer['ip'],3478));after=self.observed_baseline(s,self.base)
                trials.append({'local_port':s.getsockname()[1],'before':before,'other_ip':alternate,'after':after,'other_server':observer,'scope':'same_live_udp_socket_three_sequential_observations'})
            finally:s.close()
            self.stop.wait(.3)
        known=[]
        for t in trials:
            before,other,after=t['before'],t['other_ip'],t['after']
            if before and other and after and before['endpoint']==after['endpoint']:
                known.append('different_between_destination_ips' if before['endpoint']!=other['endpoint'] else 'same_for_tested_destination_ips')
        classification='different_between_destination_ips' if 'different_between_destination_ips' in known else 'same_for_tested_destination_ips' if known else 'undetermined'
        return {'classification':classification,'trials':trials,'dns_errors':dns_errors,
                'scope':'mapping only; sequential observation does not establish peer mapping or filtering',
                'reason':'complete_bracketed_observations' if known else 'incomplete_or_changed_baseline'}
    def source_allocation(self):
        self.emit('紧凑验证 8 个新源端口的分配：前 6 个学习，后 2 个事先预测；仅证明服务器方向')
        sockets=[];samples=[]
        try:
            first=self.socket();sockets.append(first);base_port=first.getsockname()[1]
            if base_port>65528:return {'validated':False,'classification':'unknown','reason':'source_range_boundary'}
            for i in range(1,8):
                if self.stop.is_set():break
                sockets.append(raw_socket(socket.SOCK_DGRAM,self.bind,self.index,base_port+i))
            for i,s in enumerate(sockets):
                if self.stop.is_set():break
                predicted=None
                if i>=6 and all(entry['endpoint'] for entry in samples[:6]):
                    training=[entry['endpoint'][1] for entry in samples[:6]]
                    deltas=[training[j+1]-training[j] for j in range(5)]
                    if len(set(deltas))==1 and 1<=abs(deltas[0])<=128:
                        predicted=training[5]+(i-5)*deltas[0]
                registered=getattr(self,'registered_observer',None)
                observation=registered(s,i) if registered else None
                if not observation:observation=self.query(s,self.base,retries=1)
                samples.append({'index':i,'local_port':s.getsockname()[1],
                                'predicted_before_request':predicted,
                                'observation_source':(observation or {}).get('via','udp_reply' if observation else None),
                                'endpoint':observation['endpoint'] if observation else None})
            model=allocation_model(samples)
            model['source_mode']='eight_reserved_consecutive_local_ports'
            self.emit('新源端口留出验证：'+('通过，但未证明对方方向可预测' if model['validated'] else '未通过／样本不足，不强行分类'))
            return model
        except OSError as e:return {'validated':False,'classification':'unknown','reason':'source_bind_or_observation_failed','error':str(e),'samples':samples}
        finally:
            for s in sockets:s.close()
    def run(self):
        if self.cfg.get('fast_start',False):
            self.emit('快速建立模式：直接准备活跃 UDP 套接字；完整过滤／端口规律测量保留在原版策略取证模式')
            return {'same_ip_filtering':'undetermined','cross_ip_filtering':'undetermined','filter_trials':[],
                'udp_observations':[],'public_stun':[],
                'port_pattern':{'validated':False,'classification':'unknown','reason':'not_measured_in_fast_start'},
                'allocation_prediction':{'validated':False,'classification':'unknown','reason':'not_measured_in_fast_start'},
                'cross_ip_mapping':{'classification':'undetermined','trials':[],'reason':'not_measured_in_fast_start'},
                'mapping_scope':'only current live observer candidates; operator mapping and filtering unclassified'}
        self.emit('开始测同 IP 换来源端口；使用全新套接字，避免提前放行备用端口')
        trials=[]
        for _ in range(3):
            if self.stop.is_set():break
            s=self.socket()
            try:
                before=self.observed_baseline(s,self.base);cross=self.query(s,self.base,'cross') if before else None
                after=self.observed_baseline(s,self.base) if before else None
                trials.append({'baseline_before':before,'alternate_port':cross,'baseline_after':after})
            finally:s.close()
        filtering='alternate_port_reply_received' if any(t['alternate_port'] for t in trials) else 'undetermined'
        self.emit('开始测 8 个新目标端口的映射；前 6 个学习，后 2 个验证')
        s=self.socket();observations=[]
        try:
            for i in range(8):
                observation=self.observed_baseline(s,self.base+i);observations.append(observation)
                self.stop.wait(.5)
        finally:s.close()
        ports=[o['endpoint'][1] if o else None for o in observations]
        p=pattern(ports)
        self.emit('检查公开 STUN 是否提供第二公网 IPv4；不支持时保留未确定')
        external=self.public_stun()
        self.emit('补测同一 UDP 套接字跨目的 IP 的映射；用前后服务器观察排除基线变化')
        cross_mapping=self.cross_ip_mapping()
        cross='alternate_ip_reply_received' if any(e.get('cross_ip_filtering')=='alternate_ip_reply_received' for e in external) else 'undetermined'
        allocation=self.source_allocation() if self.cfg.get('prediction_enabled',True) else {'validated':False,'classification':'unknown','reason':'disabled'}
        profile={'allocation_prediction':allocation,'same_ip_filtering':filtering,'cross_ip_filtering':cross,'filter_trials':trials,
                 'udp_observations':observations,'port_pattern':p,'public_stun':external,'cross_ip_mapping':cross_mapping,
                 'mapping_scope':'one_server_ip_eight_ports; does not establish peer mapping or port-block boundaries'}
        self.emit(f'测量完成：同 IP 来源端口测试={filtering}；跨 IP={cross}；端口规律验证={p["validated"]}')
        return profile
