import hashlib
from journal import PacketJournal,NullJournal
from transport import DataTransport,FlowBudget,MAGIC as DATA_MAGIC
from tailbridge import TailBridge,read_metadata,is_admin,command,payload_kind,driver_check
from accelerator import MixedSearch,phased_choice,CandidatePriority,FastSearch
from firewall import PeerFirewall,LocalProxyFirewall
from peersync import PeerSync,tail_ip
from probe_coverage import Coverage
from combinations import CombinationLimit
import collections
import concurrent.futures
import json
import secrets
import selectors
import socket
import struct
import threading
import time
from protection import MappingPressure,ConnectionGuard,offer,negotiated
from coexist import Coexistence
from measure import Measurements
from net import physical,raw_socket,tls_connect
from controlstream import ControlStream
from wire import pack,unpack,room_keys,endpoint,hexid
from discovery import LiveDiscovery,PairClock
from strategy import Coordination,PortSchedule
from egress import LiveEgress,ExitExplorer,extra_candidates

class Budget:
    def __init__(self,rate=20,max_new=128,protected=False,unlimited=False):
        self.unlimited=unlimited;self.interval=0. if unlimited else 1/max(1,min(240,float(rate)));self.max_new=max(16,min(2048,int(max_new)))
        self.at=0.;self.targets={};self.sent=0;self.denied=0;self.lock=threading.RLock();self.pause=False
        self.pressure=MappingPressure() if protected and not unlimited else None
    @property
    def rate_limit(self):return None if self.unlimited else round(1/self.interval)
    def reason(self,target,now):
        with self.lock:return self._reason(target,now)
    def _reason(self,target,now):
        if self.unlimited:return None
        if self.pause:return 'bifrost_protection_pause'
        if now-self.at<self.interval:return 'packet_rate_limit'
        if self.pressure:
            reason=self.pressure.reason(target,now)
            if reason:return reason
        live={t:at for t,at in self.targets.items() if now-at<15}
        return 'new_socket_target_limit' if target not in live and len(live)>=self.max_new else None
    def admit(self,target,now,authenticated=False,maintenance=False):
        with self.lock:return self._admit(target,now,authenticated,maintenance)
    def _admit(self,target,now,authenticated=False,maintenance=False):
        if self.unlimited:
            self.at=now;self.sent+=1;return True
        if self.pause and not authenticated and not (maintenance and self.pressure and target in self.pressure.targets):self.denied+=1;return False
        if now-self.at<self.interval:self.denied+=1;return False
        if self.pressure and not authenticated and self.pressure.reason(target,now):self.denied+=1;return False
        self.targets={t:at for t,at in self.targets.items() if now-at<15}
        if target not in self.targets and len(self.targets)>=self.max_new and not authenticated and not (maintenance and self.pressure and target in self.pressure.targets):self.denied+=1;return False
        self.at=now
        if self.pressure:self.pressure.used(target,now,authenticated)
        if target in self.targets or len(self.targets)<self.max_new:self.targets.setdefault(target,now)
        self.sent+=1;return True

def recv_exact(s,size):
    out=b''
    while len(out)<size:
        data=s.recv(size-len(out))
        if not data:raise OSError('TCP closed')
        out+=data
    return out
def send_frame(s,key,obj):
    data=pack(key,obj);s.sendall(struct.pack('!H',len(data))+data)
def recv_frame(s,key):
    size=struct.unpack('!H',recv_exact(s,2))[0]
    if not 38<=size<=3536:raise ValueError('invalid TCP frame length')
    obj=unpack(key,recv_exact(s,size))
    if not obj:raise ValueError('invalid TCP authentication')
    return obj

class LabClient:
    def __init__(self,cfg,code,name,emit=lambda obj:None,member_id=None,resume=None,run_number=0):
        self.cfg=dict(cfg);self.unlimited_search=bool(self.cfg.get('unlimited_search',False));self.room,self.key=room_keys(code);self.name=name.strip()
        if not 1<=len(self.name)<=32:raise ValueError('昵称需要 1–32 字符')
        self.id=member_id or secrets.token_hex(16);self.session=resume or secrets.token_hex(16);self.run_number=run_number
        if not hexid(self.id) or not hexid(self.session) or type(run_number) is not int or run_number<0:raise ValueError('invalid window room identity')
        self.started_at=time.monotonic();self.first_udp_at=None;self.first_udp_active_seconds=None
        try:self.journal=PacketJournal(self.cfg['packet_journal_dir'],self.id,limit=self.cfg.get('journal_segment_bytes',32*1024*1024),segments=self.cfg.get('journal_segments',8)) if self.cfg.get('packet_journal_dir') else NullJournal()
        except OSError as exc:
            if not self.cfg.get('journal_optional'):raise
            self.journal=NullJournal();self.journal.error=str(exc)
        self.socket_ids={};self.socket_id_lock=threading.Lock()
        self.search=MixedSearch();self.priority=CandidatePriority();self.fast_search=FastSearch();self.fast_lane_tick=0;self.challenges=collections.deque(maxlen=128);self.challenge_seen={}
        self.peer_sync=None;self.peer_sync_firewall=None;self.exchange_token=secrets.token_hex(16);self.exchange_peer_session=None;self.exchange_verified=False;self.exchange_ack=None;self.selected_peer=None;self.egress=None;self.exit_explorer=ExitExplorer();self.exit_discovery_pending=False;self.exit_initial_logged=False;self.extra_ips_seen=set();self.search_times=collections.Counter();self.search_clock_at=None;self.search_clock_reason='startup';self.last_egress_publish=0
        self.data_session=secrets.token_hex(16);self.tail=None;self.transport=None;self.transport_identity=None;self.firewall=None;self.tcp_firewall=None;self.local_firewall=None
        self.tail_failed_at=0;self.tail_bridge_error=None;self.native_thread=None;self.native_verified=False;self.native_proxy_verified=False;self.native_verified_at=0;self.first_native_at=None;self.first_tail_usable_at=None;self.tail_frames=collections.deque();self.flow=FlowBudget()
        self.tcp_candidates_at=0.;self.tcp_refresh_started=False;self.tcp_offer=None;self.tcp_offer_at=0.;self.tcp_offer_rounds=0
        self.tcp_plan=None;self.tcp_ack_plans={};self.tcp_coordination_offers=0;self.tcp_coordinated_attempts=0
        self.rate_lock=threading.Lock();self.recent_sends=collections.deque();self.recent_receives=collections.deque();self.recent_new=collections.deque();self.actual_targets={};self.actual_targets_at=0.;self.lane_sent=collections.Counter();self.search_stalls=collections.Counter();self.last_budget_keepalive=0.;self.last_budget_log=0.;self.last_socket_snapshot=0.
        self.tcp_prepare_generation=0;self.last_tcp_refresh=0.
        self.room_peer_ids=[];self.peer_completed=False;self.connected=threading.Event();self.last_snapshot=0.;self.last_peer=None;self.stage='measurement';self.prepared=False;self.finish_reason='stopped';self.active_elapsed=0.;self.wall_elapsed=0.;self.control_failures=0;self.control_reconnects=0
        self.stop=threading.Event();self.emit=emit;self.logs=[];self.profile=None;self.peer=None
        self.control=None;self.control_lock=threading.Lock();self.udp=[];self.tcp_listener=None
        self.control_health={'state':'waiting','route':None,'application_replies':0,'failure_phase':None}
        self.last_confirmed_room_members=None;self.control_soft_timeouts=0
        self.cached_search_peer=None;self.cached_search_at=0.;self.cached_search_active=False
        self.combination_limit=CombinationLimit(self.cfg.get('new_combinations_per_second'));self.combo_wait_until=0.;self.last_combo_log=-1e9
        self.peer_lease_active=False;self.coverage=Coverage();self.sync_metadata={};self.probe_firewall_state={"status":"not_requested"}
        self.recovery_cursor=0;self.recovery_pairs=[];self.recovery_peer_id=None
        self.coexist=Coexistence(bool(self.cfg.get('bifrost_coexist')) and not self.unlimited_search,self.cfg.get('bifrost_trace_path'));self.coexist_thread=None;self.coexist_state={};self.remote_pause=False;self.last_coexist_profile=0.;self.last_coexist_signature=None;self.tcp_serial=threading.Lock();self.last_tcp_new=0.
        self.protection_offer=offer(self.cfg) if self.cfg.get('protected_search') and not self.unlimited_search else None;self.protection_policy=None;self.connection_guard=ConnectionGuard();self.observer_last={};self.observer_retries={};self.udp_retry_at={};self.udp_backpressure_lanes=collections.Counter()
        self.budget=Budget(self.protection_offer['rate'] if self.protection_offer else self.cfg.get('probe_rate',20),self.protection_offer['new15'] if self.protection_offer else self.cfg.get('probe_new_targets',128),bool(self.protection_offer),unlimited=self.unlimited_search);self.pending={};self.seen={};self.replies=collections.deque(maxlen=128);self.udp_direct=False;self.tcp_direct=False
        self.stats={'udp_probe_tx':0,'udp_probe_rx':0,'udp_probe_acks':0,'tcp_attempts':0,'tcp_local_errors':0,'tcp_verified_echoes':0,
                    'tcp_network_attempts':0,'tcp_network_timeouts':0,'udp_raw_peer_rx':0,'udp_auth_rejected':0,
                    'observer_requests':0,'observer_udp_replies':0,'observer_tls_reports':0}
        self.peer_lock=threading.Lock();self.write_lock=threading.Lock();self.results_lock=threading.Lock()
        self.tcp_active=set();self.tcp_executor=None;self.own_tcp=[];self.own_udp=[]
        self.discovery=LiveDiscovery(self.cfg.get('public_only',True));self.joined=threading.Event();self.server_version=None
        self.own_tcp_active=[];self.active_port=None;self.tcp_active_disabled_until=0
        self.fast_search.unlimited=self.unlimited_search;self.fast_search.continuous_priority=bool(self.cfg.get('efficient_search')) and not self.cfg.get('restore_v105_budget');self.negotiate_protection(None)
        self.reply_proofs=collections.OrderedDict();self.last_receipt_publish=0.;self.path_roundtrips={};self.last_direct_peer_source=None;self.last_pending_prune=0.;self.paired_started=False;self.direct_path=None;self.last_direct_ack=0;self.coord=Coordination(self.id,self.cfg.get('coordination_window_seconds',35));self.schedule=PortSchedule(self.key,self.id)
    def log(self,event,**fields):
        obj={'time':time.strftime('%Y-%m-%d %H:%M:%S'),'event':event,**fields}
        with self.results_lock:self.logs.append(obj)
        self.journal.record(direction="event",actor=self.id,event=event,**fields)
        self.emit(obj)
    def control_send(self,obj):
        failed=None
        with self.control_lock:
            channel=self.control
            if channel:
                try:channel.sendall(json.dumps(obj,separators=(',',':')).encode()+b'\n');return True
                except OSError as exc:failed=exc
        if failed:self.control_lost(channel,str(failed))
        return False
    def control_lost(self,channel,message):
        with self.control_lock:
            if self.control is not channel:return
            self.control=None;self.connected.clear();self.last_snapshot=0
        try:channel.shutdown(socket.SHUT_RDWR)
        except OSError:pass
        channel.close()
        if not self.stop.is_set():
            self.control_failures+=1;self.log('control_error',message=message,recoverable=True)
    def control_read(self):
        delay=1.;successful=0
        failed_routes={}
        while not self.stop.is_set():
            channel=None;route=None;joined_at=None;validated=False;last_frame_at=None;reply_delayed=False
            try:
                now=time.monotonic()
                routes=('udp','physical','system') if self.cfg.get('control_udp_port') else ('physical','system')
                if self.cfg.get('control_tail_host'):routes=(*routes,'tail')
                routes=tuple(r for r in self.cfg.get('control_transports',routes) if r in routes)
                if not routes:raise ValueError('没有可用的协调传输方式')
                available=[r for r in routes if failed_routes.get(r,0)<=now]
                preferred=self.cfg.get('_control_route_preference',routes[0])
                available.sort(key=lambda r:r!=preferred)
                if available:self.cfg['_control_route_order']=available
                else:self.cfg['_control_route_order']=[min(failed_routes,key=failed_routes.get)]
                self.control_health.update(state='connecting',failure_phase=None)
                if self.cfg.get('room_udp_port'):
                    from roomudp import DatagramControl
                    channel=self.cfg.get('_control_factory',DatagramControl)(self.cfg,self.bind,self.index);route='room_udp'
                else:
                    raw,route=tls_connect(self.cfg,self.bind,self.index,emit=lambda **fields:self.log('control_tls_attempt',**fields),stop=self.stop)
                    channel=ControlStream(raw)
                # Queue JOIN before publishing this generation to poll/profile
                # producers. No producer may put a poll before authentication.
                channel.sendall(json.dumps({'access':self.cfg['access'],'room':self.room,'id':self.id,'name':self.name,
                    'resume':self.session,'run':self.run_number,'version':'0.9.4-lab','client_build':'1.0.18-tail'},separators=(',',':')).encode()+b'\n')
                with self.control_lock:
                    if self.stop.is_set():channel.close();return
                    self.control=channel
                self.control_health.update(state='waiting_join_reply',route=route)
                self.log('control_route',route=route,application_verified=False)
                while not self.stop.is_set():
                    interval=float(self.cfg.get('control_reply_timeout',15))
                    try:line=channel.readline(self.stop,timeout=interval)
                    except TimeoutError:
                        # A missing peer UDP reply is never a control failure.
                        # Even server snapshots may be delayed on a live TLS
                        # connection. Keep its partial frame and queued writes
                        # through a bounded application recovery window.
                        age=time.monotonic()-(last_frame_at or time.monotonic())
                        grace=max(interval,float(self.cfg.get('control_stall_timeout',60)))
                        if route!='room_udp' and (joined_at is None or age>=grace):raise
                        self.control_send({'k':'poll'})
                        self.control_health.update(state='waiting_reply',reply_age_seconds=round(age,3),hard_timeout_seconds=None if route=='room_udp' else grace)
                        if not reply_delayed:
                            reply_delayed=True;self.control_soft_timeouts+=1
                            self.log('control_reply_delayed',reply_age_seconds=round(age,3),hard_timeout_seconds=grace,
                                last_confirmed_room_members=self.last_confirmed_room_members,
                                message='房间服务器回复延迟，保持当前连接并确认恢复；未把对端UDP未命中当作故障')
                        continue
                    if not line:raise OSError('协调连接关闭')
                    last_frame_at=time.monotonic()
                    if reply_delayed:
                        reply_delayed=False;self.log('control_reply_resumed',message='房间回复已恢复；沿用同一协调连接、观察凭据和UDP源套接字')
                    obj=json.loads(line)
                    self.log('control_frame_received',route=route,kind=obj.get('k'),frame_bytes=len(line),transport=channel.snapshot())
                    if obj.get('error'):raise ValueError(str(obj['error']))
                    if obj.get('k')=='joined':
                        if obj.get('server_version')!='0.9.4-lab':raise ValueError('协调服务版本不匹配')
                        self.discovery.set_ticket(obj.get('observer_ticket'));self.server_version=obj['server_version']
                        self.control_send({'k':'stage','stage':self.stage,'epoch':self.discovery.epoch})
                        self.publish_profile();self.control_send({'k':'poll'});self.connected.set();self.joined.set();joined_at=time.monotonic()
                        self.control_health.update(state='joined_waiting_snapshot')
                    elif obj.get('k')=='peers':
                        if joined_at is None:raise ValueError('room_snapshot_before_join')
                        self.control_health.update(state='application_verified',application_replies=self.control_health['application_replies']+1,last_reply_at=time.monotonic(),transport=channel.snapshot(),error=None,failure_phase=None)
                        if not validated:
                            validated=True;self.cfg['_control_route_preference']=route;failed_routes.pop(route,None)
                            self.joined.set()
                            if successful:
                                self.control_reconnects+=1
                                self.log('control_reconnected',message='收到新的房间回复，协调连接确已恢复；保留UDP源端口和扫描进度')
                            successful+=1
                            self.log('control_application_verified',route=route,message='已收到房间回复；协调路径双向可用')
                        if time.monotonic()-joined_at>=30:delay=1.
                        if obj.get('self_id')==self.id:
                            before=self.discovery.accepted
                            for changed in self.discovery.accept(obj.get('self_udp',[]),'server_observed_tls'):
                                self.log('live_mapping',**changed,message='本代活跃套接字的服务器方向实测映射')
                            self.stats['observer_tls_reports']+=self.discovery.accepted-before
                        peers=obj.get('peers',[]);peers=[p for p in peers[:8] if isinstance(p,dict) and hexid(p.get('id')) and p['id']!=self.id] if isinstance(peers,list) else []
                        self.room_peer_ids=list(dict.fromkeys(p['id'] for p in peers));peer=peers[0] if peers else None
                        self.last_confirmed_room_members=1+len(self.room_peer_ids)
                        with self.peer_lock:
                            old=self.peer;self.peer=peer if peer and hexid(peer.get('id')) else None
                            self.last_snapshot=time.monotonic()
                            if self.peer:self.last_peer=self.peer
                            if self.peer and self.peer.get('prepared') and self.peer.get('udp'):
                                self.cached_search_peer=__import__('copy').deepcopy(self.peer);self.cached_search_at=time.monotonic()
                        if self.peer and (not old or old['id']!=self.peer['id']):self.log('peer',name=self.peer['name'],id=self.peer['id'])
                        if self.peer and (not old or old.get('tcp')!=self.peer.get('tcp') or old.get('tcp_active')!=self.peer.get('tcp_active')):
                            self.log('peer_tcp_candidates',listener_count=len(self.peer.get('tcp',[])),simultaneous_count=len(self.peer.get('tcp_active',[])))
                    elif obj.get('k')=='notice':
                        self.log('peer_notice',message=obj.get('message'))
                        if self.last_peer and obj.get('peer')==self.last_peer['id'] and obj.get('message')=='lab_test_complete':self.peer_completed=True
            except ValueError as exc:
                self.finish_reason='control_protocol_error';self.log('error',message=str(exc));self.stop.set()
            except (OSError,RuntimeError) as exc:
                if self.stop.is_set():
                    self.control_health.update(state='stopped',last_active_state=self.control_health.get('state'))
                    return
                phase='joined_reply_stalled' if joined_at is not None else 'join_reply_stalled' if channel else 'tls_connect_failed'
                self.control_health.update(state='recovering',failure_phase=phase,error=str(exc),transport=channel.snapshot() if channel else {})
                if route:
                    failed_routes[route]=time.monotonic()+30
                    self.cfg['_control_route_preference']=next((r for r in routes if r!=route and failed_routes.get(r,0)<=time.monotonic()), routes[0])
                    self.log('control_path_failed',route=route,phase=phase,application_verified=validated,transport=channel.snapshot() if channel else {},udp_transport=channel.channel.transport_stats() if channel and hasattr(channel.channel,'transport_stats') else None,message='失败路径暂时轮换；TLS握手成功不再算恢复')
                if channel:self.control_lost(channel,str(exc))
                elif not self.stop.is_set():self.log('control_connect_failed',message=str(exc),retry_seconds=delay)
            finally:
                if channel:self.control_lost(channel,'control_reader_stopped')
            if not self.stop.is_set():
                message='协调连接确已断开或持续无回复，后台恢复；等待成员加入' if self.last_confirmed_room_members in (None,1) else '协调后台恢复；已验证UDP通道独立保活，未命中时等待新鲜候选'
                self.log('control_retry',retry_seconds=delay,message=message)
                self.stop.wait(delay);delay=min(15,delay*2)
    def peer_sync_expected(self):
        peer=self.peer or self.last_peer
        session=(peer.get('profile') or {}).get('transport_session') if peer else None
        return (peer['id'],session,self.id) if peer and hexid(session) else None
    def peer_sync_payload(self):
        expected=self.peer_sync_expected()
        if not expected or not self.profile:return None
        return {'id':self.id,'to':expected[0],'name':self.name,'profile':dict(self.profile),
                'udp':list(self.own_udp),'prepared':self.prepared,'epoch':self.discovery.epoch,'version':'0.9.4-lab'}
    def start_peer_sync(self):
        if not self.cfg.get('peer_sync_overlay'):return
        metadata=self.tail.metadata if self.tail else self.sync_metadata
        local=self.cfg.get('peer_sync_bind') or next((v for v in metadata.get('tail_ips',[]) if tail_ip(v)),None)
        remote=self.cfg.get('peer_sync_host') or self.cfg.get('peer_tail_ip')
        if not local or not remote or self.cfg.get('public_only',True) and not (tail_ip(local) and tail_ip(remote)):
            self.log('peer_sync_unavailable',message='未取得双方 Tailscale IPv4，沿用加密 UDP 房间同步');return
        port=int(self.cfg.get('peer_sync_port',39613));remote_port=int(self.cfg.get('peer_sync_remote_port',port))
        try:
            self.peer_sync=PeerSync(self.key.hex(),self.data_session,(local,port),(remote,remote_port),self.peer_sync_payload,self.peer_sync_expected,self.stop,lambda e,**f:self.log(e,**f))
            if self.cfg.get('scoped_peer_firewall') and is_admin() and tail_ip(local) and tail_ip(remote):
                ident=hashlib.sha256(('peer-sync'+self.id).encode()).hexdigest()[:32]
                self.peer_sync_firewall=PeerFirewall(ident,local,[port],lambda e,**f:self.log(e,**f),overlay_scope=True);self.peer_sync_firewall.update([remote])
            self.log('peer_sync_started',**self.peer_sync.snapshot(),message='通过所选 Tailscale 对端交换本轮真实套接字观测与策略；IPv4 探测仍走物理网卡')
        except OSError as exc:self.log('peer_sync_unavailable',message=str(exc))
    def initial_exchange(self,peer,fresh):
        if not self.cfg.get('preflight_exchange'):return True
        remote=(peer.get('profile') or {}) if peer else {}
        session=remote.get('transport_session');exchange=remote.get('initial_exchange') or {}
        signature=(peer.get('id'),session) if peer else None
        if signature!=self.exchange_peer_session:
            if signature and hexid(session):self.coverage=Coverage()
            self.exchange_peer_session=signature;self.exchange_verified=False;self.exchange_ack=None;self.extra_ips_seen.clear()
        token=exchange.get('token')
        ack=token if fresh and peer and peer.get('prepared') and peer.get('udp') and hexid(token) and hexid(session) else None
        record={'protocol':1,'token':self.exchange_token,'ack':ack,'peer_session':session if ack else None,
                'scope':'current_probe_sockets_observed_destinations_only','unlimited':self.unlimited_search,
                'strategies':['nearby','original','stable_pair','range','full_ports','multi_exit']}
        if self.profile.get('initial_exchange')!=record:
            self.profile['initial_exchange']=record;self.publish_profile()
        if not self.exchange_verified and fresh and ack and exchange.get('ack')==self.exchange_token and exchange.get('peer_session')==self.data_session:
            self.exchange_verified=True
            self.log('initial_exchange_verified',peer=peer['id'],peer_session=session,own_session=self.data_session,
                     own_udp=list(self.own_udp),peer_udp=peer['udp'],peer_exit_observations=remote.get('exit_observations'),
                     source='tailscale_peer_sync' if self.peer_sync and self.peer_sync.fresh() else 'encrypted_room_snapshot',
                     message='双方已确认本轮公网观测、会话与策略信息；接下来进入协同不限额探测')
        return self.exchange_verified
    def search_peer(self,peer,now,local_candidates_ready=True):
        # A local observer expiry does not invalidate a received peer profile
        # or the coordinator handshake. Keep those two health states separate.
        self.peer_lease_active=False
        overlay=self.peer_sync.fresh(now) if self.peer_sync else None
        if overlay and overlay.get('prepared') and overlay.get('udp'):
            self.cached_search_peer=overlay;self.cached_search_at=now;return overlay,False
        fresh=bool(self.connected.is_set() and now-self.last_snapshot<8)
        valid=bool(peer and peer.get('prepared') and peer.get('udp') and peer.get('version')=='0.9.4-lab')
        if fresh and valid:
            self.cached_search_peer=peer;self.cached_search_at=now;return peer,False
        # An authoritative empty room means wait for a member, rather than
        # sending indefinitely to the previous member's cached endpoints.
        if fresh and (peer is None or self.cached_search_peer and peer.get('id')!=self.cached_search_peer.get('id')):
            return peer,False
        # Session-verified sockets remain useful during brief control gaps.
        # Freeze the running round; never trust a replacement session or an
        # explicitly empty room merely because old endpoint data exists.
        cached=self.cached_search_peer
        signature=(cached.get('id'),(cached.get('profile') or {}).get('transport_session')) if cached else None
        current_signature=(peer.get('id'),(peer.get('profile') or {}).get('transport_session')) if peer else None
        lease=float(self.cfg.get('verified_peer_lease_seconds',0))
        if peer and current_signature!=signature:return peer,False
        if (self.unlimited_search and lease>0 and cached and self.exchange_verified and
            signature==self.exchange_peer_session and cached.get('prepared') and cached.get('udp') and
            self.coord.role in ('anchor','scan','duplex') and now-self.cached_search_at<lease and not self.peer_completed):
            self.peer_lease_active=True;return cached,False
        max_age=self.cfg.get('cached_peer_max_age')
        if self.unlimited_search and self.cached_search_peer and (max_age is None or now-self.cached_search_at<float(max_age)) and not self.peer_completed:
            return self.cached_search_peer,True
        return peer,False
    def probe_firewall_event(self,event,**fields):
        status={'firewall_peer_allow':'allowed','firewall_error':'error','firewall_peer_cleanup':'cleaned'}.get(event)
        if status:self.probe_firewall_state={**self.probe_firewall_state,'status':status}
        self.log(event,**fields)
    def configure_probe_firewall(self):
        if not self.cfg.get('scoped_peer_firewall'):return
        if not is_admin():
            self.probe_firewall_state={'status':'administrator_required','local_ports':[s.getsockname()[1] for s in self.udp]}
            self.log('firewall_permission_required',**self.probe_firewall_state,message='未取得管理员权限，无法自动添加本程序入站许可；可重新以管理员身份运行，或手动放行这些 UDP 端口。')
            return
        self.probe_firewall_state={'status':'waiting_peer','local_ports':[s.getsockname()[1] for s in self.udp]}
        self.firewall=PeerFirewall(self.id,self.bind,self.probe_firewall_state['local_ports'],self.probe_firewall_event,
                                  authenticated_any_source=bool(self.cfg.get('multi_exit_search')))
    def recovery_choice(self,peer):
        """Retain peer contact while repairing control, without expanding a
        stale scan. No packet/target budget is applied to the normal scan.
        Existing UDP sockets and all search cursors survive this state.
        """
        if peer['id']!=self.recovery_peer_id or not self.recovery_pairs:
            seeds=list(dict.fromkeys(p for v in peer.get('udp',[])[:8] if (p:=endpoint(v,self.cfg.get('public_only',True)))))
            if not seeds or not self.udp:return None
            preferred=endpoint((peer.get('profile') or {}).get('source_zero_observer_endpoint'),self.cfg.get('public_only',True))
            target=preferred if preferred in seeds else seeds[0]
            self.recovery_pairs=[(s,target) for s in self.udp]
            self.recovery_peer_id=peer['id'];self.recovery_cursor=0
        return self.recovery_pairs[self.recovery_cursor%len(self.recovery_pairs)]
    def actual_rates(self,now=None):
        with self.rate_lock:return self._actual_rates(now)
    def _actual_rates(self,now=None):
        now=time.monotonic() if now is None else now
        while self.recent_sends and now-self.recent_sends[0][0]>=10:self.recent_sends.popleft()
        while self.recent_receives and now-self.recent_receives[0]>=10:self.recent_receives.popleft()
        while self.recent_new and now-self.recent_new[0]>=10:self.recent_new.popleft()
        span=max(1,min(10,now-self.started_at))
        return {'window_seconds':round(span,2),'peer_probe_tx_pps':round(sum(k=='probe' for _,k in self.recent_sends)/span,2),'observer_tx_pps':round(sum(k=='observer' for _,k in self.recent_sends)/span,2),'authenticated_rx_pps':round(len(self.recent_receives)/span,2),'new_udp_combinations_pps':round(len(self.recent_new)/span,2)}
    def room_members(self,now=None):
        now=time.monotonic() if now is None else now
        if self.peer_sync and self.peer_sync.fresh(now):return 2
        if not self.connected.is_set():return None
        if not self.last_snapshot or now-self.last_snapshot>=8:return None
        return 1+len(self.room_peer_ids)
    def control_pulse(self):
        while not self.stop.wait(1):
            if self.connected.is_set():self.control_send({'k':'poll'})
    def wait_for_coordination(self):
        began=time.monotonic();last=began
        while not self.stop.is_set():
            if self.joined.wait(1):return True
            now=time.monotonic()
            if not self.cfg.get('wait_unlimited',True) and now-began>=30:raise RuntimeError('协调服务暂不可达，详见重连记录')
            if now-last>=10:
                self.log('waiting_for_server',wait_seconds=int(now-began),message='等待协调服务并自动重连；不会因房间只有一人结束，可随时停止')
                last=now
        return False
    def summary(self):
        with self.results_lock:events=list(self.logs)
        return {'version':'1.0.18-tail','name':self.name,'id':self.id,'profile':self.profile,'events':events,
                'result':{**self.stats,'udp_direct_verified':self.udp_direct,'tcp_direct_verified':self.tcp_direct,
                          'unlimited_search':self.unlimited_search,'probe_rate_limit':self.budget.rate_limit,'probe_budget_sent':self.budget.sent,'probe_budget_denied':self.budget.denied,
                          'seconds_to_first_udp':round(self.first_udp_at-self.started_at,3) if self.first_udp_at else None,
                          'seconds_to_first_native_tailscale':round(self.first_native_at-self.started_at,3) if self.first_native_at else None,
                          'seconds_to_first_tail_usable':round(self.first_tail_usable_at-self.started_at,3) if self.first_tail_usable_at else None,
                          'peer_sync':self.peer_sync.snapshot() if self.peer_sync else None,'initial_exchange_verified':self.exchange_verified,'exit_observations':self.egress.snapshot(time.monotonic()) if self.egress else None,'search_time_by_reason':dict(self.search_times),'actual_rates':self.actual_rates(),'room_members':self.room_members(),'protection_policy':self.protection_policy,'protection_state':self.connection_guard.reason if self.protection_offer else 'disabled','bifrost_coexistence':dict(self.coexist_state),'mapping_pressure_count':len(self.budget.pressure.targets) if self.budget.pressure else None,
                          'effective_search_seconds_at_first_udp':self.first_udp_active_seconds,
                          'tcp_coordination_offers':self.tcp_coordination_offers,'tcp_coordinated_attempts':self.tcp_coordinated_attempts,
                          'search_phase':self.coord.phase,'combination_limit':self.combination_limit.snapshot(time.monotonic()),'coverage_by_exit':self.coverage.snapshot(),'verified_session_lease':self.peer_lease_active,'probe_firewall':dict(self.probe_firewall_state),'lane_sent':dict(self.lane_sent),'search_stalls':dict(self.search_stalls),'udp_backpressure_lanes':dict(self.udp_backpressure_lanes),
                          'experiment_settings':{k:self.cfg.get(k) for k in ('unlimited_search','nearby_priority','candidate_pool_priority','immediate_challenge','fast_start','coordinated_scan','phased_search','coordination_window_seconds','fast_center_search','probe_rate','probe_new_targets','wait_unlimited','tcp_rotate_source','tcp_neighbor_candidates','tcp_connect_timeout')},
                          'own_live_udp':self.discovery.endpoints(),'last_own_udp':list(self.own_udp),'paired_test_started':self.paired_started,'live_observations_accepted':self.discovery.accepted,
                          'live_observations_rejected':self.discovery.rejected,'udp_direct_live':bool(self.direct_path and self.direct_path[0].fileno()>=0 and time.monotonic()-self.last_direct_ack<8),'scan_position':self.schedule.position,'fast_center_position':self.fast_search.scan_position,'tcp_last_failure':getattr(self,'tcp_last_failure',None),'last_confirmed_room_members':self.last_confirmed_room_members,'control_soft_timeouts':self.control_soft_timeouts,'control_connected':self.connected.is_set(),'control_failures':self.control_failures,'control_reconnects':self.control_reconnects,'control_health':dict(self.control_health),'cached_search':self.cached_search_active,'candidate_age_seconds':round(time.monotonic()-self.cached_search_at,3) if self.cached_search_active else None,'active_elapsed_seconds':round(self.active_elapsed,3),'wall_elapsed_seconds':round(self.wall_elapsed,3),'finish_reason':self.finish_reason,'business_forwarding':bool(self.native_proxy_verified and self.direct_path and self.direct_path[0].fileno()>=0 and time.monotonic()-self.last_direct_ack<8),'business_forwarding_ever':bool(self.tail and self.tail.stats['tail_tx_wg_datagrams'] and self.tail.stats['tail_rx_wg_datagrams']),'tailscale_traffic_changed':bool(self.tail and self.tail.stats['tail_tx_datagrams']),
                          'tailscale_settings_changed':False,'tail_native_verified':self.native_verified,'tail_proxy_verified':self.native_proxy_verified,'tail_bridge_error':self.tail_bridge_error,'tail_health':dict(getattr(self,'native_health',{})),'tail_transport':dict(self.tail.stats) if self.tail else {},'tail_bridge_state':self.tail.snapshot() if self.tail else {},'packet_journal_directory':str(self.journal.directory) if self.journal.directory else None,'first_hit_proof':self.journal.proof_path,'packet_journal_error':self.journal.error}}
    def publish_profile(self):
        self.control_send({'k':'profile','udp':[],'tcp':self.own_tcp,'tcp_active':self.own_tcp_active,'profile':self.profile,'prepared':self.prepared})
    def registered_observer(self,s,slot,port=None):
        self.discovery.attach(slot,s);self.discovery.invalidate(slot);started=time.monotonic();request=self.discovery.request(slot,started)
        if not request:return None
        if not self.send_udp(s,request,(self.observer_address[0],port or self.observer_address[1]),started,'measurement_observer'):return None
        self.trace_packet(s,request,'tx',(self.observer_address[0],port or self.observer_address[1]),kind='observer',nonce=unpack(bytes.fromhex(self.discovery.ticket),request)['n'],lane='measurement_observer');self.stats['observer_requests']+=1
        last_poll=0
        while not self.stop.is_set() and time.monotonic()-started<4:
            result=self.discovery.slot_endpoint(slot)
            if result:return {'endpoint':result,'via':'correlated_tls_observation'}
            now=time.monotonic()
            if now-last_poll>=.3:self.control_send({'k':'poll'});last_poll=now
            self.stop.wait(.05)
        return None
    def tcp_exchange(self,s,initiator,peer):
        s.settimeout(3)
        if initiator:
            nonce=secrets.token_hex(16)
            send_frame(s,self.key,{'k':'hello','from':self.id,'to':peer['id'],'n':nonce})
            ack=recv_frame(s,self.key)
            if ack.get('k')=='hello':
                if ack.get('from')!=peer['id'] or ack.get('to')!=self.id or not hexid(ack.get('n')):raise ValueError('TCP peer mismatch')
                if self.id>peer['id']:
                    return self.tcp_respond(s,peer,ack)
                ack=recv_frame(s,self.key)
            if ack.get('k')!='hello_ack' or ack.get('n')!=nonce or ack.get('from')!=peer['id'] or ack.get('to')!=self.id:raise ValueError('TCP peer mismatch')
            payload=secrets.token_hex(256);started=time.monotonic()
            send_frame(s,self.key,{'k':'echo','n':nonce,'payload':payload})
            response=recv_frame(s,self.key)
            if response!={'k':'echo_reply','n':nonce,'payload':payload}:raise ValueError('TCP echo mismatch')
            send_frame(s,self.key,{'k':'echo_confirm','n':nonce})
            rtt=round((time.monotonic()-started)*1000,2)
        else:
            return self.tcp_respond(s,peer,recv_frame(s,self.key))
        if not self.tcp_direct:self.log('tcp_direct_verified',remote=list(s.getpeername()),echo_bytes=256,rtt_ms=rtt,
                                        message='双方 TCP 直接通道已完成认证与回显；只测量，尚未接管业务')
        self.tcp_direct=True;self.stats['tcp_verified_echoes']+=1
    def tcp_respond(self,s,peer,obj):
        nonce=obj.get('n')
        if obj.get('k')!='hello' or obj.get('from')!=peer['id'] or obj.get('to')!=self.id or not hexid(nonce):raise ValueError('TCP peer mismatch')
        send_frame(s,self.key,{'k':'hello_ack','from':self.id,'to':peer['id'],'n':nonce})
        echo=recv_frame(s,self.key)
        if echo.get('k')!='echo' or echo.get('n')!=nonce or not isinstance(echo.get('payload'),str) or len(echo['payload'])!=512:raise ValueError('invalid TCP echo')
        send_frame(s,self.key,{'k':'echo_reply','n':nonce,'payload':echo['payload']})
        if recv_frame(s,self.key)!={'k':'echo_confirm','n':nonce}:raise ValueError('TCP echo not confirmed')
        if not self.tcp_direct:self.log('tcp_direct_verified',remote=list(s.getpeername()),echo_bytes=256,rtt_ms=None)
        self.tcp_direct=True;self.stats['tcp_verified_echoes']+=1
    def tcp_task(self,target,peer,source_port,mode='listener_connect'):
        s=None;stage='bind';attempt=0
        if not self.cfg.get('raw_tcp_experiment',True):return
        serial=self.protection_offer is not None
        if serial and not self.tcp_serial.acquire(blocking=False):return
        try:
            if self.stop.is_set() or self.tcp_direct:return
            self.stats['tcp_attempts']+=1
            attempt=self.stats['tcp_attempts']
            s=raw_socket(socket.SOCK_STREAM,self.bind,self.index,source_port,reuse=True);s.settimeout(min(8,max(2,float(self.cfg.get('tcp_connect_timeout',2)))))
            if not self.tcp_permission(s,target):
                self.stats['tcp_attempts']-=1;self.log('tcp_protection_deferred',message='TCP 新连接让出预算，UDP 业务继续');return
            self.log('tcp_attempt_started',attempt=attempt,mode=mode,source_port=s.getsockname()[1],target=list(target))
            with self.peer_lock:self.tcp_active.add(s)
            stage='connect';self.stats['tcp_network_attempts']+=1
            s.connect(target);stage='peer_authentication';self.tcp_exchange(s,True,peer)
        except (OSError,ValueError) as e:
            local_error=isinstance(e,OSError) and (getattr(e,'winerror',None) in (10048,10049) or getattr(e,'errno',None) in (98,99))
            if local_error:
                self.stats['tcp_local_errors']+=1
                if stage=='connect':self.stats['tcp_network_attempts']-=1
                if mode in ('simultaneous_open','udp_coordinated_simultaneous_open'):self.tcp_active_disabled_until=time.monotonic()+10
            if isinstance(e,TimeoutError):self.stats['tcp_network_timeouts']+=1
            self.log('tcp_attempt_result',attempt=attempt,mode=mode,stage=stage,target=list(target),error=str(e),local_error=local_error)
            self.tcp_last_failure={'stage':stage,'error':str(e),'mode':mode,'target':list(target)}
        finally:
            if s:
                with self.peer_lock:self.tcp_active.discard(s)
                s.close()
            if serial:self.tcp_serial.release()
    def accepted_task(self,s,peer):
        try:self.tcp_exchange(s,False,peer)
        except (OSError,ValueError):pass
        finally:
            with self.peer_lock:self.tcp_active.discard(s)
            s.close()
    def trace_packet(self,s,data,direction,remote,**fields):
        with self.socket_id_lock:
            if s not in self.socket_ids:self.socket_ids[s]=secrets.token_hex(16)
            socket_id=self.socket_ids[s]
        try:local=list(s.getsockname())
        except OSError:local=None
        with self.rate_lock:
            now=time.monotonic();kind=fields.get('kind')
            if direction=='tx' and kind in ('probe','observer','ack'):
                self.recent_sends.append((now,kind))
                target=(socket_id,tuple(remote))
                if target not in self.actual_targets or now-self.actual_targets[target]>=180:self.recent_new.append(now)
                self.actual_targets[target]=now
                if now-self.actual_targets_at>=15:
                    self.actual_targets={k:v for k,v in self.actual_targets.items() if now-v<180};self.actual_targets_at=now
            elif direction=='rx' and kind in ('probe','ack') and fields.get('accepted'):self.recent_receives.append(now)
        return self.journal.record(actor=self.id,direction=direction,local=local,remote=list(remote),
            socket_id=socket_id,slot=self.udp.index(s) if s in self.udp else None,stage=self.stage,
            bytes=len(data),sha256=hashlib.sha256(data).hexdigest(),**fields)
    def send_udp(self,s,data,target,now,lane):
        if now<self.udp_retry_at.get(s,0):return False
        try:s.sendto(data,target)
        except OSError as exc:
            transient=isinstance(exc,BlockingIOError) or getattr(exc,'winerror',None) in (10035,10055) or exc.errno in (11,35,10035,10055)
            if not transient:raise
            self.udp_retry_at[s]=now+.001
            self.stats['udp_send_backpressure']=self.stats.get('udp_send_backpressure',0)+1
            self.udp_backpressure_lanes[lane]+=1
            if now-getattr(self,'last_send_error_log',0)>=3:
                self.last_send_error_log=now;self.log('udp_send_backpressure',message='系统暂未接受发送；保留报文与扫描位置，稍后重试',error=str(exc),lane=lane,slot=self.udp.index(s) if s in self.udp else None,target=list(target))
            return False
        self.udp_retry_at.pop(s,None);return True
    def send_observer(self,measurement,slot,now):
        sock=self.udp[slot];target=(measurement.host,measurement.base)
        if now<self.udp_retry_at.get(sock,0):return False
        cached=self.observer_retries.get(slot)
        if not cached or now-cached[1]>=10 or cached[2]!=self.discovery.ticket:
            request=self.discovery.request(slot,now)
            if not request:return False
            cached=(request,now,self.discovery.ticket);self.observer_retries[slot]=cached
        request=cached[0]
        if not self.send_udp(sock,request,target,now,'live_observer'):return False
        self.observer_retries.pop(slot,None);self.stats['observer_requests']+=1
        self.trace_packet(sock,request,'tx',target,kind='observer',nonce=unpack(bytes.fromhex(cached[2]),request)['n'],lane='live_observer')
        return True
    def send_reply(self,now):
        if not self.replies:return False
        s,target,data=self.replies[0]
        if not self.budget.admit((s.fileno(),target),now,authenticated=True) or not self.send_udp(s,data,target,now,'authenticated_reply'):return False
        self.replies.popleft();ack=unpack(self.key,data)
        self.trace_packet(s,data,'tx',target,kind=ack['k'],nonce=ack['n'],sender=self.id,receiver=ack['to'],accepted=True,lane='authenticated_reply',probe_sha256=ack.get('probe_sha256'),observed_by_peer=ack.get('seen_from'))
        if ack['k']=='ack':
            self.reply_proofs[ack['n']]=(s,target,hashlib.sha256(data).hexdigest(),ack.get('probe_sha256'),now)
            while len(self.reply_proofs)>8192:self.reply_proofs.popitem(last=False)
        if ack['k']=='tcp_offer_ack':
            plan=self.tcp_ack_plans.pop(ack['n'],None)
            if plan and not self.tcp_plan:self.tcp_plan=(plan[0],plan[1],now+.2,ack['n'])
        return True
    def send_challenge(self,peer,now):
        if not self.challenges:return False
        s,target,trigger=self.challenges[0]
        if not self.budget.admit((s.fileno(),target),now,authenticated=True):return False
        if self.trace_probe(s,target,peer,now,'received_path_challenge',trigger_nonce=trigger['nonce'],trigger_rx_seq=trigger.get('journal_seq'),trigger_probe_sha256=trigger['sha256']) is False:return False
        self.challenges.popleft();return True
    def service_peer_control(self,peer,now):
        # A scanner's continuing authenticated probes must not starve reverse
        # path verification behind its ACK backlog. Each operation still uses
        # the configured budget and retries a blocked send without advancing.
        if self.replies:self.send_reply(now)
        if self.challenges and peer:self.send_challenge(peer,now)
    def trace_probe(self,s,target,peer,now,lane,**fields):
        source=s.getsockname()[1]
        if not self.combination_limit.allows(source,target,now):
            self.combination_limit.denied+=1
            self.combo_wait_until=now+self.combination_limit.delay(now)
            if now-self.last_combo_log>=3:
                self.last_combo_log=now
                self.log('combination_limit_wait',lane=lane,target=list(target),retained_cursor=True,
                         **self.combination_limit.snapshot(now),message='达到所选每秒新增组合上限，保留当前位置；协调、回包和业务接收继续。')
            return False
        nonce=secrets.token_hex(16);data=pack(self.key,{'k':'probe','from':self.id,'to':peer['id'],'n':nonce})
        if not self.send_udp(s,data,target,now,lane):return False
        self.combination_limit.sent(source,target,now);self.combo_wait_until=0.
        tx=self.trace_packet(s,data,'tx',target,kind='probe',nonce=nonce,sender=self.id,receiver=peer['id'],
            accepted=True,lane=lane,role=self.coord.role,round=self.coord.round,scan_position=self.schedule.position,
            scan_start=self.schedule.start,scan_stride=self.schedule.stride,**fields)
        self.pending[nonce]=(s,target,now,tx);self.stats['udp_probe_tx']+=1
        return True
    def receive_udp(self,s,data,source):
        with self.peer_lock:
            peer=self.selected_peer or self.peer or (self.last_peer if self.direct_path else None)
            if self.cached_search_active and self.cached_search_peer:peer=self.cached_search_peer
        ips=self.peer_ips(peer)
        if self.direct_path:ips.add(self.direct_path[1][0])
        if source[0] in ips:self.stats['udp_raw_peer_rx']+=1
        if data.startswith(DATA_MAGIC):
            # Validated send paths can be asymmetric: A sends to B's slot 0,
            # while B sends back from its slot 1. Receiver/session-specific
            # AEAD authenticates the selected peer regardless of that port.
            if self.transport and self.tail and self.direct_path and s in self.udp and source[0] in ips:
                before=self.transport.dropped;payload=self.transport.decode(data)
                self.trace_packet(s,data,'rx',source,kind='tail_cipher',accepted=self.transport.dropped==before,fragment=self.transport.last_metadata)
                if payload:
                    delivered=self.tail.deliver(payload)
                    self.journal.record(direction='tail_decoded',native_sha256=hashlib.sha256(payload).hexdigest(),
                        native_bytes=len(payload),delivered_to_native=delivered,proxy_ready=self.tail.enabled)
            else:self.trace_packet(s,data,'rx',source,kind='tail_cipher',accepted=False,reason='no_verified_peer_transport')
            return
        obj=unpack(self.key,data);now=time.monotonic()
        if not obj and source[0] in ips:self.stats['udp_auth_rejected']+=1
        kind=(obj or {}).get('k');nonce=(obj or {}).get('n');reason=None;expected=self.pending.get(nonce) if isinstance(nonce,str) else None
        if not obj:reason='invalid_authentication'
        elif not peer or obj.get('from')!=peer['id'] or obj.get('to')!=self.id or not hexid(nonce):reason='peer_identity_or_nonce'
        elif self.cfg.get('preflight_exchange') and not self.exchange_verified:reason='initial_exchange_not_confirmed'
        elif not endpoint(source,self.cfg.get('public_only',True)):reason='invalid_peer_source'
        elif source[0] not in ips and not self.cfg.get('multi_exit_search'):reason='source_ip_not_peer'
        elif kind not in ('probe','ack','tcp_offer','tcp_offer_ack'):reason='unknown_kind'
        elif kind.startswith('tcp_') and (not self.cfg.get('raw_tcp_experiment',True) or not self.cfg.get('tcp_udp_assist',False) or not self.direct_path or s not in self.udp):reason='tcp_offer_requires_verified_udp_path'
        self.seen={n:at for n,at in self.seen.items() if now-at<8}
        if not reason and nonce in self.seen:reason='duplicate_nonce'
        if not reason and kind=='ack':
            if not expected:reason='nonce_not_pending'
            elif expected[0] is not s:reason='wrong_receive_socket'
            elif now-expected[2]>5:reason='expired_probe'
            elif len(expected)>3 and obj.get('probe_sha256') and obj['probe_sha256']!=expected[3]['sha256']:reason='probe_digest_mismatch'
        rx=self.trace_packet(s,data,'rx',source,kind=kind or 'unknown',nonce=nonce,accepted=not reason,reason=reason,
            hmac_valid=bool(obj),sender=(obj or {}).get('from'),receiver=(obj or {}).get('to'),probe_sha256=(obj or {}).get('probe_sha256'),
            observed_by_peer=(obj or {}).get('seen_from'),role=self.coord.role,round=self.coord.round)
        if reason:return
        if source[0] not in ips:
            self.stats['udp_raw_peer_rx']+=1
            self.extra_ips_seen.add(source[0]);self.log('peer_actual_exit',endpoint=list(source),scope='authenticated_selected_peer_source',message='已收到所选对端的认证报文，确认真实对端方向出口')
        if kind.startswith('tcp_'):
            self.receive_tcp_offer(obj,peer,s,source,now);self.seen[nonce]=now;return
        self.stats['udp_probe_rx']+=1;self.seen[nonce]=now
        if kind=='probe':
            self.replies.append((s,source,pack(self.key,{'k':'ack','from':self.id,'to':peer['id'],'n':nonce,
                'seen_from':list(source),'probe_sha256':rx['sha256']})))
            # Reverse verification uses the authenticated source immediately,
            # rather than waiting for the next 35-second coordination window.
            self.challenge_seen={k:v for k,v in self.challenge_seen.items() if now-v<8}
            identity=(s.fileno(),source)
            if self.cfg.get('immediate_challenge',False) and not self.direct_path and now-self.challenge_seen.get(identity,0)>1:
                self.challenge_seen[identity]=now;self.challenges.append((s,source,rx))
            if self.unlimited_search:self.service_peer_control(peer,now)
        elif kind=='ack':
            self.stats['udp_probe_acks']+=1;self.pending.pop(nonce,None)
            tx=expected[3] if len(expected)>3 else {}
            if not self.udp_direct:
                if self.first_udp_at is None:self.first_udp_at=now;self.first_udp_active_seconds=round(self.active_elapsed,3)
                self.journal.proof(tx,rx,{'actor':self.id,'peer_id':peer['id'],'lane':tx.get('lane'),
                    'rtt_ms':round((now-expected[2])*1000,2),'observed_by_peer':obj.get('seen_from'),
                    'seconds_to_first_udp':round(now-self.started_at,3),'effective_search_seconds':self.first_udp_active_seconds,
                    'meaning':'first local authenticated round trip; not proof of all preceding CGNAT state'})
                self.log('udp_direct_verified',remote=list(source),local_port=s.getsockname()[1],rtt_ms=round((now-expected[2])*1000,2),
                    nonce=nonce,lane=tx.get('lane'),probe_target=tx.get('remote'),slot=tx.get('slot'),
                    observed_by_peer=obj.get('seen_from'),first_hit_proof=self.journal.proof_path)
            # An ACK proves the original outbound destination, even if its
            # authenticated return source is a different endpoint. Do not
            # replace the known send path with an untested return address.
            path=(s,expected[1]);self.path_roundtrips={p:times for p,old in self.path_roundtrips.items() if p[0].fileno()>=0 and (times:=collections.deque((at for at in old if now-at<5),maxlen=16))}
            samples=self.path_roundtrips.setdefault(path,collections.deque(maxlen=16));samples.append(now)
            selected_samples=len(self.path_roundtrips.get(self.direct_path,()))
            choose=not self.direct_path or self.direct_path==path or now-self.last_direct_ack>=1 or len(samples)>=3 and len(samples)>selected_samples+1
            if choose:
                if self.udp_direct and self.direct_path!=path:
                    self.log('udp_path_revalidated',remote=list(path[1]),return_source=list(source),local_port=s.getsockname()[1],nonce=nonce,lane=tx.get('lane'),probe_target=tx.get('remote'),message='采用当前认证往返有效的发送路径，保留原发送目标；无需重新全端口扫描')
                self.udp_direct=True;self.direct_path=path;self.last_direct_peer_source=source;self.last_direct_ack=now
                if self.profile is not None and now-self.last_receipt_publish>=.25:
                    self.profile['udp_path_receipt']={'nonce':nonce,'probe_sha256':obj.get('probe_sha256'),'ack_sha256':hashlib.sha256(data).hexdigest(),'sender_session':self.data_session,'receiver_session':(peer.get('profile') or {}).get('transport_session')}
                    self.last_receipt_publish=now;self.publish_profile()
    def apply_path_receipt(self,peer,now):
        # A current authenticated metadata receipt is the third leg of the
        # actual UDP probe/ACK exchange, not a substituted STUN observation.
        profile=(peer or {}).get('profile') or {};receipt=profile.get('udp_path_receipt')
        if not isinstance(receipt,dict) or receipt.get('sender_session')!=profile.get('transport_session') or receipt.get('receiver_session')!=self.data_session:return False
        nonce=receipt.get('nonce');record=self.reply_proofs.get(nonce) if isinstance(nonce,str) else None
        if not record:return False
        sock,target,ack_hash,probe_hash,sent=record
        if now-sent>8 or sock.fileno()<0 or receipt.get('ack_sha256')!=ack_hash or receipt.get('probe_sha256')!=probe_hash:return False
        self.reply_proofs.pop(nonce,None);path=(sock,target)
        if self.direct_path and self.direct_path!=path and now-self.last_direct_ack<.8:return False
        if self.first_udp_at is None:
            self.first_udp_at=now;self.first_udp_active_seconds=round(self.active_elapsed,3)
            self.journal.proof({'kind':'ack','nonce':nonce,'sha256':ack_hash,'local':list(sock.getsockname()),'remote':list(target)},
                {'kind':'authenticated_metadata_receipt','nonce':nonce,'sender':peer['id'],'probe_sha256':probe_hash,'ack_sha256':ack_hash},
                {'meaning':'peer confirms receiving the ACK sent for a real authenticated UDP probe; session-bound third leg','seconds_to_first_udp':round(now-self.started_at,3)})
            self.log('udp_direct_verified',remote=list(target),local_port=sock.getsockname()[1],nonce=nonce,lane='authenticated_peer_receipt',first_hit_proof=self.journal.proof_path,message='当前对端确认收到本端实际 UDP 回复，逐包摘要匹配，双向路径已证实')
        elif self.direct_path!=path:self.log('udp_path_revalidated',remote=list(target),local_port=sock.getsockname()[1],nonce=nonce,lane='authenticated_peer_receipt')
        self.direct_path=path;self.udp_direct=True;self.last_direct_ack=now
        self.stats['udp_path_receipts']=self.stats.get('udp_path_receipts',0)+1
        return True
    def receive_tcp_offer(self,obj,peer,s,source,now):
        target=endpoint(obj.get('candidate'),self.cfg.get('public_only',True))
        # The authenticated UDP channel only coordinates the selected peer.
        # An offer cannot make us dial an unrelated machine or arbitrary LAN.
        reason='invalid_or_unrelated_candidate' if not target or target[0]!=source[0] else 'local_candidate_missing' if not self.own_tcp_active else 'local_refresh_pending' if not self.tcp_refresh_started else 'local_candidate_stale' if not self.tcp_candidates_at or now-self.tcp_candidates_at>60 else 'already_verified' if self.tcp_direct else None
        if reason:
            self.log('tcp_coordination_rejected',reason=reason,message='TCP 协同暂不可执行；UDP 业务继续运行')
            return
        nonce=obj['n']
        if obj['k']=='tcp_offer' and peer['id']<self.id:
            if len(self.tcp_ack_plans)>=4:return
            ordinal=obj.get('ordinal',0)
            ordinal=ordinal if type(ordinal) is int and 0<=ordinal<16 else 0
            reply=pack(self.key,{'k':'tcp_offer_ack','from':self.id,'to':peer['id'],'n':nonce,'candidate':self.tcp_candidate(ordinal)})
            self.tcp_ack_plans[nonce]=(target,peer);self.replies.append((s,source,reply))
            self.log('tcp_coordination_received',token=nonce,target=list(target),message='通过已验证 UDP 收到 TCP 同时打开邀请；发出回应后才安排连接')
        elif obj['k']=='tcp_offer_ack' and peer['id']>self.id and self.tcp_offer==nonce and now-self.tcp_offer_at<=5:
            rtt=now-self.tcp_offer_at;delay=max(.05,.2-min(.15,rtt/2))
            self.tcp_plan=(target,peer,now+delay,nonce);self.tcp_offer=None
            self.log('tcp_coordination_ready',token=nonce,target=list(target),coordination_rtt_ms=round(rtt*1000,2),start_delay_ms=round(delay*1000))
    def send_tcp_offer(self,peer,now):
        if not self.cfg.get('raw_tcp_experiment',True) or not self.cfg.get('tcp_udp_assist',False) or not self.direct_path or self.tcp_direct or not self.tcp_refresh_started:return
        if not self.first_udp_at or now-self.first_udp_at<.5:return
        if not self.own_tcp_active or not self.tcp_candidates_at or now-self.tcp_candidates_at>60:return
        if (peer.get('profile') or {}).get('tcp_udp_coordination')!=1 or self.id>=peer['id']:return
        if (peer.get('profile') or {}).get('client_build') in tuple('1.0.'+str(i)+'-tail' for i in range(2,10)) and not (peer.get('profile') or {}).get('tcp_offer_ready'):return
        if self.tcp_offer_rounds>=(12 if self.cfg.get('tcp_neighbor_candidates') else 4) or self.tcp_plan or now-self.tcp_offer_at<8:return
        s,target=self.direct_path
        if not self.budget.admit((s.fileno(),target),now):return
        candidate=self.tcp_candidate(self.tcp_offer_rounds)
        nonce=secrets.token_hex(16);data=pack(self.key,{'k':'tcp_offer','from':self.id,'to':peer['id'],'n':nonce,'candidate':candidate,'ordinal':self.tcp_offer_rounds})
        if not self.send_udp(s,data,target,now,'tcp_offer'):return
        self.tcp_offer=nonce;self.tcp_offer_at=now;self.tcp_offer_rounds+=1;self.tcp_coordination_offers+=1
        self.trace_packet(s,data,'tx',target,kind='tcp_offer',nonce=nonce,accepted=True,lane='tcp_udp_coordination',sender=self.id,receiver=peer['id'])
        self.log('tcp_coordination_offer',token=nonce,candidate=list(candidate),observed_candidate=list(self.own_tcp_active[0]),ordinal=self.tcp_offer_rounds-1,
            candidate_kind='observed' if list(candidate)==list(self.own_tcp_active[0]) else 'nearby_guess',message='UDP 协同 TCP 同时打开；观察地址与邻近猜测分开记录，不复用 UDP 端口')
    def tcp_candidate(self,ordinal):
        ip,port=self.own_tcp_active[0]
        offsets=(0,1,-1,2,-2,4,-4,8,-8,0,0,0) if self.cfg.get('tcp_neighbor_candidates') else (0,)
        delta=offsets[ordinal%len(offsets)]
        return [ip,port+delta if 1<=port+delta<=65535 else port]
    def service_tail(self,peer,now):
        if not self.tail or not peer:return
        metadata=(peer.get('profile') or {}).get('tailscale')
        peer_session=(peer.get('profile') or {}).get('transport_session')
        if not metadata or not hexid(peer_session):return
        identity=(peer['id'],peer_session)
        if identity!=self.transport_identity:
            self.tail.bind_peer(metadata);self.transport=DataTransport(self.key,self.id,self.data_session,peer['id'],peer_session);self.transport_identity=identity
        elif self.tail.peer!=metadata:self.tail.bind_peer(metadata)
        if not self.direct_path:return
        if not self.tail.enabled and now-self.tail_failed_at>30:
            try:self.tail.start()
            except (OSError,RuntimeError) as exc:self.tail_failed_at=now;self.tail_bridge_error=str(exc);self.log('tail_bridge_error',message=str(exc));return
            self.tail_bridge_error=None
        if not self.tail.enabled:return
        self.tail.service_capture(now)
        self.tail.poll()
        for _ in range(64):
            if not self.tail_frames:
                try:payload,origin=self.tail.next_outbound()
                except Exception:break
                frames=self.transport.encode(payload)
                digest=hashlib.sha256(payload).hexdigest()
                self.journal.record(direction='tail_encapsulate',actor=self.id,kind=payload_kind(payload),origin=origin,native_sha256=digest,
                    message_id=self.transport.message,native_bytes=len(payload),fragment_count=len(frames))
                self.tail_frames.extend((frame,origin,index,len(frames),len(payload),digest,self.transport.message,payload_kind(payload)) for index,frame in enumerate(frames))
            frame,origin,index,count,native_bytes,digest,message_id,native_kind=self.tail_frames[0]
            if origin=='bootstrap_copy' and self.tail.bootstrap_stopped.is_set():
                self.tail_frames.popleft();continue
            if not self.flow.admit(len(frame),now):break
            sock,target=self.direct_path
            try:
                if not self.send_udp(sock,frame,target,now,'tail_cipher'):break
            except ConnectionResetError:break
            self.tail_frames.popleft()
            self.trace_packet(sock,frame,'tx',target,kind='tail_cipher',origin=origin,accepted=True,native_sha256=digest,
                message_id=message_id,fragment_index=index,fragment_count=count,native_bytes=native_bytes)
            if index==count-1:
                self.tail.stats['tail_tx_bytes']+=native_bytes;self.tail.stats['tail_tx_datagrams']+=1
                if native_kind=='wireguard_data':self.tail.stats['tail_tx_wg_datagrams']+=1
                if native_kind=='disco':self.tail.stats['tail_tx_disco_datagrams']+=1
    def service_native_check(self,now):
        # Native Tailscale may already work through its own endpoint or DERP,
        # even while our separate authenticated UDP search is still running.
        if not self.tail or self.stop.is_set():return
        if self.native_thread is None or not self.native_thread.is_alive():
            # A working DERP path must not slow discovery of a newly ready proxy.
            interval=3 if self.direct_path and not self.native_proxy_verified else 15 if self.native_verified else 2
            if now-getattr(self,'last_native_check',0)>interval:
                self.last_native_check=now;self.native_thread=threading.Thread(target=self.native_check,daemon=True);self.native_thread.start()
    def negotiate_protection(self,peer):
        if not self.protection_offer:return
        policy=negotiated(self.protection_offer,(peer.get('profile') or {}).get('protected_search') if peer else None)
        if policy!=self.protection_policy:
            self.protection_policy=policy;self.budget.interval=1/policy['rate'];self.budget.max_new=policy['new15']
            self.budget.pressure.limit=policy['new180'];self.budget.pressure.burst=policy['burst'];self.budget.pressure.window=policy['window'];self.budget.pressure.spacing=policy['new_spacing_ms']/1000
            self.log('protection_policy',policy=policy,message='双方自动取较低预算；同时限制短时新映射、长期映射压力与突发，保留现有连接')
    def update_coexistence(self,peer,now):
        state=self.coexist.snapshot(now)
        if self.unlimited_search:
            self.budget.pause=False;self.remote_pause=False
            self.coexist_state={**state,'remote_pause':False,'limits_disabled':True}
            return
        self.remote_pause=bool(peer and now-self.last_snapshot<8 and (peer.get('profile') or {}).get('coexist_pause') is True)
        self.budget.pause=state['pause'] or self.remote_pause
        self.coexist_state={**state,'remote_pause':self.remote_pause}
        if self.profile is not None and self.coexist.enabled:
            signature=(state['monitor'],state['pause'],state['recovering'],state['last_signal'])
            if signature!=self.last_coexist_signature or (state['pause'] and now-self.last_coexist_profile>=5):
                self.profile['coexist_pause']=state['pause'];self.publish_profile();self.last_coexist_profile=now
                if signature!=self.last_coexist_signature:
                    self.log('bifrost_protection',**self.coexist_state,message='只读观察 Bifrost；异常时暂停新增探测，已有认证通道继续运行')
                    self.last_coexist_signature=signature
        if self.protection_policy:
            unobserved=self.coexist.enabled and not self.cfg.get('restore_v105_budget') and state['monitor'] in ('starting','trace_not_available','trace_unreadable')
            self.budget.interval=max(1/self.protection_policy['rate'],1/20 if unobserved or state['recovering'] else 0)
            # Slow the creation of state further during recovery, not data on an authenticated path.
            self.budget.pressure.spacing=max(self.protection_policy['new_spacing_ms']/1000,2 if state['recovering'] else .5 if unobserved else 0)
    def tcp_permission(self,s,target):
        if not self.cfg.get('raw_tcp_experiment',True):return False
        if not self.protection_offer:return True
        now=time.monotonic()
        if self.stop.is_set() or self.budget.pause:return False
        if self.coexist.enabled and (not self.direct_path or now-self.last_tcp_new<8):return False
        key=('tcp',s.getsockname()[1],target)
        allowed=self.budget.admit(key,now)
        if allowed:self.last_tcp_new=now
        return allowed
    def protected_observer_slot(self,now):
        if not self.connected.is_set():return None
        # One existing observer destination, never a flood after lost control.
        if now-getattr(self,'last_protected_observer',0)<.5:return None
        due=[i for i in range(len(self.udp)) if now-self.observer_last.get(i,0)>=4]
        if not due:return None
        self.last_protected_observer=now
        return min(due,key=lambda i:self.observer_last.get(i,0))
    def native_check(self):
        if self.stop.is_set():return
        errors={};output='';tsmp='';peer={};using_proxy=False;initial_proxy=False
        target=self.tail.metadata['peer_tail_ip']
        proxy_host,proxy_port=self.tail.socket.getsockname();proxy=f'{proxy_host}:{proxy_port}'
        def attempt(name,args):
            try:
                if self.stop.is_set():raise InterruptedError('session_stopping')
                result=command(args,timeout=5,stop=self.stop)
                if self.stop.is_set():raise InterruptedError('session_stopping')
                return result
            except Exception as exc:errors[name]=str(exc);return ''
        def peer_status():
            raw=attempt('status',['status','--json'])
            if not raw:return None
            try:
                status=json.loads(raw)
                return next((p for p in status.get('Peer',{}).values() if p.get('PublicKey')==self.tail.metadata['expected_peer_key']),{})
            except Exception as exc:errors['status']=str(exc);return None
        try:
            output=attempt('discovery',['ping','--c=1','--timeout=2s','--until-direct=false',target])
            peer=peer_status();initial_peer=peer;initial_addr=(peer or {}).get('CurAddr');initial_proxy=peer is not None and initial_addr==proxy
            before=[self.tail.stats.get(k,0) for k in ('tail_tx_wg_datagrams','tail_rx_wg_datagrams')]
            def fresh_data():return all(self.tail.stats.get(k,0)>v for k,v in zip(('tail_tx_wg_datagrams','tail_rx_wg_datagrams'),before))
            tsmp=attempt('tsmp',['ping','--tsmp','--c=1','--timeout=2s',target])
            peer=peer_status()
            using_proxy=peer is not None and peer.get('CurAddr')==proxy
            # A real data reply proves native availability independently of
            # which endpoint Tailscale selected. Discovery alone proves neither.
            self.native_verified=bool('pong' in tsmp.lower())
            if self.native_verified:
                self.native_verified_at=time.monotonic()
                if getattr(self,'first_tail_usable_at',None) is None:self.first_tail_usable_at=self.native_verified_at
            peerapi='';tcp_business_verified=False
            if getattr(self,'cfg',{}).get('tail_tcp_check',False):
                peerapi=attempt('peerapi',['ping','--peerapi','--c=1','--timeout=2s',target])
                peer=peer_status();using_proxy=peer is not None and peer.get('CurAddr')==proxy
                tcp_business_verified=bool('pong' in peerapi.lower() or peerapi.lower().startswith('hit peerapi of '+target+' '))
                self.native_verified=bool(self.native_verified or tcp_business_verified)
                if self.native_verified:
                    self.native_verified_at=time.monotonic()
                    if getattr(self,'first_tail_usable_at',None) is None:self.first_tail_usable_at=self.native_verified_at
            # Accepted native WireGuard traffic is also evidence when TSMP or
            # peerAPI diagnostics are blocked. Compare this selected node's
            # counters within this check; never use historical nonzero counts.
            native_delta=[int((peer or {}).get(k,0) or 0)-int((initial_peer or {}).get(k,0) or 0) for k in ('TxBytes','RxBytes')]
            live_native_traffic=bool(initial_peer and peer and all(v>=1024 for v in native_delta))
            if live_native_traffic and not self.native_verified:
                self.native_verified=True;self.native_verified_at=time.monotonic()
                if getattr(self,'first_tail_usable_at',None) is None:self.first_tail_usable_at=self.native_verified_at
            self.native_proxy_verified=bool(self.native_verified and initial_proxy and using_proxy and fresh_data() and getattr(self,'direct_path',True))
            current_addr=(peer or {}).get('CurAddr')
            route='unknown' if not peer else 'path_changed' if initial_addr!=current_addr else 'natpair_proxy' if self.native_proxy_verified else 'proxy_unconfirmed' if using_proxy else 'native_reported_direct' if current_addr else 'derp'
            if self.native_verified and route in ('natpair_proxy','native_reported_direct') and self.first_native_at is None:self.first_native_at=self.native_verified_at
            stats=dict(self.tail.stats)
            diagnosis='native_data_verified' if self.native_verified else 'native_endpoint_selected_waiting_for_data' if using_proxy else 'no_local_native_reply' if stats.get('tail_rx_disco_datagrams',0) and not stats.get('tail_local_return_datagrams',0) else 'waiting_for_native_endpoint_selection'
            discovery_ok='pong' in output.lower()
            state='data_verified' if self.native_verified else 'status_unavailable' if peer is None else 'path_unconfirmed' if initial_proxy and using_proxy and ('pong' in tsmp.lower() or 'pong' in peerapi.lower()) else 'validation_timeout' if initial_proxy and using_proxy else 'other_endpoint' if peer.get('CurAddr') and not using_proxy else 'discovery_only' if discovery_ok else 'waiting'
            self.native_health={'state':state,'checked_at':time.monotonic(),'using_proxy':using_proxy,'proxy_verified':self.native_proxy_verified,'route':route,'data_evidence':'tsmp' if 'pong' in tsmp.lower() else 'peerapi' if tcp_business_verified else 'recent_bidirectional_native_traffic' if live_native_traffic else None,'native_data_delta':native_delta,'discovery_ok':discovery_ok,'cur_addr':(peer or {}).get('CurAddr'),
                'expected_proxy':proxy,'errors':errors,'native_rx_bytes':(peer or {}).get('RxBytes'),'native_tx_bytes':(peer or {}).get('TxBytes'),
                'last_handshake':(peer or {}).get('LastHandshake'),'tcp_business_verified':tcp_business_verified,'peerapi':peerapi[-600:],
                'proxy_data_delta':[self.tail.stats.get(k,0)-v for k,v in zip(('tail_tx_wg_datagrams','tail_rx_wg_datagrams'),before)]}
            self.log('tail_native_check',using_proxy=using_proxy,native_verified=self.native_verified,native_proxy_verified=self.native_proxy_verified,route=route,cur_addr=(peer or {}).get('CurAddr'),expected_proxy=proxy,
                diagnosis=diagnosis,health=self.native_health,local_transport=stats,discovery=output[-1200:],wireguard_tsmp=tsmp[-600:])
        except Exception as exc:
            self.native_verified=False;self.native_proxy_verified=False
            self.native_health={'state':'status_unavailable','checked_at':time.monotonic(),'errors':{'check':str(exc)}}
            if not self.stop.is_set():self.log('tail_native_check',native_verified=False,health=self.native_health,message=str(exc))
        # Refresh even after discovery/TSMP failure, at most once per 15 s.
        if not self.stop.is_set() and time.monotonic()-getattr(self,'last_native_metadata',0)>15:
            self.last_native_metadata=time.monotonic()
            try:
                metadata=read_metadata(target,preferred_port=self.tail.metadata.get('udp_port'),stop=self.stop)
                if self.stop.is_set():return
                if self.tail.refresh(metadata):
                    if getattr(self,'local_firewall',None):self.local_firewall.update(metadata['udp_port'])
                    self.profile['tailscale']=metadata;self.publish_profile();self.log('tail_metadata_refreshed',message='已刷新 Tailscale UDP 端口／发现身份／候选地址')
            except Exception as exc:
                if not self.stop.is_set():self.log('tail_metadata_refresh_error',message=str(exc))
    def targets(self,peer):
        seed=[endpoint(p,self.cfg.get('public_only',True)) for p in peer.get('udp',[])[:16]]
        seed=list(dict.fromkeys(p for p in seed if p))
        if not seed:return []
        result=list(seed);profile=peer.get('profile') or {};p=profile.get('port_pattern') or {}
        for ip,port in dict.fromkeys(seed[:2]+seed[-2:]):
            value=p.get('step') if p.get('validated') else 1
            step=value if type(value) is int and 1<=abs(value)<=128 else 1
            for shift in (-2,-1,1,2,3,4):
                candidate=(ip,port+shift*step)
                if 1<=candidate[1]<=65535 and candidate not in result:result.append(candidate)
        # Small candidate set only; no unbounded or 65535-port traversal.
        return result[:24]
    def peer_hints(self):return (getattr(self.tail,'metadata',{}) if self.tail else self.sync_metadata).get('peer_endpoints',[])
    def peer_ips(self,peer):
        peer=peer or {};public=self.cfg.get('public_only',True)
        ips={p[0] for p in peer.get('udp',[]) if endpoint(p,public)}
        if self.cfg.get('multi_exit_search'):ips.update(ep[0] for ep,reason in extra_candidates(peer,self.peer_hints(),public))
        return ips|self.extra_ips_seen
    def prepare_tcp(self,measurement,listener,refresh=False):
        if self.protection_offer:
            if not self.tcp_serial.acquire(blocking=False):return
            try:return self._prepare_tcp(measurement,listener,refresh)
            finally:self.tcp_serial.release()
        return self._prepare_tcp(measurement,listener,refresh)
    def _prepare_tcp(self,measurement,listener,refresh=False):
        if not self.cfg.get('raw_tcp_experiment',True) or self.stop.is_set() or self.budget.pause or (self.coexist.enabled and not self.direct_path):return
        self.tcp_prepare_generation+=1;self.last_tcp_refresh=time.monotonic()
        if refresh and self.cfg.get('tcp_rotate_source',False):
            reserved=raw_socket(socket.SOCK_STREAM,self.bind,self.index,reuse=True)
            self.active_port=reserved.getsockname()[1];reserved.close()
            self.profile['tcp_offer_ready']=False;self.own_tcp_active=[];self.tcp_candidates_at=0
            self.publish_profile()
        observe_port=measurement.base+(self.tcp_prepare_generation-1)%8 if self.cfg.get('tcp_mapping_retry',False) else measurement.base+1 if refresh else measurement.base
        tcp=measurement.tcp_observe(observe_port,listener.getsockname()[1])
        self.own_tcp=[tcp['endpoint']] if tcp.get('endpoint') else []
        if not tcp.get('endpoint') and not self.stop.is_set():self.log('tcp_mapping_error',message=tcp.get('error'),observation=tcp,server_port=observe_port,generation=self.tcp_prepare_generation)
        if self.stop.is_set():return
        active=measurement.tcp_observe(observe_port,self.active_port)
        self.own_tcp_active=[active['endpoint']] if active.get('endpoint') else []
        if not active.get('endpoint') and not self.stop.is_set():self.log('tcp_mapping_error',mode='simultaneous_open',message=active.get('error'),observation=active,server_port=observe_port,generation=self.tcp_prepare_generation)
        if not self.stop.is_set():
            self.tcp_candidates_at=time.monotonic() if self.own_tcp_active else 0
            self.profile['tcp_offer_ready']=bool(self.direct_path and self.own_tcp_active)
            if refresh:self.tcp_offer_rounds=0
            self.log('tcp_prepared',listener_candidates=list(self.own_tcp),simultaneous_candidates=list(self.own_tcp_active),
                simultaneous_mapping_available=bool(self.own_tcp_active),mapping_results={'listener':tcp,'simultaneous':active},
                message='TCP 候选准备完成；后台准备不会阻塞 UDP 探测')
            self.publish_profile()
    def run(self,measure_only=False):
        selector=selectors.DefaultSelector();control_thread=None;pulse_thread=None;tcp_prepare_thread=None
        try:
            self.bind,self.index=(self.cfg['bind'],int(self.cfg.get('if_index',0))) if self.cfg.get('bind') else physical()
            self.log('interface',ip=self.bind,index=self.index)
            if self.coexist.enabled:
                self.coexist.poll();self.coexist_thread=threading.Thread(target=self.coexist.run,args=(self.stop,),daemon=True);self.coexist_thread.start()
                self.budget.pause=self.coexist.snapshot(time.monotonic())['pause']
            import platform,traceback
            self.log('runtime',version='1.0.18-tail',os=platform.platform(),architecture=platform.machine(),python=platform.python_version(),
                actual_administrator=is_admin(),scoped_peer_firewall=bool(self.cfg.get('scoped_peer_firewall')),
                tailscale_bridge=bool(self.cfg.get('tailscale_bridge')),tcp_udp_assist=bool(self.cfg.get('tcp_udp_assist')),production_mode=bool(self.cfg.get('production_mode')),
                session_mode=self.cfg.get('session_mode'),udp_only=bool(self.cfg.get('udp_only')))
            if self.cfg.get('tailscale_bridge',False) and not measure_only:
                if not is_admin():raise RuntimeError('Tailscale 接入需右键以管理员身份运行；仅诊断模式无需管理员')
                self.log('tail_driver_checked',**driver_check())
                metadata=self.cfg.get('_metadata_reader',read_metadata)(self.cfg.get('peer_tail_ip',''),stop=self.stop)
                self.tail=TailBridge(metadata,lambda event,**fields:self.log(event,**fields),self.journal,bind_ip=self.bind,
                                     capture_factory=self.cfg.get('_capture_factory'))
                selector.register(self.tail.socket,selectors.EVENT_READ,'tail')
                if self.cfg.get('scoped_peer_firewall',False):
                    self.local_firewall=LocalProxyFirewall(self.id,self.bind,self.tail.socket.getsockname()[1],lambda event,**fields:self.log(event,**fields))
                    self.local_firewall.update(metadata['udp_port'])
                self.log('tail_selected',peer_tail_ip=metadata['peer_tail_ip'],udp_port=metadata['udp_port'],proxy=list(self.tail.socket.getsockname()),settings_changed=False)
            elif self.cfg.get('tail_metadata_only') and not measure_only:
                try:
                    # Only status/netmap reads. No native UDP port query, capture
                    # driver, local proxy or Tailscale settings are involved.
                    self.sync_metadata=read_metadata(self.cfg.get('peer_tail_ip',''),port=1,stop=self.stop)
                    self.sync_metadata.pop('udp_port',None)
                    self.log('tail_sync_only',message='只通过 Tailscale 交换本轮信息；独立测试本程序 IPv4 UDP 打洞，不接入 Tailscale 数据流。')
                except (OSError,RuntimeError,ValueError) as exc:
                    self.log('peer_sync_unavailable',message='读取 Tailscale 同步信息失败，使用加密 UDP 房间同步：'+str(exc))
            self.log('experiment_settings',new_combinations_per_second=self.combination_limit.limit,nearby_priority=bool(self.cfg.get('nearby_priority')),fast_start=bool(self.cfg.get('fast_start')),
                immediate_challenge=bool(self.cfg.get('immediate_challenge')),coordinated_scan=self.cfg.get('coordinated_scan',True),
                probe_packet_limit_per_second=self.budget.rate_limit,new_socket_targets_per_15_seconds=None if self.unlimited_search else self.budget.max_new,unlimited_search=self.unlimited_search,
                fast_center_search=bool(self.cfg.get('fast_center_search')),candidate_pool_priority=bool(self.cfg.get('candidate_pool_priority')),priority_candidate_max_pps=2,
                phased_search=bool(self.cfg.get('phased_search')),coordination_window_seconds=self.cfg.get('coordination_window_seconds',35),
                message='新版双方握手同步独立阶段：附近、原版分工、固定源分工、观察区间、原版分工、反向固定源分工；原版阶段不混入附近矩阵' if self.cfg.get('phased_search') else '旧式混合探测')
            measurement=Measurements(self.cfg,self.bind,self.index,self.stop,lambda message:self.log('measurement',message=message))
            self.observer_address=(measurement.host,measurement.base)
            control_thread=threading.Thread(target=self.control_read,daemon=True);control_thread.start()
            pulse_thread=threading.Thread(target=self.control_pulse,daemon=True);pulse_thread.start()
            if not self.wait_for_coordination():return
            measurement.tcp_permission=self.tcp_permission
            measurement.registered_observer=self.registered_observer
            measurement.trace_packet=self.trace_packet
            self.profile=dict(measurement.run());self.profile['strategy_protocol']=1 if self.cfg.get('coordinated_scan',True) else 0;self.profile['client_build']='1.0.18-tail';self.profile['unlimited_search']=self.unlimited_search;self.profile['punch_epoch']=secrets.token_hex(16);self.log('profile',profile=self.profile)
            if self.protection_offer:self.profile['protected_search']=dict(self.protection_offer)
            self.profile['tcp_udp_coordination']=1 if self.cfg.get('tcp_udp_assist',False) else 0
            if self.cfg.get('phased_search',False):self.profile['search_phase_protocol']=1
            self.profile['transport_session']=self.data_session
            if self.tail:self.profile['tailscale']=self.tail.metadata
            if measure_only or self.stop.is_set():
                if measure_only:self.finish_reason='measurement_complete'
                return
            # Eight source sockets are a bounded experimental pool, not a claim
            # that the observer endpoints transfer to the peer destination.
            self.discovery.new_epoch();self.stage='main'
            self.control_send({'k':'stage','stage':self.stage,'epoch':self.discovery.epoch})
            justified=self.profile['port_pattern'].get('validated') or self.profile['same_ip_filtering']=='alternate_port_reply_received'
            pool_size=8 if self.cfg.get('coordinated_scan',True) or justified else 2
            for _ in range(min(pool_size,max(1,int(self.cfg.get('lab_sockets',8))))):
                if self.stop.is_set():break
                s=measurement.socket();slot=len(self.udp);self.discovery.attach(slot,s)
                self.udp.append(s)
                s.setblocking(False);selector.register(s,selectors.EVENT_READ,'udp')
            if self.cfg.get('live_egress_discovery'):
                self.egress=LiveEgress(self.cfg,self.udp,self.bind,self.index,self.stop,lambda event,**fields:self.log(event,**fields));self.exit_discovery_pending=True
                self.log('exit_discovery_started',timeout_seconds=4,scope='actual_probe_sockets',message='先测本轮探测套接字的多服务器公网出口，最多4秒；未把它当成已验证对端映射')
            self.configure_probe_firewall()
            listener=None
            if self.cfg.get('raw_tcp_experiment',True):
                listener=raw_socket(socket.SOCK_STREAM,self.bind,self.index,reuse=True)
                self.tcp_listener=listener;listener.listen(4);listener.setblocking(False)
                selector.register(listener,selectors.EVENT_READ,'tcp')
                reserved=raw_socket(socket.SOCK_STREAM,self.bind,self.index,reuse=True);self.active_port=reserved.getsockname()[1];reserved.close()
                if self.cfg.get('scoped_peer_firewall',False) and self.tail:
                    self.tcp_firewall=PeerFirewall(self.id,self.bind,[listener.getsockname()[1],self.active_port],lambda event,**fields:self.log(event,**fields),protocol='TCP')
                if self.cfg.get('fast_start',False):
                    tcp_prepare_thread=threading.Thread(target=self.prepare_tcp,args=(measurement,listener),daemon=True)
                    tcp_prepare_thread.start()
                else:self.prepare_tcp(measurement,listener)
            self.prepared=not self.exit_discovery_pending
            if self.cfg.get('coordinated_scan_v2'):self.profile['coordination_protocol']=2
            self.initial_exchange(None,False);self.start_peer_sync();self.publish_profile()
            self.tcp_executor=concurrent.futures.ThreadPoolExecutor(max_workers=1 if self.protection_offer else 2) if listener else None
            last_poll=last_status=last_tcp=last_observer=last_direct_probe=0;cursor=0;futures=[];observer_cursor=0;outbound=None
            duration=min(28800,max(10,float(self.cfg.get('duration',300))))
            clock=PairClock(float('inf') if self.cfg.get('production_mode',False) else duration,
                float('inf') if self.cfg.get('production_mode',False) or self.cfg.get('wait_unlimited',False) else min(600,max(10,float(self.cfg.get('wait_seconds',300)))),
                float('inf') if self.cfg.get('production_mode',False) or self.cfg.get('wait_unlimited',False) else min(1800,max(5,float(self.cfg.get('peer_gap_seconds',300)))))
            visited_targets=set();visited_paths=set();candidate_signature=None;last_coverage=0
            self.log('waiting',seconds=duration,source_sockets=len(self.udp),message='等待服务器汇报双方活跃地址；双方准备好后才开始有效计时')
            peer_version_warned=False;role_state=None;was_ready=None;current_peer_id=None
            while not self.stop.is_set():
                now=time.monotonic()
                if self.egress:
                    self.egress.tick(now,self.send_udp,self.trace_packet,self.direct_path[0] if self.direct_path else None)
                    if self.egress.dirty and now-self.last_egress_publish>=1 or now-self.last_egress_publish>=5:
                        self.profile['exit_observations']=self.egress.snapshot(now);self.egress.dirty=False;self.last_egress_publish=now;self.publish_profile()
                    if self.exit_discovery_pending and self.egress.initial_complete(now):
                        self.exit_discovery_pending=False;self.prepared=True;self.profile['exit_observations']=self.egress.snapshot(now);self.publish_profile()
                        self.log('exit_discovery_complete',**self.egress.snapshot(now),message='当前多服务器方向公网出口已整理；缺失的反射服务不阻塞后续打洞，后台继续刷新')
                if now-last_poll>=2:self.control_send({'k':'poll'});last_poll=now
                with self.peer_lock:peer=self.peer
                self.own_udp=self.discovery.endpoints(now)
                zero=self.discovery.slot_endpoint(0,now)
                peer,cached_search=self.search_peer(peer,now,bool(self.own_udp if self.protection_offer else zero))
                if cached_search!=self.cached_search_active:
                    self.recovery_pairs=[];self.recovery_cursor=0
                    self.log('cached_search_started' if cached_search else 'cached_search_ended',
                        candidate_age_seconds=round(now-self.cached_search_at,3) if self.cached_search_peer else None,
                        message='候选／协调恢复中：固定目标维持联系，保留原扫描位置；后台恢复' if cached_search else '恢复新鲜房间信息，续接原扫描位置；或对端已报告完成')
                self.cached_search_active=cached_search;self.selected_peer=peer
                overlay_fresh=bool(self.peer_sync and self.peer_sync.fresh(now))
                exchange_ready=self.initial_exchange(peer,not cached_search and (self.peer_lease_active or overlay_fresh or self.connected.is_set() and now-self.last_snapshot<8))
                if exchange_ready and not cached_search:self.apply_path_receipt(peer,now)
                self.negotiate_protection(peer)
                self.update_coexistence(peer,now)
                if self.firewall and peer:self.firewall.update(self.peer_ips(peer))
                if self.tcp_firewall and peer:
                    self.tcp_firewall.update_ports([listener.getsockname()[1],self.active_port])
                    self.tcp_firewall.update([ep[0] for p in peer.get('udp',[]) if (ep:=endpoint(p,True))])
                if self.profile.get('source_zero_observer_endpoint')!=zero:
                    self.profile['source_zero_observer_endpoint']=zero;self.publish_profile()
                ready=bool((self.peer_lease_active or overlay_fresh or cached_search or (self.connected.is_set() and now-self.last_snapshot<8 and (self.unlimited_search or (self.own_udp if self.protection_offer else zero)))) and peer and peer.get('prepared') and peer.get('udp') and peer.get('version')=='0.9.4-lab')
                ready=ready and not self.exit_discovery_pending and exchange_ready
                if self.tail and peer:ready=ready and bool((peer.get('profile') or {}).get('tailscale') and hexid((peer.get('profile') or {}).get('transport_session')))
                search_allowed=self.connection_guard.step(now,ready,(self.connected.is_set() and now-self.last_snapshot<8) if self.cfg.get('efficient_search') else None) if self.protection_offer else ready
                dense_gate=self.cfg.get('_dense_allowed')
                dense_wait=bool(dense_gate and not self.direct_path and not dense_gate())
                if dense_wait:search_allowed=False
                if self.budget.pause:
                    search_allowed=False;self.connection_guard.reason='bifrost_local_pause' if self.coexist_state.get('pause') else 'bifrost_peer_pause'
                self.wall_elapsed=now-clock.prepared_at if clock.prepared_at is not None else 0
                if ready!=was_ready:
                    if not ready and not self.protection_offer and not self.unlimited_search:
                        role_state=None;self.coord=Coordination(self.id,self.cfg.get('coordination_window_seconds',35));self.profile['punch_epoch']=secrets.token_hex(16);self.profile.pop('punch_coord',None);self.publish_profile()
                    if was_ready is not None:self.log('testing_resumed' if ready else 'testing_paused',message='双方地址已恢复，继续有效计时' if ready else '协调连接或对端地址未齐全，暂停扫描和有效计时')
                    was_ready=ready
                began,elapsed,expired=clock.step(now,bool(self.direct_path) or (search_allowed and not cached_search));self.active_elapsed=elapsed
                reason='exit_discovery' if self.exit_discovery_pending else 'verified_path' if self.direct_path else 'verified_session_lease' if self.peer_lease_active else 'coordinator_stale' if cached_search else 'initial_exchange' if peer and not exchange_ready else 'waiting_peer' if not ready else 'phase_handshake' if self.cfg.get('coordinated_scan',True) and self.coord.role not in ('anchor','scan','duplex') else 'active_probe'
                if dense_wait and ready:reason='mesh_scheduling_or_business_priority'
                if self.search_clock_at is not None:self.search_times[self.search_clock_reason]+=max(0,now-self.search_clock_at)
                self.search_clock_at=now;self.search_clock_reason=reason
                if self.peer_completed and clock.started is not None and not self.cfg.get('production_mode',False):
                    self.finish_reason='peer_completed';self.log('test_complete',reason=self.finish_reason,active_seconds=round(elapsed,2),message='对端已完成有效计时，本端同步结束；记录本端实际有效秒数');break
                if began:
                    self.paired_started=True
                    self.log('testing',seconds=duration,source_sockets=len(self.udp),own_candidates=self.own_udp,peer_candidates=peer['udp'],message='双方已准备，开始有效双端计时；候选地址不代表直连成功')
                if peer and peer.get('version')!='0.9.4-lab' and not peer_version_warned:
                    peer_version_warned=True;self.log('waiting_reason',message='对方版本不同，请双方使用新版诊断助手')
                if expired:
                    if clock.reason=='active_duration_complete':self.control_send({'k':'notice','message':'lab_test_complete'})
                    self.finish_reason=clock.reason;self.log('test_timeout' if clock.reason!='active_duration_complete' else 'test_complete',reason=clock.reason,active_seconds=round(elapsed,2),message='有效双端测试完成' if clock.reason=='active_duration_complete' else '等待双方恢复超过时限，本轮结束')
                    if clock.started is None:self.log('waiting_timeout',message='双方活跃地址未齐全，本轮未开始有效双端测试',own_candidates=self.own_udp,peer_candidates=(peer or {}).get('udp',[]))
                    break
                self.service_peer_control(peer,now)
                if self.udp:
                    protected_slot=self.protected_observer_slot(now) if self.protection_offer else None
                    due=protected_slot is not None if self.protection_offer else now-last_observer>=(.15 if self.cfg.get('fast_start',False) and not self.direct_path and len(self.own_udp)<len(self.udp) else .5)
                    if due:
                        slot=protected_slot if self.protection_offer else observer_cursor%len(self.udp)
                        if self.direct_path and self.udp[slot] is self.direct_path[0]:
                            alternatives=[i for i,probe_socket in enumerate(self.udp) if probe_socket is not self.direct_path[0]]
                            slot=alternatives[0] if alternatives else None
                        sock=self.udp[slot] if slot is not None else None
                        if sock is not None and self.budget.admit((sock.fileno(),(measurement.host,measurement.base)),now,maintenance=True):
                            if self.send_observer(measurement,slot,now):
                                if self.protection_offer:self.observer_last[slot]=now
                                last_observer=now;observer_cursor=slot+1
                            elif self.protection_offer:self.last_protected_observer=0.
                if peer and current_peer_id!=peer['id']:
                    if current_peer_id is not None:
                        self.direct_path=None;self.udp_direct=False;self.tcp_direct=False;self.pending.clear()
                    current_peer_id=peer['id']
                if self.tcp_offer and now-self.tcp_offer_at>5:
                    self.log('tcp_coordination_timeout',token=self.tcp_offer,message='协同邀请无回应，继续保留普通 TCP 候选尝试')
                    self.tcp_offer=None
                if self.direct_path and now-self.last_direct_ack>=8:
                    self.log('udp_path_expired',message='命中路径连续 8 秒未取得认证回应，恢复协调探测；历史成功保留在记录')
                    self.direct_path=None;self.native_proxy_verified=False;self.tail_frames.clear()
                    # Expiry of our outer tunnel does not establish failure of
                    # native Tailscale, which may have switched to another route.
                    if getattr(self,'native_health',{}).get('route')=='natpair_proxy':
                        self.native_verified=False;self.native_health['state']='validation_timeout'
                    self.tcp_plan=None;self.tcp_offer=None;self.tcp_ack_plans.clear()
                tcp_refresh_due=(not self.own_tcp_active or bool(self.direct_path and not self.tcp_direct and now-self.tcp_candidates_at>45))
                tcp_idle=(outbound is None or outbound.done()) and not any(not f.done() for f in futures) and not self.tcp_plan and not self.tcp_offer and not self.tcp_ack_plans
                if listener and not self.budget.pause and (not self.coexist.enabled or self.direct_path) and self.cfg.get('tcp_mapping_retry',False) and (search_allowed or self.direct_path or not self.protection_offer) and tcp_refresh_due and tcp_idle and now-self.last_tcp_refresh>=(120 if self.protection_offer else 30) and self.tcp_prepare_generation<(64 if self.cfg.get('tcp_rotate_source') else 12 if self.direct_path else 8) and (not tcp_prepare_thread or not tcp_prepare_thread.is_alive()):
                    tcp_prepare_thread=threading.Thread(target=self.prepare_tcp,args=(measurement,listener,True),daemon=True);tcp_prepare_thread.start()
                    self.log('tcp_mapping_retry',message='TCP 候选失败后后台重试不同观察端口；UDP 不等待重试')
                if now-self.last_socket_snapshot>=15:
                    self.last_socket_snapshot=now
                    self.log('socket_mapping_snapshot',scope='observer_direction_only',sockets=[{'slot':i,'local':list(s.getsockname()),'observer_endpoint':self.discovery.slot_endpoint(i,now)} for i,s in enumerate(self.udp)])
                if listener and not self.budget.pause and self.cfg.get('tcp_udp_assist',False) and self.direct_path and not self.tcp_refresh_started and (not tcp_prepare_thread or not tcp_prepare_thread.is_alive()):
                    self.tcp_refresh_started=True
                    if self.tcp_candidates_at and now-self.tcp_candidates_at<60 and self.own_tcp_active:
                        self.profile['tcp_offer_ready']=True;self.publish_profile()
                        self.log('tcp_candidates_recent',age_seconds=round(now-self.tcp_candidates_at,3),message='使用刚观测到的 TCP 专用候选，避免重复同一 TCP 五元组触发 TIME_WAIT 冲突')
                    else:
                        tcp_prepare_thread=threading.Thread(target=self.prepare_tcp,args=(measurement,listener,True),daemon=True);tcp_prepare_thread.start()
                        self.log('tcp_refresh_started',message='UDP 成功后后台刷新 TCP 专用候选；UDP 通道保持运行')
                path_peer=peer or (self.last_peer if self.direct_path else None)
                if path_peer and (search_allowed or self.direct_path) and clock.started is not None:
                    peer=path_peer
                    if self.peer_lease_active:
                        changed,role=False,self.coord.role or getattr(self,'last_search_role',None) or 'synchronizing'
                    else:
                        changed,role=self.coord.step(peer,self.profile,now) if ready and not cached_search and self.cfg.get('coordinated_scan',True) else (False,getattr(self,'last_search_role',None) or 'synchronizing' if cached_search else 'legacy_candidates' if ready else 'waiting')
                    # Do useful work while control-round acknowledgement is
                    # delayed. Both v110 peers derive complementary warmup roles.
                    # Return to the negotiated strategy as soon as it is ready.
                    if self.unlimited_search and role not in ('anchor','scan','duplex') and clock.started is not None and now-clock.started>=3:
                        role='anchor' if self.id<peer['id'] else 'scan'
                    if role in ('anchor','scan','duplex'):self.last_search_role=role
                    if changed:
                        self.profile['punch_coord']=dict(self.coord.record);self.publish_profile();self.control_send({'k':'poll'})
                    state=(self.coord.round,role,self.coord.mode,self.coord.phase)
                    if state!=role_state:
                        role_state=state;self.log('coordination',round=self.coord.round,role=role,mode=self.coord.mode,search_phase=self.coord.phase,
                            message='轮次同步／固定目标多源保活／固定源端口分批扫描；混合 NAT4 为实验，不保证直连')
                    targets=self.targets(peer)
                    if self.cfg.get('multi_exit_search'):
                        extra=extra_candidates(peer,self.peer_hints(),self.cfg.get('public_only',True))
                        extra_signature=tuple(extra)
                        if extra_signature!=getattr(self,'last_extra_signature',None):
                            self.last_extra_signature=extra_signature;self.log('exit_candidate_pool',candidates=[{'endpoint':list(ep),'source':why,'peer_path_verified':False} for ep,why in extra],message='多出口实测与候选分开；原版附近策略保留，另行验证额外IP')
                    signature=tuple(targets)
                    if signature!=candidate_signature:
                        candidate_signature=signature
                        self.log('candidate_pool',source_sockets=len(self.udp),observed_count=len(peer.get('udp',[])),
                                 target_count=len(targets),targets=[list(t) for t in targets],
                                 message='服务器观察地址与附近猜测候选；同 IP 零步长不能推出跨 IP 不变')
                    if (targets or self.direct_path) and self.udp:
                        quantum_start=time.monotonic()
                        for batch_index in range(256 if self.unlimited_search and not self.direct_path else 1):
                            if self.stop.is_set() or (batch_index and time.monotonic()-quantum_start>=.004):break
                            if self.unlimited_search:now=time.monotonic()
                            if not targets:targets=[self.direct_path[1]]
                            s=self.udp[cursor%len(self.udp)];target=targets[(cursor//len(self.udp))%len(targets)];is_scan=False
                            active_role=role if role in ('anchor','scan','duplex') else None
                            if active_role:
                                choice=self.schedule.choice(active_role,self.coord.round,peer,len(self.udp),self.cfg.get('public_only',True))
                                if choice:
                                    slot,target,is_scan=choice;s=self.udp[slot]
                            lane='full_scan' if is_scan else 'fixed_target' if active_role else 'candidate_pool'
                            phased=bool(not cached_search and self.cfg.get('phased_search') and self.profile.get('search_phase_protocol')==(peer.get('profile') or {}).get('search_phase_protocol')==1)
                            if phased and not self.direct_path and active_role:
                                choice=phased_choice(self.coord,self.search,self.schedule,peer,len(self.udp),now,self.cfg.get('public_only',True))
                                if choice:
                                    slot,target,lane=choice;s=self.udp[slot];is_scan=lane=='full_scan'
                                    if self.coord.phase in ('nearby','range'):active_role=None
                            elif self.cfg.get('nearby_priority',False) and not phased and not self.direct_path:
                                choice=self.search.choice(peer,len(self.udp),now,self.cfg.get('public_only',True))
                                if choice:
                                    slot,target,lane=choice;s=self.udp[slot];is_scan=False;active_role=None
                            if self.cfg.get('fast_center_search',False) and not self.direct_path and self.fast_lane_tick%5!=4:
                                choice=self.fast_search.protected_choice(peer,len(self.udp),role,now,self.cfg.get('public_only',True)) if self.protection_offer or self.unlimited_search else self.fast_search.choice(peer,len(self.udp),role,self.cfg.get('public_only',True))
                                if choice:slot,target,lane=choice;s=self.udp[slot];is_scan=False;active_role=None
                            if self.cfg.get('candidate_pool_priority',False) and not self.direct_path and now-self.budget.at>=self.budget.interval:
                                choice=self.priority.choice(peer,len(self.udp),now,self.cfg.get('public_only',True),targets)
                                if choice:slot,target,lane=choice;s=self.udp[slot];is_scan=False;active_role=None
                            if self.cfg.get('multi_exit_search') and not self.direct_path and not cached_search and role in ('anchor','scan','duplex') and self.fast_lane_tick%8==7:
                                choice=self.exit_explorer.choice(peer,len(self.udp),self.peer_hints(),self.cfg.get('public_only',True))
                                if choice:slot,target,lane,exit_ip,exit_reason=choice;s=self.udp[slot];is_scan=False;active_role=None
                            if cached_search and self.unlimited_search and not self.direct_path:
                                recovery=self.recovery_choice(peer)
                                if recovery:s,target=recovery;is_scan=False;active_role=None;lane='control_recovery_keepalive'
                            if self.direct_path:s,target=self.direct_path;is_scan=False;active_role=None;lane='direct_keepalive'
                            if (self.protection_offer or self.unlimited_search) and not self.direct_path and role not in ('anchor','scan','duplex'):
                                target=endpoint((peer.get('profile') or {}).get('source_zero_observer_endpoint'),self.cfg.get('public_only',True)) or endpoint(peer['udp'][0],self.cfg.get('public_only',True));s=self.udp[0];lane='coordination_keepalive';is_scan=False;active_role=None
                            due=now-last_direct_probe>=(.1 if self.unlimited_search and self.tail and (not self.native_proxy_verified or now-self.last_direct_ack>1) else .5) if self.direct_path else now-getattr(self,'last_recovery_probe',0)>=.5 if lane=='control_recovery_keepalive' else now-getattr(self,'last_sync_probe',0)>=.5 if lane=='coordination_keepalive' else now-self.budget.at>=self.budget.interval
                            if self.unlimited_search and not due:break
                            admitted=due and self.budget.admit((s.fileno(),target),now,authenticated=bool(self.direct_path))
                            if due and not admitted and lane in ('full_scan','nearby_matrix','observed_range','center_scan','fresh_center_scan','fast_anchor','priority_candidates','candidate_pool','fixed_target','coordination_keepalive'):
                                # Keep an existing path active when the new-target
                                # budget is full; never advance the scan for a denial.
                                prior_lane=lane
                                reason=self.budget.reason((s.fileno(),target),now) or 'budget_denied';self.search_stalls[reason]+=1
                                if now-self.last_budget_log>=3:
                                    self.last_budget_log=now;self.log('search_budget_stall',lane=lane,reason=reason,slot=self.udp.index(s),target=list(target),retained_cursor=True,active_targets=len(self.budget.targets),scan_position=self.schedule.position)
                                fallback=endpoint((peer.get('profile') or {}).get('source_zero_observer_endpoint'),self.cfg.get('public_only',True)) or endpoint(peer['udp'][0],self.cfg.get('public_only',True))
                                target=fallback;s=self.udp[0];is_scan=False;active_role=None
                                lane='scan_budget_keepalive' if prior_lane=='full_scan' else 'search_budget_keepalive'
                                admitted=bool(now-self.last_budget_keepalive>=.5 and target and self.budget.admit((s.fileno(),target),now))
                                if admitted:self.last_budget_keepalive=now
                            if admitted:
                                if self.trace_probe(s,target,peer,now,lane,candidate_cursor=cursor,
                                    schedule_tick=self.schedule.tick,schedule_source_slot=self.schedule.local_slot) is False:break
                                cursor+=1
                                self.lane_sent[lane]+=1
                                if lane=='coordination_keepalive':self.last_sync_probe=now
                                if lane=='priority_candidates':self.priority.sent()
                                if lane in ('exit_ip_nearby','exit_ip_full_scan'):self.exit_explorer.sent(lane,target[0])
                                self.coverage.sent(target[0],target[1],self.udp.index(s))
                                if lane=='control_recovery_keepalive':self.recovery_cursor+=1;self.last_recovery_probe=now
                                if not self.direct_path and lane!='control_recovery_keepalive':self.fast_lane_tick+=1
                                if lane in ('center_scan','fast_anchor','fresh_center_scan'):self.fast_search.sent(lane)
                                if self.cfg.get('nearby_priority',False) and not self.direct_path and lane!='control_recovery_keepalive':self.search.sent(lane)
                                visited_targets.add(target);visited_paths.add((s.fileno(),target))
                                self.stats['udp_unique_targets']=len(visited_targets);self.stats['udp_unique_socket_targets']=len(visited_paths)
                                if self.direct_path:last_direct_probe=now
                                if active_role:self.schedule.sent(active_role,is_scan)
                                self.stats['scan_packets_sent']=self.schedule.position
                    futures=[f for f in futures if not f.done()]
                    if listener:self.send_tcp_offer(peer,now)
                    if listener and not self.budget.pause and self.tcp_plan and not self.tcp_direct and now>=self.tcp_plan[2] and (outbound is None or outbound.done()) and len(futures)<2 and self.stats['tcp_attempts']<(128 if self.cfg.get('tcp_neighbor_candidates') else 20) and now>=self.tcp_active_disabled_until:
                        target,planned_peer,at,token=self.tcp_plan;self.tcp_plan=None
                        if now-at<=3 and planned_peer['id']==peer['id']:
                            self.tcp_coordinated_attempts+=1
                            outbound=self.tcp_executor.submit(self.tcp_task,target,peer,self.active_port,'udp_coordinated_simultaneous_open');futures.append(outbound);last_tcp=now
                    tcp_targets=[endpoint(p,self.cfg.get('public_only',True)) for p in peer.get('tcp',[])[:8]]
                    tcp_targets=[p for p in tcp_targets if p]
                    active_targets=[endpoint(p,self.cfg.get('public_only',True)) for p in peer.get('tcp_active',[])[:1]]
                    active_targets=[p for p in active_targets if p]
                    simultaneous=bool(self.cfg.get('tcp_simultaneous_enabled',True) and self.own_tcp_active and active_targets and now>=self.tcp_active_disabled_until and (not tcp_targets or self.stats['tcp_attempts']%3==2))
                    if simultaneous:tcp_targets=active_targets
                    if listener and now-last_coverage>=10:
                        self.log('tcp_coverage',own_listener_count=len(self.own_tcp),own_simultaneous_count=len(self.own_tcp_active),
                                 peer_listener_count=len(peer.get('tcp',[])),peer_simultaneous_count=len(active_targets),
                                 simultaneous_possible=bool(self.own_tcp_active and active_targets),message='仅报告实际可执行模式；缺少候选不能视为该模式已失败')
                        last_coverage=now
                    attempt_limit=(4 if not self.direct_path else 8) if self.cfg.get('tcp_udp_assist',False) else 20
                    if listener and not self.budget.pause and (not self.coexist.enabled or self.direct_path) and ready and tcp_targets and not self.tcp_direct and not self.tcp_plan and not self.tcp_offer and now-last_tcp>=1 and len(futures)<2 and (outbound is None or outbound.done()) and self.stats['tcp_attempts']<attempt_limit:
                        target=tcp_targets[self.stats['tcp_attempts']%len(tcp_targets)]
                        source_port=self.active_port if simultaneous else 0
                        outbound=self.tcp_executor.submit(self.tcp_task,target,peer,source_port,'simultaneous_open' if simultaneous else 'listener_connect');futures.append(outbound);last_tcp=now
                self.service_tail(path_peer,now)
                self.service_native_check(now)
                if self.native_verified and now-self.native_verified_at>30:self.native_verified=False;self.native_proxy_verified=False
                os_backpressure=any(now<at for at in self.udp_retry_at.values())
                for key,_ in selector.select(min(.01,self.combo_wait_until-now) if self.combo_wait_until>now and not self.direct_path else .001 if os_backpressure else .005 if cached_search and not self.direct_path else 0 if self.unlimited_search and search_allowed and not self.direct_path and self.coord.role in ('anchor','scan','duplex') else .001 if self.cfg.get('fast_center_search',False) and not self.direct_path else .005 if self.tail and self.tail.enabled else .01 if self.cfg.get('fast_start',False) else .05):
                    if key.data=='udp':
                        drain_start=time.monotonic()
                        for receive_index in range(128 if self.unlimited_search else 1):
                            if receive_index and time.monotonic()-drain_start>=.004:break
                            try:
                                data,source=key.fileobj.recvfrom(65535)
                                before=self.discovery.accepted
                                if self.egress and self.egress.receive(key.fileobj,data,source,time.monotonic()):
                                    self.trace_packet(key.fileobj,data,'rx',source,kind='egress_stun_reply',accepted=True);continue
                                for changed in self.discovery.receive(data,source,(measurement.host,measurement.base)):self.log('live_mapping',**changed)
                                self.stats['observer_udp_replies']+=self.discovery.accepted-before
                                if source!=(measurement.host,measurement.base):self.receive_udp(key.fileobj,data,source)
                                else:self.trace_packet(key.fileobj,data,'rx',source,kind='observer_reply',accepted=self.discovery.accepted>before)
                            except BlockingIOError:break
                            except ConnectionResetError:continue
                    elif key.data=='tail':self.tail.poll()
                    else:
                        try:s,source=listener.accept()
                        except BlockingIOError:continue
                        ips={p[0] for p in (peer or {}).get('tcp',[])}|{p[0] for p in (peer or {}).get('udp',[])}
                        if not peer or source[0] not in ips or len(futures)>=2:s.close();continue
                        with self.peer_lock:self.tcp_active.add(s)
                        futures.append(self.tcp_executor.submit(self.accepted_task,s,peer))
                if now-self.last_pending_prune>=.25:
                    self.pending={n:p for n,p in self.pending.items() if now-p[2]<5};self.last_pending_prune=now
                if now-last_status>=2:
                    self.log('status',**self.stats,udp_direct_verified=self.udp_direct,tcp_direct_verified=self.tcp_direct,
                             udp_direct_live=bool(self.direct_path),coordination_role=role_state[1] if role_state else 'waiting',scan_position=self.schedule.position,peer_ready=ready,own_candidate_count=len(self.own_udp),peer_candidate_count=len((peer or {}).get('udp',[])),
                             tail_native_verified=self.native_verified,tail_proxy_verified=self.native_proxy_verified,tail_health=dict(getattr(self,'native_health',{})),tail_transport=dict(self.tail.stats) if self.tail else {},tail_bridge_state=self.tail.snapshot() if self.tail else {},
                             combination_limit=self.combination_limit.snapshot(now),coverage_by_exit=self.coverage.snapshot(),verified_session_lease=self.peer_lease_active,probe_firewall=dict(self.probe_firewall_state),exit_observations=self.egress.snapshot(now) if self.egress else None,search_time_by_reason={k:round(v,2) for k,v in self.search_times.items()},search_pause_reason=self.search_clock_reason,actual_rates=self.actual_rates(now),room_members=self.room_members(now),unlimited_search=self.unlimited_search,peer_unlimited_search=bool(((peer or {}).get('profile') or {}).get('unlimited_search')),probe_rate_limit=self.budget.rate_limit,fast_center_position=self.fast_search.scan_position,
                             protection_policy=self.protection_policy,protection_state=self.connection_guard.reason if self.protection_offer else 'disabled',bifrost_coexistence=dict(self.coexist_state),mapping_pressure_count=len(self.budget.pressure.targets) if self.budget.pressure else None,
                             tcp_last_failure=getattr(self,'tcp_last_failure',None),
                             seconds_to_first_udp=round(self.first_udp_at-self.started_at,3) if self.first_udp_at else None,
                             effective_search_seconds_at_first_udp=self.first_udp_active_seconds,
                             seconds_to_first_native_tailscale=round(self.first_native_at-self.started_at,3) if self.first_native_at else None,
                             seconds_to_first_tail_usable=round(self.first_tail_usable_at-self.started_at,3) if self.first_tail_usable_at else None,
                             nearby_packets=self.search.nearby.cursor,range_packets=self.search.dense.position,search_phase=self.coord.phase,
                             lane_sent=dict(self.lane_sent),search_stalls=dict(self.search_stalls),udp_backpressure_lanes=dict(self.udp_backpressure_lanes),
                             last_confirmed_room_members=self.last_confirmed_room_members,control_soft_timeouts=self.control_soft_timeouts,tail_bridge_error=self.tail_bridge_error,control_connected=self.connected.is_set(),control_health=dict(self.control_health),cached_search=cached_search,candidate_age_seconds=round(now-self.cached_search_at,3) if cached_search else None,
                             peer_sync=self.peer_sync.snapshot() if self.peer_sync else None,initial_exchange_verified=self.exchange_verified,search_reason=self.search_clock_reason,wall_elapsed=int(self.wall_elapsed),phase='testing_cached' if cached_search else 'testing' if ready else 'paused' if clock.started is not None else 'waiting',elapsed=int(elapsed),wait_elapsed=int(now-clock.prepared_at));last_status=now
        except Exception as e:
            if not self.stop.is_set():self.finish_reason='runtime_error';self.log('error',message=str(e),traceback=__import__('traceback').format_exc())
        finally:
            if self.finish_reason=='active_duration_complete':
                with self.control_lock:ending_channel=self.control
                if ending_channel and hasattr(ending_channel,'flush'):ending_channel.flush(.5)
            self.stop.set()
            if self.peer_sync:self.peer_sync.close()
            if self.egress:self.egress.close()
            self.log('session_cleanup',message='停止发包，关闭房间连接与UDP接入，等待本轮后台任务退出')
            with self.control_lock:
                channel=self.control;self.control=None;self.connected.clear()
            if channel:
                try:channel.shutdown(socket.SHUT_RDWR)
                except OSError:pass
                channel.close()
            if control_thread:control_thread.join(2)
            if pulse_thread:pulse_thread.join(2)
            if self.coexist_thread:self.coexist_thread.join(2)
            if tcp_prepare_thread:tcp_prepare_thread.join(7)
            with self.peer_lock:
                active=list(self.tcp_active)
            for s in active:
                try:s.shutdown(socket.SHUT_RDWR)
                except OSError:pass
                s.close()
            if self.tcp_executor:self.tcp_executor.shutdown(wait=True,cancel_futures=True)
            selector.close()
            if self.tail:self.tail.close()
            if self.native_thread:self.native_thread.join()
            if self.peer_sync_firewall:self.peer_sync_firewall.close()
            if self.local_firewall:self.local_firewall.close()
            if self.tcp_firewall:self.tcp_firewall.close()
            if self.firewall:self.firewall.close()
            for s in self.udp:s.close()
            if self.tcp_listener:self.tcp_listener.close()
            self.log('finished',udp_direct_verified=self.udp_direct,tcp_direct_verified=self.tcp_direct,paired_test_started=self.paired_started,measurement_only=measure_only,finish_reason='measurement_complete' if measure_only else self.finish_reason,active_seconds=round(self.active_elapsed,2),
                     message='所有本次测量与双端探测已停止；原有 Tailscale 设置保持不变，本次接入已停止')
            self.journal.close()
