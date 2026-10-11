"""Full mesh orchestration around the unchanged, proven two-peer search."""
import collections,copy,hashlib,hmac,itertools,json,pathlib,secrets,threading,time,zipfile
from client import LabClient
from combinations import CombinationLimit
from coexistguard import application_guard
from meshcontrol import ControlMux
from meshplan import pair_key
from meshtail import TailManager
from net import physical
from tailbridge import is_admin,driver_check
from wire import room_keys,hexid

VERSION='1.2.0-mesh'

class PairClient(LabClient):
    def __init__(self,owner,peer,code,cfg):
        self.owner=owner;self.root_peer_id=peer['id'];self.peer_generation=peer['profile']['generation'];self.pair_token=hashlib.sha256(code.encode()).hexdigest()[:32]
        self.peer_tail_ip=peer['profile'].get('tail',{}).get('tail_ip','');self.proof_saved=False;self.new_probe_times=collections.deque()
        self.guard_candidates=collections.OrderedDict();self.guard_retry_cursor=0;self.last_guard_retry=0.;self.guard_denial=None
        ident=hashlib.sha256((code+owner.id).encode()).hexdigest()[:32]
        resume=hashlib.sha256((code+owner.session).encode()).hexdigest()[:32]
        cfg={**cfg,'peer_tail_ip':self.peer_tail_ip,'_dense_allowed':self.dense_allowed,'_control_factory':owner.mux.channel,
             '_metadata_reader':owner.tail.read_metadata if owner.tail else None,'peer_sync_overlay':False,'tail_metadata_only':False,
             'production_mode':True,'run_continuously':True,'wait_unlimited':True,'journal_optional':True,'journal_segment_bytes':4*1024*1024,'journal_segments':4,
             'packet_journal_dir':str(owner.directory/'pairs'/self.pair_token) if owner.directory else None}
        if owner.tail:cfg['_capture_factory']=lambda port,endpoints:owner.tail.hub.subscribe(self.pair_token,port,endpoints)
        super().__init__(cfg,code,owner.name,emit=self.on_event,member_id=ident,resume=resume,run_number=owner.run_number)
        # Successful new combinations share one atomic rolling window per host.
        self.combination_limit=owner.combinations;self.logs=collections.deque(maxlen=3000)
        if self.journal.error:self.log('evidence_disk_error',message='报文日志不可写，继续网络运行：'+self.journal.error)
    def dense_allowed(self):return self.owner.dense_allowed(self.root_peer_id,self.peer_generation)
    def on_event(self,event):
        if event.get('event')=='status':self.owner.pair_status[self.root_peer_id]=event
        elif event.get('event') not in ('control_frame_received','live_mapping','socket_mapping_snapshot','search_budget_stall'):
            self.owner.log('pair_event',peer_id=self.root_peer_id,peer_name=self.owner.peers.get(self.root_peer_id,{}).get('name',''),pair_id=self.pair_token,pair_event=event)
    def trace_packet(self,*args,**fields):
        fields.update(mesh_pair_id=self.pair_token,mesh_task_id=self.owner.task_id(self.root_peer_id),root_peer_id=self.root_peer_id)
        return super().trace_packet(*args,**fields)
    def trace_probe(self,s,target,peer,now,lane,**fields):
        with self.combination_limit.lock:
            before=self.combination_limit.total;result=super().trace_probe(s,target,peer,now,lane,**fields)
            if result and self.owner.coexist_guard:
                self.guard_candidates[(s,target)]=now;self.guard_candidates.move_to_end((s,target))
                while len(self.guard_candidates)>128:self.guard_candidates.popitem(last=False)
            elif (self.owner.coexist_guard and not self.direct_path and self.guard_denial and
                self.guard_denial[:3]==(s,target,now) and self.guard_denial[3] in
                ('mapping_footprint_budget','mapping_burst_budget','health_new_pause')):
                self.retry_guard_candidates(peer,now)
            if self.combination_limit.total>before:
                self.new_probe_times.append(now);self.owner.new_probe_times.append(now)
            return result
    def retry_guard_candidates(self,peer,now):
        # Retain the NEW candidate cursor. Recheck only a bounded existing set
        # so most other mappings can stop being refreshed and age out.
        if now-self.last_guard_retry<.05:return False
        guard=self.owner.coexist_guard;ips=self.peer_ips(peer)
        with guard.lock:
            guard._expire(now)
            candidates=[(sock,ep) for sock,ep in self.guard_candidates if sock.fileno()>=0 and ep[0] in ips and
                (sock.getsockname()[1],ep[0],ep[1]) in guard.touched]
        if not candidates:return False
        sock,ep=candidates[self.guard_retry_cursor%len(candidates)]
        if super().trace_probe(sock,ep,peer,now,'coexist_existing_candidate_retry',new_scan_cursor_retained=True):
            self.guard_retry_cursor+=1;self.last_guard_retry=now
            self.stats['coexist_candidate_retries']=self.stats.get('coexist_candidate_retries',0)+1
            self.lane_sent['coexist_existing_candidate_retry']+=1
            return True
        return False
    def send_udp(self,s,data,target,now,lane):
        guard=self.owner.coexist_guard
        if not guard:return super().send_udp(s,data,target,now,lane)
        priority=lane in ('authenticated_reply','received_path_challenge','live_observer','measurement_observer','tail_cipher','tcp_offer') or bool(self.direct_path and s is self.direct_path[0] and target==self.direct_path[1])
        with guard.lock:
            allowed,delay,reason=guard.permit(s.getsockname()[1],target,now,priority)
            if not allowed:
                self.guard_denial=(s,target,now,reason)
                self.combo_wait_until=max(self.combo_wait_until,now+delay)
                return False
            success=super().send_udp(s,data,target,now,lane)
            if success:guard.commit(s.getsockname()[1],target,time.monotonic(),priority)
            return success
    def actual_rates(self,now=None):
        now=time.monotonic() if now is None else now;result=super().actual_rates(now)
        with self.combination_limit.lock:
            while self.new_probe_times and now-self.new_probe_times[0]>=10:self.new_probe_times.popleft()
            result['new_udp_combinations_pps']=round(len(self.new_probe_times)/max(1,min(10,now-self.started_at)),2)
        return result
    def summary(self):
        result=super().summary();peer=self.peer or {};remote=peer.get('profile') or {};exchange=remote.get('initial_exchange') or {}
        result['mesh_gate_evidence']={'prepared':self.prepared,'peer_prepared':peer.get('prepared'),'peer_candidates':len(peer.get('udp',[])),
            'remote_exchange_present':bool(exchange),'remote_ack_matches':exchange.get('ack')==self.exchange_token,
            'remote_ack_session_matches':exchange.get('peer_session')==self.data_session,
            'control_age_seconds':round(time.monotonic()-self.last_snapshot,2) if self.last_snapshot else None,
            'task_state':(self.owner.tasks.get(self.root_peer_id) or {}).get('state'),'coexist_guard_enabled':bool(self.owner.coexist_guard)}
        result['mesh_gate_evidence']['scheduling']=self.owner.scheduling_state(self.root_peer_id,self.peer_generation)
        return result
    def service_native_check(self,now):
        if not self.tail or not self.owner.tail or self.stop.is_set():return
        manager=self.owner.tail;manager.register_proxy(self.peer_tail_ip,self.tail)
        h=manager.route_health(self.peer_tail_ip);self.native_verified=bool(h.get('native_verified'));self.native_proxy_verified=bool(h.get('proxy_verified') and self.direct_path)
        self.native_health={**h,'route':'native_reported_direct' if h.get('route') in ('ipv4','ipv6') else h.get('route','unknown'),'native_route':h.get('route'),'proxy_verified':self.native_proxy_verified}
        if self.native_verified:
            self.native_verified_at=now
            if self.first_tail_usable_at is None:self.first_tail_usable_at=now
            if h.get('route') in ('ipv4','ipv6','natpair_proxy') and self.first_native_at is None:self.first_native_at=now
        if now-getattr(self,'last_shared_metadata',0)>2:
            self.last_shared_metadata=now
            try:
                metadata=manager.read_metadata(self.peer_tail_ip)
                if self.tail.refresh(metadata):
                    if self.local_firewall:self.local_firewall.update(metadata['udp_port'])
                    self.profile['tailscale']=metadata;self.publish_profile()
            except (OSError,RuntimeError,ValueError) as exc:self.tail_bridge_error=str(exc)
    def run(self,measure_only=False):
        try:super().run(measure_only)
        finally:
            if self.owner.tail and self.tail:self.owner.tail.unregister_proxy(self.peer_tail_ip,self.tail)

class MultiClient:
    def __init__(self,cfg,code,name,emit=lambda e:None,member_id=None,resume=None,run_number=0):
        self.cfg=dict(cfg);self.code=code;self.room,self.key=room_keys(code);self.id=member_id or secrets.token_hex(16);self.session=resume or secrets.token_hex(16);self.run_number=run_number
        self.name=name.strip();self.emit=emit
        if not 1<=len(self.name)<=32:raise ValueError('昵称需要 1–32 字符')
        self.topology=self.cfg.get('mesh_topology','full_mesh');self.role=self.cfg.get('mesh_role','player');self.game_port=int(self.cfg.get('mc_game_port',25565))
        if self.topology not in ('full_mesh','star') or self.role not in ('host','player') or not 1<=self.game_port<=65535:raise ValueError('房间模式、角色或游戏端口无效')
        self.generation=secrets.token_hex(16);self.stop=threading.Event();self.lock=threading.RLock();self.logs=collections.deque(maxlen=5000)
        self.started_at=time.monotonic();self.peers={};self.tasks={};self.pairs={};self.pair_status={};self.retired=[];self.pair_history=collections.deque(maxlen=56);self.mesh={};self.last_snapshot=0;self.connected=False
        self.control=None;self.mux=None;self.tail=None;self.thread=None;self.combinations=CombinationLimit(self.cfg.get('new_combinations_per_second'));self.new_probe_times=collections.deque();self.prepared_tasks=[];self.retry_at={};self.pair_waits={}
        self.coexist_guard=application_guard(self.cfg) if self.cfg.get('mesh_coexist_guard') else None
        base=self.cfg.get('packet_journal_dir');self.directory=pathlib.Path(base)/('mesh-'+time.strftime('%Y%m%d-%H%M%S')+'-'+self.generation[:8]) if base else None
        if self.directory:
            try:self.directory.mkdir(parents=True,exist_ok=False)
            except OSError as exc:self.directory=None;self.log('evidence_disk_error',message='日志目录不可写，网络继续运行：'+str(exc))
    def log(self,event,**fields):
        obj={'time':time.strftime('%Y-%m-%d %H:%M:%S'),'event':event,**fields}
        with self.lock:self.logs.append(obj)
        self.emit(obj)
    def pair_code(self,peer):
        records=sorted([(self.id,self.generation),(peer['id'],peer['profile']['generation'])])
        return hmac.digest(self.key,b'NATPair-mesh-pair-v1\0'+json.dumps(records,separators=(',',':')).encode(),'sha256').hex()
    def task_id(self,peer_id):return (self.tasks.get(peer_id) or {}).get('id')
    def business_pending(self):
        with self.lock:engines=[p['client'] for p in self.pairs.values()]
        return any(c.direct_path and c.tail and c.tail.enabled and (c.tail_frames or not c.tail.outbound.empty()) for c in engines)
    def dense_allowed(self,peer_id,generation):
        if not self.related_peer(peer_id):return False
        task=self.tasks.get(peer_id)
        if not task or task.get('state')!='go' or task.get('generations',{}).get(peer_id)!=generation or time.monotonic()>task.get('local_until',0):return False
        if self.native_direct(peer_id):return False
        return not self.business_pending()
    def related_peer(self,peer_id):
        return self.topology!='star' or self.mesh.get('host_id') in (self.id,peer_id)
    def scheduling_state(self,peer_id,generation):
        now=time.monotonic();task=self.tasks.get(peer_id)
        if not self.last_snapshot or now-self.last_snapshot>=8:return '等待新鲜的房间调度回复'
        if self.mesh.get('fresh_members') is not None and peer_id not in self.mesh['fresh_members']:return '等待对方恢复房间心跳'
        if not task:return '等待协调服务分配本对轮次'
        if task.get('generations',{}).get(peer_id)!=generation:return '等待本轮信息对齐'
        if now>=task.get('local_until',0):return '等待当前探测任务续期'
        if task.get('state')!='go':return '双方准备／交换本轮信息'
        if self.business_pending():return '业务传输优先，探测让行'
        return '正在打洞'
    def native_direct(self,peer_id):
        peer=self.peers.get(peer_id);target=(peer or {}).get('profile',{}).get('tail',{}).get('tail_ip')
        h=self.tail.route_health(target) if self.tail and target else {}
        return h.get('native_verified') and h.get('route') in ('ipv4','ipv6')
    def link_report(self,peer_id,peer):
        item=self.pairs.get(peer_id);c=item['client'] if item else None;target=peer['profile'].get('tail',{}).get('tail_ip')
        health=self.tail.route_health(target) if self.tail and target else {}
        return {'peer_generation':peer['profile']['generation'],'udp_live':bool(c and not c.stop.is_set() and c.direct_path and c.direct_path[0].fileno()>=0 and time.monotonic()-c.last_direct_ack<8),
                'native_verified':bool(health.get('native_verified')),'native_route':health.get('route'),'proxy_verified':bool(health.get('proxy_verified'))}
    def publish(self):
        with self.lock:peers=dict(self.peers);pairs=dict(self.pairs)
        prepared=[]
        for peer_id,task in self.tasks.items():
            c=(pairs.get(peer_id) or {}).get('client')
            if c and c.prepared and c.exchange_verified and c.peer and c.peer.get('prepared'):prepared.append(task['id'])
        own=self.tail.own if self.tail else {}
        profile={'generation':self.generation,'client_build':VERSION,'tail':dict(own),'bridge':bool(self.cfg.get('tailscale_bridge')),
                 'topology':self.topology,'role':self.role,'game_port':self.game_port,
                 'links':{i:self.link_report(i,p) for i,p in peers.items()},'prepared_tasks':prepared}
        self.control.sendall(json.dumps({'k':'profile','profile':profile,'prepared':True}).encode()+b'\n')
    def start_pair(self,peer):
        if not self.related_peer(peer['id']):return
        if len(self.pairs)>=7:return
        p=peer['profile'];bridge=bool(self.cfg.get('tailscale_bridge') and p.get('bridge'))
        cfg={**self.cfg,'tailscale_bridge':bridge,'tail_tcp_check':False,'bind':self.bind,'if_index':self.index}
        if bridge:
            target=p.get('tail',{}).get('tail_ip');reported=p.get('tail',{}).get('node_key')
            if not target or not reported:return self.wait_pair(peer,'等待对方公布 Tailscale 地址和节点身份')
            if not self.tail:return self.wait_pair(peer,'等待本机 Tailscale 身份读取')
            health=self.tail.route_health(target)
            if health.get('native_verified') and health.get('route') in ('ipv4','ipv6'):return
            try:meta=self.tail.read_metadata(target)
            except RuntimeError as exc:return self.wait_pair(peer,str(exc))
            if not health.get('checked_at') and not health.get('last_attempt'):return self.wait_pair(peer,'正在核实原生路径；随后启动辅助 UDP')
            if meta['expected_peer_key']!=reported:
                return self.wait_pair(peer,'房间报告与 Tailscale 当前节点身份尚未对齐，等待刷新')
        c=PairClient(self,peer,self.pair_code(peer),cfg)
        thread=threading.Thread(target=c.run,name='NATPair-pair-'+peer['id'][:8],daemon=True)
        with self.lock:self.pairs[peer['id']]={'client':c,'thread':thread,'generation':p['generation'],'joined_at':time.monotonic()}
        self.pair_waits.pop(peer['id'],None)
        thread.start();self.log('pair_started',peer_id=peer['id'],peer_name=peer['name'],pair_id=c.pair_token,tailscale_bridge=bridge)
    def wait_pair(self,peer,message):
        previous=self.pair_waits.get(peer['id']);self.pair_waits[peer['id']]={'message':message,'generation':peer['profile']['generation']}
        if previous!=self.pair_waits[peer['id']]:self.log('peer_identity_wait',peer_id=peer['id'],peer_name=peer['name'],message=message)
    def retire_pair(self,peer_id,reason='peer_left_or_generation_changed'):
        with self.lock:
            item=self.pairs.pop(peer_id,None)
            if item:
                item['peer_id']=peer_id;item['retire_reason']=reason;self.retired.append(item)
        if item:
            item['client'].stop.set();self.pair_status.pop(peer_id,None)
            self.log('pair_retired',peer_id=peer_id,reason=reason,message='仅清理该成员对；其他通道保持运行')
    def collect_retired(self):
        # Summarize only after the engine has completed cleanup. Keep bounded
        # memory, and preserve the outcome on disk even when the member left.
        with self.lock:items=list(self.retired)
        for item in items:
            if item['thread'].is_alive():continue
            c=item['client'];summary=c.summary()
            selected={'udp_direct_verified','udp_path_revalidated','tail_actual_path','error','finished','control_lost','control_retry'}
            record={'peer_id':item['peer_id'],'peer_generation':item['generation'],'pair_id':c.pair_token,
                    'reason':item['retire_reason'],'child_id':c.id,'result':summary['result'],
                    'events':[e for e in summary['events'] if e['event'] in selected][-64:]}
            with self.lock:
                if not any(value is item for value in self.retired):continue
                self.retired=[value for value in self.retired if value is not item];self.pair_history.append(record)
            if self.directory:
                try:(self.directory/('retired-pair-'+c.pair_token+'.json')).write_text(json.dumps(record,ensure_ascii=False,indent=2),encoding='utf8')
                except OSError as exc:self.log('evidence_disk_error',message=str(exc))
    def accept(self,obj):
        mesh=obj.get('mesh')
        if not isinstance(mesh,dict) or mesh.get('protocol')!=1:raise ValueError('当前协调服务不支持多人版，请使用完整新版配置')
        if self.topology=='star' and mesh.get('topology')!='star':raise ValueError('协调服务不支持 MC 星形模式，请使用新版完整配置')
        live=set(mesh['members']);peers={p['id']:p for p in obj.get('peers',[]) if p.get('id') in live and hexid((p.get('profile') or {}).get('generation'))}
        # A missing/stale coordinator record does not prove that a verified
        # peer tunnel died. Only an exact-generation explicit leave, a new
        # generation, or failed authenticated maintenance retires that edge.
        departures=mesh.get('departures',{})
        for ident,old_peer in self.peers.items():
            if ident in peers:continue
            item=self.pairs.get(ident);c=item['client'] if item else None
            exited=(departures.get(ident) or {}).get('generation')==old_peer['profile']['generation']
            healthy=bool(c and not c.stop.is_set() and c.direct_path and time.monotonic()-c.last_direct_ack<8) or self.native_direct(ident)
            if healthy and not exited:peers[ident]={**old_peer,'coordinator_stale':True}
        now=time.monotonic()
        with self.lock:
            old=self.peers;self.peers=peers;self.mesh=mesh;self.last_snapshot=now;self.connected=True
        for ident,item in list(self.pairs.items()):
            if ident not in peers or item['generation']!=peers[ident]['profile']['generation'] or not self.related_peer(ident):
                reason='explicit_leave' if (departures.get(ident) or {}).get('generation')==item['generation'] else 'new_generation' if ident in peers else 'peer_missing_and_path_not_live'
                self.retire_pair(ident,reason)
        tasks={}
        for task in mesh.get('tasks',[]):
            if self.id not in task.get('members',[]) or task['generations'].get(self.id)!=self.generation:continue
            peer_id=next((i for i in task['members'] if i!=self.id),None)
            if peer_id not in peers or task['generations'].get(peer_id)!=peers[peer_id]['profile']['generation']:continue
            if not self.related_peer(peer_id):continue
            tasks[peer_id]={**task,'local_until':now+max(0,float(task['remaining_seconds']))}
        self.tasks=tasks
        if self.tail:self.tail.set_targets({p['profile'].get('tail',{}).get('tail_ip'):i for i,p in peers.items() if self.related_peer(i) and p['profile'].get('tail',{}).get('tail_ip')})
        if set(old)!=set(peers):self.log('members_changed',room_members=len(live),peer_names=[p['name'] for p in peers.values()])
    def maintain(self):
        now=time.monotonic()
        for peer_id,task in list(self.tasks.items()):
            if peer_id in self.pairs or self.native_direct(peer_id) or now<self.retry_at.get(peer_id,0):continue
            peer=self.peers.get(peer_id)
            if peer:
                try:self.start_pair(peer)
                except (OSError,RuntimeError,ValueError) as exc:self.log('pair_start_error',peer_id=peer_id,message=str(exc));self.retry_at[peer_id]=now+3
        for peer_id,item in list(self.pairs.items()):
            c=item['client']
            if not item['thread'].is_alive():
                self.retire_pair(peer_id,'engine_finished');self.retry_at[peer_id]=now+3;continue
            if c.first_udp_at and not c.proof_saved:
                c.proof_saved=True
                proof={'version':VERSION,'pair_id':c.pair_token,'mesh_task_id':self.task_id(peer_id),'member_id':self.id,'peer_id':peer_id,
                       'peer_name':self.peers.get(peer_id,{}).get('name'),'peer_generation':c.peer_generation,
                       'seconds_to_first_udp':round(c.first_udp_at-c.started_at,3),'effective_seconds_to_first_udp':c.first_udp_active_seconds,
                       'first_hit_proof':c.journal.proof_path,'probe_tx':c.stats['udp_probe_tx'],'probe_rx':c.stats['udp_probe_rx']}
                self.log('pair_first_success',**proof)
                if self.directory:
                    try:(self.directory/('first-success-'+c.pair_token+'.json')).write_text(json.dumps(proof,ensure_ascii=False,indent=2),encoding='utf8')
                    except OSError as exc:self.log('evidence_disk_error',message=str(exc))
        # Keep no stopped engines after their cleanup. Evidence stays on disk.
        self.collect_retired()
    def rows(self):
        rows=[]
        for ident,peer in self.peers.items():
            item=self.pairs.get(ident);c=item['client'] if item else None;link=self.link_report(ident,peer);task=self.tasks.get(ident)
            route=link.get('native_route');verified=link['native_verified'];live=link['udp_live']
            if self.stop.is_set():state='已停止（本轮曾验证 UDP）' if c and c.udp_direct else '已停止'
            elif verified and route=='ipv6':state='原生 IPv6 直连 · 跳过辅助'
            elif verified and route=='ipv4':state='原生 IPv4 直连 · 跳过辅助'
            elif not self.related_peer(ident):state='其他玩家 · 无需辅助互连' if self.mesh.get('host_id') else '等待房主加入 · 暂不探测'
            elif live and link['proxy_verified']:state='NATPair UDP 直连 · Tailscale 已验证'
            elif live:
                if not c or not c.tail:state='UDP 已验证'
                elif verified and route=='derp':state='UDP 已验证 · Tailscale 经 DERP，代理待选用'
                elif verified:state='UDP 已验证 · Tailscale 已可用，代理路径核实中'
                else:state='UDP 已验证 · 等待 Tailscale 数据确认'
            else:
                state=self.scheduling_state(ident,peer['profile']['generation'])
                if state=='正在打洞' and self.coexist_guard:
                    g=self.coexist_guard.snapshot()
                    if g['current_pressure']:state=f'复测已有候选 · 新增预算约 {g["new_budget_wait_seconds"]:.0f} 秒后重试'
                if verified and route=='derp':state+='；Tailscale DERP 可用'
            wait=self.pair_waits.get(ident)
            if not item and wait and wait['generation']==peer['profile']['generation'] and not (verified and route in ('ipv4','ipv6')):state=wait['message']
            rates=c.actual_rates() if c else {};stats=c.stats if c else {};elapsed=round(time.monotonic()-item['joined_at'],1) if item else 0
            if peer.get('coordinator_stale'):state+=' · 房间信息同步延迟'
            rows.append({'id':ident,'name':peer['name'],'tail_ip':peer['profile'].get('tail',{}).get('tail_ip',''),'state':state,
                         'native_route':route,'native_verified':verified,'udp_live':live,'tail_proxy_verified':link['proxy_verified'],
                         'probe_tx':stats.get('udp_probe_tx',0),'probe_rx':stats.get('udp_probe_rx',0),'probe_pps':rates.get('peer_probe_tx_pps',0),
                         'new_pps':rates.get('new_udp_combinations_pps',0),'elapsed_seconds':elapsed,'effective_seconds':round(c.active_elapsed,1) if c else 0,
                         'first_udp_seconds':round(c.first_udp_at-c.started_at,3) if c and c.first_udp_at else None,
                         'room_seconds_to_first_udp':round(c.first_udp_at-self.started_at,3) if c and c.first_udp_at else None,
                         'outer_endpoint':list(c.direct_path[1]) if c and c.direct_path else None,'tail_error':c.tail_bridge_error if c else None})
        return rows
    def status(self):
        now=time.monotonic()
        with self.combinations.lock:
            while self.new_probe_times and now-self.new_probe_times[0]>=10:self.new_probe_times.popleft()
            new_pps=round(len(self.new_probe_times)/max(1,min(10,now-self.started_at)),2)
        rows=self.rows()
        return {'version':VERSION,'running':not self.stop.is_set(),'room_members':len(self.mesh.get('members',[])) if self.connected else None,
                'possible_pairs':self.mesh.get('possible_pairs',0),'completed_pairs':self.mesh.get('completed_pairs',0),'rows':rows,
                'actual_probe_packets_pps':round(sum(r['probe_pps'] for r in rows),2),
                'elapsed_seconds':round(time.monotonic()-self.started_at,1),'coordination_age_seconds':round(time.monotonic()-self.last_snapshot,2) if self.last_snapshot else None,
                'combination_limit':self.combinations.snapshot(now),'actual_new_probe_combinations_pps':new_pps,'shared_control':self.mux.snapshot() if self.mux else None,
                'coexist_guard':self.coexist_guard.snapshot(now) if self.coexist_guard else {'enabled':False},
                'topology':self.topology,'role':self.role,'mc_host_id':self.mesh.get('host_id'),
                'mc_host_name':self.mesh.get('host_name',''),'mc_host_tail_ip':self.mesh.get('host_tail_ip',''),
                'mc_game_port':self.mesh.get('game_port'),
                'mc_connect_address':str(self.mesh['host_tail_ip'])+':'+str(self.mesh['game_port']) if self.topology=='star' and self.mesh.get('host_tail_ip') and self.mesh.get('game_port') else '',
                'shared_capture':self.tail.hub.snapshot() if self.tail else None,'tail_manager_error':self.tail.error if self.tail else None,
                'tail_manager':self.tail.snapshot() if self.tail and hasattr(self.tail,'snapshot') else {'own':dict(self.tail.own)} if self.tail else None,
                'waiting_alone':len(self.mesh.get('members',[]))==1,'active_dense_peers':[i for i in self.tasks if self.dense_allowed(i,self.tasks[i]['generations'][i])]}
    def summary(self):
        # A probe holds the shared combination lock and may emit a root event.
        # Never hold the root event lock while waiting on a child/rate lock.
        with self.lock:pairs=dict(self.pairs);history=list(self.pair_history);events=list(self.logs)
        return {'version':VERSION,'name':self.name,'member_id':self.id,'generation':self.generation,'mesh_snapshot':copy.deepcopy(self.mesh),'result':self.status(),
            'pairs':{i:item['client'].summary() for i,item in pairs.items()},'pair_history':history,'events':events}
    def run(self,measure_only=False):
        last_status=last_publish=0
        try:
            self.bind,self.index=(self.cfg['bind'],int(self.cfg.get('if_index',0))) if self.cfg.get('bind') else physical()
            if self.cfg.get('tailscale_bridge'):
                if not is_admin():raise RuntimeError('Tailscale 接入请以管理员身份运行；纯 UDP 多人测试不要求接入驱动')
                self.log('driver_checked',**driver_check())
            if self.cfg.get('tailscale_bridge') or self.cfg.get('tail_metadata_only'):
                self.tail=TailManager(self.stop,lambda event,**kw:self.log(event,**kw),bool(self.cfg.get('tailscale_bridge')));self.tail.start()
            self.mux=ControlMux(self.cfg,self.bind,self.index,self.stop,lambda event,**kw:self.log(event,**kw));self.control=self.mux.channel()
            self.control.sendall(json.dumps({'access':self.cfg['access'],'room':self.room,'id':self.id,'name':self.name,'resume':self.session,'run':self.run_number,'version':VERSION,'multi_protocol':1,
                'topology':self.topology,'role':self.role,'game_port':self.game_port}).encode()+b'\n')
            self.publish();self.log('mesh_started',max_members=8,topology=self.topology,role=self.role,game_port=self.game_port,new_combinations_per_second=self.combinations.limit,
                message='MC 星形房间；仅房主与玩家配对，等待房主时不扫描。' if self.topology=='star' else '全员互连；已通成员对继续传输，每台电脑同时集中探测一对。房间只有一人时持续等待。')
            while not self.stop.is_set():
                try:
                    obj=json.loads(self.control.readline(self.stop,timeout=.1))
                    if obj.get('error'):raise ValueError(str(obj['error']))
                    if obj.get('k')=='peers':self.accept(obj)
                except TimeoutError:pass
                now=time.monotonic();self.maintain()
                if self.coexist_guard:self.coexist_guard.poll(now)
                if now-last_publish>=.4:self.publish();last_publish=now
                if now-last_status>=1:self.log('mesh_status',**self.status());last_status=now
                if self.cfg.get('mesh_test_duration') and now-self.started_at>=float(self.cfg['mesh_test_duration']):break
        except Exception as exc:
            if not self.stop.is_set():self.log('error',message=str(exc),traceback=__import__('traceback').format_exc())
        finally:
            self.stop.set()
            all_items=list(self.pairs.values())+self.retired
            for item in all_items:item['client'].stop.set()
            while any(item['thread'].is_alive() for item in all_items):
                for item in all_items:item['thread'].join(.1)
            self.collect_retired()
            if self.tail:self.tail.close()
            if self.control:self.control.close()
            if self.mux:self.mux.close()
            if self.directory:
                try:(self.directory/'mesh-summary.json').write_text(json.dumps(self.summary(),ensure_ascii=False,indent=2),encoding='utf8')
                except OSError as exc:self.log('evidence_disk_error',message=str(exc))
            self.log('mesh_finished',message='本轮房间、成员对和共享接入资源已停止')

def export_mesh(client,path):
    path=pathlib.Path(path);summary=client.summary()
    if path.suffix.lower()!='.zip':path.write_text(json.dumps(summary,ensure_ascii=False,indent=2),encoding='utf8');return
    with zipfile.ZipFile(path,'w',zipfile.ZIP_DEFLATED) as out:
        out.writestr('summary.json',json.dumps(summary,ensure_ascii=False,indent=2))
        if client.directory:
            # Never compress while holding a packet writer or socket lock.
            total=0
            for file in client.directory.rglob('*'):
                if not file.is_file() or file.suffix not in ('.json','.jsonl'):continue
                try:
                    size=file.stat().st_size;total+=size
                    if total>512*1024*1024:break
                    out.write(file,'evidence/'+file.relative_to(client.directory).as_posix())
                except OSError:continue
