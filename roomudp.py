"""Independent encrypted room snapshots: no ordered TLS stream to rebuild."""
import collections,hashlib,hmac,json,secrets,select,socket,struct,threading,time,zlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag
HEADER=struct.Struct('!4s16sQHH');MAGIC=b'NPR2';CHUNK=900;MAX_PARTS=48

class Codec:
    def __init__(self,access,server=False):
        self.root=bytes.fromhex(access);self.server=server;self.parts={}
    def key(self,sid,reply):
        return hmac.digest(self.root,b'NATPair-room-snapshot-v2\0'+sid+bytes([reply]),'sha256')
    def encode(self,sid,seq,obj,compress=False):
        raw=json.dumps(obj,separators=(',',':')).encode()
        if len(raw)>MAX_PARTS*CHUNK:raise ValueError('room_snapshot_too_large')
        if compress:
            packed=b'\0Z1'+zlib.compress(raw,3)
            if len(packed)<len(raw):raw=packed
        count=(len(raw)+CHUNK-1)//CHUNK
        if not 1<=count<=MAX_PARTS:raise ValueError('room_snapshot_too_large')
        aes=AESGCM(self.key(sid,self.server));packets=[]
        for i in range(count):
            header=HEADER.pack(MAGIC,sid,seq,i,count);nonce=secrets.token_bytes(12)
            packets.append(header+nonce+aes.encrypt(nonce,raw[i*CHUNK:(i+1)*CHUNK],header))
        return packets
    def decode(self,data,origin):
        if not HEADER.size+28<len(data)<=HEADER.size+28+CHUNK:return None
        magic,sid,seq,i,count=HEADER.unpack(data[:HEADER.size])
        if magic!=MAGIC or not 0<seq<2**63 or not 1<=count<=MAX_PARTS or i>=count:return None
        try:raw=AESGCM(self.key(sid,not self.server)).decrypt(data[HEADER.size:HEADER.size+12],data[HEADER.size+12:],data[:HEADER.size])
        except InvalidTag:return None
        now=time.monotonic();self.parts={k:v for k,v in self.parts.items() if now-v[0]<3}
        key=(origin,sid,seq)
        if key not in self.parts and len(self.parts)>=128:return None
        entry=self.parts.setdefault(key,(now,count,{}))
        if entry[1]!=count:return None
        entry[2][i]=raw
        if len(entry[2])!=count:return None
        self.parts.pop(key,None)
        try:
            raw=b''.join(entry[2][n] for n in range(count))
            if raw.startswith(b'\0Z1'):
                decoder=zlib.decompressobj();raw=decoder.decompress(raw[3:],MAX_PARTS*CHUNK+1)
                if len(raw)>MAX_PARTS*CHUNK or decoder.unconsumed_tail or decoder.unused_data or not decoder.eof:return None
            obj=json.loads(raw)
        except (ValueError,UnicodeDecodeError,zlib.error):return None
        return (sid,seq,obj) if isinstance(obj,dict) else None

class DatagramControl:
    def __init__(self,cfg,bind,index):
        self.cfg=cfg;self.address=(cfg.get('control_tail_host') or cfg['host'],int(cfg['room_udp_port']))
        self.addresses=list(dict.fromkeys([self.address,(cfg['host'],int(cfg['room_udp_port']))]));self.active_address=None
        from net import raw_socket
        self.socket=socket.socket(socket.AF_INET,socket.SOCK_DGRAM) if cfg.get('control_tail_host') else raw_socket(socket.SOCK_DGRAM,bind,index)
        if cfg.get('control_tail_host'):self.socket.bind(('0.0.0.0',0))
        self.socket.setblocking(False);self.codec=Codec(cfg['access']);self.sid=secrets.token_bytes(16)
        self.lock=threading.Lock();self.state={};self.closed=False;self.sequence=0;self.last_received=0
        self.last_send=0.;self.ticket=None;self.lines=collections.deque();self.notices=[]
        self.stats={'tx_frames':0,'rx_frames':0,'tx_bytes':0,'rx_bytes':0,'queue_peak':1,'wire_tx':0,'wire_rx':0,'compressed_snapshots':0,'last_tx_parts':0,'incomplete_sequences':0}
        try:self.socket.setsockopt(socket.SOL_SOCKET,socket.SO_RCVBUF,1024*1024)
        except OSError:pass
    def sendall(self,data):
        obj=json.loads(data);kind=obj.get('k')
        with self.lock:
            if self.closed:raise OSError('room_udp_closed')
            if 'room' in obj:self.state.update(obj)
            elif kind=='stage':self.state.update(stage=obj['stage'],epoch=obj['epoch'])
            elif kind=='profile':self.state.update(profile=obj.get('profile'),prepared=obj.get('prepared',False),tcp=obj.get('tcp',[]),tcp_active=obj.get('tcp_active',[]))
            elif kind=='notice':self.notices.append(obj.get('message',''))
            self.stats['tx_frames']+=1
    def send_snapshot(self,leave=False):
        with self.lock:
            if not self.state.get('room') or (self.closed and not leave):return
            self.sequence+=1;seq=self.sequence
            obj={**self.state,'k':'leave' if leave else 'sync','notices':self.notices[:8],'room_wire':3}
            packets=self.codec.encode(self.sid,seq,obj,compress=True);self.stats['last_tx_parts']=len(packets);self.stats['compressed_snapshots']+=1
        # Complete independent snapshots race both own-server paths. A recent
        # partial success must not pin all future messages to a lossy path.
        targets=self.addresses
        for target in targets:
            for packet in packets:
                try:self.socket.sendto(packet,target)
                except OSError as exc:
                    if getattr(exc,'winerror',None) in (10035,10055,10054) or isinstance(exc,BlockingIOError):break
                    raise
                self.stats['wire_tx']+=1;self.stats['tx_bytes']+=len(packet)
        self.last_send=time.monotonic()
    def readline(self,stop,timeout=15):
        deadline=time.monotonic()+timeout
        while not stop.is_set() and not self.closed:
            if self.lines:return self.lines.popleft()
            now=time.monotonic()
            if now-self.last_send>=.5:self.send_snapshot()
            if now>=deadline:raise TimeoutError('room_udp_reply_timeout')
            ready,_,_=select.select([self.socket],[],[],min(.05,deadline-now))
            if not ready:continue
            try:data,origin=self.socket.recvfrom(2048)
            except OSError as exc:
                if getattr(exc,'winerror',None)==10054 or isinstance(exc,BlockingIOError):continue
                raise
            if origin not in self.addresses:continue
            self.stats['wire_rx']+=1;decoded=self.codec.decode(data,origin)
            if not decoded:
                self.stats['incomplete_sequences']=len(self.codec.parts);continue
            sid,seq,obj=decoded
            if sid!=self.sid or seq<=self.last_received:continue
            self.active_address=origin
            self.last_received=seq;self.stats['rx_frames']+=1;self.stats['rx_bytes']+=len(data)
            self.stats['last_receive_at']=time.monotonic();self.stats['incomplete_sequences']=len(self.codec.parts)
            if obj.get('error'):self.lines.append(json.dumps(obj).encode()+b'\n');continue
            if obj.get('k')!='snapshot':continue
            with self.lock:self.notices=[]
            if obj.get('observer_ticket')!=self.ticket:
                self.ticket=obj['observer_ticket'];self.lines.append(json.dumps({'k':'joined','observer_ticket':self.ticket,'server_version':'0.9.4-lab'}).encode()+b'\n')
            self.lines.append(json.dumps({'k':'peers','peers':obj.get('peers',[]),'self_udp':obj.get('self_udp',[]),'self_id':obj.get('self_id'),'mesh':obj.get('mesh')}).encode()+b'\n')
            for notice in obj.get('notices',[])[:8]:self.lines.append(json.dumps({'k':'notice',**notice}).encode()+b'\n')
        raise OSError('room_udp_cancelled')
    def snapshot(self):return {**self.stats,'udp_source':list(self.socket.getsockname()) if not self.closed else None,'server':self.active_address,'protocol':'encrypted_independent_snapshots'}
    def flush(self,timeout=.5):return True
    def shutdown(self,*args):self.close()
    def close(self):
        if self.closed:return
        try:self.send_snapshot(leave=True)
        except OSError:pass
        self.closed=True;self.socket.close()

class RoomWriter:
    def __init__(self):self.closed=False;self.notices=[]
    def is_closing(self):return self.closed
    def close(self):self.closed=True
    def write(self,data):
        obj=json.loads(data)
        if obj.get('k')=='notice':self.notices.append({k:v for k,v in obj.items() if k!='k'})
    async def drain(self):pass

# Imported by the server only. Each snapshot is complete and newer snapshots
# supersede lost ones. A missing fragment never blocks following messages.
import asyncio
class RoomUDPServer(asyncio.DatagramProtocol):
    def __init__(self,service):
        self.service=service;self.codec=Codec(service.access,True);self.latest={};self.closed_sids={};self.transport=None;self.timer=None
    def connection_made(self,transport):
        self.transport=transport;self.timer=asyncio.get_running_loop().call_later(5,self.prune)
    def prune(self):
        now=time.monotonic();self.latest={k:v for k,v in self.latest.items() if now-v[1]<120};self.closed_sids={k:v for k,v in self.closed_sids.items() if now-v<120}
        for room,members in list(self.service.rooms.items()):
            for ident,m in list(members.items()):
                if m.get('room_udp_sid') and (now-m['last']>120 or m['writer'].closed):
                    members.pop(ident,None);self.service.tickets.pop(m['ticket_id'],None)
            if not members:self.service.rooms.pop(room,None)
        if hasattr(self.service,'mesh_planners'):
            self.service.mesh_planners={k:v for k,v in self.service.mesh_planners.items() if k in self.service.rooms}
        if self.transport and not self.transport.is_closing():self.timer=asyncio.get_running_loop().call_later(5,self.prune)
    def connection_lost(self,exc):
        if self.timer:self.timer.cancel()
    def datagram_received(self,data,addr):
        decoded=self.codec.decode(data,addr)
        if not decoded:return
        sid,seq,obj=decoded
        if sid in self.closed_sids:return
        prior=self.latest.get(sid)
        if prior and seq<=prior[0]:return
        if not prior and len(self.latest)>=512:return
        self.latest[sid]=(seq,time.monotonic())
        try:reply=self.sync(sid,obj)
        except (ValueError,KeyError,TypeError):return
        if obj.get('k')=='leave':
            self.latest.pop(sid,None);self.closed_sids[sid]=time.monotonic()
            if len(self.closed_sids)>2048:self.closed_sids=dict(sorted(self.closed_sids.items(),key=lambda item:item[1])[-1024:])
        if reply:
            packets=self.codec.encode(sid,seq,reply,compress=obj.get('room_wire')==3)
            # Independent duplicate fragments improve completion under loss;
            # legacy v1.0.16 clients still receive their original JSON framing.
            for _ in range(2 if obj.get('room_wire')==3 and len(packets)>1 else 1):
                for packet in packets:self.transport.sendto(packet,addr)
    def sync(self,sid,obj):
        from wire import hexid,endpoint
        room,ident,resume=obj.get('room'),obj.get('id'),obj.get('resume');name=obj.get('name');run=obj.get('run',0)
        if not hexid(room,64) or not hexid(ident) or not hexid(resume) or not isinstance(name,str) or not 1<=len(name)<=32 or type(run) is not int or run<0:return
        members=self.service.rooms.get(room,{})
        if obj.get('multi_protocol')==1:
            for stale,entry in list(members.items()):
                if entry.get('multi_protocol') and time.monotonic()-entry['last']>=120:
                    members.pop(stale,None);self.service.tickets.pop(entry['ticket_id'],None);entry['writer'].close()
        previous=members.get(ident)
        if previous and (previous.get('resume')!=resume or run<previous.get('run',0)):return {'error':'superseded_session'}
        if obj.get('k')=='leave':
            if previous and previous.get('room_udp_sid')==sid and previous.get('run',0)==run:
                if previous.get('multi_protocol'):
                    planner=getattr(self.service,'mesh_planners',{}).get(room)
                    if planner:planner.leave(ident,(previous.get('profile') or {}).get('generation'))
                members.pop(ident,None);self.service.tickets.pop(previous['ticket_id'],None);previous['writer'].close()
                if not members:self.service.rooms.pop(room,None)
            return
        if obj.get('k')!='sync':return
        multi=obj.get('multi_protocol')==1
        if members and any(bool(m.get('multi_protocol'))!=multi for m in members.values()):return {'error':'room_version_mismatch'}
        topology=obj.get('topology','full_mesh');role=obj.get('role','player');game_port=obj.get('game_port',25565)
        if multi:
            if topology not in ('full_mesh','star') or role not in ('host','player') or type(game_port) is not int or not 1<=game_port<=65535:return {'error':'invalid_room_mode_or_game_port'}
            if any(m.get('topology','full_mesh')!=topology for m in members.values()):return {'error':'同一房间不能混用全员互连和 MC 星形模式，请所有人选择同一模式'}
            if previous and previous.get('role','player')!=role:return {'error':'切换房主角色请先停止并退出房间'}
            if topology=='star' and role=='host' and any(i!=ident and m.get('role')=='host' for i,m in members.items()):return {'error':'房间已有房主，请选择玩家；更换房主需要原房主先退出'}
        if not previous and len(members)>=(8 if multi else 2):return {'error':'mesh_room_limit_eight' if multi else 'diagnostic_room_limit_two'}
        if previous and previous.get('room_udp_sid')==sid:m=previous
        else:
            if previous:self.service.tickets.pop(previous['ticket_id'],None);previous['writer'].close()
            ticket=secrets.token_hex(32);ticket_id=hashlib.sha256(bytes.fromhex(ticket)).hexdigest()
            m={'id':ident,'name':name,'writer':RoomWriter(),'lock':asyncio.Lock(),'udp':[],'tcp':[],'tcp_active':[],
               'profile':{},'last':time.monotonic(),'resume':resume,'run':run,'room_udp_sid':sid,'epoch':None,'stage':'measurement',
               'ticket':ticket,'ticket_id':ticket_id,'observed':{},'prepared':False,'version':'0.9.4-lab'}
            m['multi_protocol']=multi
            m.update(topology=topology,role=role,game_port=game_port)
            self.service.rooms.setdefault(room,{})[ident]=m;self.service.tickets[ticket_id]=m
            print(json.dumps({'event':'room_udp_joined','id':ident,'run':run,'replaced':bool(previous)}),flush=True)
        m['last']=time.monotonic();m['name']=name
        epoch=obj.get('epoch');stage=obj.get('stage','measurement')
        if hexid(epoch) and stage in ('measurement','main'):
            if epoch!=m['epoch']:m['observed'].clear()
            m['epoch']=epoch;m['stage']=stage
        profile=obj.get('profile') or {}
        if not isinstance(profile,dict) or len(json.dumps(profile))>24000:return {'error':'invalid_profile'}
        m['profile']=profile;m['prepared']=obj.get('prepared') is True
        for field,count in [('tcp',8),('tcp_active',1)]:
            m[field]=[list(p) for p in (endpoint(x,self.service.public) for x in obj.get(field,[])[:count]) if p]
        for message in obj.get('notices',[])[:8]:
            for other in self.service.rooms[room].values():
                if other is not m and isinstance(other['writer'],RoomWriter):other['writer'].notices.append({'peer':ident,'message':str(message)[:500]})
        notices=m['writer'].notices[:8];m['writer'].notices=[]
        result={'k':'snapshot','observer_ticket':m['ticket'],'self_id':ident,'self_udp':self.service.observations(m),
                'peers':[self.service.peer_snapshot(p) for p in self.service.rooms[room].values() if p is not m], 'notices':notices}
        if multi:
            from meshplan import MeshPlanner
            if not hasattr(self.service,'mesh_planners'):self.service.mesh_planners={}
            planner=self.service.mesh_planners.setdefault(room,MeshPlanner(getattr(self.service,'mesh_window',120)))
            result['mesh']=planner.snapshot(self.service.rooms[room])
        return result
