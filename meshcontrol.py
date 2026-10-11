"""One UDP socket multiplexes the main room and isolated two-member engines."""
import collections,json,queue,secrets,select,socket,threading,time
from roomudp import Codec,DatagramControl
from net import raw_socket

class ControlMux:
    def __init__(self,cfg,bind,index,stop,emit):
        self.cfg=cfg;self.stop=stop;self.emit=emit;self.lock=threading.RLock();self.channels={};self.closed=False
        self.targets=list(dict.fromkeys([(cfg.get('control_tail_host') or cfg['host'],int(cfg['room_udp_port'])),(cfg['host'],int(cfg['room_udp_port']))]))
        self.socket=socket.socket(socket.AF_INET,socket.SOCK_DGRAM) if cfg.get('control_tail_host') else raw_socket(socket.SOCK_DGRAM,bind,index)
        if cfg.get('control_tail_host'):self.socket.bind(('0.0.0.0',0))
        self.socket.setblocking(False);self.socket.setsockopt(socket.SOL_SOCKET,socket.SO_RCVBUF,2*1024*1024)
        if hasattr(socket,'SIO_UDP_CONNRESET'):self.socket.ioctl(socket.SIO_UDP_CONNRESET,False)
        self.codec=Codec(cfg['access']);self.tx=0;self.rx=0;self.thread=threading.Thread(target=self.run,name='NATPair-room-mux',daemon=True);self.thread.start()
    def channel(self,cfg=None,bind=None,index=None):
        c=MuxChannel(self)
        with self.lock:
            if self.closed:raise OSError('mesh_mux_closed')
            self.channels[c.sid]=c
        return c
    def send(self,c,leave=False):
        with c.lock:
            if not c.state.get('room') or c.closed and not leave:return
            c.sequence+=1
            packets=c.codec.encode(c.sid,c.sequence,{**c.state,'k':'leave' if leave else 'sync','notices':c.notices[:8],'room_wire':3},compress=True)
        with self.lock:
            if self.closed:return
            for target in self.targets:
                for data in packets:
                    try:self.socket.sendto(data,target);self.tx+=1
                    except (BlockingIOError,ConnectionResetError):break
                    except OSError as exc:
                        if not self.closed:c.last_error=str(exc)
                        break
        c.last_send=time.monotonic()
    def run(self):
        while not self.stop.is_set() and not self.closed:
            with self.lock:channels=list(self.channels.values())
            now=time.monotonic()
            for c in channels:
                if now-c.last_send>=.5:
                    try:self.send(c)
                    except (OSError,ValueError) as exc:c.last_error=str(exc)
            try:
                if not select.select([self.socket],[],[],.02)[0]:continue
                for _ in range(256):
                    try:data,origin=self.socket.recvfrom(2048)
                    except (BlockingIOError,ConnectionResetError):break
                    if origin not in self.targets:continue
                    self.rx+=1;decoded=self.codec.decode(data,origin)
                    if not decoded:continue
                    sid,seq,obj=decoded
                    with self.lock:c=self.channels.get(sid)
                    if c:c.accept(seq,obj,origin)
            except (OSError,ValueError):
                if not self.closed:self.stop.wait(.05)
    def close(self):
        if self.closed:return
        with self.lock:channels=list(self.channels.values())
        for c in channels:c.close()
        self.closed=True;self.socket.close();self.thread.join(3)
    def snapshot(self):
        with self.lock:return {'channels':len(self.channels),'wire_tx':self.tx,'wire_rx':self.rx,'source':list(self.socket.getsockname()) if not self.closed else None,'protocol':'shared_encrypted_udp_snapshots'}

class MuxChannel(DatagramControl):
    def __init__(self,mux):
        self.mux=mux;self.cfg=mux.cfg;self.socket=mux.socket;self.addresses=mux.targets;self.active_address=None
        self.sid=secrets.token_bytes(16);self.codec=Codec(mux.cfg['access']);self.lock=threading.RLock();self.state={};self.closed=False
        self.sequence=0;self.last_received=0;self.last_send=0;self.ticket=None;self.lines=collections.deque();self.notices=[];self.last_error=None
        self.stats={'tx_frames':0,'rx_frames':0};self.queue=queue.Queue(8)
    def send_snapshot(self,leave=False):self.mux.send(self,leave)
    def accept(self,seq,obj,origin):
        with self.lock:
            if self.closed or seq<=self.last_received:return
            self.last_received=seq;self.active_address=origin;self.stats['rx_frames']+=1;self.stats['last_receive_at']=time.monotonic()
            # Complete snapshots replace each other; never let a slow consumer
            # build an ordered backlog of already obsolete room state.
            if self.queue.full():
                try:self.queue.get_nowait()
                except queue.Empty:pass
            self.queue.put_nowait(obj)
    def readline(self,stop,timeout=15):
        deadline=time.monotonic()+timeout
        while not stop.is_set() and not self.closed:
            if self.lines:return self.lines.popleft()
            if time.monotonic()>=deadline:raise TimeoutError('mesh_snapshot_timeout')
            try:obj=self.queue.get(timeout=min(.05,max(.001,deadline-time.monotonic())))
            except queue.Empty:continue
            if obj.get('error'):return json.dumps(obj).encode()+b'\n'
            if obj.get('k')!='snapshot':continue
            with self.lock:self.notices=[]
            if obj.get('observer_ticket')!=self.ticket:
                self.ticket=obj['observer_ticket'];self.lines.append(json.dumps({'k':'joined','observer_ticket':self.ticket,'server_version':'0.9.4-lab'}).encode()+b'\n')
            self.lines.append(json.dumps({'k':'peers','peers':obj.get('peers',[]),'self_udp':obj.get('self_udp',[]),'self_id':obj.get('self_id'),'mesh':obj.get('mesh')}).encode()+b'\n')
        raise OSError('mesh_channel_cancelled')
    def snapshot(self):return {**self.stats,'udp_source':list(self.socket.getsockname()) if not self.mux.closed else None,'last_error':self.last_error,'protocol':'multiplexed_room_snapshot'}
    def close(self):
        if self.closed:return
        try:self.send_snapshot(leave=True)
        except (OSError,ValueError):pass
        self.closed=True
        with self.mux.lock:self.mux.channels.pop(self.sid,None)
