"""Correlate server observations with a live socket and a fresh request."""
import hashlib,secrets,threading,time
from wire import endpoint,pack,unpack,hexid

class LiveDiscovery:
    def __init__(self,public=True):
        self.public=public;self.ticket=None;self.sockets={};self.pending={};self.paths={};self.seen={}
        self.lock=threading.Lock();self.accepted=0;self.rejected=0;self.epoch=secrets.token_hex(16)
    def set_ticket(self,ticket):
        if not hexid(ticket,64):raise ValueError('invalid observer ticket')
        with self.lock:self.ticket=ticket;self.pending.clear();self.paths.clear();self.seen.clear()
    def new_epoch(self):
        with self.lock:
            self.epoch=secrets.token_hex(16);self.pending.clear();self.paths.clear();self.seen.clear();self.sockets.clear()
        return self.epoch
    def invalidate(self,slot):
        with self.lock:self.paths.pop(slot,None)
    def attach(self,slot,s):
        with self.lock:
            if self.sockets.get(slot) is not s:
                self.paths.pop(slot,None)
                self.pending={n:p for n,p in self.pending.items() if p[0]!=slot}
            self.sockets[slot]=s
    def request(self,slot,now=None):
        now=time.monotonic() if now is None else now
        with self.lock:
            if not self.ticket or slot not in self.sockets:return None
            self.pending={n:p for n,p in self.pending.items() if now-p[2]<15}
            nonce=secrets.token_hex(16);self.pending[nonce]=(slot,self.sockets[slot],now)
            return pack(bytes.fromhex(self.ticket),{'k':'observe','n':nonce,'slot':slot,'epoch':self.epoch,
                'ticket_id':hashlib.sha256(bytes.fromhex(self.ticket)).hexdigest(),'pad':'0'*32})
    def accept(self,records,source,now=None):
        now=time.monotonic() if now is None else now;changed=[]
        with self.lock:
            for record in records[:8] if isinstance(records,list) else []:
                if not isinstance(record,dict):self.rejected+=1;continue
                nonce=record.get('nonce');expected=self.pending.get(nonce) if isinstance(nonce,str) else None
                slot=record.get('slot');age=record.get('age_seconds');ep=endpoint(record.get('endpoint'),self.public)
                if record.get('epoch')!=self.epoch or not expected or type(slot) is not int or slot!=expected[0] or self.sockets.get(slot) is not expected[1] or expected[1].fileno()<0 or now-expected[2]>=15 or type(age) not in (int,float) or not 0<=age<15 or not ep:
                    self.rejected+=1;continue
                old=self.paths.get(slot);self.paths[slot]={'endpoint':ep,'at':expected[2],'source':source}
                if not old or old['endpoint']!=ep:changed.append({'slot':slot,'endpoint':list(ep),'source':source})
                if nonce not in self.seen:self.accepted+=1;self.seen[nonce]=now
            self.seen={n:t for n,t in self.seen.items() if now-t<15}
        return changed
    def receive(self,data,origin,expected_origin,now=None):
        now=time.monotonic() if now is None else now
        with self.lock:ticket=self.ticket
        if not ticket or origin!=expected_origin:return []
        obj=unpack(bytes.fromhex(ticket),data)
        if not obj or obj.get('k')!='observed' or obj.get('mode')!='observe' or obj.get('source_index')!=0:return []
        with self.lock:p=self.pending.get(obj.get('n'))
        if not p:return []
        return self.accept([{'slot':p[0],'nonce':obj['n'],'epoch':obj.get('epoch'),'age_seconds':0,'endpoint':obj.get('endpoint')}],'udp_reply',now)
    def endpoints(self,now=None):
        now=time.monotonic() if now is None else now
        with self.lock:return [list(ep) for ep in dict.fromkeys(p['endpoint'] for slot,p in self.paths.items() if now-p['at']<15 and self.sockets[slot].fileno()>=0)]
    def slot_endpoint(self,slot,now=None):
        now=time.monotonic() if now is None else now
        with self.lock:
            path=self.paths.get(slot);sock=self.sockets.get(slot)
            return list(path['endpoint']) if path and sock and sock.fileno()>=0 and now-path['at']<15 else None

class PairClock:
    """Count only intervals for which both ends have fresh live candidates."""
    def __init__(self,duration,wait_limit=300,gap_limit=300):
        self.duration=duration;self.wait_limit=wait_limit;self.gap_limit=gap_limit
        self.prepared_at=None;self.started=None;self.last=None;self.was_ready=False;self.elapsed=0.;self.gap_at=None;self.reason=None
    def step(self,now,ready):
        if self.prepared_at is None:self.prepared_at=now
        if self.last is not None and self.was_ready and ready:self.elapsed+=max(0,now-self.last)
        began=self.started is None and ready
        if began:self.started=now
        if ready:self.gap_at=None
        elif self.gap_at is None:self.gap_at=now
        self.last=now;self.was_ready=ready
        expired=False
        if self.started is None and now-self.prepared_at>=self.wait_limit:expired=True;self.reason='initial_wait_timeout'
        elif self.elapsed>=self.duration:expired=True;self.reason='active_duration_complete'
        elif self.started is not None and self.gap_at is not None and now-self.gap_at>=self.gap_limit:expired=True;self.reason='peer_or_control_gap_timeout'
        return began,self.elapsed,expired
