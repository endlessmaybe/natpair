"""Optional rolling-second limit for *successful new probe combinations*."""
import collections
import threading

class CombinationLimit:
    def __init__(self,limit=None):
        if limit is not None and (type(limit) is not int or limit<=0):
            raise ValueError('new combination limit must be a positive integer')
        self.limit=limit;self.windows=collections.deque();self.seen={}
        self.total=0;self.denied=0;self.lock=threading.RLock()
    def _expire(self,now):
        while self.windows and now-self.windows[0]>=1:self.windows.popleft()
    def _known(self,source,target):
        bits=self.seen.get((source,target[0]))
        byte,bit=divmod(target[1]-1,8)
        return bool(bits is not None and bits[byte]&(1<<bit))
    def allows(self,source,target,now):
        with self.lock:
            self._expire(now)
            return self.limit is None or self._known(source,target) or len(self.windows)<self.limit
    def sent(self,source,target,now):
        with self.lock:
            self._expire(now)
            if self._known(source,target):return
            key=(source,target[0]);bits=self.seen.get(key)
            if bits is None:bits=bytearray(8192);self.seen[key]=bits
            byte,bit=divmod(target[1]-1,8);bits[byte]|=1<<bit
            self.total+=1
            if self.limit is not None:self.windows.append(now)
    def delay(self,now):
        with self.lock:
            self._expire(now)
            return max(0,self.windows[0]+1-now) if self.limit and len(self.windows)>=self.limit else 0
    def snapshot(self,now):
        with self.lock:
            self._expire(now)
            return {'new_per_second_limit':self.limit,'new_last_second':len(self.windows),
                    'successful_unique_combinations':self.total,'denied':self.denied,
                    'scope':'local_udp_source_port_x_peer_ipv4_x_peer_port; repeats_are_free'}
