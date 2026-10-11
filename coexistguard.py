"""Optional, per-application proactive shaping; never controls Bifrost.

The footprint is our recently touched UDP tuples, NOT the ISP's NAT table.
Budgets are conservative tunables, not measured Bifrost/CGNAT capacity.
Successful sends alone consume budget. Maintenance always has priority.
"""
import collections
import datetime
import threading
import time
from coexist import Coexistence


class FreshHealthTrace(Coexistence):
    def __init__(self, path=None):
        super().__init__(True, path)
        self.events=collections.deque(maxlen=32)
        self.event_serial=0

    def signal(self, line, now, wall=None):
        try:
            parts=line.split('|',3)
            stamp=datetime.datetime.fromisoformat(parts[0]).timestamp()
            message=parts[3]
        except (ValueError,IndexError):return
        wall=time.time() if wall is None else wall
        age=wall-stamp
        # An old warning at application startup is not a current fault.
        if age < -1 or age > 2:return
        marker=next((m for m in ('runtime-dataplane-miss','runtime-connect-failed',
            'runtime-mihomo-readback-transient-unhealthy') if m in message),None)
        if not marker:return
        with self.lock:
            identity=(stamp,marker)
            if identity in self.seen:return
            self.seen={x for x in self.seen if wall-x[0]<120};self.seen.add(identity)
            self.event_serial+=1
            self.events.append((self.event_serial,now-max(0,age),marker))

    def recent(self):
        with self.lock:return list(self.events)


class CoexistGuard:
    def __init__(self,cfg=None,clock=time.monotonic):
        cfg=cfg or {};self.clock=clock;self.lock=threading.RLock()
        self.packet_ceiling=int(cfg.get('coexist_packet_ceiling',1000))
        self.new_ceiling=int(cfg.get('coexist_new_ceiling',200))
        self.burst_window=float(cfg.get('coexist_burst_window',15))
        self.burst_limit=int(cfg.get('coexist_burst_limit',900))
        self.footprint_window=float(cfg.get('coexist_footprint_window',180))
        self.footprint_limit=int(cfg.get('coexist_footprint_limit',2400))
        if min(self.packet_ceiling,self.new_ceiling,self.burst_window,self.burst_limit,self.footprint_window,self.footprint_limit)<=0:
            raise ValueError('共存探测预算必须大于零')
        self.packet_ceiling=min(1000,self.packet_ceiling)
        self.new_ceiling=min(self.packet_ceiling,self.new_ceiling)
        now=clock();self.tokens=2.;self.token_at=now;self.next_new=now
        self.touched=collections.OrderedDict();self.new_times=collections.deque()
        self.sent_packets=0;self.fresh_combinations=0;self.priority_packets=0
        self.denied=collections.Counter();self.last_pressure=None
        self.monitor=FreshHealthTrace(cfg.get('bifrost_trace_path'))
        self.last_poll=0.;self.serial=0;self.reduced_until=0.;self.new_pause_until=0.;self.last_signal=None

    def _expire(self,now):
        while self.touched and now-next(iter(self.touched.values()))>=self.footprint_window:self.touched.popitem(last=False)
        while self.new_times and now-self.new_times[0]>=self.burst_window:self.new_times.popleft()

    def rates(self,now):
        return (min(250,self.packet_ceiling),min(50,self.new_ceiling)) if now<self.reduced_until else (self.packet_ceiling,self.new_ceiling)

    def poll(self,now=None,wall=None):
        now=self.clock() if now is None else now
        with self.lock:
            if now-self.last_poll<.2:return
            self.last_poll=now
        self.monitor.poll(now,wall)
        with self.lock:
            for serial,at,marker in self.monitor.recent():
                if serial<=self.serial:continue
                self.serial=serial;self.last_signal=marker
                self.reduced_until=max(self.reduced_until,at+15)
                if marker!='runtime-mihomo-readback-transient-unhealthy':
                    self.new_pause_until=max(self.new_pause_until,at+10)
                # Do not spend accumulated tokens as a catch-up burst.
                self.tokens=min(self.tokens,1.)

    def permit(self,source,target,now,priority=False):
        """Caller holds lock until send outcome is committed."""
        self._expire(now)
        key=(source,target[0],target[1]);fresh=key not in self.touched
        if priority:return True,0.,None
        rate,new_rate=self.rates(now)
        self.tokens=min(2.,self.tokens+max(0,now-self.token_at)*rate);self.token_at=now
        reason=None;delay=0.
        if self.tokens<1:reason='packet_pacing';delay=(1-self.tokens)/rate
        elif fresh and now<self.new_pause_until:reason='health_new_pause';delay=self.new_pause_until-now
        elif fresh and len(self.touched)>=self.footprint_limit:
            reason='mapping_footprint_budget';delay=next(iter(self.touched.values()))+self.footprint_window-now
        elif fresh and len(self.new_times)>=self.burst_limit:
            reason='mapping_burst_budget';delay=self.new_times[0]+self.burst_window-now
        elif fresh and now<self.next_new:reason='new_mapping_pacing';delay=self.next_new-now
        if reason:
            self.denied[reason]+=1
            if reason not in ('packet_pacing','new_mapping_pacing'):self.last_pressure=reason
            return False,max(.0005,delay),reason
        return True,0.,None

    def commit(self,source,target,now,priority=False):
        self._expire(now);key=(source,target[0],target[1]);fresh=key not in self.touched
        self.touched[key]=now;self.touched.move_to_end(key)
        if fresh:
            self.new_times.append(now);self.fresh_combinations+=1
            if not priority:self.next_new=now+1/self.rates(now)[1]
        if priority:self.priority_packets+=1
        else:self.tokens-=1;self.sent_packets+=1

    def snapshot(self,now=None):
        now=self.clock() if now is None else now
        with self.lock:
            self._expire(now);rate,new_rate=self.rates(now)
            pressure='health_new_pause' if now<self.new_pause_until else 'mapping_footprint_budget' if len(self.touched)>=self.footprint_limit else 'mapping_burst_budget' if len(self.new_times)>=self.burst_limit else None
            wait=self.new_pause_until-now if pressure=='health_new_pause' else next(iter(self.touched.values()))+self.footprint_window-now if pressure=='mapping_footprint_budget' else self.new_times[0]+self.burst_window-now if pressure=='mapping_burst_budget' else 0.
            return {'enabled':True,'scope':'all member pairs in this application; retained across stop/start',
                'packet_ceiling':self.packet_ceiling,'effective_packet_ceiling':rate,'effective_new_ceiling':new_rate,
                'max_catchup_burst':2,'burst_window':self.burst_window,'burst_limit':self.burst_limit,
                'fresh_in_burst_window':len(self.new_times),'footprint_window':self.footprint_window,
                'footprint_limit':self.footprint_limit,'recently_touched_combinations':len(self.touched),
                'model_is_actual_nat_table':False,'health_new_pause_seconds':round(max(0,self.new_pause_until-now),2),
                'new_budget_wait_seconds':round(max(0,wait),2),'candidate_retry_limit':128,'candidate_retry_ceiling':20,
                'reduced_seconds':round(max(0,self.reduced_until-now),2),'monitor':self.monitor.status,
                'last_signal':self.last_signal,'last_pressure':self.last_pressure,'current_pressure':pressure,'denied':dict(self.denied),
                'shaped_probe_packets':self.sent_packets,'priority_packets':self.priority_packets,
                'fresh_combinations':self.fresh_combinations,'maintenance_exempt':True,'guarantees_bifrost_uptime':False}


_guards={};_guards_lock=threading.Lock()
def application_guard(cfg):
    # Stopping/rejoining must not forget still-live upstream mappings.
    # Separate test fixtures may supply an explicitly isolated scope.
    signature=(cfg.get('_guard_scope','application'),tuple((k,str(v)) for k,v in sorted(cfg.items()) if k.startswith('coexist_')),cfg.get('bifrost_trace_path'))
    with _guards_lock:
        if signature not in _guards:_guards[signature]=CoexistGuard(cfg)
        return _guards[signature]
