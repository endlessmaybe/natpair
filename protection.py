"""Bound only this process's UDP exploration; never edit other clients."""
import collections

def offer(cfg):
    result={'protocol':1,'rate':max(10,min(80,int(cfg.get('probe_rate',80)))),
        'new15':max(8,min(64,int(cfg.get('probe_new_targets',64)))),
        'new180':256,'burst':8,'window':180,'coord_window':60,'new_spacing_ms':0}
    if cfg.get('bifrost_coexist') and not cfg.get('restore_v105_budget'):
        result.update(new180=192,burst=2,window=180,new_spacing_ms=250)
    return result

def negotiated(local,remote):
    # Missing/old peer means local protection still applies, at lower rate.
    compatible=isinstance(remote,dict) and remote.get('protocol')==1
    result=dict(local)
    for key in ('rate','new15','new180','burst'):
        value=remote.get(key) if compatible else (20 if key=='rate' else local[key])
        if type(value) is not int or value<=0:value=local[key]
        result[key]=min(local[key],value)
    for key in ('window','new_spacing_ms'):
        value=remote.get(key,local[key]) if compatible else local[key]
        if type(value) is not int or not 0<=value<=600000:value=local[key]
        result[key]=max(local[key],value)
    result['peer_supported']=compatible
    return result

class MappingPressure:
    """Conservative rolling usage estimate, not the operator's NAT table."""
    def __init__(self,limit=256,window=180,burst=8):
        self.spacing=0.;self.last_new=None;self.limit=limit;self.window=window;self.burst=burst;self.targets={};self.new_times=collections.deque()
    def reason(self,target,now):
        self.targets={t:at for t,at in self.targets.items() if now-at<self.window}
        while self.new_times and now-self.new_times[0]>=1:self.new_times.popleft()
        if target in self.targets:return None
        if self.last_new is not None and now-self.last_new<self.spacing:return 'new_mapping_pacing_limit'
        if len(self.targets)>=self.limit:return 'long_mapping_pressure_limit'
        if len(self.new_times)>=self.burst:return 'new_mapping_burst_limit'
        return None
    def used(self,target,now,authenticated=False):
        if target not in self.targets:
            if authenticated and len(self.targets)>=self.limit:return
            self.new_times.append(now);self.last_new=now
        self.targets[target]=now

class ConnectionGuard:
    def __init__(self):self.gap_at=None;self.ever_healthy=False;self.was_healthy=None;self.cooldown_until=0;self.stable_at=None;self.reason='waiting_for_candidates'
    def step(self,now,healthy,coordination_ok=None):
        if coordination_ok is not None:return self.efficient_step(now,healthy,coordination_ok)
        if not healthy:
            if self.was_healthy is True:self.cooldown_until=max(self.cooldown_until,now+30)
            self.was_healthy=False;self.stable_at=None;self.reason='coordination_or_candidates_unavailable';return False
        if self.was_healthy is not True:self.stable_at=now
        self.was_healthy=True
        if now<self.cooldown_until:self.reason='connection_recovery_cooldown';return False
        if now-self.stable_at<2:self.reason='checking_connection_stability';return False
        self.reason='normal';return True

    def efficient_step(self,now,healthy,coordination_ok):
        if not healthy:
            if self.gap_at is None:self.gap_at=now
            self.stable_at=None;self.was_healthy=False
            if self.ever_healthy and (not coordination_ok or now-self.gap_at>=8):
                self.cooldown_until=max(self.cooldown_until,now+10)
            self.reason='coordination_or_candidates_unavailable'
            return False
        if self.was_healthy is not True:self.stable_at=now
        self.gap_at=None;self.was_healthy=True;self.ever_healthy=True
        if now<self.cooldown_until:self.reason='connection_recovery_cooldown';return False
        if now-self.stable_at<.5:self.reason='checking_connection_stability';return False
        self.reason='normal';return True
