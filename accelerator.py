"""Continuous nearby search, followed by dense observed-range search."""
from wire import endpoint

class FastSearch:
    """Centered scan plus bounded anchor pool, advanced only after send.

    The server-observed center is a hypothesis. An authenticated reply,
    not a predicted port, selects the usable path. Original lanes remain.
    """
    def __init__(self):
        self.tick=0;self.scan_position=0;self.anchor_position=0;self.center=None;self.lane=None
    def choice(self,peer,count,role,public=True):
        seeds=list(dict.fromkeys(p for p in (endpoint(v,public) for v in peer.get('udp',[])[:8]) if p))
        if not seeds or not count:return None
        preferred=endpoint((peer.get('profile') or {}).get('source_zero_observer_endpoint'),public)
        seed=preferred if preferred in seeds else min(seeds)
        if self.center is None or self.center[0]!=seed[0]:self.center=seed;self.scan_position=0
        scan=self.tick%8>=6 if role=='anchor' else self.tick%8<6 if role=='scan' else self.tick%2==1
        if scan:
            index=self.scan_position%65535
            delta=0 if index==0 else (index+1)//2*(1 if index%2 else -1)
            target=(self.center[0],1+(self.center[1]-1+delta)%65535)
            self.lane='center_scan'
            return self.scan_position//65535%count,target,self.lane
        anchors=[]
        for delta in (0,-2,-1,1,2):
            p=(seed[0],seed[1]+delta)
            if 1<=p[1]<=65535 and p not in anchors:anchors.append(p)
        anchors.extend(p for p in seeds if p not in anchors)
        slots=list(dict.fromkeys([*([1] if count>1 else []),0,*([3] if count>3 else []),*range(count)]))
        self.lane='fast_anchor'
        return slots[self.anchor_position%count],anchors[self.anchor_position//count%len(anchors)],self.lane
    def sent(self,lane):
        self.tick+=1
        if lane=='center_scan':self.scan_position+=1
        if lane=='fresh_center_scan':self.fresh_position+=1
        if lane=='fast_anchor':self.anchor_position+=1

    def protected_choice(self,peer,count,role,now,public=True):
        seeds=[p for p in (endpoint(v,public) for v in peer.get('udp',[])[:8]) if p]
        if not seeds or not count:return None
        preferred=endpoint((peer.get('profile') or {}).get('source_zero_observer_endpoint'),public)
        seed=preferred if preferred in seeds else seeds[0]
        if role=='anchor':
            saved=self.tick;self.tick=0
            result=self.choice(peer,count,'anchor',public);self.tick=saved;return result
        if role not in ('scan','duplex'):return None
        if getattr(self,'fresh_center',None) is None or self.fresh_center[0]!=seed[0] or (abs(self.fresh_center[1]-seed[1])>=16 and now-getattr(self,'fresh_at',0)>=30):
            self.fresh_center=seed;self.fresh_position=0;self.fresh_at=now
        if self.tick%4!=3 and not getattr(self,'continuous_priority',False) or self.tick%4==3 and getattr(self,'continuous_priority',False):
            # Unlimited mode covers the nearby 257 ports on every source first,
            # then expands to the next band instead of looping the same matrix.
            index=(self.fresh_position//(257*count)*257+self.fresh_position%257)%65535 if getattr(self,'unlimited',False) else self.fresh_position%257
            delta=0 if index==0 else (index+1)//2*(1 if index%2 else -1)
            return self.fresh_position//257%count,(self.fresh_center[0],1+(self.fresh_center[1]-1+delta)%65535),'fresh_center_scan'
        saved=self.tick;self.tick=0
        result=self.choice(peer,count,'scan',public);self.tick=saved;return result

class CandidatePriority:
    """Try fresh observer and bounded nearby candidates continuously.

    The 1.0.1 chain opened from local slot 3 to an observer port minus 2;
    its reverse challenge used local slot 0. Prioritize those local sources
    and small offsets, then cover the full bounded candidate matrix. A peer
    endpoint list position is NOT a peer source slot. Guesses remain guesses.
    """
    def __init__(self):self.cursor=0;self.last_attempt=0.;self.signature=None;self.choices=[]
    def choice(self,peer,count,now,public=True,targets=None):
        if now-self.last_attempt<.5:return None
        self.last_attempt=now
        seeds=list(dict.fromkeys(p for p in (endpoint(v,public) for v in peer.get('udp',[])[:8]) if p))
        ips={ip for ip,port in seeds}
        candidates=seeds if targets is None else list(dict.fromkeys(p for p in (endpoint(v,public) for v in targets[:24]) if p and p[0] in ips))
        signature=(tuple(seeds),tuple(candidates),count)
        if signature!=self.signature:
            self.signature=signature;self.choices=[]
            if candidates and count:
                pairs=[]
                if count>3:
                    pairs.extend((3,(ip,port-2)) for ip,port in seeds if (ip,port-2) in candidates and (ip,port-2) not in seeds)
                pairs.extend((0,target) for target in seeds if target in candidates)
                pairs.extend((slot,target) for slot in dict.fromkeys([0,*([3] if count>3 else []),*range(count)]) for target in candidates)
                self.choices=list(dict.fromkeys(pairs))
        if not self.choices:return None
        slot,target=self.choices[self.cursor%len(self.choices)]
        return slot,target,'priority_candidates'
    def sent(self):self.cursor+=1
def phased_choice(coord,search,schedule,peer,count,now,public=True):
    """A synchronized round selects one algorithm; anchor work is not mixed."""
    phase=coord.phase
    if phase=='nearby':return search.nearby.choice(peer,count,now,public)
    if phase=='range':return search.dense.phase_choice(peer,count,coord.round,public)
    choice=schedule.choice(coord.role,coord.round,peer,count,public)
    if not choice:return None
    slot,target,scan=choice
    if phase=='stable_pair' and coord.role=='anchor':slot=0
    return slot,target,'full_scan' if scan else 'fixed_target'
class NearbySearch:
    def __init__(self):self.cursor=0;self.started=None;self.signature=None;self.choices=[]
    def rebuild(self,peer,count,public):
        seeds=list(dict.fromkeys(p for p in (endpoint(x,public) for x in peer.get('udp',[])[:8]) if p))
        signature=(tuple(seeds),count)
        if signature==self.signature:return
        self.signature=signature;self.choices=[]
        # Every source gets exact observed addresses and ±1/±2 first. In
        # v094, the winning peer port was observer port +2 during sync.
        targets=[]
        for delta in (0,1,-1,2,-2,3,-3,4,-4,8,-8,16,-16,32,-32):
            for ip,port in seeds:
                if 1<=port+delta<=65535 and (ip,port+delta) not in targets:targets.append((ip,port+delta))
        targets=targets[:96]
        for target in targets:
            for slot in range(count):self.choices.append((slot,target))
    def choice(self,peer,count,now,public=True):
        if self.started is None:self.started=now
        self.rebuild(peer,count,public)
        if not self.choices:return None
        # Start with all source/nearby-target combinations for 120 seconds,
        # then dedicate one third of packets to it. No 35-second sync gate.
        slot,target=self.choices[self.cursor%len(self.choices)]
        return slot,target,'nearby_matrix'
    def sent(self):self.cursor+=1

class DenseScan:
    def __init__(self):self.position=0;self.phase_positions={};self.last_phase_key=None
    def phase_choice(self,peer,count,round_number,public=True):
        seeds=[p for p in (endpoint(x,public) for x in peer.get('udp',[])[:8]) if p]
        if not seeds or not count:return None
        preferred=endpoint((peer.get('profile') or {}).get('source_zero_observer_endpoint'),public)
        seed=preferred if preferred in seeds else seeds[0]
        # These are hypotheses around observed ports, not claimed CGN blocks.
        radius=(1024,4096)[min(max(0,round_number//6),1)]
        low,high=max(1,seed[1]-radius),min(65535,seed[1]+radius);span=high-low+1
        key=(seed[0],low,high,count);position=self.phase_positions.get(key,0);self.last_phase_key=key
        return position//span%count,(seed[0],low+position%span),'observed_range'
    def choice(self,peer,count,public=True):
        seeds=[p for p in (endpoint(x,public) for x in peer.get('udp',[])[:8]) if p]
        if not seeds:return None
        ip=seeds[0][0];ports=[p[1] for p in seeds if p[0]==ip]
        low,high=max(1,min(ports)-64),min(65535,max(ports)+64)
        if high-low>4096:return None
        # Dense bounded range first; unlike a 65535-port permutation it
        # reaches the current observed allocation neighborhood early.
        span=high-low+1;slot=self.position//span%count;port=low+self.position%span
        return slot,(ip,port),'observed_range'
    def sent(self):
        self.position+=1
        if self.last_phase_key is not None:self.phase_positions[self.last_phase_key]=self.phase_positions.get(self.last_phase_key,0)+1

class MixedSearch:
    """Favor nearby candidates while continuously reserving the original lane."""
    def __init__(self):self.nearby=NearbySearch();self.dense=DenseScan();self.tick=0
    def choice(self,peer,count,now,public=True):
        if self.nearby.started is None:self.nearby.started=now
        early=now-self.nearby.started<120
        if self.tick%5< (4 if early else 3):return self.nearby.choice(peer,count,now,public)
        if not early and self.tick%5==3:return self.dense.choice(peer,count,public)
        return None
    def sent(self,lane):
        self.tick+=1
        if lane=='nearby_matrix':self.nearby.sent()
        elif lane=='observed_range':self.dense.sent()
