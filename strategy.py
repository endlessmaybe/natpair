"""Bounded coordinated experiments. Observer mappings are not peer mappings."""
import hashlib
import math
import secrets
from wire import endpoint,hexid

def allocation_model(samples):
    result={'validated':False,'classification':'unknown','scope':'fresh_source_sockets_to_one_observer_only',
            'samples':samples,'reason':'eight_complete_ordered_samples_required'}
    if len(samples)!=8 or any(not s.get('endpoint') for s in samples):return result
    if len({s['endpoint'][0] for s in samples})!=1:
        result['reason']='public_ip_changed';return result
    ports=[s['endpoint'][1] for s in samples]
    deltas=[ports[i+1]-ports[i] for i in range(5)]
    if len(set(deltas))!=1 or not 1<=abs(deltas[0])<=128:
        result['classification']='not_validated';result['reason']='training_not_a_small_nonzero_constant_step';return result
    step=deltas[0];predicted=[ports[5]+step,ports[5]+2*step]
    result.update(step=step,predicted_holdout=predicted,actual_holdout=ports[6:])
    if predicted!=ports[6:]:
        result['classification']='not_validated';result['reason']='heldout_prediction_failed';return result
    result.update(validated=True,classification='observer_easy_inc' if step>0 else 'observer_easy_dec',
                  reason='six_training_two_unseen_holdout_matched')
    return result

def prediction_step(profile):
    model=(profile or {}).get('allocation_prediction') or {}
    value=model.get('step')
    return value if model.get('validated') is True and type(value) is int and 1<=abs(value)<=128 else None

def mapping_stable(profile):
    """Evidence for tested destinations only; says nothing about filtering."""
    p=profile or {};pattern=p.get('port_pattern') or {};cross=p.get('cross_ip_mapping') or {}
    trials=cross.get('trials') or [];ips=set()
    if pattern.get('validated') is not True or pattern.get('step')!=0 or cross.get('classification')!='same_for_tested_destination_ips':return False
    for trial in trials:
        before=trial.get('before') or {};other=trial.get('other_ip') or {};after=trial.get('after') or {};server=trial.get('other_server') or {}
        if before.get('endpoint') and before.get('endpoint')==other.get('endpoint')==after.get('endpoint') and server.get('ip'):ips.add(server['ip'])
    return len(ips)>=2

class Coordination:
    """Two-party prepare/ack/go handshake, monotonic local round duration."""
    def __init__(self,ident,window=35):
        self.remote_epoch=None;self.id=ident;self.window=window;self.record={};self.peer_id=None;self.at=None;self.round=-1;self.role=None;self.mode=None;self.phase=None
    def step(self,peer,profile,now):
        remote=peer.get('profile') or {};other=peer.get('id')
        if not hexid(other) or remote.get('strategy_protocol')!=1:
            self.role=None;return False,'incompatible'
        if other!=self.peer_id or remote.get('punch_epoch')!=self.remote_epoch:
            self.remote_epoch=remote.get('punch_epoch');self.peer_id=other;self.record={};self.at=None;self.round=-1;self.role=None
        leader=self.id<other;incoming=remote.get('punch_coord') or {};changed=False
        stable_rounds=profile.get('coordination_protocol')==remote.get('coordination_protocol')==2
        if not isinstance(incoming,dict):incoming={}
        if leader:
            peer_running=incoming.get('state')=='running' and incoming.get('token')==self.record.get('token') and incoming.get('round')==self.round
            if not self.record or (self.at is not None and now-self.at>=self.window and (not stable_rounds or peer_running)):
                self.round+=1;mine=prediction_step(profile);theirs=prediction_step(remote)
                self.mode='both_observer_predictable' if mine and theirs else 'mixed_observer_prediction' if mine or theirs else 'unclassified_experiment'
                # Every third round also reverses roles. Predictability applies
                # only to observer samples, never assumed for the peer path.
                base='scan' if mine and not theirs else 'anchor' if theirs and not mine else 'anchor'
                role=base if self.round%3!=2 else ('scan' if base=='anchor' else 'anchor')
                if mine and theirs and self.round%3!=2:role='duplex'
                if not mine and not theirs:role='anchor' if self.round%2==0 else 'scan'
                mine_stable,theirs_stable=mapping_stable(profile),mapping_stable(remote)
                if mine_stable or theirs_stable:
                    self.mode='tested_stable_mapping_both' if mine_stable and theirs_stable else 'tested_stable_mapping_mixed'
                    role='anchor' if theirs_stable else 'scan'
                phased=profile.get('search_phase_protocol')==remote.get('search_phase_protocol')==1
                self.phase=('nearby','original','stable_pair','range','original','stable_pair')[self.round%6] if phased else None
                if self.phase=='stable_pair':role='anchor' if self.round%6==2 else 'scan'
                self.record={'protocol':1,'token':secrets.token_hex(16),'state':'prepare','round':self.round,
                             'leader_role':role,'window_seconds':self.window,'mode':self.mode}
                if phased:self.record.update(search_phase=self.phase,phase_protocol=1)
                self.at=None;self.role=None;changed=True
            elif self.record['state']=='prepare' and incoming.get('state')=='ack' and incoming.get('token')==self.record['token']:
                self.record={**self.record,'state':'go'};self.at=now;self.role=self.record['leader_role'];changed=True
        elif incoming.get('protocol')==1 and hexid(incoming.get('token')) and incoming.get('state') in ('prepare','go'):
            if type(incoming.get('round')) is not int or incoming['round']<0 or incoming.get('leader_role') not in ('anchor','scan','duplex'):return False,'invalid'
            if incoming['round']<self.round:return False,'stale'
            if incoming.get('state')=='prepare':
                if self.record.get('token')!=incoming['token']:
                    self.round=incoming['round'];self.record={'protocol':1,'token':incoming['token'],'state':'ack','round':self.round}
                    self.at=None;self.role=None;changed=True
            elif self.record.get('token')==incoming['token'] and self.record.get('state') in ('ack','running'):
                if self.record['state']=='ack':
                    self.round=incoming['round'];self.mode=incoming.get('mode');self.at=now
                    self.phase=incoming.get('search_phase') if incoming.get('phase_protocol')==1 and profile.get('search_phase_protocol')==1 else None
                    self.role='duplex' if incoming['leader_role']=='duplex' else 'scan' if incoming['leader_role']=='anchor' else 'anchor'
                    self.record={**self.record,'state':'running'};changed=True
        if self.at is not None and now-self.at>=self.window and not stable_rounds:self.role=None
        return changed,self.role or 'synchronizing'

class PortSchedule:
    """A reproducible permutation, advanced only for packets actually sent."""
    def __init__(self,key,ident):
        digest=hashlib.sha256(key+ident.encode()).digest()
        self.start=int.from_bytes(digest[:4],'big')%65535
        self.stride=int.from_bytes(digest[4:8],'big')%65535 or 1
        while math.gcd(self.stride,65535)!=1:self.stride=(self.stride+1)%65535 or 1
        self.position=0;self.round=None;self.anchor=None;self.tick=0;self.local_slot=0
    def choice(self,role,round_number,peer,source_count,public=True):
        seeds=list(dict.fromkeys(p for p in (endpoint(v,public) for v in peer.get('udp',[])[:8]) if p))
        preferred=endpoint((peer.get('profile') or {}).get('source_zero_observer_endpoint'),public)
        if preferred in seeds:seeds=[preferred]+[p for p in seeds if p!=preferred]
        if not seeds or not source_count:return None
        if round_number!=self.round:
            self.round=round_number;self.tick=0;self.local_slot=0
            seed=seeds[0];step=prediction_step(peer.get('profile'))
            offset=(0,20,8)[round_number%3]*step if step and not mapping_stable(peer.get('profile')) else 0
            port=max(1,min(65535,seed[1]+offset));self.anchor=(seed[0],port)
        if mapping_stable(peer.get('profile')) and self.anchor!=seeds[0]:self.anchor=seeds[0]
        if role in ('anchor','duplex'):return self.local_slot%source_count,self.anchor,False
        if role=='scan':
            # Keep some contact with observed candidates, independent of scans.
            if self.tick%5==0:return 0,seeds[0],False
            port=1+(self.start+self.position*self.stride)%65535
            return 0,(seeds[0][0],port),True
        return 0,seeds[0],False
    def sent(self,role,is_scan):
        self.tick+=1
        if role in ('anchor','duplex'):self.local_slot+=1
        if is_scan:self.position+=1
