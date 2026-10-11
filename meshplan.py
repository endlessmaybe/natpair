"""Coordinator leases a matching of pairs; connected edges never scan again."""
import hashlib,itertools,secrets,time
from wire import hexid

def pair_key(a,b):return ':'.join(sorted((a,b)))
def generations(a,b):return {m['id']:(m.get('profile') or {}).get('generation') for m in (a,b)}

class MeshPlanner:
    def __init__(self,window=120):
        self.window=max(1,float(window));self.active={};self.served={};self.serial=0;self.departures={}
    def leave(self,ident,generation):
        self.departures[ident]={'generation':generation,'at':time.monotonic()}
    def report(self,a,b):
        p=(a.get('profile') or {}).get('links',{}).get(b['id'],{})
        return p if p.get('peer_generation')==(b.get('profile') or {}).get('generation') else {}
    def complete(self,a,b):
        x,y=self.report(a,b),self.report(b,a)
        return (x.get('udp_live') and y.get('udp_live')) or any(
            p.get('native_verified') and p.get('native_route') in ('ipv4','ipv6') for p in (x,y))
    def snapshot(self,members,now=None):
        now=time.monotonic() if now is None else now
        live={i:m for i,m in members.items() if now-m['last']<15}
        valid={i:m for i,m in live.items() if hexid((m.get('profile') or {}).get('generation'))}
        all_valid={i:m for i,m in members.items() if hexid((m.get('profile') or {}).get('generation'))}
        topology=next((m.get('topology','full_mesh') for m in members.values()),'full_mesh')
        hosts=[m for m in all_valid.values() if m.get('role')=='host'] if topology=='star' else []
        host=hosts[0] if len(hosts)==1 else None
        def eligible(group):
            return {pair_key(a['id'],b['id']):(a,b) for a,b in itertools.combinations(group.values(),2)
                if topology!='star' or host and host['id'] in (a['id'],b['id'])}
        pairs=eligible(valid);all_pairs=eligible(all_valid)
        completed={k for k,(a,b) in all_pairs.items() if (a['id'] in live or b['id'] in live) and self.complete(a,b)}
        for key,task in list(self.active.items()):
            nodes=pairs.get(key)
            if (nodes and task['generations']==generations(*nodes) and key not in completed and
                task['state']=='go' and now>=task['until'] and len(set(pairs)-completed)<=1):
                # With a single pending edge there is no fairness benefit in
                # throwing away the negotiated task every two minutes.
                task['until']=now+self.window
            if not nodes or task['generations']!=generations(*nodes) or key in completed or now>=task['until']:
                self.active.pop(key);self.served[key]=now
                continue
            if task['state']=='prepare' and all(task['id'] in (m.get('profile') or {}).get('prepared_tasks',[]) for m in nodes):
                task.update(state='go',until=now+self.window);self.served[key]=now
        busy={i for t in self.active.values() for i in t['members']}
        ordered=sorted((k for k in pairs if k not in completed and k not in self.active),key=lambda k:(self.served.get(k,-1e30),k))
        for key in ordered:
            a,b=pairs[key]
            if a['id'] in busy or b['id'] in busy:continue
            self.serial+=1
            self.active[key]={'id':secrets.token_hex(16),'pair':key,'members':sorted((a['id'],b['id'])),
                'generations':generations(a,b),'state':'prepare','until':now+30,'serial':self.serial}
            busy.update((a['id'],b['id']))
        self.served={k:v for k,v in self.served.items() if k in pairs}
        self.departures={i:d for i,d in self.departures.items() if now-d['at']<120}
        return {'protocol':1,'members':sorted(members),'fresh_members':sorted(live),'departures':self.departures,
                'topology':topology,'supported_topologies':['full_mesh','star'],
                'host_id':host['id'] if host else None,'host_generation':(host.get('profile') or {}).get('generation') if host else None,
                'host_name':host.get('name','') if host else '',
                'host_tail_ip':((host.get('profile') or {}).get('tail') or {}).get('tail_ip','') if host else '',
                'game_port':host.get('game_port',25565) if host else None,
                'possible_pairs':len(all_pairs),'completed_pairs':len(completed),
                'window_seconds':self.window,'tasks':[{k:v for k,v in t.items() if k!='until'}|{'remaining_seconds':round(max(0,t['until']-now),3)} for t in self.active.values()]}
