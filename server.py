"""Separate low-volume authenticated diagnostic service; no business relay."""
import argparse
import base64
import asyncio
import collections
import hashlib
import json
import pathlib
import secrets
import ssl
import time
from wire import pack,unpack,hexid,endpoint

class LabServer:
    def __init__(self,access,public=True):
        self.access=access;self.key=bytes.fromhex(access);self.public=public
        self.rooms={};self.udp=[];self.budget={};self.stats=collections.Counter();self.tickets={}
    def admit(self,ip):
        now=time.monotonic();at,left=self.budget.get(ip,(now,10.))
        left=min(10.,left+max(0,now-at)*20)
        self.budget[ip]=(now,max(0,left-1))
        if len(self.budget)>2048:self.budget={k:v for k,v in self.budget.items() if now-v[0]<60}
        return left>=1
    def udp_receive(self,data,addr,index):
        if not self.admit(addr[0]):return
        obj=unpack(self.key,data);member=None;key=self.key
        if obj is None and 38<=len(data)<=3536:
            try:hint=json.loads(data[4:-32])
            except (ValueError,TypeError):return
            if not isinstance(hint,dict):return
            member=self.tickets.get(hint.get('ticket_id'))
            if not member or time.monotonic()-member['last']>30:return
            key=bytes.fromhex(member['ticket']);obj=unpack(key,data)
        if not obj or obj.get('k') not in ('observe','cross') or not hexid(obj.get('n')):return
        self.stats['requests']+=1
        if member:
            slot=obj.get('slot')
            if type(slot) is not int or not 0<=slot<8 or obj.get('k')!='observe' or not hexid(obj.get('epoch')) or obj.get('epoch')!=member.get('epoch'):return
            if member.get('stage')=='main' and index!=0:return
            member['observed'][slot]={'slot':slot,'endpoint':list(addr),'nonce':obj['n'],'epoch':obj['epoch'],'at':time.monotonic()}
        reply=pack(key,{'k':'observed','n':obj['n'],'endpoint':list(addr),'source_index':index,'mode':obj['k'],'epoch':obj.get('epoch')})
        # No arbitrary destination: only reply to the authenticated source.
        sender=self.udp[1] if obj['k']=='cross' and index==0 else self.udp[index]
        if not getattr(self,'test_drop_observer_responses',False) and not (member and getattr(self,'test_drop_registered_responses',False)):
            sender.sendto(reply,addr);self.stats['responses']+=1
    def observations(self,member):
        now=time.monotonic()
        return [{'slot':v['slot'],'epoch':v['epoch'],'endpoint':v['endpoint'],'nonce':v['nonce'],'age_seconds':round(now-v['at'],3),'scope':'server_destination_only'}
                for v in member['observed'].values() if now-v['at']<15 and v['epoch']==member.get('epoch')]
    def peer_snapshot(self,member):
        observed=self.observations(member)
        udp=[v['endpoint'] for v in observed] if member.get('version')=='0.9.4-lab' else member['udp']
        reported=[]
        for r in ((member.get('profile') or {}).get('exit_observations') or {}).get('observations',[])[:32]:
            if isinstance(r,dict) and type(r.get('age_seconds')) in (int,float) and 0<=r['age_seconds']<30 and (p:=endpoint(r.get('endpoint'),self.public)):reported.append(list(p))
        if not udp:udp=list(dict.fromkeys(tuple(p) for p in reported))[:8]
        return {'id':member['id'],'name':member['name'],'udp':udp,'tcp':member['tcp'],'tcp_active':member['tcp_active'],'profile':member['profile'],
                'topology':member.get('topology','full_mesh'),'role':member.get('role','player'),
                'prepared':bool(member['prepared'] and member.get('stage')=='main' and udp),'epoch':member.get('epoch'),'version':member['version'],'udp_source':'server_observed' if observed else 'client_reported_stun' if reported else 'client_reported'}
    async def observe_tcp(self,reader,writer):
        try:
            line=await asyncio.wait_for(reader.readline(),4)
            obj=unpack(self.key,base64.b64decode(line.strip(),validate=True))
            if not obj or obj.get('k')!='tcp_observe' or not hexid(obj.get('n')):return
            result={'k':'observed','n':obj['n'],'endpoint':list(writer.get_extra_info('peername')[:2])}
            writer.write(base64.b64encode(pack(self.key,result))+b'\n');await writer.drain()
        except (ValueError,OSError,asyncio.TimeoutError):pass
        finally:writer.close()
    async def send(self,member,obj):
        async with member['lock']:
            writer=member['writer']
            if writer.is_closing():raise ConnectionError('control_writer_closing')
            try:writer.write(json.dumps(obj,separators=(',',':')).encode()+b'\n')
            except AttributeError:
                # CPython's SSL transport may discard its protocol while close
                # is racing a queued completion notification.
                if writer.is_closing():raise ConnectionError('control_writer_closed_during_send') from None
                raise
            await asyncio.wait_for(member['writer'].drain(),4)
    async def control(self,reader,writer):
        member=None;room=None;reason='rejected_join'
        try:
            obj=json.loads(await asyncio.wait_for(reader.readline(),10))
            if obj.get('k')=='control_health':
                if obj.get('access')!=self.access or not hexid(obj.get('nonce')):return
                padding=obj.get('padding','')
                if not isinstance(padding,str) or len(padding)>4096:return
                writer.write(json.dumps({'k':'control_ready','nonce':obj['nonce'],'padding':padding},separators=(',',':')).encode()+b'\n')
                await asyncio.wait_for(writer.drain(),4)
                obj=json.loads(await asyncio.wait_for(reader.readline(),10))
            room=obj.get('room');ident=obj.get('id');name=obj.get('name')
            if obj.get('access')!=self.access or not hexid(room,64) or not hexid(ident) or not isinstance(name,str) or not 1<=len(name)<=32:return
            members=self.rooms.setdefault(room,{})
            previous=members.get(ident);resume=obj.get('resume')
            if not hexid(resume):return
            run=obj.get('run',0)
            if type(run) is not int or run<0:return
            if (previous and (previous.get('resume')!=resume or run<previous.get('run',0))) or (not previous and len(members)>=2):
                writer.write(b'{"error":"diagnostic_room_limit_two"}\n');await writer.drain();return
            if previous:
                self.tickets.pop(previous['ticket_id'],None);previous['writer'].close()
            ticket=secrets.token_hex(32);ticket_id=hashlib.sha256(bytes.fromhex(ticket)).hexdigest()
            member={'id':ident,'name':name,'writer':writer,'lock':asyncio.Lock(),'udp':[], 'tcp':[], 'profile':None,'last':time.monotonic(),
                    'resume':resume,'run':run,'epoch':None,'stage':'measurement','ticket':ticket,'ticket_id':ticket_id,'observed':{},'prepared':False,'version':obj.get('version','0.9-lab'),'tcp_active':[]}
            members[ident]=member
            self.tickets[ticket_id]=member
            await self.send(member,{'k':'joined','id':ident,'observer_ticket':ticket,'server_version':'0.9.4-lab'})
            reason='peer_eof';print(json.dumps({'event':'control_joined','id':ident,'resumed':bool(previous)}),flush=True)
            while True:
                line=await asyncio.wait_for(reader.readline(),120)
                if not line:break
                obj=json.loads(line);kind=obj.get('k');member['last']=time.monotonic()
                if kind=='stage' and hexid(obj.get('epoch')) and obj.get('stage') in ('measurement','main'):
                    if member['epoch']!=obj['epoch']:
                        member['observed'].clear();member['prepared']=False
                    member['epoch']=obj['epoch'];member['stage']=obj['stage']
                if kind=='profile':
                    # Clients authenticate to the private coordinator. Candidate
                    # targets must be public IPv4 and are bounded; never scan arbitrary hosts.
                    udp=[endpoint(p,self.public) for p in obj.get('udp',[])[:16]]
                    tcp=[endpoint(p,self.public) for p in obj.get('tcp',[])[:8]]
                    member['udp']=[list(p) for p in udp if p];member['tcp']=[list(p) for p in tcp if p]
                    active=[endpoint(p,self.public) for p in obj.get('tcp_active',[])[:1]]
                    member['tcp_active']=[list(p) for p in active if p]
                    profile=obj.get('profile')
                    member['profile']=profile if isinstance(profile,dict) and len(json.dumps(profile))<24000 else {}
                    member['prepared']=obj.get('prepared') is True
                if kind in ('profile','poll'):
                    peers=[self.peer_snapshot(m) for m in members.values() if m is not member]
                    await self.send(member,{'k':'peers','peers':peers,'self_udp':self.observations(member),'self_id':ident})
                elif kind=='notice':
                    # Reporting control only, not a path counted as direct.
                    for m in list(members.values()):
                        if m is not member:
                            try:await self.send(m,{'k':'notice','peer':ident,'message':str(obj.get('message',''))[:500]})
                            except (OSError,asyncio.TimeoutError):
                                print(json.dumps({'event':'notice_recipient_closed','id':m['id']}),flush=True)
        except (ValueError,KeyError,TypeError,OSError,asyncio.TimeoutError) as exc:reason=type(exc).__name__
        finally:
            if member:
                print(json.dumps({'event':'control_closed','id':member['id'],'reason':reason}),flush=True)
                self.tickets.pop(member['ticket_id'],None)
                members=self.rooms.get(room,{})
                if members.get(member['id']) is member:members.pop(member['id'],None)
                if not members:self.rooms.pop(room,None)
            writer.close()

class Observer(asyncio.DatagramProtocol):
    def __init__(self,service,index):self.service,self.index=service,index
    def connection_made(self,transport):self.service.udp.append(transport)
    def datagram_received(self,data,addr):self.service.udp_receive(data,addr,self.index)

async def start(service,host,base,control,cert,key,extra_control_host=None):
    loop=asyncio.get_running_loop();listeners=[]
    try:
        for i in range(8):
            transport,_=await loop.create_datagram_endpoint(lambda i=i:Observer(service,i),local_addr=(host,base+i))
            listeners.append(transport)
            tcp=await asyncio.start_server(service.observe_tcp,host,base+i,limit=4096)
            listeners.append(tcp)
            print('observer ready',i,transport.get_extra_info('sockname'),[s.getsockname() for s in tcp.sockets],flush=True)
        ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);ctx.minimum_version=ssl.TLSVersion.TLSv1_2;ctx.load_cert_chain(cert,key)
        listeners.append(await asyncio.start_server(service.control,host,control,ssl=ctx,limit=32768))
        if extra_control_host and extra_control_host!=host:
            listeners.append(await asyncio.start_server(service.control,extra_control_host,control,ssl=ctx,limit=32768))
        if getattr(service,'room_udp_port',None):
            from roomudp import RoomUDPServer
            for address in dict.fromkeys([host,extra_control_host]):
                if address:
                    transport,_=await loop.create_datagram_endpoint(lambda:RoomUDPServer(service),local_addr=(address,service.room_udp_port))
                    listeners.append(transport)
        return listeners
    except BaseException:
        for listener in listeners:listener.close()
        raise

async def main():
    parser=argparse.ArgumentParser();parser.add_argument('--config',required=True);parser.add_argument('--cert',required=True);parser.add_argument('--key',required=True)
    args=parser.parse_args();cfg=json.loads(pathlib.Path(args.config).read_text())
    service=LabServer(cfg['access']);service.room_udp_port=cfg.get('room_udp_port');listeners=await start(service,'204.152.206.124',39601,39610,args.cert,args.key,cfg.get('control_tail_bind'))
    print('NATPair Lab v0.9.4 diagnostic listeners ready',flush=True)
    await asyncio.Event().wait()
if __name__=='__main__':asyncio.run(main())
