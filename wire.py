import hashlib
import hmac
import ipaddress
import json
import secrets
import struct

MAGIC=b'NPL9'
def canonical(obj):return json.dumps(obj,separators=(',',':'),sort_keys=True).encode()
def pack(key,obj):
    body=canonical(obj)
    if len(body)>3500:raise ValueError('frame too large')
    return MAGIC+body+hmac.digest(key,body,'sha256')
def unpack(key,data):
    if not data.startswith(MAGIC) or not 38<=len(data)<=3536:return None
    body,tag=data[4:-32],data[-32:]
    if not hmac.compare_digest(tag,hmac.digest(key,body,'sha256')):return None
    try:
        obj=json.loads(body)
        return obj if isinstance(obj,dict) else None
    except (ValueError,TypeError):return None
def hexid(value,size=32):return isinstance(value,str) and len(value)==size and all(c in '0123456789abcdef' for c in value)
def endpoint(value,public=True):
    try:
        ip,port=value
        addr=ipaddress.ip_address(ip)
        if addr.version!=4 or (public and not addr.is_global) or type(port) is not int or not 1<=port<=65535:return None
        return str(addr),port
    except (ValueError,TypeError):return None
def room_keys(code):
    value=''.join(code.upper().split()).replace('-','')
    if not 20<=len(value)<=100 or not value.isalnum():raise ValueError('房间码至少 20 位字母或数字')
    key=hashlib.sha256(b'NATPair-Lab-v09:'+value.encode()).digest()
    return hashlib.sha256(key).hexdigest(),key
def pattern(ports):
    # Six training samples, two independent future destinations as holdout.
    if len(ports)!=8 or any(type(p) is not int or not 1<=p<=65535 for p in ports):
        return {'validated':False,'reason':'eight_complete_samples_required'}
    differences=[ports[i+1]-ports[i] for i in range(5)]
    step=differences[0]
    if abs(step)>128 or any(d!=step for d in differences):
        return {'validated':False,'reason':'training_not_consistent'}
    predicted=[ports[5]+step,ports[5]+2*step]
    good=predicted==ports[6:]
    return {'validated':good,'step':step,'holdout_expected':predicted,'holdout_observed':ports[6:],
            'reason':'holdout_passed' if good else 'holdout_failed',
            'scope':'same_observer_ip_new_destination_ports; peer allocation still unproven'}

COOKIE=0x2112a442
def stun_request(transaction,change=0):
    body=struct.pack('!HHI',3,4,change) if change else b''
    return struct.pack('!HHI',1,len(body),COOKIE)+transaction+body
def parse_stun(data,transaction):
    if len(data)<20:return None
    kind,length,cookie=struct.unpack('!HHI',data[:8])
    if kind!=0x101 or cookie!=COOKIE or data[8:20]!=transaction or length%4 or len(data)!=20+length:return None
    out={};offset=20
    while offset<len(data):
        if offset+4>len(data):return None
        typ,size=struct.unpack('!HH',data[offset:offset+4]);offset+=4
        if offset+size>len(data):return None
        value=data[offset:offset+size];offset+=(size+3)&~3
        if typ in (1,0x20,0x802b,0x802c) and len(value)==8 and value[1]==1:
            port=struct.unpack('!H',value[2:4])[0];ipbytes=value[4:8]
            if typ==0x20:
                port^=COOKIE>>16;ipbytes=bytes(a^b for a,b in zip(ipbytes,struct.pack('!I',COOKIE)))
            out[{1:'mapped',0x20:'mapped',0x802b:'origin',0x802c:'other'}[typ]]=(str(ipaddress.IPv4Address(ipbytes)),port)
    return out if 'mapped' in out else None
