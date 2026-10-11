"""AEAD, direction-specific sessions, fragmentation, replay rejection."""
import hashlib,hmac,secrets,struct,time
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
MAGIC=b'NPT1';HEADER=struct.Struct('!4s16s16s16s12s');FRAGMENT=struct.Struct('!QHHI')
MAX_DATAGRAM=1180;CHUNK=MAX_DATAGRAM-HEADER.size-16-FRAGMENT.size

class ReplayWindow:
    def __init__(self):self.high=-1;self.bits=0
    def accept(self,number):
        if number<0 or number>=2**63:return False
        if number>self.high:
            delta=number-self.high;self.bits=((self.bits<<delta)|1)&((1<<4096)-1) if delta<4096 else 1;self.high=number;return True
        offset=self.high-number
        if offset>=4096 or self.bits&(1<<offset):return False
        self.bits|=1<<offset;return True

class DataTransport:
    def __init__(self,root,ident,session,peer,peer_session):
        self.ident=bytes.fromhex(ident);self.session=bytes.fromhex(session);self.peer=bytes.fromhex(peer);self.peer_session=bytes.fromhex(peer_session)
        def key(a,b,sa,sb):return hmac.digest(root,b'NATPair-Tail-data-v1\0'+a+b+sa+sb,'sha256')
        self.tx=AESGCM(key(self.ident,self.peer,self.session,self.peer_session));self.rx=AESGCM(key(self.peer,self.ident,self.peer_session,self.session))
        self.prefix=secrets.token_bytes(4);self.sequence=0;self.message=0;self.window=ReplayWindow();self.parts={};self.dropped=0;self.last_metadata=None
    def encode(self,payload):
        if not isinstance(payload,bytes) or not 1<=len(payload)<=65507:raise ValueError('invalid Tailscale datagram size')
        count=(len(payload)+CHUNK-1)//CHUNK;self.message+=1;out=[]
        for index in range(count):
            self.sequence+=1;nonce=self.prefix+struct.pack('!Q',self.sequence)
            head=HEADER.pack(MAGIC,self.ident,self.peer,self.session,nonce)
            plain=FRAGMENT.pack(self.message,index,count,len(payload))+payload[index*CHUNK:(index+1)*CHUNK]
            out.append(head+self.tx.encrypt(nonce,plain,head))
        return out
    def decode(self,data,now=None):
        self.last_metadata=None
        now=time.monotonic() if now is None else now
        if not HEADER.size+16+FRAGMENT.size<len(data)<=MAX_DATAGRAM:self.dropped+=1;return None
        try:
            magic,sender,receiver,session,nonce=HEADER.unpack(data[:HEADER.size])
            if (magic,sender,receiver,session)!=(MAGIC,self.peer,self.ident,self.peer_session):raise ValueError('wrong peer/session')
            plain=self.rx.decrypt(nonce,data[HEADER.size:],data[:HEADER.size]);message,index,count,total=FRAGMENT.unpack(plain[:FRAGMENT.size])
            chunk=plain[FRAGMENT.size:]
            if not 1<=total<=65507 or count!=(total+CHUNK-1)//CHUNK or index>=count or len(chunk)!=min(CHUNK,total-index*CHUNK):raise ValueError('bad fragment')
            if not self.window.accept(struct.unpack('!Q',nonce[4:])[0]):raise ValueError('replay')
            self.last_metadata={'message_id':message,'fragment_index':index,'fragment_count':count,'native_bytes':total,'transport_sequence':struct.unpack('!Q',nonce[4:])[0]}
            self.parts={k:v for k,v in self.parts.items() if now-v['at']<3}
            if message not in self.parts:
                if len(self.parts)>=128:raise ValueError('reassembly budget full')
                self.parts[message]={'at':now,'total':total,'count':count,'chunks':{}}
            record=self.parts[message]
            if record['total']!=total or record['count']!=count:raise ValueError('fragment conflict')
            record['chunks'][index]=chunk
            if len(record['chunks'])==count:
                self.parts.pop(message);return b''.join(record['chunks'][i] for i in range(count))
        except Exception:self.dropped+=1
        return None

class FlowBudget:
    """Business uses an existing tuple: cap throughput without new NAT states."""
    def __init__(self,rate=1250000,burst=131072):self.rate=rate;self.burst=burst;self.credit=float(burst);self.at=time.monotonic()
    def admit(self,size,now=None):
        now=time.monotonic() if now is None else now;self.credit=min(self.burst,self.credit+max(0,now-self.at)*self.rate);self.at=now
        if size>self.credit:return False
        self.credit-=size;return True
