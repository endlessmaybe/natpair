"""Local loopback fixtures shared by the current NATPair Mesh tests."""
import asyncio, datetime, hashlib, pathlib, secrets, threading, time
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from server import LabServer, start
from roomudp import RoomUDPServer

ROOT = pathlib.Path(__file__).parent

class Service:
    def __init__(self):
        assets=ROOT/'test-assets'/secrets.token_hex(8);assets.mkdir(parents=True,exist_ok=True)
        key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
        subject=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'localhost')]);now=datetime.datetime.now(datetime.timezone.utc)
        cert=x509.CertificateBuilder().subject_name(subject).issuer_name(subject).public_key(key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(now-datetime.timedelta(days=1)).not_valid_after(now+datetime.timedelta(days=1)).sign(key,hashes.SHA256())
        self.cert=assets/'cert.pem';self.keyfile=assets/'key.pem'
        self.cert.write_bytes(cert.public_bytes(serialization.Encoding.PEM));self.keyfile.write_bytes(key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
        self.access=secrets.token_hex(32);self.service=LabServer(self.access,public=False);self.loop=asyncio.new_event_loop();self.ready=threading.Event();self.error=None
        self.unhandled=[];self.loop.set_exception_handler(lambda loop,context:self.unhandled.append(context))
        self.cfg={'host':'127.0.0.1','access':self.access,'pin':hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest(),'public_only':False,'stun_hosts':[],'bind':'127.0.0.1','if_index':0,'duration':10,'lab_sockets':2}
        self.thread=threading.Thread(target=self.run,daemon=True);self.thread.start();assert self.ready.wait(10)
        if self.error:raise self.error
    def run(self):
        asyncio.set_event_loop(self.loop)
        async def begin():
            for _ in range(30):
                # Avoid consecutive Windows ephemeral ports left in TIME_WAIT
                # by previous reflection tests; isolate the listener range.
                base=20000+secrets.randbelow(24000)
                if base>65520:continue
                try:
                    self.listeners=await start(self.service,'127.0.0.1',base,base+9,str(self.cert),str(self.keyfile))
                    self.cfg.update(lab_udp_base=base,lab_control_port=base+9);return
                except OSError:self.service.udp=[]
            raise RuntimeError('No free observer range')
        try:self.loop.run_until_complete(begin())
        except Exception as e:self.error=e
        self.ready.set()
        if not self.error:self.loop.run_forever()
    def stop(self):
        async def close():
            for m in list(self.service.rooms.values()):
                for client in list(m.values()):client['writer'].close()
            for listener in self.listeners:listener.close()
            await asyncio.sleep(.1)
        asyncio.run_coroutine_threadsafe(close(),self.loop).result(10);self.loop.call_soon_threadsafe(self.loop.stop);self.thread.join(10);self.loop.close()
        assert not self.unhandled,self.unhandled

def udp_service():
    service=Service()
    async def listen():
        return await service.loop.create_datagram_endpoint(lambda:RoomUDPServer(service.service),local_addr=('127.0.0.1',0))
    transport,protocol=asyncio.run_coroutine_threadsafe(listen(),service.loop).result(3)
    service.listeners.append(transport);service.cfg['room_udp_port']=transport.get_extra_info('sockname')[1]
    service.cfg.update(fast_start=True,unlimited_search=True,production_mode=True,raw_tcp_experiment=False,
                       immediate_challenge=True,fast_center_search=True,control_reply_timeout=.3)
    return service,protocol

def until(predicate,seconds=8):
    end=time.monotonic()+seconds
    while time.monotonic()<end:
        if predicate():return True
        time.sleep(.02)
    return False
