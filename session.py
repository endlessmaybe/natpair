"""One window owns one room identity and serializes complete run cleanup."""
import hashlib,json,os,pathlib,secrets,socket,threading
from client import LabClient

class SessionRunner:
    def __init__(self,emit,identity_path=None,factory=LabClient):
        self.emit=emit;self.factory=factory;self.lock=threading.RLock();self.client=None;self.thread=None
        self.phase='idle';self.generation=0;self.path=pathlib.Path(identity_path) if identity_path else None
        device=hashlib.sha256((socket.gethostname()+'\0'+os.environ.get('USERNAME','')).encode()).hexdigest()
        self.identity={'device':device,'id':secrets.token_hex(16),'resume':secrets.token_hex(16),'run':0}
        if self.path and self.path.is_file():
            try:
                d=json.loads(self.path.read_text(encoding='utf8'))
                if d.get('device')==device and all(isinstance(d.get(k),str) and len(d[k])==32 and all(c in '0123456789abcdef' for c in d[k]) for k in ('id','resume')) and type(d.get('run')) is int and d['run']>=0:self.identity=d
            except (OSError,ValueError):pass
    def start(self,cfg,code,name,measure_only=False):
        with self.lock:
            if self.thread and self.thread.is_alive():raise RuntimeError('上一轮仍在停止清理，请等待“清理完成”后再加入')
            self.generation+=1;generation=self.generation;self.identity['run']+=1
            if self.path:
                self.path.parent.mkdir(parents=True,exist_ok=True)
                pending=self.path.with_suffix('.pending');pending.write_text(json.dumps(self.identity),encoding='utf8');pending.replace(self.path)
            def emit(obj):self.emit({**obj,'generation':generation})
            c=self.factory(dict(cfg),code,name,emit,member_id=self.identity['id'],resume=self.identity['resume'],run_number=self.identity['run'])
            self.client=c;self.phase='running'
            def work():
                try:c.run(measure_only)
                finally:
                    with self.lock:self.phase='idle'
                    emit({'event':'session_closed','message':'本轮线程、连接与接入资源清理完成，可以重新加入'})
            self.thread=threading.Thread(target=work,name=f'NATPair-session-{generation}',daemon=True)
            self.thread.start();return c
    def stop(self):
        with self.lock:
            if self.client and self.thread and self.thread.is_alive():
                self.phase='stopping';self.client.stop.set()
    def running(self):return bool(self.thread and self.thread.is_alive())
