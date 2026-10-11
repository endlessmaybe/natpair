"""Read only Bifrost's health trace. Never control its service or network."""
import datetime
import os
import pathlib
import threading
import time

class Coexistence:
    def __init__(self, enabled=False, path=None):
        self.enabled=enabled
        self.path=pathlib.Path(path or os.path.join(os.environ.get('PROGRAMDATA','C:/ProgramData'),'Bifrost','live-service-trace.log'))
        self.offset=None;self.identity=None;self.partial=b'';self.status='disabled' if not enabled else 'starting'
        self.soft_times=[];self.seen=set();self.until=0.;self.recovery_until=0.;self.last_signal=None;self.lock=threading.Lock()
    def signal(self, line, now, wall=None):
        # Never retain raw lines, node names, credentials, or other user data.
        if not self.enabled:return
        try:
            date,message=line.split('|',3)[0],line.split('|',3)[3]
            stamp=datetime.datetime.fromisoformat(date).timestamp()
        except (ValueError,IndexError):return
        age=(time.time() if wall is None else wall)-stamp
        if age < -5 or age > 120:return
        reason=None
        for marker in ('runtime-dataplane-miss','runtime-mihomo-readback-transient-unhealthy',
                       'runtime-connect-failed','runtime-mihomo-cutover-reselected',
                       'command-start action=disconnect','command-start action=connect'):
            if marker in message:reason=marker;break
        if reason:
            with self.lock:
                identity=(stamp,reason)
                if identity in self.seen:return
                self.seen={x for x in self.seen if (time.time() if wall is None else wall)-x[0]<120};self.seen.add(identity)
                soft=reason=='runtime-mihomo-readback-transient-unhealthy' or (reason=='runtime-dataplane-miss' and 'candidate-unhealthy=True' not in message)
                if soft:
                    self.soft_times=[t for t in self.soft_times if stamp-t<15];self.soft_times.append(stamp)
                severe=not soft or len(self.soft_times)>=3
                duration=90 if severe else 5
                expiry=now+max(0,duration-max(0,age))
                self.until=max(self.until,expiry)
                if expiry>now:self.recovery_until=max(self.recovery_until,expiry+(120 if severe else 10))
                self.last_signal=reason
    def poll(self, now=None, wall=None):
        if not self.enabled:return
        now=time.monotonic() if now is None else now
        try:
            with self.path.open('rb') as f:
                stat=os.fstat(f.fileno());identity=(stat.st_dev,stat.st_ino)
                reset=self.offset is None or identity!=self.identity or stat.st_size<self.offset
                if reset:
                    self.offset=max(0,stat.st_size-32768);self.partial=b''
                f.seek(self.offset);data=f.read(32768);self.offset=f.tell();self.identity=identity
                if reset and self.offset-len(data)>0:data=data.partition(b'\n')[2]
            rows=(self.partial+data).split(b'\n');self.partial=rows.pop()[-4096:]
            for raw in rows:self.signal(raw.decode('utf-8','replace'),now,wall)
            self.status='trace_monitoring'
        except FileNotFoundError:self.status='trace_not_available'
        except OSError:self.status='trace_unreadable'
    def snapshot(self, now):
        with self.lock:
            return {'monitor':self.status,'pause':bool(self.enabled and now<self.until),
                    'remaining_seconds':max(0,int(self.until-now+.999)),
                    'recovering':bool(self.enabled and self.until<=now<self.recovery_until),
                    'last_signal':self.last_signal}
    def run(self, stop):
        while not stop.is_set():
            self.poll()
            if stop.wait(1):break
