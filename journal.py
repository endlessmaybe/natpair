"""Bounded packet metadata journal and a separate immutable first-hit proof."""
import collections,datetime,json,pathlib,threading,time

class PacketJournal:
    def __init__(self,directory,ident,limit=32*1024*1024,segments=8):
        self.directory=pathlib.Path(directory)/('session-'+datetime.datetime.now().strftime('%Y%m%d-%H%M%S-%f')+'-'+ident[:8])
        self.directory.mkdir(parents=True,exist_ok=False)
        self.limit=limit;self.segments=segments;self.index=0;self.sequence=0;self.size=0
        self.lock=threading.Lock();self.recent=collections.deque(maxlen=600);self.file=None;self.error=None;self.proof_path=None;self.flushed_at=0
        self.opening=(self.directory/'opening-exchanges.jsonl').open('w',encoding='utf-8');self.opening_count=0;self.peer_arrived=False
        try:self._open()
        except (OSError,ValueError):
            try:self.opening.close()
            except (OSError,ValueError):pass
            self.opening=None;raise
    def _open(self):
        if self.file:self.file.close()
        path=self.directory/f'packets-{self.index:04d}.jsonl';self.file=path.open('w',encoding='utf-8',buffering=65536);self.size=0
        stale=self.directory/f'packets-{self.index-self.segments:04d}.jsonl'
        if stale.exists():stale.unlink()
    def record(self,**fields):
        with self.lock:
            self.sequence+=1
            item={'journal_seq':self.sequence,'wall_ns':time.time_ns(),'mono_ns':time.monotonic_ns(),**fields}
            line=json.dumps(item,separators=(',',':'),ensure_ascii=True)+'\n';self.recent.append(item)
            try:
                if self.file is None:return item
                if self.size+len(line)>self.limit:self.index+=1;self._open()
                self.file.write(line);self.size+=len(line)
                if fields.get('accepted') and fields.get('kind') in ('probe','ack') and fields.get('direction')=='rx':self.peer_arrived=True
                if self.peer_arrived and fields.get('accepted') and fields.get('kind') in ('probe','ack') and self.opening_count<10000:
                    self.opening.write(line);self.opening_count+=1
                if time.monotonic()-self.flushed_at>=1:
                    self.file.flush();self.opening.flush();self.flushed_at=time.monotonic()
            except (OSError,ValueError) as exc:
                self.error=str(exc)
                for stream in (self.file,self.opening):
                    if stream:
                        try:stream.close()
                        except (OSError,ValueError):pass
                self.file=self.opening=None
            return item
    def proof(self,tx,rx,context):
        with self.lock:
            if self.proof_path:return
            if self.error and self.file is None:return
            path=self.directory/'first-hit-proof.json'
            data={'version':1,'source':'authenticated_nonce_correlation','tx':tx,'rx':rx,'context':context,'recent_metadata':list(self.recent)}
            try:
                if self.file:self.file.flush()
                if self.opening:self.opening.flush()
                path.write_text(json.dumps(data,ensure_ascii=True,indent=2),encoding='utf-8');self.proof_path=str(path)
            except OSError as exc:self.error=str(exc)
    def close(self):
        with self.lock:
            for stream in (self.file,self.opening):
                if stream:
                    try:stream.close()
                    except (OSError,ValueError) as exc:self.error=str(exc)
            self.file=self.opening=None
    def flush(self):
        with self.lock:
            if self.file:self.file.flush()
            if self.opening:self.opening.flush()

class NullJournal:
    directory=None;proof_path=None;error=None
    def record(self,**fields):return fields
    def proof(self,*args):pass
    def close(self):pass
    def flush(self):pass
