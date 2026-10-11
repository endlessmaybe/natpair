"""Final-binary regression: real UDP/AEAD with one unavailable bootstrap capture.

Native endpoints and discovery packets are synthetic. This is not a native
Tailscale authentication or real WinDivert driver-open test.
"""
import hashlib,queue,secrets,socket,struct,time
from tailbridge import TailBridge,DISCO
from transport import DataTransport

class Journal:
    def __init__(self):self.rows=[]
    def record(self,**kw):self.rows.append(kw)

class Capture:
    def __init__(self,*args):self.q=queue.Queue()
    def recv(self):
        item=self.q.get()
        if item is None:raise OSError('closed')
        return item
    def close(self):self.q.put(None)

class ResourceError(OSError):
    winerror=1450

def run():
    sockets=[];bridges=[];attempts=[];events=[];journals=[Journal(),Journal()]
    report={'version':'1.0.18-tail','passed':False,'scope':'real local UDP, AEAD fragmentation, native proxy sockets; synthetic native peers and injected capture failure; no native Tailscale authentication or real driver open'}
    try:
        for _ in range(4):
            s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.bind(('127.0.0.1',0));s.settimeout(2);sockets.append(s)
        native=sockets[:2];outer=sockets[2:]
        def fail(*args):attempts.append(args);raise ResourceError('injected WinDivertOpen 1450')
        for i in range(2):
            meta={'node_key':str(i),'expected_peer_key':str(1-i),'disco_key':'discokey:'+str(i+1)*64,
                'udp_port':native[i].getsockname()[1],'peer_endpoints':[['1.1.1.1',41641]],'peer_tail_ip':'100.1.1.'+str(2-i)}
            b=TailBridge(meta,lambda e,**kw:events.append({'event':e,**kw}),journals[i],Capture if i==0 else fail)
            # The synthetic failure must not open/probe the actual kernel driver.
            b._diagnose=lambda:None;bridges.append(b)
        for i,b in enumerate(bridges):b.bind_peer(bridges[1-i].metadata);b.start()
        root=secrets.token_bytes(32);a,sa,b,sb=[secrets.token_hex(16) for _ in range(4)]
        transports=[DataTransport(root,a,sa,b,sb),DataTransport(root,b,sb,a,sa)]
        def forward(i,payload):
            recovered=None
            for frame in transports[i].encode(payload):
                outer[i].sendto(frame,outer[1-i].getsockname())
                data,source=outer[1-i].recvfrom(65535)
                assert source==outer[i].getsockname()
                recovered=transports[1-i].decode(data) or recovered
            assert recovered==payload
            assert bridges[1-i].deliver(recovered)
            data,source=native[1-i].recvfrom(65535)
            assert data==payload and source==bridges[1-i].socket.getsockname()
        # A current runtime public key need not match either SelfNode snapshot.
        # Regress the actual v116 failure in the final executable as well.
        discovery=DISCO+bytes.fromhex('33'*32)+secrets.token_bytes(40)
        # Exercise the capture thread's current-source/current-peer scope checks.
        total=28+len(discovery)
        packet=struct.pack('!BBHHHBBH4s4s',0x45,0,total,1,0,64,17,0,socket.inet_aton('127.0.0.1'),socket.inet_aton('1.1.1.1'))
        packet+=struct.pack('!4H',native[0].getsockname()[1],41641,8+len(discovery),0)+discovery
        bridges[0].capture.q.put(packet)
        payload,origin=bridges[0].outbound.get(timeout=2);assert origin=='bootstrap_copy';forward(0,payload)
        reply=DISCO+bytes.fromhex('44'*32)+secrets.token_bytes(40)
        native[1].sendto(reply,bridges[1].socket.getsockname());time.sleep(.01);bridges[1].poll()
        payload,origin=bridges[1].next_outbound();assert origin=='tailscale_local_proxy';forward(1,payload)
        sizes=[]
        for i,size in ((0,1280),(1,1440),(0,65504),(1,1280)):
            payload=struct.pack('<I',4)+secrets.token_bytes(size-4)
            native[i].sendto(payload,bridges[i].socket.getsockname());time.sleep(.01);bridges[i].poll()
            queued,origin=bridges[i].next_outbound();assert queued==payload and origin=='tailscale_local_proxy'
            forward(i,payload);sizes.append(size)
        for offset in range(8):
            bridges[1].refresh({**bridges[1].metadata,'peer_endpoints':[['1.1.1.1',42000+offset]]})
            bridges[1].service_capture(time.monotonic()+1000)
        assert len(attempts)==1 and all(b.enabled and b.bootstrap_stopped.is_set() for b in bridges)
        assert all(b.stats['tail_tx_wg_datagrams']==0 for b in bridges) # counted by client only
        assert all(b.stats['tail_rx_wg_datagrams']>=2 for b in bridges)
        assert all(any(row.get('direction')=='tail_deliver' for row in j.rows) for j in journals)
        assert not any(row.get('direction')=='tail_deliver_rejected' for j in journals for row in j.rows)
        assert bridges[0].stats['tail_peer_disco_snapshot_mismatches']==1
        assert bridges[1].stats['tail_peer_disco_snapshot_mismatches']==1
        assert all(any(r.get('disco_sender_key') for r in j.rows if r.get('direction')=='tail_deliver') for j in journals)
        report.update(passed=True,injected_error=1450,capture_attempts=len(attempts),forwarded_data_sizes=sizes,
            stale_disco_snapshots_forwarded=True,public_sender_keys_recorded=True,
            bridge_states=[b.snapshot() for b in bridges],native_delivery_counts=[b.stats['tail_rx_datagrams'] for b in bridges],
            journal_digests=[[row.get('sha256') for row in j.rows if row.get('direction')=='tail_deliver'] for j in journals])
    except Exception as exc:report['error']=repr(exc)
    finally:
        for b in bridges:b.close()
        for s in sockets:s.close()
    report['closed_cleanly']=all(b.socket.fileno()==-1 and (b.thread is None or not b.thread.is_alive()) for b in bridges)
    report['passed']=report['passed'] and report['closed_cleanly']
    return report

def run_repeated(count=5):
    import gc,threading
    from driverdiag import resources
    cycles=[]
    for _ in range(count):
        report=run();gc.collect()
        report['process_handles']=resources().get('own_process_handles');report['threads_after_cleanup']=len(threading.enumerate());cycles.append(report)
    handles=[c['process_handles'] for c in cycles if c['process_handles'] is not None]
    no_growth=not handles or max(handles)-min(handles)<=3
    return {'passed':all(c['passed'] and c['threads_after_cleanup']==1 for c in cycles) and no_growth,
        'version':'1.0.18-tail','cycles':cycles,'handles_stable':no_growth,
        'scope':'five bridge lifecycles in one executable process; synthetic capture failure 1450; real local UDP and AEAD, synthetic native Tailscale packets'}
