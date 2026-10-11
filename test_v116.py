import ctypes,queue,secrets,socket,time,unittest
from unittest.mock import patch
from bridgecheck import run,ResourceError,Capture,Journal
from tailbridge import TailBridge,DISCO,WinSniffer,compact_filter,load_driver,BASE
from test_tail import ip_packet
from health import native_label

class PassiveTests(unittest.TestCase):
    def test_full_clients_bridge_when_peer_driver_open_fails(self):
        from test_tail import TailTests
        TailTests.run_native_tunnel_case(self,passive_peer=True)
    def bridge(self,factory=None):
        native=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);native.bind(('127.0.0.1',0));native.settimeout(.2);self.addCleanup(native.close)
        meta={'node_key':'a','expected_peer_key':'b','disco_key':'discokey:'+'11'*32,'udp_port':native.getsockname()[1],
            'peer_endpoints':[['1.1.1.1',41641]],'peer_tail_ip':'100.1.1.2'}
        events=[];j=Journal();b=TailBridge(meta,lambda e,**kw:events.append((e,kw)),j,factory or Capture)
        b._diagnose=lambda:None;self.addCleanup(b.close)
        b.bind_peer({'node_key':'b','expected_peer_key':'a','disco_key':'discokey:'+'22'*32});b.start()
        return b,native,j,events
    def test_real_udp_encrypted_passive_bootstrap_and_fragmented_data(self):
        report=run();self.assertTrue(report['passed'],report);self.assertEqual(report['capture_attempts'],1)
    def test_failed_capture_does_not_disable_local_delivery(self):
        def fail(*args):raise ResourceError('1450')
        b,n,j,events=self.bridge(fail)
        self.assertTrue(b.enabled);self.assertIsNone(b.capture)
        payload=DISCO+bytes.fromhex('22'*32)+secrets.token_bytes(40)
        self.assertTrue(b.deliver(payload));self.assertEqual(n.recvfrom(65535)[0],payload)
        self.assertTrue(b.snapshot()['proxy_ready']);self.assertEqual(b.stats['tail_rx_disco_datagrams'],1)
        self.assertIn('tail_capture_unavailable',[e for e,_ in events])
    def test_failed_capture_keeps_backoff_across_metadata_refresh(self):
        calls=[]
        def fail(*args):calls.append(args);raise ResourceError('1450')
        b,n,j,events=self.bridge(fail)
        first=b.capture_retry_at
        for p in range(42000,42010):b.refresh({**b.metadata,'peer_endpoints':[['1.1.1.1',p]]})
        b.service_capture(first-.1);self.assertEqual(len(calls),1)
        b.service_capture(first+.1);self.assertEqual(len(calls),2);self.assertGreaterEqual(b.capture_retry_at-first,60)
    def test_passive_return_cancels_further_driver_retries(self):
        calls=[]
        def fail(*args):calls.append(args);raise ResourceError('1450')
        b,n,j,events=self.bridge(fail)
        n.sendto(DISCO+bytes.fromhex('11'*32)+secrets.token_bytes(40),b.socket.getsockname());time.sleep(.01);b.poll()
        b.service_capture(time.monotonic()+10000);self.assertEqual(len(calls),1)
    def test_capture_recv_failure_keeps_native_socket_working(self):
        b,n,j,events=self.bridge();b.capture.close();deadline=time.monotonic()+1
        while b.capture is not None and time.monotonic()<deadline:time.sleep(.01)
        self.assertTrue(b.enabled);self.assertIsNone(b.capture)
        payload=DISCO+bytes.fromhex('22'*32)+secrets.token_bytes(40)
        self.assertTrue(b.deliver(payload));self.assertEqual(n.recvfrom(65535)[0],payload)
    def test_compact_capture_still_requires_current_source_and_selected_peer(self):
        b,n,j,events=self.bridge();payload=DISCO+bytes.fromhex('11'*32)+secrets.token_bytes(40)
        b.capture.q.put(ip_packet(payload,source=('127.0.0.1',b.metadata['udp_port']+1)))
        b.capture.q.put(ip_packet(payload,source=('127.0.0.1',b.metadata['udp_port']),target=('1.1.1.2',41641)))
        b.capture.q.put(ip_packet(payload,source=('127.0.0.1',b.metadata['udp_port'])))
        self.assertEqual(b.outbound.get(timeout=1)[0],payload);self.assertEqual(b.stats['bootstrap_scope_rejected'],2)
    def test_snapshot_mismatch_is_forwarded_but_closed_proxy_is_rejected(self):
        b,n,j,events=self.bridge();payload=DISCO+bytes.fromhex('33'*32)+secrets.token_bytes(40)
        self.assertTrue(b.deliver(payload));self.assertEqual(n.recvfrom(65535)[0],payload)
        self.assertFalse(j.rows[-1]['disco_peer_snapshot_matches'])
        b.close();self.assertFalse(b.deliver(payload));self.assertEqual(j.rows[-1]['reason'],'local_proxy_not_ready')
    def test_new_capture_failure_during_refresh_does_not_disable_proxy(self):
        b,n,j,events=self.bridge()
        def fail(*args):raise ResourceError('1450')
        b.capture_factory=fail;b.refresh({**b.metadata,'peer_endpoints':[['1.1.1.1',42000]]})
        self.assertTrue(b.enabled);self.assertIsNone(b.capture)
    def test_ui_does_not_treat_passive_proxy_as_native_success(self):
        s={'udp_direct_live':True,'tail_bridge_state':{'proxy_ready':True,'capture_warning':'1450','bootstrap_stopped':False}}
        self.assertIn('监听异常',native_label(s));self.assertNotIn('已可用',native_label(s))
        s.update(tail_native_verified=True,tail_health={'route':'natpair_proxy'});s['tail_bridge_state']['bootstrap_stopped']=True
        self.assertEqual(native_label(s),'已可用，走 NATPair 直连')

class FilterTests(unittest.TestCase):
    def test_actual_dll_compiles_and_evaluates_compact_filter(self):
        dll,_=load_driver()
        compile=dll.WinDivertHelperCompileFilter
        compile.argtypes=[ctypes.c_char_p,ctypes.c_int,ctypes.c_void_p,ctypes.c_uint,ctypes.POINTER(ctypes.c_char_p),ctypes.POINTER(ctypes.c_uint)];compile.restype=ctypes.c_bool
        error=ctypes.c_char_p();pos=ctypes.c_uint()
        filters=[compact_filter(41641),'outbound and ip and udp and udp.SrcPort == 41641 and ('+' or '.join(f'(ip.DstAddr == {ip} and udp.DstPort == {port})' for ip,port in [
            ('100.106.91.210',41641),('112.49.193.186',27387),('112.49.193.186',41641),('112.49.193.186',27624),('112.49.193.186',27388),('172.27.48.1',41641),('192.168.31.195',41641),('198.18.0.1',41641)])+')']
        for f in filters:self.assertTrue(compile(f.encode(),0,None,0,ctypes.byref(error),ctypes.byref(pos)),error.value)
        evaluate=dll.WinDivertHelperEvalFilter;evaluate.argtypes=[ctypes.c_char_p,ctypes.c_void_p,ctypes.c_uint,ctypes.c_void_p];evaluate.restype=ctypes.c_bool
        addr=ctypes.create_string_buffer(80);ctypes.c_uint32.from_buffer(addr,8).value=1<<17
        valid=DISCO+bytes.fromhex('11'*32)+secrets.token_bytes(40)
        for payload,port,expected in [(valid,41641,True),(valid,41642,False),(b'xx'+valid[2:],41641,False),(valid[:40],41641,False)]:
            packet=ip_packet(payload,source=('192.168.1.103',port));self.assertEqual(evaluate(filters[0].encode(),packet,len(packet),addr),expected)
    def mock_dll(self,errors):
        class Func:
            def __init__(self,call):self.call=call
            def __call__(self,*args):return self.call(*args)
        seq=iter(errors);calls=[]
        def open(*args):
            calls.append(args);code=next(seq);ctypes.set_last_error(code);return ctypes.c_void_p(-1).value if code else 42
        class DLL:pass
        dll=DLL();dll.WinDivertOpen=Func(open);dll.WinDivertRecv=Func(lambda *args:False);dll.WinDivertClose=Func(lambda *args:True)
        return dll,calls
    def test_resource_error_has_compact_readonly_fallback(self):
        dll,calls=self.mock_dll([1450,0])
        with patch('tailbridge.load_driver',return_value=(dll,BASE/'driver')):
            s=WinSniffer(41641,[('1.1.1.1',41641)]);self.assertEqual(s.mode,'compact_disco');self.assertEqual(len(calls),2)
            self.assertTrue(all(args[3]==5 for args in calls));s.close()
    def test_repeated_1450_preserves_both_attempt_details(self):
        dll,calls=self.mock_dll([1450,1450])
        with patch('tailbridge.load_driver',return_value=(dll,BASE/'driver')):
            with self.assertRaises(OSError) as ctx:WinSniffer(41641,[('1.1.1.1',41641)])
        self.assertEqual(ctx.exception.winerror,1450);self.assertEqual(len(ctx.exception.capture_diagnostics['attempts']),2)
    def test_non_resource_error_does_not_retry_broader_filter(self):
        dll,calls=self.mock_dll([5])
        with patch('tailbridge.load_driver',return_value=(dll,BASE/'driver')):
            with self.assertRaises(OSError):WinSniffer(41641,[('1.1.1.1',41641)])
        self.assertEqual(len(calls),1)

if __name__=='__main__':unittest.main()

class DiagnosticTests(unittest.TestCase):
    def api(self,fail=False):
        from ctypes import wintypes as w
        class Func:
            def __init__(self,f):self.f=f
            def __call__(self,*a):return self.f(*a)
        class Head(ctypes.Structure):
            _fields_=[('key',ctypes.c_byte*16),('name',w.LPWSTR),('description',w.LPWSTR),('flags',w.DWORD)]
        class API:pass
        api=API();api.rows=[Head(),Head()];api.rows[0].name='WinDivert outbound IPv4';api.rows[1].name='Other provider'
        api.array=(ctypes.c_void_p*2)(*[ctypes.addressof(x) for x in api.rows]);api.closed=[];api.freed=0
        def handle(value):
            def call(*args):ctypes.cast(args[-1],ctypes.POINTER(w.HANDLE)).contents.value=value;return 0
            return call
        def enum(engine,enumerator,limit,entries,count):
            ctypes.cast(entries,ctypes.POINTER(ctypes.c_void_p)).contents.value=ctypes.addressof(api.array)
            ctypes.cast(count,ctypes.POINTER(w.DWORD)).contents.value=2
            return 1450 if fail else 0
        def free(ptr):api.freed+=1;ctypes.cast(ptr,ctypes.POINTER(ctypes.c_void_p)).contents.value=None
        api.FwpmEngineOpen0=Func(handle(11));api.FwpmCalloutCreateEnumHandle0=Func(handle(12));api.FwpmCalloutEnum0=Func(enum)
        api.FwpmFreeMemory0=Func(free);api.FwpmEngineClose0=Func(lambda *a:api.closed.append('engine') or 0)
        api.FwpmCalloutDestroyEnumHandle0=Func(lambda *a:api.closed.append('enum') or 0)
        return api
    def test_wfp_snapshot_reads_names_and_releases_all_resources(self):
        from driverdiag import callout_snapshot
        api=self.api();d=callout_snapshot(api=api)
        self.assertEqual(d['count'],2);self.assertEqual(d['windivert_count'],1);self.assertTrue(d['complete'])
        self.assertEqual(api.freed,1);self.assertEqual(api.closed,['enum','engine'])
    def test_wfp_error_also_frees_buffers_and_closes_handles(self):
        from driverdiag import callout_snapshot
        api=self.api(True);d=callout_snapshot(api=api)
        self.assertEqual(d['error'],1450);self.assertEqual(api.freed,1);self.assertEqual(api.closed,['enum','engine'])
    def test_current_windows_resource_snapshot_is_not_peer_attribution(self):
        import os
        from driverdiag import resources
        d=resources();self.assertEqual(d['pid'],os.getpid());self.assertGreater(d['own_process_handles'],0)
        self.assertGreater(d['performance']['page_size'],0);self.assertIn('not a kernel failure stack',d['scope'])
