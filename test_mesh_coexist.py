import datetime,json,pathlib,secrets,socket,threading,time,unittest
from unittest.mock import MagicMock,patch
from coexistguard import CoexistGuard,FreshHealthTrace
from meshclient import MultiClient,PairClient
from meshapp import COEXIST_SPEED,speed_settings
from test_v114 import udp_service,until
from meshapp import defaults

ROOT=pathlib.Path(__file__).parent

class GuardTests(unittest.TestCase):
    def test_spacing_prevents_256_packet_catchup_burst_and_failed_send_is_free(self):
        guard=CoexistGuard(clock=lambda:100)
        with guard.lock:
            # Two tokens available at first; a send that the OS rejects uses none.
            self.assertTrue(guard.permit(50000,('127.0.0.1',1234),100)[0])
            self.assertTrue(guard.permit(50000,('127.0.0.1',1234),100)[0])
            guard.commit(50000,('127.0.0.1',1234),100)
            guard.commit(50000,('127.0.0.1',1234),100)
            self.assertFalse(guard.permit(50000,('127.0.0.1',1234),100)[0])
            accepted=0
            for _ in range(256):
                if guard.permit(50000,('127.0.0.1',1234),105)[0]:
                    guard.commit(50000,('127.0.0.1',1234),105);accepted+=1
            self.assertEqual(accepted,2,'long idle must not accumulate catchup tokens')

    def test_timed_shared_senders_count_actual_datagrams_and_do_not_exceed_ceiling(self):
        guard=CoexistGuard();sockets=[socket.socket(socket.AF_INET,socket.SOCK_DGRAM) for _ in range(3)]
        recv=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);recv.bind(('127.0.0.1',0));recv.settimeout(.01)
        for s in sockets:s.bind(('127.0.0.1',0))
        events=[];stop=threading.Event();target=recv.getsockname();deadline=time.monotonic()+.55;received=[]
        def drain():
            while not stop.is_set():
                try:received.append(recv.recvfrom(1024))
                except socket.timeout:pass
        def work(s):
            while time.monotonic()<deadline:
                now=time.monotonic()
                with guard.lock:
                    if guard.permit(s.getsockname()[1],target,now)[0]:
                        s.sendto(b'paced',target);at=time.monotonic();guard.commit(s.getsockname()[1],target,at);events.append(at)
                time.sleep(.0004)
        drainer=threading.Thread(target=drain);workers=[threading.Thread(target=work,args=(s,)) for s in sockets]
        try:
            drainer.start()
            for t in workers:t.start()
            for t in workers:t.join(3)
            time.sleep(.05)
            self.assertGreater(len(events),100)
            self.assertEqual(len(events),len(received))
            for at in events:self.assertLessEqual(sum(at<=t<at+.01 for t in events),12)
            self.assertLessEqual(len(events),552)
        finally:
            stop.set();drainer.join(2)
            for s in sockets+[recv]:s.close()

    def test_pressure_uses_last_touch_and_priority_never_waits(self):
        guard=CoexistGuard({'coexist_burst_limit':2,'coexist_footprint_limit':2},clock=lambda:100)
        guard.commit(50000,('127.0.0.1',1),100)
        guard.commit(50000,('127.0.0.1',2),101)
        allowed,delay,reason=guard.permit(50000,('127.0.0.1',3),102)
        self.assertFalse(allowed);self.assertEqual(reason,'mapping_footprint_budget')
        # Refresh first mapping: it no longer expires at 280.
        guard.commit(50000,('127.0.0.1',1),279,priority=True)
        self.assertFalse(guard.permit(50000,('127.0.0.1',3),280)[0])
        self.assertTrue(guard.permit(50000,('127.0.0.1',3),280,priority=True)[0])
        self.assertTrue(guard.permit(50000,('127.0.0.1',3),282)[0])

    def test_expired_mapping_counts_as_new_again_and_old_warning_does_not_pause(self):
        guard=CoexistGuard(clock=lambda:100)
        guard.commit(50000,('127.0.0.1',1),100)
        guard.commit(50000,('127.0.0.1',1),281)
        self.assertEqual(guard.fresh_combinations,2)
        stamp=datetime.datetime.fromtimestamp(1000,datetime.timezone.utc).isoformat()
        guard.monitor.signal(stamp+'|pid=1|tid=1|runtime-dataplane-miss',300,wall=1003)
        self.assertEqual(guard.monitor.recent(),[])

    def test_missing_health_trace_keeps_proactive_sending_enabled(self):
        guard=CoexistGuard({'bifrost_trace_path':str(ROOT/(secrets.token_hex(16)+'.missing'))},clock=lambda:100)
        guard.poll(100)
        self.assertEqual(guard.snapshot(100)['monitor'],'trace_not_available')
        self.assertTrue(guard.permit(50000,('127.0.0.1',1234),100)[0])

    def test_fresh_warning_slows_without_room_reset_and_has_bounded_recovery(self):
        path=ROOT/'test-assets'/('coexist-trace-'+secrets.token_hex(4)+'.log')
        path.parent.mkdir(exist_ok=True)
        guard=CoexistGuard({'bifrost_trace_path':str(path)},clock=lambda:100)
        stamp=datetime.datetime.fromtimestamp(1000,datetime.timezone.utc).isoformat()
        path.write_text(stamp+'|pid=1|tid=1|runtime-dataplane-miss code=TEST\n',encoding='utf8')
        guard.poll(100,wall=1000)
        before=guard.snapshot(100)
        self.assertEqual(before['effective_packet_ceiling'],250)
        self.assertFalse(guard.permit(50000,('127.0.0.1',1),100)[0])
        self.assertTrue(guard.permit(50000,('127.0.0.1',1),100,priority=True)[0])
        guard.poll(101,wall=1001);self.assertEqual(guard.serial,1)
        self.assertEqual(guard.snapshot(116)['effective_packet_ceiling'],1000)
        self.assertEqual(guard.snapshot(116)['health_new_pause_seconds'],0)

    def test_stop_start_retains_guard_but_raw_modes_preserve_behavior(self):
        cfg={'mesh_coexist_guard':True,'_guard_scope':secrets.token_hex(8)}
        a=MultiClient(cfg,'AA'*16,'a');g=a.coexist_guard
        g.commit(50000,('127.0.0.1',1),time.monotonic());a.stop.set()
        b=MultiClient(cfg,'AA'*16,'b')
        self.assertIs(g,b.coexist_guard);self.assertEqual(len(g.touched),1)
        self.assertTrue(speed_settings(COEXIST_SPEED)['mesh_coexist_guard'])
        for name in ('不限额：有效连续探测','新增组合：1000/秒（全机共享）'):
            c=MultiClient(speed_settings(name),'AA'*16,'c');self.assertIsNone(c.coexist_guard)
        self.assertEqual(speed_settings('新增组合：1000/秒（全机共享）')['new_combinations_per_second'],1000)

    def test_pair_denial_retains_cursor_while_ack_and_existing_path_continue(self):
        owner=MultiClient({'mesh_coexist_guard':True,'_guard_scope':secrets.token_hex(8),'coexist_footprint_limit':1},'AA'*16,'a');owner.mux=MagicMock()
        peer={'id':'b'*32,'udp':[['127.0.0.1',1234]],'profile':{'generation':'c'*32}}
        c=PairClient(owner,peer,owner.pair_code(peer),{'public_only':False,'unlimited_search':True})
        sock=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);sock.bind(('127.0.0.1',0));c.udp=[sock]
        target=('127.0.0.1',1234);guard=owner.coexist_guard
        try:
            guard.commit(sock.getsockname()[1],('127.0.0.1',4321),time.monotonic())
            cursor=c.schedule.position
            self.assertFalse(c.trace_probe(sock,target,peer,time.monotonic(),'full_scan'))
            self.assertEqual(c.schedule.position,cursor);self.assertEqual(c.stats['udp_probe_tx'],0)
            self.assertTrue(c.send_udp(sock,b'ack',target,time.monotonic(),'authenticated_reply'))
            c.direct_path=(sock,target)
            self.assertTrue(c.trace_probe(sock,target,peer,time.monotonic(),'direct_keepalive'))
            self.assertEqual(c.stats['udp_probe_tx'],1)
        finally:sock.close();c.journal.close()

    def test_protected_room_survives_pressure_and_same_window_rejoin(self):
        service,_=udp_service();engines=[];threads=[]
        code=secrets.token_hex(16);cfg=defaults(service.cfg)|{'mesh_coexist_guard':True,'coexist_footprint_limit':128,'coexist_burst_limit':64,'_guard_scope':secrets.token_hex(8),
            'scoped_peer_firewall':False,'live_egress_discovery':False,'tailscale_bridge':False,'public_only':False}
        try:
            a=MultiClient(cfg,code,'a');b=MultiClient(cfg,code,'b');engines+=[a,b]
            for c in engines:
                t=threading.Thread(target=c.run,daemon=True);threads.append(t);t.start()
            self.assertTrue(until(lambda:len(a.pairs)==len(b.pairs)==1,15))
            self.assertTrue(until(lambda:any(c.direct_path for c in [a.pairs[b.id]['client'],b.pairs[a.id]['client']]),15))
            # Fill our estimated footprint after establishment. Authenticated
            # replies/keepalives continue despite withholding new scan targets.
            guard=a.coexist_guard
            with guard.lock:
                for port in range(1,129):guard.commit(49999,('127.0.0.1',port),time.monotonic(),priority=True)
            ca=a.pairs[b.id]['client'];before=ca.stats['udp_probe_acks'];time.sleep(2)
            self.assertTrue(ca.direct_path);self.assertGreater(ca.stats['udp_probe_acks'],before)
            self.assertLessEqual(ca.stats['udp_probe_acks']-before,6,'pure UDP established path must not keep probing at startup rate')
            self.assertFalse(any(e['event']=='error' for c in engines for e in c.logs))
            b.stop.set();threads[1].join(8);self.assertFalse(threads[1].is_alive())
            b2=MultiClient(cfg,code,'b-again');engines.append(b2);t=threading.Thread(target=b2.run,daemon=True);threads.append(t);t.start()
            self.assertIs(b2.coexist_guard,a.coexist_guard)
            self.assertTrue(until(lambda:b2.id in a.pairs and a.id in b2.pairs,15))
            self.assertTrue(a.connected and b2.connected)
        finally:
            for c in engines:c.stop.set()
            for t in threads:t.join(10)
            service.stop()
            self.assertFalse(any(t.is_alive() for t in threads))

if __name__=='__main__':unittest.main()
