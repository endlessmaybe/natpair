import asyncio,json,pathlib,secrets,socket,sys,tempfile,threading,time,unittest
from unittest.mock import patch
from session import SessionRunner
from client import LabClient
from tailbridge import TailBridge,run_command
from roomudp import Codec,RoomUDPServer
from test_lab import Service

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

class Lifecycle114Tests(unittest.TestCase):
    def test_same_controllers_restart_same_room_five_times_and_authenticate(self):
        service,protocol=udp_service();controllers=[SessionRunner(lambda e:None) for _ in range(2)]
        code=secrets.token_hex(16);checks=[]
        try:
            for n in range(5):
                cs=[s.start(service.cfg,code,str(i)) for i,s in enumerate(controllers)]
                self.assertTrue(until(lambda:all(c.udp_direct and c.stats['udp_probe_acks']>=3 for c in cs),12))
                checks.append({'cycle':n,'ids':[c.id for c in cs],'data_sessions':[c.data_session for c in cs],
                    'epochs':[c.discovery.epoch for c in cs],'acks':[c.stats['udp_probe_acks'] for c in cs],
                    'reconnects':[c.control_reconnects for c in cs]})
                for s in controllers:s.stop()
                self.assertTrue(until(lambda:not any(s.running() for s in controllers)))
                self.assertTrue(until(lambda:not service.service.rooms))
                self.assertTrue(all(all(x.fileno()<0 for x in c.udp) for c in cs))
                self.assertFalse(any(e['event']=='error' for c in cs for e in c.logs))
            self.assertEqual(len({x['ids'][0] for x in checks}),1)
            self.assertEqual(len({x['data_sessions'][0] for x in checks}),5)
            self.assertEqual(len({x['epochs'][0] for x in checks}),5)
            pathlib.Path(__file__).with_name('same-process-restart-check.json').write_text(json.dumps({'passed':True,'cycles':checks},indent=2))
        finally:
            for s in controllers:
                s.stop()
                if s.thread:s.thread.join(5)
            service.stop()

    def test_dropped_udp_room_replies_resume_without_new_socket_or_ticket(self):
        service,protocol=udp_service();s=SessionRunner(lambda e:None);c=s.start(service.cfg,secrets.token_hex(16),'solo')
        original=protocol.datagram_received;drop=threading.Event()
        def receive(data,addr):
            if not drop.is_set():original(data,addr)
        try:
            self.assertTrue(until(lambda:c.last_confirmed_room_members==1))
            channel=c.control;port=channel.socket.getsockname()[1];ticket=c.discovery.ticket
            with patch.object(protocol,'datagram_received',side_effect=receive):
                drop.set();time.sleep(1.8)
                self.assertEqual(c.control_failures,0);self.assertIs(c.control,channel)
                self.assertGreater(c.control_soft_timeouts,0);self.assertEqual(c.discovery.ticket,ticket)
                drop.clear();self.assertTrue(until(lambda:c.control_health['state']=='application_verified'))
                self.assertEqual(c.control_reconnects,0);self.assertEqual(c.control.socket.getsockname()[1],port)
        finally:s.stop();s.thread.join(5);service.stop()

    def test_stale_previous_seat_is_replaced_only_with_same_resume_and_higher_run(self):
        service,protocol=udp_service();s=SessionRunner(lambda e:None);code=secrets.token_hex(16)
        c=s.start(service.cfg,code,'seat')
        try:
            self.assertTrue(until(lambda:c.last_confirmed_room_members==1));old=service.service.rooms[c.room][c.id]
            # Drop the explicit leave and ignore closing the old socket so the
            # server still holds its seat when the next window run begins.
            with patch.object(c.control,'send_snapshot',return_value=None):s.stop();s.thread.join(5)
            self.assertIs(service.service.rooms[c.room][c.id],old)
            fresh=s.start(service.cfg,code,'seat');self.assertTrue(until(lambda:fresh.last_confirmed_room_members==1))
            member=service.service.rooms[fresh.room][fresh.id]
            self.assertIsNot(member,old);self.assertEqual(len(service.service.rooms[fresh.room]),1)
            self.assertNotEqual(old['ticket'],member['ticket']);self.assertTrue(old['writer'].closed)
            rejected=protocol.sync(b'X'*16,{'k':'sync','room':fresh.room,'id':fresh.id,'resume':fresh.session,'name':'late','run':1})
            self.assertEqual(rejected,{'error':'superseded_session'});self.assertIs(service.service.rooms[fresh.room][fresh.id],member)
        finally:s.stop();s.thread.join(5);service.stop()

    def test_closed_bridge_cannot_restart_from_late_metadata_refresh(self):
        metadata={'node_key':'own','expected_peer_key':'peer','udp_port':41641,'disco_key':'d','peer_endpoints':[]}
        b=TailBridge(metadata,lambda *a,**k:None,__import__('journal').NullJournal());b.close()
        self.assertFalse(b.refresh({**metadata,'udp_port':50000}))
        with self.assertRaisesRegex(RuntimeError,'已关闭'):b.start()
        self.assertFalse(b.enabled);self.assertEqual(b.socket.fileno(),-1)

    def test_stop_cancels_only_own_slow_command(self):
        stop=threading.Event();failures=[]
        def work():
            try:run_command([sys.executable,'-B','-c','import time; time.sleep(30)'],40,stop)
            except InterruptedError:failures.append(True)
        t=threading.Thread(target=work);t.start();time.sleep(.2);at=time.monotonic();stop.set();t.join(2)
        self.assertFalse(t.is_alive());self.assertTrue(failures);self.assertLess(time.monotonic()-at,1.5)

    def test_codec_loss_reordering_forgery_and_replay_do_not_block_next_snapshot(self):
        access=secrets.token_hex(32);a=Codec(access);b=Codec(access,True);sid=secrets.token_bytes(16)
        wire=a.encode(sid,1,{'body':'a'*5000})
        self.assertIsNone(b.decode(wire[0][:-1]+bytes([wire[0][-1]^1]),('127.0.0.1',1)))
        for packet in wire[:-1]:self.assertIsNone(b.decode(packet,('127.0.0.1',1)))
        next_wire=a.encode(sid,2,{'body':'b'*5000});result=None
        for packet in reversed(next_wire):result=b.decode(packet,('127.0.0.1',1)) or result
        self.assertEqual(result,(sid,2,{'body':'b'*5000}))

    def test_window_identity_survives_app_restart_and_busy_start_is_rejected(self):
        with tempfile.TemporaryDirectory(dir=r'H:\CodexTemp\tmp') as d:
            p=pathlib.Path(d)/'identity.json';s=SessionRunner(lambda e:None,p)
            s.identity['run']=7;p.write_text(json.dumps(s.identity));other=SessionRunner(lambda e:None,p)
            self.assertEqual(s.identity,other.identity)
            stop=threading.Event();other.thread=threading.Thread(target=lambda:stop.wait(2));other.thread.start()
            try:
                with self.assertRaisesRegex(RuntimeError,'停止清理'):other.start({},'AB'*16,'busy')
            finally:stop.set();other.thread.join(3)

if __name__=='__main__':unittest.main(verbosity=2)
