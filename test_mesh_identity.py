import json,pathlib,subprocess,threading,time,unittest
from unittest.mock import MagicMock,patch
from meshclient import MultiClient
from meshtail import TailManager
from tailbridge import read_metadata

STATUS={'BackendState':'Running'}
OWN={'Key':'nodekey:own','DiscoKey':'discokey:'+'11'*32,'Addresses':['100.99.0.1/32']}
PEER={'Key':'nodekey:peer','DiscoKey':'discokey:'+'22'*32,'Addresses':['100.99.0.2/32'],'Endpoints':None}
NETMAP={'SelfNode':OWN,'Peers':[PEER,{'Key':'offline','Addresses':None,'Endpoints':None}]}
def commands(args,**kwargs):return json.dumps(STATUS if args[0]=='status' else NETMAP)

class IdentityTests(unittest.TestCase):
    def test_nullable_peer_endpoints_are_valid_absent_candidates(self):
        m=read_metadata('100.99.0.2',port=41641,snapshots=(STATUS,NETMAP))
        self.assertEqual(m['peer_endpoints'],[]);self.assertEqual(m['expected_peer_key'],'nodekey:peer')
    def test_identity_is_published_before_udp_port_timeout_and_recovers(self):
        manager=TailManager(threading.Event(),lambda *a,**k:None,True);manager.set_targets({'100.99.0.2':'b'})
        with patch('meshtail.command',side_effect=commands),patch('meshtail.native_udp_port',side_effect=subprocess.TimeoutExpired(['powershell'],12)):
            with self.assertRaises(subprocess.TimeoutExpired):manager.refresh()
        self.assertEqual(manager.own['tail_ip'],'100.99.0.1');self.assertTrue(manager.ready.is_set());self.assertIsNone(manager.port)
        with patch('meshtail.command',side_effect=commands),patch('meshtail.native_udp_port',return_value=41641):manager.refresh()
        self.assertEqual(manager.read_metadata('100.99.0.2')['udp_port'],41641)
    def test_port_query_is_independent_of_any_other_tail_peer(self):
        manager=TailManager(threading.Event(),lambda *a,**k:None,True)
        def cmd(args,**kwargs):return json.dumps(STATUS if args[0]=='status' else {'SelfNode':OWN,'Peers':[]})
        with patch('meshtail.command',side_effect=cmd),patch('meshtail.native_udp_port',return_value=41641):manager.refresh()
        self.assertEqual(manager.own['tail_ip'],'100.99.0.1');self.assertEqual(manager.port,41641)
    def test_unexpected_refresh_exception_is_logged_and_worker_retries(self):
        stop=threading.Event();events=[];manager=TailManager(stop,lambda e,**k:events.append((e,k)),True)
        failures=iter([subprocess.TimeoutExpired(['tailscale'],5),TypeError('nullable endpoint'),None])
        def refreshed():
            failure=next(failures)
            if failure:raise failure
            manager.own={'node_key':'own','tail_ip':'100.99.0.1'};stop.set()
        with patch.object(manager,'refresh',side_effect=refreshed):
            # Eliminate backoff in this unit test only.
            with patch.object(stop,'wait',return_value=False):manager.run()
        self.assertEqual([x[1]['error_type'] for x in events],['TimeoutExpired','TypeError'])
        self.assertEqual(manager.own['tail_ip'],'100.99.0.1')
    def test_one_bad_peer_does_not_prevent_other_metadata_or_own_identity(self):
        manager=TailManager(threading.Event(),lambda *a,**k:None,False);manager.set_targets({'100.99.0.2':'b','100.99.0.3':'c'})
        with patch('meshtail.command',side_effect=commands):manager.refresh()
        self.assertIn('100.99.0.2',manager.metadata);self.assertIn('100.99.0.3',manager.metadata_errors)
        self.assertEqual(manager.own['tail_ip'],'100.99.0.1')
    def test_missing_room_peer_identity_is_visible_instead_of_silent_zero_packets(self):
        owner=MultiClient({'tailscale_bridge':True},'AA'*16,'a');owner.bind='127.0.0.1';owner.index=0;owner.tail=MagicMock();owner.tail.route_health.return_value={}
        peer={'id':'b'*32,'name':'b','profile':{'generation':'c'*32,'bridge':True,'tail':{}}}
        owner.peers={peer['id']:peer};owner.start_pair(peer)
        self.assertEqual(owner.pairs,{});self.assertIn('等待对方公布',owner.rows()[0]['state'])
        self.assertEqual([e['event'] for e in owner.logs],['peer_identity_wait'])

if __name__=='__main__':unittest.main()
