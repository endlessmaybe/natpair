import unittest
from firewall import PeerFirewall,quote

class FirewallTests(unittest.TestCase):
    def test_exact_executable_ports_and_peer_scope_and_cleanup(self):
        scripts=[];events=[]
        def run(script):scripts.append(script);return {'rule':'mocked'}
        guard=PeerFirewall('11'*16,'192.168.31.195',[40001,40002],lambda event,**fields:events.append((event,fields)),run,program="H:/Apps/O'Brien/NATPairTail.exe")
        guard.update(['36.249.212.18','192.168.0.1','36.249.212.18']);guard.thread.join(2)
        self.assertEqual(len(scripts),1);script=scripts[0]
        self.assertIn('-Protocol UDP',script);self.assertIn('-LocalPort 40001,40002',script)
        self.assertIn("-RemoteAddress '36.249.212.18'",script);self.assertNotIn("-RemoteAddress 'Any'",script)
        self.assertIn("O''Brien",script);self.assertNotIn('Disable',script);self.assertNotIn('Bifrost',script)
        guard.update(['36.249.212.18']);self.assertEqual(len(scripts),1)
        guard.close();self.assertIn("-Name 'NATPairTail-"+'11'*16+"'",scripts[-1]);self.assertIn('Remove-NetFirewallRule',scripts[-1])
        self.assertNotIn('*',scripts[-1]);self.assertEqual(events[-1][0],'firewall_peer_cleanup')
    def test_partial_command_failure_still_attempts_exact_cleanup(self):
        scripts=[];events=[]
        def run(script):
            scripts.append(script)
            if len(scripts)==1:raise TimeoutError('synthetic timeout after rule creation')
        guard=PeerFirewall('22'*16,'192.168.31.195',[40001],lambda event,**fields:events.append(event),run)
        guard.update(['36.249.212.18']);guard.thread.join(2);guard.close()
        self.assertIn('firewall_error',events);self.assertIn('Remove-NetFirewallRule',scripts[-1])
    def test_invalid_ports_or_identifier_never_invoke_commands(self):
        for ident,ports in [('invalid',[40001]),('11'*16,[0]),('11'*16,list(range(40001,40010))),('11'*16,[True])]:
            with self.assertRaises(ValueError):PeerFirewall(ident,'192.168.31.195',ports,lambda *args:None)
