import json,pathlib,time
from unittest.mock import patch
from test_v114 import udp_service
from test_mesh import FakeTailManager
from meshapp import gui,MC_MODE
r=pathlib.Path(__file__).parent;service,_=udp_service();report={};controller=None
cfg=service.cfg|{'scoped_peer_firewall':False,'live_egress_discovery':False,'_guard_scope':'star-gui-check'}
FakeTailManager.instances={};FakeTailManager.counter=0
def check(root,ui):
    global controller
    ui['mode'].set(MC_MODE);ui['mc_role'].set('房主');ui['mc_port'].set('41234');root.update_idletasks()
    shown=bool(ui['mc_controls'].winfo_manager());ui['start']();controller=ui['session'];deadline=time.monotonic()+9
    def inspect():
        c=ui['state']['client']
        if c and c.connected and '41234' in ui['mc_address'].get():
            report.update(passed=shown and c.topology=='star' and c.role=='host' and c.game_port==41234 and '房主' in ui['room_state'].get() and not c.pairs,
                mc_controls_present=shown,actual_host_port=True,hidden_window=root.state()=='withdrawn',room_state=ui['room_state'].get(),mc_address=ui['mc_address'].get(),solo_no_scan=True)
            controller.stop()
            def finish():
                if controller.running():root.after(50,finish)
                else:
                    # Wait for normal UI completion to clear the old address.
                    if ui['mc_address'].get()!='已退出房间':root.after(50,finish);return
                    report['stopped_address_cleared']=True;root.destroy()
            finish()
        elif time.monotonic()>deadline:report.update(passed=False,reason='MC room timeout');controller.stop();root.destroy()
        else:root.after(50,inspect)
    root.after(200,inspect)
try:
    with patch('meshclient.TailManager',FakeTailManager),patch('meshapp.is_admin',return_value=True),patch('meshclient.is_admin',return_value=True),patch('meshclient.driver_check',return_value={'passed':True}):gui(cfg,check)
finally:
    if controller:controller.stop();controller.thread.join(10)
    service.stop()
(r/'star-gui-check.json').write_text(json.dumps(report,ensure_ascii=False,indent=2),encoding='utf8');print(json.dumps(report,ensure_ascii=False));assert report['passed']
