import json,pathlib,time
from test_v114 import udp_service
from meshapp import gui,COEXIST_SPEED
r=pathlib.Path(__file__).parent;service,_=udp_service();report={};controller=None
cfg=service.cfg|{'scoped_peer_firewall':False,'live_egress_discovery':False,'_guard_scope':'gui-check'}
def check(root,ui):
    global controller
    selected=ui['speed'].get();ui['mode'].set('仅 UDP 打洞（不接入 Tailscale）');ui['start']();controller=ui['session'];deadline=time.monotonic()+8
    def inspect():
        c=ui['state']['client']
        if c and c.connected and '1 人' in ui['room_state'].get():
            root.update_idletasks()
            report.update(passed=selected==COEXIST_SPEED and bool(c.coexist_guard) and '共存' in ui['status'].get(),
                default_coexist_selected=selected==COEXIST_SPEED,solo_waiting=True,hidden_window=root.state()=='withdrawn',
                requested_height=root.winfo_reqheight(),minimum_height=root.minsize()[1],status_label=ui['status'].get())
            controller.stop()
            def finish():
                if controller.running():root.after(50,finish)
                else:root.destroy()
            finish()
        elif time.monotonic()>deadline:report.update(passed=False,reason='room timeout');controller.stop();root.destroy()
        else:root.after(50,inspect)
    root.after(200,inspect)
try:gui(cfg,check)
finally:
    if controller:controller.stop();controller.thread.join(10)
    service.stop()
(r/'coexist-gui-check.json').write_text(json.dumps(report,ensure_ascii=False,indent=2),encoding='utf8');print(json.dumps(report,ensure_ascii=False));assert report['passed']
