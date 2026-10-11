"""Windows full-mesh room UI and command-line validation."""
import argparse,json,os,pathlib,queue,secrets,sys
from session import SessionRunner
from meshclient import MultiClient,export_mesh,VERSION
from tailbridge import is_admin,driver_check
BASE=pathlib.Path(sys.executable).parent if getattr(sys,'frozen',False) else pathlib.Path(__file__).parent
COEXIST_SPEED='Bifrost 共存：平滑探测，最高1000包/秒'
MC_MODE='MC 星形房间（Tailscale 接入）'

def speed_settings(value):
    return {'mesh_coexist_guard':value==COEXIST_SPEED,'new_combinations_per_second':1000 if value.startswith('新增') else None}

def mode_settings(value,role='玩家',port='25565'):
    if value==MC_MODE:
        try:port=int(port)
        except (ValueError,TypeError):raise ValueError('MC 游戏端口需要填写整数')
        if not 1<=port<=65535:raise ValueError('MC 游戏端口需要在 1–65535 之间')
        return {'tailscale_bridge':True,'mesh_topology':'star','mesh_role':'host' if role=='房主' else 'player','mc_game_port':port}
    return {'tailscale_bridge':value.startswith('接入'),'mesh_topology':'full_mesh','mesh_role':'player'}

def defaults(cfg):
    return {**cfg,'unlimited_search':True,'protected_search':False,'bifrost_coexist':False,'raw_tcp_experiment':False,
            'tcp_udp_assist':False,'tcp_mapping_retry':False,'scoped_peer_firewall':cfg.get('scoped_peer_firewall',True),'coordinated_scan':True,
            'fast_start':True,'nearby_priority':True,'immediate_challenge':True,'phased_search':True,
            'coordination_window_seconds':60,'candidate_pool_priority':True,'fast_center_search':True,
            'restore_v105_budget':True,'efficient_search':True,'preflight_exchange':True,'peer_sync_overlay':False,
            'wait_unlimited':True,'run_continuously':True,'packet_journal_dir':str(BASE/'packet-logs')}

def new_code():
    text=secrets.token_hex(16).upper();return '-'.join(text[i:i+8] for i in range(0,32,8))

def gui(cfg,check=None):
    import tkinter as tk
    from tkinter import ttk,messagebox,filedialog
    root=tk.Tk()
    if check:root.withdraw()
    root.title('NATPair v1.2.0 · MC 星形房间与持续复测');root.geometry('1080x800');root.minsize(780,640)
    root.columnconfigure(0,weight=1);root.rowconfigure(0,weight=1)
    panel=ttk.Frame(root,padding=12);panel.grid(sticky='nsew');panel.columnconfigure(1,weight=1);panel.rowconfigure(6,weight=2);panel.rowconfigure(9,weight=1)
    ttk.Label(panel,text='NATPair · 全员互连 / MC 星形房间',font=('Microsoft YaHei UI',18,'bold')).grid(row=0,column=0,columnspan=3,sticky='w')
    ttk.Label(panel,text='最多 8 人 · 原生 IPv6 / IPv4 直连优先 · 每对独立恢复 · 打通即用，其余继续探测').grid(row=1,column=0,columnspan=3,sticky='w',pady=(3,10))
    name=tk.StringVar(value=os.environ.get('COMPUTERNAME','whb'));code=tk.StringVar(value=new_code())
    ttk.Label(panel,text='我的昵称').grid(row=2,column=0,sticky='w');nickname=ttk.Entry(panel,textvariable=name);nickname.grid(row=2,column=1,sticky='ew',pady=3)
    ttk.Label(panel,text='共同房间码').grid(row=3,column=0,sticky='w');room_entry=ttk.Entry(panel,textvariable=code);room_entry.grid(row=3,column=1,sticky='ew',pady=3)
    generate_button=ttk.Button(panel,text='生成新房间码',command=lambda:code.set(new_code()));generate_button.grid(row=3,column=2,padx=6)
    controls=ttk.Frame(panel);controls.grid(row=4,column=0,columnspan=3,sticky='ew',pady=6)
    control_line=ttk.Frame(controls);control_line.pack(fill='x')
    mode=tk.StringVar(value='接入 Tailscale（全员互连）');speed=tk.StringVar(value=COEXIST_SPEED)
    modes=ttk.Combobox(control_line,textvariable=mode,state='readonly',width=35,values=['接入 Tailscale（全员互连）',MC_MODE,'仅 UDP 打洞（不接入 Tailscale）']);modes.pack(side='left')
    ttk.Label(control_line,text='  探测档位 ').pack(side='left');speeds=ttk.Combobox(control_line,textvariable=speed,state='readonly',width=39,values=['不限额：有效连续探测','新增组合：1000/秒（全机共享）',COEXIST_SPEED]);speeds.pack(side='left')
    mc_role=tk.StringVar(value='玩家');mc_port=tk.StringVar(value='25565');mc_address=tk.StringVar(value='等待房主公布 Tailscale 地址')
    mc_controls=ttk.Frame(controls)
    mc_line=ttk.Frame(mc_controls);mc_line.pack(fill='x',pady=(7,3))
    ttk.Label(mc_line,text='我的角色 ').pack(side='left');roles=ttk.Combobox(mc_line,textvariable=mc_role,state='readonly',width=9,values=['房主','玩家']);roles.pack(side='left')
    ttk.Label(mc_line,text='  Java 服务端 / 开放局域网端口 ').pack(side='left');game_port_entry=ttk.Entry(mc_line,textvariable=mc_port,width=9);game_port_entry.pack(side='left')
    ttk.Label(mc_controls,text='一人选房主，其余选玩家；端口由房主填写，玩家自动使用。房主先启动 MC 服务 / 开放到局域网。').pack(anchor='w')
    mc_addr_line=ttk.Frame(mc_controls);mc_addr_line.pack(fill='x',pady=3)
    ttk.Label(mc_addr_line,text='MC 直连地址 ').pack(side='left');ttk.Entry(mc_addr_line,textvariable=mc_address,state='readonly',width=34).pack(side='left')
    def copy_mc_address():
        value=mc_address.get()
        if value and value[0].isdigit():root.clipboard_clear();root.clipboard_append(value)
    ttk.Button(mc_addr_line,text='复制地址',command=copy_mc_address).pack(side='left',padx=6)
    def show_mc(*args):
        if mode.get()==MC_MODE:mc_controls.pack(fill='x')
        else:mc_controls.pack_forget()
    mode.trace_add('write',show_mc)
    room_state=tk.StringVar(value='当前房间：未加入');ttk.Label(panel,textvariable=room_state,font=('Microsoft YaHei UI',10,'bold')).grid(row=5,column=0,columnspan=3,sticky='w',pady=5)
    columns=('name','tail_ip','state','probe','rate','first')
    table=ttk.Treeview(panel,columns=columns,show='headings',height=7);table.grid(row=6,column=0,columnspan=3,sticky='nsew')
    for key,label,width in [('name','成员',120),('tail_ip','Tailscale 地址',115),('state','当前连接方式 / 阶段',330),('probe','实际探测 发/收',105),('rate','实发 / 新增（秒）',140),('first','首次 UDP 用时',110)]:
        table.heading(key,text=label);table.column(key,width=width,minwidth=65,stretch=True)
    scroll=ttk.Scrollbar(panel,orient='vertical',command=table.yview);scroll.grid(row=6,column=3,sticky='ns');table.configure(yscrollcommand=scroll.set)
    status=tk.StringVar(value='同一房间所有成员自动互相配对，无需逐个填写对方地址。')
    status_label=ttk.Label(panel,textvariable=status,wraplength=1000);status_label.grid(row=7,column=0,columnspan=3,sticky='ew',pady=6)
    root.bind('<Configure>',lambda e:status_label.configure(wraplength=max(650,panel.winfo_width()-35)) if e.widget is root else None)
    buttons=ttk.Frame(panel);buttons.grid(row=8,column=0,columnspan=3,sticky='ew',pady=6)
    messages=queue.Queue(2000);state={'client':None}
    def receive(event):
        try:messages.put_nowait(event)
        except queue.Full:pass
    session=SessionRunner(receive,BASE/'mesh-session-identity.json',factory=MultiClient)
    def start():
        if session.running():return
        try:selected=mode_settings(mode.get(),mc_role.get(),mc_port.get())
        except ValueError as exc:messagebox.showerror('设置无效',str(exc));return
        bridge=selected['tailscale_bridge']
        if bridge and not is_admin():messagebox.showerror('需要管理员权限','接入 Tailscale 请关闭后右键“以管理员身份运行”；纯 UDP 模式可直接运行。');return
        current={**defaults(cfg),'tail_metadata_only':False,**selected,**speed_settings(speed.get())}
        try:state['client']=session.start(current,code.get(),name.get())
        except (ValueError,RuntimeError,OSError) as exc:messagebox.showerror('无法启动',str(exc));return
        mc_address.set('等待房主公布 Tailscale 地址')
        for widget in (nickname,room_entry,generate_button,modes,speeds,roles,game_port_entry,start_button):widget.configure(state='disabled')
        room_state.set('当前房间：正在加入');table.delete(*table.get_children())
    def stop():session.stop();status.set('正在停止并清理所有成员对；清理完成后可以原窗口重新加入。')
    def export():
        if not state['client']:return
        target=filedialog.asksaveasfilename(initialdir=str(BASE),initialfile='NATPair-Mesh-test.zip',defaultextension='.zip',filetypes=[('取证 ZIP','*.zip')])
        if target:
            import threading
            def work():
                try:export_mesh(state['client'],target);receive({'event':'exported','message':'已导出 '+target})
                except (OSError,ValueError) as exc:receive({'event':'error','message':str(exc)})
            threading.Thread(target=work,daemon=True).start()
    start_button=ttk.Button(buttons,text='加入房间 / 开始',command=start);start_button.pack(side='left');ttk.Button(buttons,text='停止并退出房间',command=stop).pack(side='left',padx=8)
    ttk.Button(buttons,text='导出完整记录',command=export).pack(side='right')
    log=tk.Text(panel,height=7,state='disabled',wrap='word');log.grid(row=9,column=0,columnspan=3,sticky='nsew')
    scrollbar=ttk.Scrollbar(panel,command=log.yview);scrollbar.grid(row=9,column=3,sticky='ns');log.configure(yscrollcommand=scrollbar.set)
    def write(text):
        log.configure(state='normal');log.insert('end',text+'\n')
        if int(log.index('end-1c').split('.')[0])>600:log.delete('1.0','100.0')
        log.see('end');log.configure(state='disabled')
    def pump():
        for _ in range(150):
            try:event=messages.get_nowait()
            except queue.Empty:break
            if event.get('generation') and event['generation']!=session.generation:continue
            kind=event.get('event')
            if kind=='mesh_status':
                count=event.get('room_members');room_state.set(f'当前房间：{count} 人（含自己） · 全网已通 {event["completed_pairs"]}/{event["possible_pairs"]} 对' if count is not None else '当前房间：正在等待协调回复')
                if event.get('topology')=='star':
                    room_state.set(f'当前 MC 房间：{count} 人（含自己） · 房主：{event.get("mc_host_name") or "等待加入"} · 已通 {event["completed_pairs"]}/{event["possible_pairs"]} 条房主连接')
                    mc_address.set(event.get('mc_connect_address') or '等待房主公布 Tailscale 地址')
                rows=event['rows'];ids={r['id'] for r in rows}
                for iid in table.get_children():
                    if iid not in ids:table.delete(iid)
                for r in rows:
                    seconds=r.get('room_seconds_to_first_udp');first='—' if seconds is None else f'{int(seconds)//60}分{int(seconds)%60}秒'
                    values=(r['name'],r['tail_ip'],r['state'],f'{r["probe_tx"]}/{r["probe_rx"]}',f'{r["probe_pps"]:.1f} / {r["new_pps"]:.1f}',first)
                    if table.exists(r['id']):table.item(r['id'],values=values)
                    else:table.insert('','end',iid=r['id'],values=values)
                combo=event['combination_limit'];label='不限额；业务 / 回包 / 保活优先' if not combo['new_per_second_limit'] else '全机新增组合上限 1000/秒；重发不限额'
                guard=event.get('coexist_guard',{})
                if guard.get('enabled'):
                    why={'mapping_footprint_budget':'近期组合预算','mapping_burst_budget':'短时新增预算','health_new_pause':'健康检查异常'}.get(guard.get('current_pressure'),'平滑发送')
                    if guard['health_new_pause_seconds']:why='健康检查异常，暂缓新增'
                    elif guard.get('current_pressure'):why=f'新增预算约 {guard["new_budget_wait_seconds"]:.0f} 秒后重试；有探测轮次时复测已有候选'
                    label=f'共存：扫描最高 {guard["effective_packet_ceiling"]} 包/秒，新增最高 {guard["effective_new_ceiling"]}/秒 · 近期组合 {guard["recently_touched_combinations"]}/{guard["footprint_limit"]}（估计值） · {why}'
                    if guard['monitor']!='trace_monitoring':label+=' · Bifrost 日志不可读，仅主动预算保护'
                status.set(('房间只有你，持续等待其他成员。' if event['waiting_alone'] else f'当前集中探测 {len(event["active_dense_peers"])} 对；已通成员立即可用。')+
                    f' {label} · 近10秒实发 {event.get("actual_probe_packets_pps",0):.1f} 包/秒，新增 {event["actual_new_probe_combinations_pps"]:.1f}/秒 · 本轮成功新增 {combo["successful_unique_combinations"]} · 已运行 {int(event["elapsed_seconds"])} 秒'+(' · Tailscale 状态读取异常：'+event['tail_manager_error'] if event['tail_manager_error'] else ''))
            elif kind=='session_closed':
                for widget in (nickname,room_entry,generate_button,game_port_entry,start_button):widget.configure(state='normal')
                modes.configure(state='readonly');speeds.configure(state='readonly');roles.configure(state='readonly');room_state.set('当前房间：已退出');mc_address.set('已退出房间');write(event['message'])
            elif kind=='pair_event':
                e=event['pair_event'];write(event['time']+' '+event.get('peer_name','')+' '+e['event']+' '+str(e.get('message','')))
            else:write(event.get('time','')+' '+kind+' '+str(event.get('message') or {k:v for k,v in event.items() if k not in ('event','time','generation')}))
        root.after(100,pump)
    def close():
        stop()
        def finish():
            if session.running():root.after(100,finish)
            else:root.destroy()
        finish()
    root.protocol('WM_DELETE_WINDOW',close);root.after(100,pump)
    if check:root.after(100,lambda:check(root,{'session':session,'state':state,'start':start,'mode':mode,'speed':speed,'code':code,'table':table,'status':status,'room_state':room_state,'mc_role':mc_role,'mc_port':mc_port,'mc_address':mc_address,'mc_controls':mc_controls}))
    root.mainloop()

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--cli',action='store_true');parser.add_argument('--config');parser.add_argument('--code');parser.add_argument('--name',default=os.environ.get('COMPUTERNAME','whb'))
    parser.add_argument('--udp-only',action='store_true');parser.add_argument('--new-combinations-per-second',type=int);parser.add_argument('--coexist',action='store_true');parser.add_argument('--result');parser.add_argument('--duration',type=float);parser.add_argument('--self-check',action='store_true');parser.add_argument('--tail-check',action='store_true');parser.add_argument('--target')
    parser.add_argument('--star-role',choices=['host','player']);parser.add_argument('--game-port',type=int,default=25565)
    args=parser.parse_args()
    if args.tail_check:
        import threading,traceback
        from meshtail import TailManager
        manager=TailManager(threading.Event(),lambda *a,**k:None,True)
        if args.target:manager.set_targets({args.target:'diagnostic'})
        try:
            manager.refresh();report={'version':VERSION,'passed':bool(manager.own.get('tail_ip') and manager.port and (not args.target or args.target in manager.metadata)),
                'manager':manager.snapshot(),'scope':'read-only native Tailscale identity, UDP port and peer metadata; no capture, firewall or proxy changes'}
        except Exception as exc:report={'version':VERSION,'passed':False,'error_type':type(exc).__name__,'error':str(exc),'traceback':traceback.format_exc(),'manager':manager.snapshot()}
        if args.result:pathlib.Path(args.result).write_text(json.dumps(report,ensure_ascii=False,indent=2),encoding='utf8')
        if not report['passed']:raise SystemExit(1)
        return
    if args.self_check:
        try:report={'version':VERSION,**driver_check()}
        except (OSError,RuntimeError) as exc:report={'version':VERSION,'passed':False,'error':str(exc)}
        if args.result:pathlib.Path(args.result).write_text(json.dumps(report,ensure_ascii=False,indent=2),encoding='utf8')
        if not report['passed']:raise SystemExit(1)
        return
    cfg=defaults(json.loads(pathlib.Path(args.config or BASE/'config.json').read_text(encoding='utf8')))
    if not args.cli:return gui(cfg)
    cfg['tailscale_bridge']=not args.udp_only;cfg['new_combinations_per_second']=args.new_combinations_per_second
    cfg['mesh_coexist_guard']=args.coexist
    if args.star_role:
        cfg.update(mesh_topology='star',mesh_role=args.star_role,mc_game_port=args.game_port)
    if args.duration:cfg['mesh_test_duration']=args.duration
    if not args.code:parser.error('CLI requires --code')
    c=MultiClient(cfg,args.code,args.name,lambda e:print(json.dumps(e,ensure_ascii=False),flush=True) if not getattr(sys,'frozen',False) else None)
    c.run()
    if args.result:export_mesh(c,args.result)
    if any(e['event']=='error' for e in c.logs):raise SystemExit(1)
if __name__=='__main__':main()
