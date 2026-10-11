"""Session modes: UDP-only has no Tailscale dependency or overlay transport."""
MODE_TAIL='接入 Tailscale（快速）'
MODE_UDP='仅 UDP 打洞（不接入 Tailscale）'
MODE_UDP_SYNC='仅 UDP 打洞（Tailscale 同步信息）'

def configure_mode(cfg,mode,measure_only=False):
    result=dict(cfg);udp_only=mode in (MODE_UDP,MODE_UDP_SYNC);sync_only=mode==MODE_UDP_SYNC
    bridge=mode==MODE_TAIL and not measure_only
    result.update(session_mode=mode,udp_only=udp_only,tailscale_bridge=bridge,
        production_mode=bridge or (udp_only and not measure_only and bool(cfg.get('run_continuously'))),
        tail_tcp_check=bridge,scoped_peer_firewall=not measure_only,tail_metadata_only=sync_only and not measure_only,
        raw_tcp_experiment=False,tcp_udp_assist=False)
    if mode==MODE_UDP:
        result.update(peer_sync_overlay=False,control_tail_host='',control_transports=['system','physical'],
            peer_tail_ip='',peer_sync_host='',peer_sync_bind='')
    elif sync_only:result['peer_sync_overlay']=not measure_only
    return result
