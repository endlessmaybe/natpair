"""Display present evidence separately from historical success."""
def native_label(status,bridge=True):
    label=_native_label(status,bridge)
    state=status.get('tail_bridge_state') or {}
    if bridge and status.get('udp_direct_live') and state.get('proxy_ready') and state.get('capture_warning') and not state.get('bootstrap_stopped'):
        label+='；监听异常，等待对端引导'
    return label

def _native_label(status,bridge=True):
    if not bridge:return '仅诊断'
    if status.get('tail_bridge_error'):
        return 'NATPair 接入失败，原生仍经 DERP 可用' if status.get('tail_native_verified') and (status.get('tail_health') or {}).get('route')=='derp' else 'NATPair 接入失败，见接入异常'
    health=status.get('tail_health') or {}
    if status.get('tail_native_verified'):
        route=health.get('route')
        if route=='native_reported_direct' and str(health.get('cur_addr','')).startswith('['):
            return '已可用，原生 IPv6 直连'+('，TCP 检查通过' if health.get('tcp_business_verified') else '')
        label={'natpair_proxy':'已可用，走 NATPair 直连','proxy_unconfirmed':'已可用，代理路径待确认',
            'native_reported_direct':'已可用，Tailscale 报告直连','derp':'已可用，经 DERP 中继',
            'path_changed':'已可用，路径切换中','unknown':'已可用，路径读取待复核'}.get(route,'已可用，数据检查通过')
        return label+'，TCP 检查通过' if health.get('tcp_business_verified') else label
    state=health.get('state')
    if state=='data_verified':return '最近验证已过期，待复核'
    if state=='path_unconfirmed':return '探测有回复，代理数据路径待确认'
    if state=='validation_timeout':
        return '曾成功，当前数据验证超时' if status.get('seconds_to_first_native_tailscale') is not None else '代理已选中，数据验证超时'
    if state=='other_endpoint':return '探测已通，当前未选代理' if health.get('discovery_ok') else '当前未选代理'
    if state=='status_unavailable':return '状态读取失败，待复核'
    if state=='discovery_only':return '发现探测已通，数据待验证'
    if not status.get('udp_direct_live'):
        return '等待 UDP 恢复，原生待验证' if status.get('udp_direct_verified') else '原生待验证，UDP 探测中'
    return '正在建立原生通路'
