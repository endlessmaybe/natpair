"""Bounded, local diagnostics. Never stop services, uninstall or change filters."""
import ctypes,os,time
from ctypes import wintypes as w

def resources():
    result={'at':time.time(),'pid':os.getpid(),'scope':'local resource snapshot; not a kernel failure stack'}
    if os.name!='nt':return {**result,'available':False}
    k=ctypes.WinDLL('kernel32',use_last_error=True)
    class Memory(ctypes.Structure):
        _fields_=[('length',w.DWORD),('load',w.DWORD)]+[(n,ctypes.c_ulonglong) for n in ('physical_total','physical_available','commit_limit','commit_available','virtual_total','virtual_available','extended_available')]
    m=Memory();m.length=ctypes.sizeof(m)
    if k.GlobalMemoryStatusEx(ctypes.byref(m)):result['memory']={n:getattr(m,n) for n,_ in m._fields_[1:]}
    k.GetCurrentProcess.restype=w.HANDLE
    count=w.DWORD();k.GetProcessHandleCount.argtypes=[w.HANDLE,ctypes.POINTER(w.DWORD)]
    if k.GetProcessHandleCount(k.GetCurrentProcess(),ctypes.byref(count)):result['own_process_handles']=count.value
    class Performance(ctypes.Structure):
        _fields_=[('size',w.DWORD)]+[(n,ctypes.c_size_t) for n in ('commit_total','commit_limit','commit_peak','physical_total','physical_available','system_cache','kernel_total','kernel_paged','kernel_nonpaged','page_size')]+[(n,w.DWORD) for n in ('handles','processes','threads')]
    p=Performance();p.size=ctypes.sizeof(p)
    api=ctypes.WinDLL('psapi',use_last_error=True)
    if api.GetPerformanceInfo(ctypes.byref(p),p.size):result['performance']={n:getattr(p,n) for n,_ in p._fields_[1:]}
    return result

def device_probe():
    """Open/close existing WinDivert device only. No install, IOCTL or capture."""
    if os.name!='nt':return {'available':False}
    k=ctypes.WinDLL('kernel32',use_last_error=True)
    k.CreateFileW.argtypes=[w.LPCWSTR,w.DWORD,w.DWORD,ctypes.c_void_p,w.DWORD,w.DWORD,w.HANDLE];k.CreateFileW.restype=w.HANDLE
    k.CloseHandle.argtypes=[w.HANDLE];k.CloseHandle.restype=w.BOOL
    h=k.CreateFileW('\\\\.\\WinDivert',0xc0000000,0,None,3,0x40000080,None)
    if h in (None,ctypes.c_void_p(-1).value):
        return {'opened':False,'winerror':ctypes.get_last_error(),'stage':'CreateFile existing device; no filter startup'}
    try:return {'opened':True,'stage':'CreateFile succeeded on subsequent diagnostic attempt; original failure stage remains unproven'}
    finally:k.CloseHandle(h)

def collect():
    result=resources()
    try:result['device']=device_probe()
    except Exception as exc:result['device']={'diagnostic_error':str(exc)}
    try:result['wfp']=callout_snapshot()
    except Exception as exc:result['wfp']={'diagnostic_error':str(exc)}
    return result

def callout_snapshot(max_pages=32,api=None):
    """Read management-plane callouts; this is not a kernel-only callout census."""
    if api is None:
        if os.name!='nt':return {'available':False}
        api=ctypes.WinDLL('fwpuclnt',use_last_error=True)
    class Head(ctypes.Structure):
        _fields_=[('key',ctypes.c_byte*16),('name',w.LPWSTR),('description',w.LPWSTR),('flags',w.DWORD)]
    signatures={
        'FwpmEngineOpen0':[w.LPCWSTR,w.DWORD,ctypes.c_void_p,ctypes.c_void_p,ctypes.POINTER(w.HANDLE)],
        'FwpmEngineClose0':[w.HANDLE],
        'FwpmCalloutCreateEnumHandle0':[w.HANDLE,ctypes.c_void_p,ctypes.POINTER(w.HANDLE)],
        'FwpmCalloutDestroyEnumHandle0':[w.HANDLE,w.HANDLE],
        'FwpmCalloutEnum0':[w.HANDLE,w.HANDLE,w.DWORD,ctypes.POINTER(ctypes.c_void_p),ctypes.POINTER(w.DWORD)],
        'FwpmFreeMemory0':[ctypes.POINTER(ctypes.c_void_p)]}
    for name,args in signatures.items():getattr(api,name).argtypes=args;getattr(api,name).restype=w.DWORD if name!='FwpmFreeMemory0' else None
    engine=w.HANDLE();enum=w.HANDLE();result={'scope':'read-only WFP management snapshot, at most 4096 objects; cannot identify unlisted kernel registrations','count':0,'windivert_count':0,'windivert_names':{},'complete':False}
    code=api.FwpmEngineOpen0(None,10,None,None,ctypes.byref(engine))
    if code:return {**result,'error':int(code),'stage':'engine_open'}
    try:
        code=api.FwpmCalloutCreateEnumHandle0(engine,None,ctypes.byref(enum))
        if code:return {**result,'error':int(code),'stage':'create_enum'}
        try:
            for _ in range(max_pages):
                entries=ctypes.c_void_p();count=w.DWORD()
                try:
                    code=api.FwpmCalloutEnum0(engine,enum,128,ctypes.byref(entries),ctypes.byref(count))
                    if code:return {**result,'error':int(code),'stage':'enum_page'}
                    if count.value>128:raise RuntimeError('unexpected WFP enumeration size')
                    pointers=ctypes.cast(entries,ctypes.POINTER(ctypes.c_void_p))
                    for i in range(count.value):
                        head=ctypes.cast(pointers[i],ctypes.POINTER(Head)).contents;name=(head.name or '')[:160]
                        result['count']+=1
                        if 'windivert' in name.lower():
                            result['windivert_count']+=1
                            if len(result['windivert_names'])<32 or name in result['windivert_names']:result['windivert_names'][name]=result['windivert_names'].get(name,0)+1
                    if count.value<128:result['complete']=True;break
                finally:
                    if entries.value:api.FwpmFreeMemory0(ctypes.byref(entries))
        finally:api.FwpmCalloutDestroyEnumHandle0(engine,enum)
    finally:api.FwpmEngineClose0(engine)
    return result
