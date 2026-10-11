"""Separate multiplayer listeners; the existing two-player service is untouched."""
import argparse,asyncio,json,pathlib
from server import LabServer,start

class MeshServer(LabServer):
    def admit(self,ip):
        import time
        now=time.monotonic();at,left=self.budget.get(ip,(now,40.))
        left=min(40.,left+max(0,now-at)*160)
        self.budget[ip]=(now,max(0,left-1))
        if len(self.budget)>2048:self.budget={k:v for k,v in self.budget.items() if now-v[0]<60}
        return left>=1

async def main():
    parser=argparse.ArgumentParser();parser.add_argument('--config',required=True);parser.add_argument('--cert',required=True);parser.add_argument('--key',required=True)
    args=parser.parse_args();cfg=json.loads(pathlib.Path(args.config).read_text())
    service=MeshServer(cfg['access']);service.room_udp_port=cfg['room_udp_port'];service.mesh_window=cfg.get('mesh_window_seconds',120)
    listeners=await start(service,cfg.get('listen_host','204.152.206.124'),cfg['lab_udp_base'],cfg['lab_control_port'],args.cert,args.key,cfg.get('control_tail_bind'))
    print('NATPair Mesh v1.1.0 ready',flush=True)
    try:await asyncio.Event().wait()
    finally:
        for listener in listeners:listener.close()
if __name__=='__main__':asyncio.run(main())
