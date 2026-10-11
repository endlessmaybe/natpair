"""Successful probe target coverage, independent of the scheduler."""
import threading

class Coverage:
    """Cumulative target coverage survives journal rotation, ~8KB per bitmap."""
    def __init__(self):self.rows={};self.lock=threading.Lock()
    @staticmethod
    def add(row,port):
        byte,bit=divmod(port-1,8);mask=1<<bit
        if not row['bits'][byte]&mask:
            row['bits'][byte]|=mask;row['unique']+=1
        row['sent']+=1
    def sent(self,ip,port,slot):
        with self.lock:
            if ip not in self.rows and len(self.rows)>=32:return
            row=self.rows.get(ip)
            if row is None:
                row={'bits':bytearray(8192),'unique':0,'sent':0,'slots':{}};self.rows[ip]=row
            self.add(row,port)
            source=row['slots'].get(slot)
            if source is None:
                source={'bits':bytearray(8192),'unique':0,'sent':0};row['slots'][slot]=source
            self.add(source,port)
    def snapshot(self):
        with self.lock:
            return {ip:{'unique_ports':row['unique'],'sent':row['sent'],
                        'source_slots':{str(slot):{'unique_ports':r['unique'],'sent':r['sent']}
                                        for slot,r in row['slots'].items()}}
                    for ip,row in self.rows.items()}
