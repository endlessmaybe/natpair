"""Export UDP metadata and correlate both ends without clock synchronization.

These are client-attested metadata, not a cryptographically signed audit of
the operating system or of an operator's inaccessible CGNAT mapping table.
"""
import argparse,json,pathlib,zipfile

def export_evidence(client,path):
    path=pathlib.Path(path)
    if path.suffix.lower()!='.zip':
        path.write_text(json.dumps(client.summary(),ensure_ascii=False,indent=2),encoding='utf-8');return
    journal=client.journal
    # Snapshot under the writer lock, then compress outside it. Compressing
    # hundreds of MiB under the lock can block keepalive for >8 seconds.
    snapshot=[]
    with journal.lock:
        if journal.file:journal.file.flush()
        if journal.opening:journal.opening.flush()
        summary=client.summary()
        files=[f for f in sorted(journal.directory.iterdir()) if f.suffix in ('.json','.jsonl')]
        if sum(f.stat().st_size for f in files)>320*1024*1024:raise ValueError('evidence exceeds 320 MiB')
        snapshot=[(f.name,f.read_bytes()) for f in files]
    # Bounded immutable in-memory snapshot: no temporary files on either PC.
    with zipfile.ZipFile(path,'w',compression=zipfile.ZIP_DEFLATED) as out:
        out.writestr('summary.json',json.dumps(summary,ensure_ascii=False,indent=2))
        for name,data in snapshot:out.writestr('evidence/'+name,data)

def load_bundle(path):
    path=pathlib.Path(path);records={};proofs=[];invalid=0;total=0
    def read(name,data):
        nonlocal invalid
        if name.endswith('first-hit-proof.json'):
            try:
                p=json.loads(data);proofs.append(p)
                for item in [p.get('tx',{}),p.get('rx',{}),*p.get('recent_metadata',[])]:add(item)
            except (ValueError,TypeError):invalid+=1
        elif name.endswith('.jsonl'):
            for line in data.splitlines():
                if line:
                    try:add(json.loads(line))
                    except (ValueError,TypeError):invalid+=1
    def add(item):
        if not isinstance(item,dict):raise ValueError('metadata record must be an object')
        if item.get('direction') in ('tx','rx') and item.get('kind') in ('probe','ack'):
            key=(item.get('actor'),item.get('journal_seq'))
            if key in records and records[key]!=item:raise ValueError('conflicting sequence')
            records[key]=item
    if path.is_dir():
        files=[(f.name,f) for f in sorted(path.iterdir()) if f.suffix in ('.json','.jsonl')]
        for name,f in files:
            total+=f.stat().st_size
            if total>320*1024*1024:raise ValueError('evidence exceeds 320 MiB')
            read(name,f.read_text(encoding='utf-8'))
    else:
        with zipfile.ZipFile(path) as z:
            for member in z.infolist():
                if not member.filename.endswith(('.json','.jsonl')):continue
                total+=member.file_size
                if total>320*1024*1024:raise ValueError('evidence exceeds 320 MiB')
                read(member.filename,z.read(member).decode('utf-8'))
    return list(records.values()),proofs,invalid

def valid_local(p):
    tx,rx=p.get('tx') or {},p.get('rx') or {}
    return bool(tx.get('kind')=='probe' and tx.get('direction')=='tx' and tx.get('accepted') is True
        and rx.get('kind')=='ack' and rx.get('direction')=='rx' and rx.get('accepted') is True and rx.get('hmac_valid') is True
        and tx.get('nonce') and tx.get('nonce')==rx.get('nonce') and tx.get('socket_id')==rx.get('socket_id')
        and tx.get('actor')==rx.get('actor')==tx.get('sender')==rx.get('receiver')
        and tx.get('receiver')==rx.get('sender') and tx.get('mono_ns',0)<rx.get('mono_ns',0)
        and rx['mono_ns']-tx['mono_ns']<=5_000_000_000 and tx.get('sha256')==rx.get('probe_sha256'))

def analyze(paths):
    records=[];proofs=[];invalid=0
    for path in paths:
        r,p,i=load_bundle(path);records.extend(r);proofs.extend(p);invalid+=i
    dedup={}
    for r in records:
        key=(r.get('actor'),r.get('journal_seq'))
        if key in dedup and dedup[key]!=r:invalid+=1
        dedup[key]=r
    records=list(dedup.values());answers=[]
    for p in proofs:
        tx,rx=p.get('tx') or {},p.get('rx') or {};local=valid_local(p)
        item={'actor':tx.get('actor'),'nonce':tx.get('nonce'),'local_evidence_valid':local,'unique_four_packet_chain':False,
            'lane':tx.get('lane'),'source_slot':tx.get('slot'),'local_socket':tx.get('local'),
            'probe_target':tx.get('remote'),'authenticated_reply_source':rx.get('remote'),
            'source_observed_by_peer':rx.get('observed_by_peer'),'reason':'local_proof_invalid' if not local else 'counterpart_records_missing'}
        if local and tx.get('trigger_nonce'):
            received=[r for r in records if r.get('actor')==tx['actor'] and r.get('direction')=='rx'
                and r.get('kind')=='probe' and r.get('accepted') is True and r.get('hmac_valid') is True
                and r.get('nonce')==tx['trigger_nonce'] and r.get('sha256')==tx.get('trigger_probe_sha256')
                and r.get('journal_seq')==tx.get('trigger_rx_seq') and r.get('socket_id')==tx.get('socket_id')
                and r.get('remote')==tx.get('remote') and r.get('mono_ns',0)<tx.get('mono_ns',0)]
            causes=[r for r in records if r.get('actor')==tx['receiver'] and r.get('direction')=='tx' and r.get('kind')=='probe'
                and r.get('nonce')==tx['trigger_nonce'] and r.get('sha256')==tx.get('trigger_probe_sha256') and r.get('accepted') is True]
            if len(received)==1 and len(causes)==1:
                item['triggering_probe']={k:causes[0].get(k) for k in ('actor','nonce','lane','slot','local','remote','journal_seq')}
            else:item['triggering_probe_incomplete']=True
        if local:
            probes=[r for r in records if r.get('actor')==tx['receiver'] and r.get('direction')=='rx'
                and r.get('kind')=='probe' and r.get('accepted') is True and r.get('hmac_valid') is True
                and r.get('nonce')==tx['nonce'] and r.get('sha256')==tx['sha256'] and r.get('sender')==tx['sender'] and r.get('receiver')==tx['receiver']]
            acks=[r for r in records if r.get('actor')==tx['receiver'] and r.get('direction')=='tx'
                and r.get('kind')=='ack' and r.get('accepted') is True and r.get('nonce')==tx['nonce']
                and r.get('sha256')==rx['sha256'] and r.get('probe_sha256')==tx['sha256'] and r.get('sender')==rx['sender'] and r.get('receiver')==rx['receiver']]
            chains=[(a,b) for a in probes for b in acks if a.get('socket_id')==b.get('socket_id')
                and a.get('local')==b.get('local') and a.get('remote')==b.get('remote')==rx.get('observed_by_peer')
                and a.get('mono_ns',0)<b.get('mono_ns',0) and a.get('journal_seq',0)<b.get('journal_seq',0)]
            if len(chains)==1:
                a,b=chains[0];item.update(unique_four_packet_chain=True,reason='nonce_and_both_datagram_digests_matched',
                    peer_receive_slot=a.get('slot'),peer_local_socket=a.get('local'),
                    packet_sequences={'probe_tx':tx.get('journal_seq'),'probe_rx':a.get('journal_seq'),
                        'ack_tx':b.get('journal_seq'),'ack_rx':rx.get('journal_seq')})
            elif chains:item['reason']='multiple_matching_chains'
        answers.append(item)
    return {'format':'NATPair-Trace-evidence-v1','invalid_metadata_records':invalid,'first_hits':answers,
        'all_hits_uniquely_correlated':bool(answers) and not invalid and all(x['unique_four_packet_chain'] for x in answers),
        'scope':'identifies each successful probe strategy and socket; does not uniquely identify prior NAT priming or operator mapping rules'}

def main():
    p=argparse.ArgumentParser(description='Correlate NATPair packet evidence from both ends')
    p.add_argument('bundles',nargs='+');p.add_argument('--output');args=p.parse_args();result=analyze(args.bundles)
    text=json.dumps(result,ensure_ascii=False,indent=2)
    if args.output:pathlib.Path(args.output).write_text(text,encoding='utf-8')
    else:print(text)
if __name__=='__main__':main()
