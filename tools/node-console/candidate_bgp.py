"""Transactional configuration for the fixed isolated three-node BGP cohort."""
import hashlib
import json
import os
import pathlib
import subprocess
import signal
import time
import candidate_status as c

def default_config(node):
    peers = []
    for other, addresses in c.ADDRESSES.items():
        if other == node: continue
        for family, address in zip((4,6), addresses):
            peers.append(dict(address=address, family=family, remote_asn=c.NODES[other], enabled=True, keepalive_seconds=3, hold_seconds=9))
    return dict(local_asn=c.NODES[node], router_id=c.ADDRESSES[node][0], peers=peers,
                announcements=[dict(role=r, family=f, enabled=True) for r in ('normal','dns64') for f in (4,6)])

def validate(node, obj):
    expected = default_config(node)
    if not isinstance(obj,dict) or set(obj) != set(expected): raise ValueError('configuration fields')
    if type(obj['local_asn']) is not int or obj['local_asn'] != expected['local_asn'] or obj['router_id'] != expected['router_id']: raise ValueError('fixed local identity')
    if not isinstance(obj['peers'],list) or len(obj['peers']) != 4: raise ValueError('four fixed peers')
    lookup = {p['address']:p for p in expected['peers']}
    seen = set()
    for p in obj['peers']:
        if not isinstance(p,dict) or set(p) != set(expected['peers'][0]) or p['address'] not in lookup or p['address'] in seen: raise ValueError('fixed peer fields')
        seen.add(p['address']); e=lookup[p['address']]
        if type(p['family']) is not int or type(p['remote_asn']) is not int or p['family']!=e['family'] or p['remote_asn']!=e['remote_asn'] or type(p['enabled']) is not bool: raise ValueError('fixed peer identity')
        k,h=p['keepalive_seconds'],p['hold_seconds']
        if type(k) is not int or type(h) is not int or not 3<=k<=30 or not 9<=h<=90 or h<3*k: raise ValueError('timer bounds')
    if any(not any(p['enabled'] and p['family']==f for p in obj['peers']) for f in (4,6)): raise ValueError('one enabled peer per family required')
    announcements=obj['announcements']
    if not isinstance(announcements,list) or len(announcements)!=4: raise ValueError('four announcements')
    if any(not isinstance(a,dict) or set(a)!={'role','family','enabled'} or type(a['family']) is not int or type(a['enabled']) is not bool for a in announcements): raise ValueError('announcement fields')
    if {(a['role'],a['family']) for a in announcements}!={(r,f) for r in ('normal','dns64') for f in (4,6)}: raise ValueError('fixed announcements')
    return dict(local_asn=obj['local_asn'],router_id=obj['router_id'],peers=sorted(obj['peers'],key=lambda p:p['address']),announcements=sorted(announcements,key=lambda a:(a['role'],a['family'])))

def test_client():
    """Root-enrolled receive-only test client; never accepted from browser input."""
    path=c.BASE/'test-client.json'
    if not path.exists(): return None
    value=c.read(path)
    if not isinstance(value,dict) or set(value)!={'schema','name','asn','ipv4','ipv6'} or type(value['schema']) is not int or value['schema']!=1 or value['name']!='secdns-test-client109' or type(value['asn']) is not int or value['asn']!=65109:
        raise ValueError('fixed test client identity')
    import ipaddress
    for family,subnet in ((4,'100.91.1.0/24'),(6,'2001:470:f9d1:9001::/64')):
        address=value['ipv'+str(family)]
        parsed=ipaddress.ip_address(address)
        network=ipaddress.ip_network(subnet)
        if parsed.version!=family or str(parsed)!=address or parsed not in network or parsed==network.network_address or (family==4 and parsed==network.broadcast_address) or address in {a for pair in c.ADDRESSES.values() for a in pair} or parsed.is_multicast or parsed.is_unspecified:
            raise ValueError('test client address scope')
    return value


def get(node):
    path=c.BASE/'bgp-console.json'
    config=validate(node,c.read(path) if path.exists() else default_config(node))
    client=test_client()
    revision_input=config if client is None else dict(config=config,test_client=client)
    revision=hashlib.sha256(json.dumps(revision_input,sort_keys=True,separators=(',',':')).encode()).hexdigest()
    return dict(schema=1,node=node,revision=revision,config=config)

def render(node, config):
    config=validate(node,config)
    client=test_client()
    lines=['hostname secdns-'+node,'log stdout warnings','bgp as-path access-list LOCAL-ONLY permit ^$']
    for f in (4,6):
        kind='ip' if f==4 else 'ipv6'
        for i,prefix in enumerate(sorted(p for p in c.PREFIXES if (':' in p)==(f==6))): lines.append(f'{kind} prefix-list EXACT{f} seq {(i+1)*10} permit {prefix}')
    for name in c.NODES:
        preference={'cix106':300,'intel108':200,'amd103':100}[name]
        for f in (4,6): lines += [f'route-map IN-{name}-{f} permit 10',f' match {"ip" if f==4 else "ipv6"} address prefix-list EXACT{f}',f' set local-preference {preference}']
    for f in (4,6): lines += [f'route-map OUT-{f} permit 10',f' match {"ip" if f==4 else "ipv6"} address prefix-list EXACT{f}',' match as-path LOCAL-ONLY']
    if client: lines += ['route-map TEST-CLIENT-DENY deny 10']
    lines += [f'router bgp {config["local_asn"]}',f' bgp router-id {config["router_id"]}',' no bgp default ipv4-unicast',' bgp graceful-restart-disable']
    for p in config['peers']:
        a=p['address'];f=p['family']
        lines += [f' neighbor {a} remote-as {p["remote_asn"]}',f' neighbor {a} port 1179',f' neighbor {a} update-source {c.ADDRESSES[node][0 if f==4 else 1]}',f' neighbor {a} timers {p["keepalive_seconds"]} {p["hold_seconds"]}']
        if not p['enabled']: lines.append(f' neighbor {a} shutdown')
    if client:
        for f in (4,6):
            address=client['ipv'+str(f)]
            lines += [f' neighbor {address} remote-as {client["asn"]}',f' neighbor {address} port 1179',f' neighbor {address} update-source {c.ADDRESSES[node][0 if f==4 else 1]}',f' neighbor {address} timers 3 9']
    for f in (4,6):
        lines.append(f' address-family ipv{f} unicast')
        for p in config['peers']:
            if p['family']!=f: continue
            a=p['address'];name=next(n for n,aa in c.ADDRESSES.items() if a in aa)
            lines += [f'  neighbor {a} activate',f'  neighbor {a} route-map IN-{name}-{f} in',f'  neighbor {a} route-map OUT-{f} out']
        if client:
            address=client['ipv'+str(f)]
            lines += [f'  neighbor {address} activate',f'  neighbor {address} route-map TEST-CLIENT-DENY in',f'  neighbor {address} route-map OUT-{f} out']
        lines.append(' exit-address-family')
    return '\n'.join(lines)+'\n'

def atomic_text(path,text):
    temp=path.with_name(path.name+'.tmp-'+os.urandom(16).hex())
    fd=os.open(str(temp),os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
    try:
        if path.exists():
            c.secure(path);meta=path.stat();os.fchown(fd,meta.st_uid,meta.st_gid);os.fchmod(fd,meta.st_mode&0o777)
        with os.fdopen(fd,'w') as f: f.write(text);f.flush();os.fsync(f.fileno())
        os.replace(temp,path)
        fd=os.open(str(path.parent),os.O_DIRECTORY)
        try: os.fsync(fd)
        finally: os.close(fd)
    finally:
        if temp.exists():temp.unlink()

def restart():
    p=subprocess.run(['systemctl','restart','secdns-candidate-routing.service'],capture_output=True,text=True,timeout=15)
    if p.returncode: raise RuntimeError('candidate routing restart failed')

def read_request(node, payload):
    if not isinstance(payload,dict) or set(payload)!={'expected_revision','config'}: raise ValueError('request fields')
    old=get(node)
    if payload['expected_revision']!=old['revision']:raise ValueError('configuration changed; refresh')
    return old,validate(node,payload['config'])

def preflight(node,config):
    path=c.BASE/('bgp-check-'+os.urandom(16).hex()+'.conf')
    try:
        atomic_text(path,render(node,config))
        p=subprocess.run(['/usr/lib/frr/bgpd','-C','-S','-Z','-p','0','-P','0','-f',str(path)],capture_output=True,text=True,timeout=5)
        if p.returncode:raise ValueError('FRR rejected configuration')
    finally:
        if path.exists():path.unlink()

def lock_file():
    folder=c.BASE/'console-receipts';folder.mkdir(mode=0o700,exist_ok=True);c.secure(folder,True)
    path=folder/'operation.lock'
    f=os.fdopen(os.open(str(path),os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600),'w')
    c.secure(path)
    return f

def rollback_locked(node,receipt,path):
    if receipt['node']!=node or receipt['action']!='bgp-apply':raise ValueError('receipt identity')
    if receipt['status']!='pending':return
    atomic_text(c.BASE/'bgp.conf',receipt['old_bgp'])
    c.atomic(c.BASE/'bgp-console.json',validate(node,receipt['old_config']))
    c.atomic(c.BASE/'maintenance.json',{'withdraw':True})
    restart()
    c.atomic(c.BASE/'maintenance.json',{'withdraw':receipt['old_withdraw']})
    deadline=time.monotonic()+40
    while True:
        result=c.snapshot(node)
        config=receipt['old_config']
        expected={p['address']:p['enabled'] for p in config['peers']}
        flags={(a['role'],a['family']):a['enabled'] for a in config['announcements']}
        baseline={(p['role'],p['family']):p['healthy'] for p in receipt.get('old_profile_health',[])}
        ready=not result['stale'] and len(result['peers'])==4 and all((p['state']=='Established')==expected[p['address']] for p in result['peers'])
        ready=ready and all(p['healthy'] is not None and p['advertised']==(p['healthy'] and flags[p['role'],p['family']] and not receipt['old_withdraw']) for p in result['profiles'])
        ready=ready and all(p['healthy'] is True or baseline.get((p['role'],p['family']),True) is not True for p in result['profiles'])
        ready=ready and get(node)['config']==validate(node,config) and (c.BASE/'bgp.conf').read_text()==receipt['old_bgp']
        if ready:break
        if time.monotonic()>deadline:raise RuntimeError('rollback not observed; receipt remains pending')
        time.sleep(1)
    receipt.update(status='rolled_back',confirmed=False)
    c.atomic(path,receipt)

def rollback(node,request_id):
    c.identity(node)
    if not c.re.fullmatch(r'[0-9a-f-]{36}',request_id):raise ValueError('request')
    path=c.BASE/'console-receipts'/(request_id+'.json')
    receipt=c.read(path)
    if receipt.get('node')!=node or receipt.get('request_id')!=request_id or receipt.get('action')!='bgp-apply':raise ValueError('rollback ownership')
    if receipt['status']=='pending':terminate_worker(receipt,node,request_id)
    with lock_file() as lock:
        deadline=time.monotonic()+5
        while True:
            try:c.fcntl.flock(lock,c.fcntl.LOCK_EX|c.fcntl.LOCK_NB);break
            except BlockingIOError:
                if time.monotonic()>deadline:raise RuntimeError('rollback lock unavailable; receipt pending')
                time.sleep(.1)
        receipt=c.read(path)
        if receipt['request_id']!=request_id:raise ValueError('receipt mismatch')
        rollback_locked(node,receipt,path)

def worker_identity(pid):
    proc=pathlib.Path('/proc')/str(pid)
    return (proc/'stat').read_text().rsplit(')',1)[1].split()[19],(proc/'cmdline').read_bytes().decode().split('\0')[:-1]

def terminate_worker(receipt,node,request_id):
    pid=receipt.get('worker_pid')
    try:start,command=worker_identity(pid)
    except FileNotFoundError:return False
    if pid!=os.getpid() and start==receipt.get('worker_start') and command[-3:]==['bgp-apply',node,request_id] and str(c.BASE/'candidate_status.py') in command:
        os.kill(pid,signal.SIGKILL);return True
    return False

def apply(node,request_id,payload):
    c.identity(node)
    if not c.re.fullmatch(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',request_id):raise ValueError('request')
    path=c.BASE/'console-receipts'/(request_id+'.json')
    with lock_file() as lock:
        c.fcntl.flock(lock,c.fcntl.LOCK_EX|c.fcntl.LOCK_NB)
        digest=hashlib.sha256(json.dumps(payload,sort_keys=True).encode()).hexdigest()
        if path.exists():
            receipt=c.read(path)
            if receipt.get('action')!='bgp-apply' or receipt.get('payload_digest')!=digest or receipt.get('node')!=node:raise ValueError('request already bound')
            result=c.snapshot(node);result['operation']={k:receipt[k] for k in ('request_id','action','status','confirmed')};result['bgp']=get(node);return result
        for p in path.parent.glob('*.json'):
            prior=c.read(p)
            if prior.get('action')=='bgp-apply' and prior.get('status')=='pending':raise ValueError('pending transaction requires reconciliation')
        old,config=read_request(node,payload)
        before=c.snapshot(node)
        if before['stale']:raise ValueError('fresh inspection required')
        preflight(node,config)
        c.secure(c.BASE/'bgp.conf')
        receipt=dict(request_id=request_id,action='bgp-apply',node=node,status='pending',confirmed=False,payload_digest=digest,old_config=old['config'],old_bgp=(c.BASE/'bgp.conf').read_text(),old_withdraw=before['maintenance']['withdraw'],worker_pid=os.getpid(),worker_start=pathlib.Path('/proc/self/stat').read_text().rsplit(')',1)[1].split()[19])
        receipt['old_profile_health']=[{k:p[k] for k in ('role','family','healthy')} for p in before['profiles']]
        c.atomic(path,receipt)
        unit='secdns-bgp-rollback-'+request_id
        try:
            c.run(['systemd-run','--unit='+unit,'--on-active=120s','--timer-property=AccuracySec=1s','/usr/bin/python3',str(c.BASE/'candidate_status.py'),'bgp-rollback',node,request_id])
            c.atomic(c.BASE/'maintenance.json',{'withdraw':True})
            # Existing health controller drains before private daemon replacement.
            deadline=time.monotonic()+8
            while True:
                withdrawn=c.snapshot(node)
                if not withdrawn['stale'] and not any(p['advertised'] for p in withdrawn['profiles']):break
                if time.monotonic()>deadline:raise RuntimeError('withdrawal not observed')
                time.sleep(.5)
            atomic_text(c.BASE/'bgp.conf',render(node,config));c.atomic(c.BASE/'bgp-console.json',config)
            restart()
            c.atomic(c.BASE/'maintenance.json',{'withdraw':receipt['old_withdraw']})
            deadline=time.monotonic()+40
            while True:
                result=c.snapshot(node)
                expected={p['address']:p['enabled'] for p in config['peers']}
                peers_ok=len(result['peers'])==4 and all((p['state']=='Established')==expected[p['address']] for p in result['peers'])
                flags={(a['role'],a['family']):a['enabled'] for a in config['announcements']}
                profiles_ok=all(p['healthy'] is True and p['advertised']==(flags[p['role'],p['family']] and not receipt['old_withdraw']) for p in result['profiles'])
                if not result['stale'] and peers_ok and profiles_ok:break
                if time.monotonic()>deadline:raise RuntimeError('configuration did not converge')
                time.sleep(1)
            receipt.update(status='confirmed',confirmed=True);c.atomic(path,receipt)
        except Exception:
            rollback_locked(node,receipt,path)
            result=c.snapshot(node)
        finally:
            # A failed stop leaves a harmless receipt-checking timer, not a later rollback.
            if receipt['status']!='pending':subprocess.run(['systemctl','stop',unit+'.timer'],capture_output=True,timeout=3)
        result['operation']={k:receipt[k] for k in ('request_id','action','status','confirmed')};result['bgp']=get(node)
        return result
