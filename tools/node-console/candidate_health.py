"""Root-owned upstream health settings, hot reload, durable rollback watchdog."""
import hashlib
import json
import os
import pathlib
import signal
import subprocess
import time
import candidate_status as c
import candidate_bgp as bgp
import health_settings as settings

def get(node):
    c.identity(node)
    config=settings.load(c.BASE/'health-settings.json')
    return dict(schema=1,node=node,revision=settings.revision(config),config=config,derived=dict(stale_seconds=settings.stale_seconds(config)))

def read_request(node,payload):
    if not isinstance(payload,dict) or set(payload)!={'expected_revision','config'}: raise ValueError('request fields')
    old=get(node)
    if payload['expected_revision']!=old['revision']:raise ValueError('configuration changed; refresh')
    return old,settings.validate(payload['config'])

def wait_ready(node,revision,baseline,timeout):
    deadline=time.monotonic()+timeout
    while True:
        result=c.snapshot(node)
        before={(p['role'],p['family']):p for p in baseline}
        ready=not result['stale'] and result.get('health_settings_revision')==revision
        ready=ready and len(result['profiles'])==4 and all(p['healthy'] is True or before[p['role'],p['family']]['healthy'] is not True for p in result['profiles'])
        ready=ready and all(p['advertised']==before[p['role'],p['family']]['advertised'] for p in result['profiles'])
        if ready:return result
        if time.monotonic()>deadline:raise RuntimeError('settings recovery not observed')
        time.sleep(.5)

def rollback_locked(node,receipt,path):
    if receipt['node']!=node or receipt['action']!='health-apply':raise ValueError('receipt identity')
    if receipt['status']!='pending':return
    config=settings.validate(receipt['old_config'])
    c.atomic(c.BASE/'health-settings.json',config)
    if c.snapshot(node).get('upstream_worker_failed') is True and not receipt.get('rollback_routing_restart'):
        # The stopped worker cannot acknowledge rollback. Kill its owned process
        # tree through the private routing unit, never restart the DNS process.
        receipt['rollback_routing_restart']=True;c.atomic(path,receipt)
        bgp.restart()
    wait_ready(node,settings.revision(config),receipt['old_profiles'],90)
    if get(node)['config']!=config:raise ValueError('rollback configuration mismatch')
    receipt.update(status='rolled_back',confirmed=False);c.atomic(path,receipt)

def rollback(node,request_id):
    c.identity(node)
    if not c.re.fullmatch(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',request_id):raise ValueError('request')
    path=c.BASE/'console-receipts'/(request_id+'.json');receipt=c.read(path)
    if receipt.get('node')!=node or receipt.get('request_id')!=request_id or receipt.get('action')!='health-apply':raise ValueError('rollback ownership')
    if receipt['status']=='pending':
        try:
            start,command=bgp.worker_identity(receipt['worker_pid'])
            if receipt['worker_pid']!=os.getpid() and start==receipt['worker_start'] and command[-3:]==['health-apply',node,request_id] and str(c.BASE/'candidate_status.py') in command:os.kill(receipt['worker_pid'],signal.SIGKILL)
        except FileNotFoundError:pass
    with bgp.lock_file() as lock:
        deadline=time.monotonic()+5
        while True:
            try:c.fcntl.flock(lock,c.fcntl.LOCK_EX|c.fcntl.LOCK_NB);break
            except BlockingIOError:
                if time.monotonic()>deadline:raise RuntimeError('rollback lock unavailable')
                time.sleep(.1)
        rollback_locked(node,c.read(path),path)

def apply(node,request_id,payload):
    c.identity(node)
    if not c.re.fullmatch(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',request_id):raise ValueError('request')
    path=c.BASE/'console-receipts'/(request_id+'.json')
    with bgp.lock_file() as lock:
        c.fcntl.flock(lock,c.fcntl.LOCK_EX|c.fcntl.LOCK_NB)
        digest=hashlib.sha256(json.dumps(payload,sort_keys=True).encode()).hexdigest()
        if path.exists():
            receipt=c.read(path)
            if receipt.get('action')!='health-apply' or receipt.get('payload_digest')!=digest or receipt.get('node')!=node:raise ValueError('request already bound')
            result=c.snapshot(node);result['operation']={k:receipt[k] for k in ('request_id','action','status','confirmed')};result['health_settings']=get(node);return result
        for p in path.parent.glob('*.json'):
            prior=c.read(p)
            if prior.get('status')=='pending':raise ValueError('pending transaction requires reconciliation')
        old,config=read_request(node,payload);before=c.snapshot(node)
        if before['stale']:raise ValueError('fresh inspection required')
        receipt=dict(request_id=request_id,action='health-apply',node=node,status='pending',confirmed=False,payload_digest=digest,old_config=old['config'],old_profiles=before['profiles'],worker_pid=os.getpid(),worker_start=bgp.worker_identity(os.getpid())[0])
        c.atomic(path,receipt);unit='secdns-health-rollback-'+request_id
        try:
            c.run(['systemd-run','--unit='+unit,'--on-active=100s','--timer-property=AccuracySec=1s','/usr/bin/python3',str(c.BASE/'candidate_status.py'),'health-rollback',node,request_id])
            c.atomic(c.BASE/'health-settings.json',config)
            result=wait_ready(node,settings.revision(config),before['profiles'],85)
            if get(node)['config']!=config:raise ValueError('configuration mismatch')
            receipt.update(status='confirmed',confirmed=True);c.atomic(path,receipt)
        except Exception:
            rollback_locked(node,receipt,path);result=c.snapshot(node)
        finally:
            if receipt['status']!='pending':subprocess.run(['systemctl','stop',unit+'.timer'],capture_output=True,timeout=3)
        result['operation']={k:receipt[k] for k in ('request_id','action','status','confirmed')};result['health_settings']=get(node);return result
