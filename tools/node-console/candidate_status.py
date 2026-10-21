"""Fixed, root-only isolated candidate inspection and maintenance control."""
import datetime
import fcntl
import json
import os
import pathlib
import stat
import subprocess
import sys
import time
import re

BASE = pathlib.Path('/opt/secdns-persistent-20261021')
NODES = {'amd103': 65101, 'cix106': 65102, 'intel108': 65103}
UNITS = {'amd103': 'era-secdns-manual-preview-p1.service', 'cix106': 'era-secdns-manual-preview-cix-p3.service', 'intel108': 'era-secdns-manual-preview-intel-p3.service'}
PREFIXES = {'203.0.113.53/32', '203.0.113.64/32', '2001:db8:53::53/128', '2001:db8:53::64/128'}
ADDRESSES = {'amd103': ('100.91.1.82', '2001:470:f9d1:9001:be24:11ff:fe53:e209'), 'cix106': ('100.91.1.83', '2001:470:f9d1:9001:45:52ff:fe41:106'), 'intel108': ('100.91.1.84', '2001:470:f9d1:9001:45:52ff:fe41:108')}

def secure(path, directory=False):
    s = path.lstat()
    if s.st_uid != 0 or s.st_mode & 0o022 or not (stat.S_ISDIR(s.st_mode) if directory else stat.S_ISREG(s.st_mode)):
        raise ValueError('unsafe candidate file')

def read(path):
    secure(path)
    return json.loads(path.read_text())

def atomic(path, obj):
    tmp = path.with_name(path.name + '.tmp-' + os.urandom(16).hex())
    fd = os.open(str(tmp), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    try:
        with os.fdopen(fd, 'w') as f:
            json.dump(obj, f)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
        fd = os.open(str(path.parent), os.O_DIRECTORY)
        try: os.fsync(fd)
        finally: os.close(fd)
    finally:
        if tmp.exists(): tmp.unlink()

def run(args):
    p = subprocess.run(args, capture_output=True, text=True, timeout=3)
    if p.returncode: raise RuntimeError('candidate command failed')
    if len(p.stdout) > 262144: raise RuntimeError('oversized candidate response')
    return p.stdout

def vty(command):
    return json.loads(run(['vtysh', '--vty_socket', str(BASE/'state'), '-d', 'bgpd', '-c', command]))

def advertised_prefixes(routes, family):
    if not isinstance(routes, dict) or not isinstance(routes.get('advertisedRoutes'), dict):
        raise ValueError('unrecognized advertisement response')
    prefixes = set(routes['advertisedRoutes'])
    allowed = {p for p in PREFIXES if (':' in p) == (family == 6)}
    if not prefixes <= allowed or any(not isinstance(v, dict) for v in routes['advertisedRoutes'].values()):
        raise ValueError('unexpected advertised prefix')
    return sorted(prefixes)

def identity(node):
    secure(BASE, True)
    c, h = read(BASE/'config-prepared.json'), read(BASE/'health.json')
    if node not in NODES or c['node'] != node or c['unit'] != UNITS[node] or h['bgp_asn'] != NODES[node] or set(h['allowed_prefixes']) != PREFIXES:
        raise ValueError('candidate identity mismatch')
    if len(h['entries']) != 4 or {e['prefix'] for e in h['entries']} != PREFIXES:
        raise ValueError('candidate profiles mismatch')
    return c, h

def snapshot(node):
    c, h = identity(node)
    errors = []
    props = run(['systemctl', 'show', c['unit'], '-p', 'ActiveState', '-p', 'MainPID'])
    props = dict(line.split('=', 1) for line in props.splitlines() if '=' in line)
    maintenance = read(BASE/'maintenance.json')
    if set(maintenance) != {'withdraw'} or type(maintenance['withdraw']) is not bool: raise ValueError('maintenance schema')
    heartbeat = None
    # Current boot only: monotonic times from an earlier boot cannot look fresh.
    for line in run(['journalctl', '-b', '-u', 'secdns-candidate-routing.service', '-n', '20', '-o', 'cat', '--no-pager']).splitlines():
        try:
            item = json.loads(line)
            if item.get('type') == 'health': heartbeat = item
        except ValueError: pass
    age = time.monotonic() - heartbeat['observed_monotonic'] if heartbeat else None
    fresh = age is not None and 0 <= age <= 12 and len(heartbeat.get('healthy', [])) == 4 and all(type(v) is bool for v in heartbeat['healthy'])
    if not fresh: errors.append('DNS health observations are stale or unavailable')
    peers = []
    try:
        summary = vty('show bgp summary json')
        for family in (4, 6):
            afi = summary['ipv%dUnicast' % family]
            expected = {a[0 if family == 4 else 1] for n, a in ADDRESSES.items() if n != node}
            if afi['as'] != NODES[node] or set(afi['peers']) != expected: raise ValueError('unexpected candidate peers')
            for address, p in afi['peers'].items():
                # FRR addresses are validated before forming a read-only command.
                import ipaddress
                ipaddress.ip_address(address)
                routes = vty('show bgp ipv%d unicast neighbors %s advertised-routes json' % (family, address))
                prefixes = advertised_prefixes(routes, family)
                peers.append({'address': address, 'family': family, 'state': p.get('state', 'Unknown'), 'prefixes': prefixes})
    except (KeyError, RuntimeError, ValueError, subprocess.SubprocessError, OSError):
        errors.append('BGP advertisement inspection unavailable')
    profiles = []
    for i, e in enumerate(h['entries']):
        targets = [p for p in peers if p['family'] == e['family'] and p['state'] == 'Established' and e['prefix'] in p['prefixes']]
        profiles.append({'role': e['role'], 'family': e['family'], 'prefix': e['prefix'], 'healthy': heartbeat['healthy'][i] if fresh else None, 'advertised': bool(targets)})
    return {'schema': 1, 'node': node, 'observed_at': datetime.datetime.now(datetime.timezone.utc).isoformat(), 'reachable': True, 'stale': bool(errors), 'errors': errors, 'heartbeat_age_seconds': age, 'daemon': {'active': props.get('ActiveState') == 'active', 'pid': int(props.get('MainPID', 0))}, 'maintenance': maintenance, 'profiles': profiles, 'peers': peers}

def operate(node, action, request_id):
    if action not in ('drain', 'resume') or not re.fullmatch(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', request_id): raise ValueError('invalid operation')
    identity(node)
    receipts = BASE/'console-receipts'
    receipts.mkdir(mode=0o700, exist_ok=True)
    secure(receipts, True)
    lock = receipts/'operation.lock'
    fd = os.open(str(lock), os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'w') as f:
        secure(lock)
        fcntl.flock(f, fcntl.LOCK_EX | fcntl.LOCK_NB)
        path = receipts/(request_id+'.json')
        if path.exists():
            old = read(path)
            if old['action'] != action or old['node'] != node: raise ValueError('request already bound to another operation')
            result = snapshot(node)
            result['operation'] = old
            return result  # Never replay a persisted intent, even after uncertainty.
        before = snapshot(node)
        if before['stale']: raise ValueError('fresh inspection required before operation')
        operation = {'request_id': request_id, 'action': action, 'node': node, 'confirmed': False, 'status': 'pending'}
        atomic(path, operation)  # Durable intent precedes mutation.
        atomic(BASE/'maintenance.json', {'withdraw': action == 'drain'})
        deadline = time.monotonic() + 15
        while True:
            result = snapshot(node)
            ok = not result['stale'] and result['maintenance']['withdraw'] == (action == 'drain')
            ok = ok and all(p['advertised'] == (action == 'resume') for p in result['profiles'])
            if action == 'resume': ok = ok and all(p['healthy'] is True for p in result['profiles'])
            if ok or time.monotonic() >= deadline: break
            time.sleep(1)
        operation.update(confirmed=bool(ok), status='confirmed' if ok else 'uncertain')
        atomic(path, operation)
        result['operation'] = operation
        return result

def main():
    if len(sys.argv) not in (3, 4): raise ValueError('arguments')
    action, node = sys.argv[1:3]
    if action == 'status' and len(sys.argv) == 3: result = snapshot(node)
    elif len(sys.argv) == 4: result = operate(node, action, sys.argv[3])
    else: raise ValueError('arguments')
    print(json.dumps(result))

if __name__ == '__main__':
    try: main()
    except Exception:
        print(json.dumps({'schema': 1, 'error': 'Candidate inspection or operation could not be confirmed; do not replay uncertain operations.'}))
        sys.exit(1)
