"""Windows console adapter; only the three isolated candidates are addressable."""
import json
import os
import pathlib
import subprocess
import sys
import uuid

BASE = pathlib.Path('C:/Users/zhouchenh/.codex/infra-discovery-2026-10-17')
KEYS = pathlib.Path('C:/Users/zhouchenh/.ssh')
NODES = {
    'amd103': ('100.91.1.82', 'era-dns-candidate-amd_ed25519', 'candidate-known-hosts'),
    'cix106': ('100.91.1.83', 'era-secdns-cix106_ed25519', 'lxc-three-node-prep-r3/cix106-known-hosts'),
    'intel108': ('100.91.1.84', 'era-secdns-intel108_ed25519', 'lxc-three-node-prep-r3/intel108-known-hosts'),
}
SSH = 'C:/Windows/System32/OpenSSH/ssh.exe'

def invoke(action, node, request_id=None, payload=None):
    host, key, trust = NODES[node]
    args = [SSH, '-F', 'NUL', '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=yes', '-o', 'IdentitiesOnly=yes', '-o', 'ConnectTimeout=4', '-o', 'ServerAliveInterval=3', '-o', 'ServerAliveCountMax=2', '-i', str(KEYS/key), '-o', 'UserKnownHostsFile='+str(BASE/trust), 'root@'+host,
            '/usr/bin/python3 /opt/secdns-persistent-20261021/candidate_status.py '+action+' '+node+((' '+request_id) if request_id else '')]
    p = subprocess.run(args, input=json.dumps(payload) if payload is not None else None, capture_output=True, text=True, timeout=100 if action=='bgp-apply' else (12 if action in ('status','bgp-get','bgp-validate') else 30))
    if p.returncode or len(p.stdout) > 262144: raise RuntimeError('candidate unavailable or operation unconfirmed')
    result = json.loads(p.stdout)
    if result.get('schema') != 1 or result.get('node') != node: raise ValueError('invalid candidate response')
    return result

def main():
    if len(sys.argv) not in (3, 4): raise ValueError('invalid arguments')
    action, node = sys.argv[1:3]
    if node not in NODES or action not in ('status', 'drain', 'resume','bgp-get','bgp-validate','bgp-apply'): raise ValueError('unknown candidate action')
    payload=None
    if action in ('bgp-validate','bgp-apply'):
        raw=sys.stdin.read(16385)
        if len(raw)>16384:raise ValueError('payload size')
        payload=json.loads(raw)
        if not isinstance(payload,dict) or set(payload)!={'expected_revision','config'}:raise ValueError('payload fields')
    if action in ('status','bgp-get','bgp-validate'):
        if len(sys.argv) != 3: raise ValueError('arguments')
        return invoke(action, node,payload=payload)
    if len(sys.argv) != 4 or str(uuid.UUID(sys.argv[3])) != sys.argv[3]: raise ValueError('invalid request identifier')
    # All GUI changes serialize across nodes so two simultaneous drains cannot
    # each rely on the other node. This file is on the local trusted Windows host.
    import msvcrt
    state = BASE/'secdns-node-console-20261021'/'adapter-state'
    state.mkdir(exist_ok=True)
    with (state/'mutation.lock').open('a+b') as lock:
        lock.seek(0)
        if lock.read(1) == b'': lock.write(b'0'); lock.flush()
        lock.seek(0)
        msvcrt.locking(lock.fileno(), msvcrt.LK_NBLCK, 1)
        if action in ('drain','bgp-apply'):
            safe = False
            for other in NODES:
                if other == node: continue
                try:
                    s = invoke('status', other)
                    safe = (not s['stale'] and s['daemon']['active'] and not s['maintenance']['withdraw'] and len(s['profiles']) == 4 and all(p['healthy'] is True and p['advertised'] for p in s['profiles']))
                    if safe: break
                except (RuntimeError, ValueError, OSError, subprocess.SubprocessError): pass
            if not safe: raise ValueError('drain requires another healthy advertising candidate')
        return invoke(action, node, sys.argv[3],payload)

if __name__ == '__main__':
    try: print(json.dumps(main()))
    except Exception:
        print(json.dumps({'schema': 1, 'error': 'Candidate request unavailable, blocked, or unconfirmed. Refresh status; do not replay an uncertain operation.'}))
        sys.exit(1)
