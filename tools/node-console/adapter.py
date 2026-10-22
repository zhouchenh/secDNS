"""Windows/Linux console adapter for the three isolated candidates only."""
from contextlib import contextmanager
import json
import os
import pathlib
import re
import subprocess
import stat
import sys

BASE = pathlib.Path('C:/Users/zhouchenh/.codex/infra-discovery-2026-10-17')
KEYS = pathlib.Path('C:/Users/zhouchenh/.ssh')
NODES = {
    'amd103': ('100.91.1.82', 'era-dns-candidate-amd_ed25519', 'candidate-known-hosts'),
    'cix106': ('100.91.1.83', 'era-secdns-cix106_ed25519', 'lxc-three-node-prep-r3/cix106-known-hosts'),
    'intel108': ('100.91.1.84', 'era-secdns-intel108_ed25519', 'lxc-three-node-prep-r3/intel108-known-hosts'),
}
SSH = 'C:/Windows/System32/OpenSSH/ssh.exe'
ACTIONS = ('status', 'drain', 'resume', 'bgp-get', 'bgp-validate', 'bgp-apply', 'health-apply', 'health-get', 'health-validate')


def canonical_request_id(value):
    return isinstance(value, str) and re.fullmatch(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', value) is not None


def platform_paths(platform=None):
    platform = sys.platform if platform is None else platform
    if platform == 'win32':
        return dict(ssh=SSH, null='NUL', keys=KEYS, trust=BASE,
                    state=BASE/'secdns-node-console-20261021'/'adapter-state')
    if platform == 'linux':
        return dict(ssh='/usr/bin/ssh', null='/dev/null',
                    keys=pathlib.Path('/etc/secdns-admin/ssh/keys'),
                    trust=pathlib.Path('/etc/secdns-admin/ssh/known-hosts'),
                    state=pathlib.Path('/var/lib/secdns-admin/adapter-state'))
    raise RuntimeError('unsupported adapter platform')


def verify_private_path(path, secret=False, directory=False):
    """Linux service inputs cannot be redirected by another local account."""
    path = pathlib.Path(path)
    for item in (path, *path.parents):
        info = item.lstat()
        if stat.S_ISLNK(info.st_mode) or info.st_uid not in (0, os.geteuid()):
            raise PermissionError('unsafe adapter path')
        if info.st_mode & 0o022 and not (item != path and stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and info.st_mode & stat.S_ISVTX):
            raise PermissionError('writable adapter path')
        if item == path:
            if directory and not stat.S_ISDIR(info.st_mode):
                raise PermissionError('adapter state is not a directory')
            if not directory and not stat.S_ISREG(info.st_mode):
                raise PermissionError('adapter credential is not a file')
            if secret and info.st_mode & 0o077:
                raise PermissionError('adapter key permissions')


@contextmanager
def mutation_lock(state=None):
    paths = platform_paths()
    state = paths['state'] if state is None else pathlib.Path(state)
    state.mkdir(mode=0o700, exist_ok=True)
    if sys.platform == 'linux':
        verify_private_path(state, directory=True)
        info = state.lstat()
        if info.st_uid != os.geteuid() or info.st_mode & 0o077:
            raise PermissionError('adapter state must be private')
    # The service owns this private directory. Never follow a lock-file symlink.
    flags = os.O_RDWR | os.O_CREAT | getattr(os, 'O_NOFOLLOW', 0)
    with os.fdopen(os.open(str(state/'mutation.lock'), flags, 0o600), 'r+b') as lock:
        if sys.platform == 'linux':
            info = os.fstat(lock.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
                raise PermissionError('adapter lock must be private')
        if sys.platform == 'win32':
            import msvcrt
            if lock.read(1) == b'':
                lock.write(b'0')
                lock.flush()
            lock.seek(0)
            msvcrt.locking(lock.fileno(), msvcrt.LK_NBLCK, 1)
        else:
            import fcntl
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield
        # Closing the descriptor also releases the lock after exceptions.

def invoke(action, node, request_id=None, payload=None, *, guard=False):
    if action not in ACTIONS or node not in NODES:
        raise ValueError('unknown candidate action')
    if action in ('drain', 'resume', 'bgp-apply', 'health-apply'):
        if not canonical_request_id(request_id):
            raise ValueError('invalid request identifier')
    elif request_id is not None:
        raise ValueError('unexpected request identifier')
    if guard and action != 'status':
        raise ValueError('invalid guard action')
    observation = action in ('status', 'bgp-get', 'bgp-validate', 'health-get', 'health-validate')
    # Interactive observations fit inside the API's 30-second deadline. The
    # two cohort checks retain their original budget before a bounded mutation.
    interactive_status = action == 'status' and not guard
    deadline = (25 if interactive_status else 12) if observation else (100 if action in ('bgp-apply','health-apply') else 30)
    keepalives = 8 if interactive_status else 2
    paths = platform_paths()
    host, key, trust = NODES[node]
    if sys.platform == 'linux':
        verify_private_path(paths['keys']/key, secret=True)
        verify_private_path(paths['trust']/trust)
    args = [paths['ssh'], '-F', paths['null'], '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=yes', '-o', 'IdentitiesOnly=yes', '-o', 'ConnectTimeout=4', '-o', 'ServerAliveInterval=3', '-o', 'ServerAliveCountMax='+str(keepalives), '-i', str(paths['keys']/key), '-o', 'UserKnownHostsFile='+str(paths['trust']/trust), 'root@'+host,
            '/usr/bin/python3 /opt/secdns-persistent-20261021/candidate_status.py '+action+' '+node+((' '+request_id) if request_id else '')]
    p = subprocess.run(args, input=json.dumps(payload) if payload is not None else None, capture_output=True, text=True, timeout=deadline)
    if p.returncode or len(p.stdout) > 262144: raise RuntimeError('candidate unavailable or operation unconfirmed')
    result = json.loads(p.stdout)
    if result.get('schema') != 1 or result.get('node') != node: raise ValueError('invalid candidate response')
    return result

def main():
    if len(sys.argv) not in (3, 4): raise ValueError('invalid arguments')
    action, node = sys.argv[1:3]
    if node not in NODES or action not in ACTIONS: raise ValueError('unknown candidate action')
    payload=None
    if action in ('bgp-validate','bgp-apply','health-validate','health-apply'):
        raw=sys.stdin.read(16385)
        if len(raw)>16384:raise ValueError('payload size')
        payload=json.loads(raw)
        if not isinstance(payload,dict) or set(payload)!={'expected_revision','config'}:raise ValueError('payload fields')
    if action in ('status','bgp-get','bgp-validate', 'health-get', 'health-validate'):
        if len(sys.argv) != 3: raise ValueError('arguments')
        return invoke(action, node,payload=payload)
    if len(sys.argv) != 4 or not canonical_request_id(sys.argv[3]): raise ValueError('invalid request identifier')
    # All GUI changes serialize across nodes so two simultaneous drains cannot
    # each rely on the other node. One private lock serves this console process family.
    with mutation_lock():
        if action in ('drain','bgp-apply', 'health-apply'):
            safe = False
            for other in NODES:
                if other == node: continue
                try:
                    s = invoke('status', other, guard=True)
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
