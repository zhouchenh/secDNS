"""Minimal Linux probe for appliances lacking unittest/tempfile; no SSH is run.

Run only from an explicitly disposable directory: python3 test_adapter_native_probe.py.
All files created by this probe are synthetic local lock/path fixtures.
"""
import json
import os
import pathlib
import subprocess
import sys
import adapter as a


def rejected(call):
    try:
        call()
    except (OSError, RuntimeError, ValueError):
        return
    raise AssertionError('unsafe input accepted')


def acquire(state):
    with a.mutation_lock(state):
        pass


def main():
    assert sys.platform == 'linux'
    if len(sys.argv) == 3 and sys.argv[1] == '--child':
        try:
            acquire(pathlib.Path(sys.argv[2]))
        except (OSError, ValueError, RuntimeError):
            print('blocked')
            return 23
        print('acquired')
        return 0
    root = pathlib.Path(__file__).resolve().parent / ('probe-' + os.urandom(8).hex())
    root.mkdir(mode=0o700)
    state = root / 'state'
    child = [sys.executable, str(pathlib.Path(__file__).resolve()), '--child', str(state)]
    with a.mutation_lock(state):
        result = subprocess.run(child, capture_output=True, text=True, timeout=8)
        assert result.returncode == 23 and result.stdout.strip() == 'blocked', result.stderr
    result = subprocess.run(child, capture_output=True, text=True, timeout=8)
    assert result.returncode == 0 and result.stdout.strip() == 'acquired', result.stderr
    try:
        with a.mutation_lock(state): raise RuntimeError('synthetic')
    except RuntimeError:
        pass
    assert subprocess.run(child, capture_output=True, timeout=8).returncode == 0
    lock = state / 'mutation.lock'
    lock.chmod(0o644)
    rejected(lambda: acquire(state))
    lock.unlink()
    lock.mkdir()
    rejected(lambda: acquire(state))
    lock.rmdir()
    target = root / 'dummy'
    target.write_text('synthetic fixture, not a credential')
    target.chmod(0o600)
    lock.symlink_to(target)
    rejected(lambda: acquire(state))
    assert target.read_text() == 'synthetic fixture, not a credential'
    lock.unlink()
    for mode in (0o755, 0o777):
        state.chmod(mode)
        rejected(lambda: acquire(state))
    state.chmod(0o700)
    alias = root / 'alias'
    alias.symlink_to(state, target_is_directory=True)
    rejected(lambda: acquire(alias))
    alias.unlink()
    a.verify_private_path(target, secret=True)
    alias.symlink_to(target)
    rejected(lambda: a.verify_private_path(alias, secret=True))
    alias.unlink()
    target.chmod(0o644)
    rejected(lambda: a.verify_private_path(target, secret=True))
    target.chmod(0o600)
    root.chmod(0o777)
    rejected(lambda: a.verify_private_path(target, secret=True))
    root.chmod(0o700)
    calls = []
    original_run, original_verify = a.subprocess.run, a.verify_private_path
    a.subprocess.run = lambda args, **kwargs: calls.append((args, kwargs)) or subprocess.CompletedProcess(args, 0, '{"schema":1,"node":"amd103"}', '')
    try:
        # Actual missing fixed credential paths must stop before subprocess.
        original_paths = a.platform_paths
        a.platform_paths = lambda: dict(original_paths(), keys=root / 'missing', trust=root / 'missing')
        rejected(lambda: a.invoke('status', 'amd103'))
        assert not calls
        a.platform_paths = original_paths
        a.verify_private_path = lambda *args, **kwargs: None
        for action,node,identifier in [('shell','amd103',None),('status','100.91.1.47',None),('status','amd103; id',None),('drain','amd103','; id')]:
            rejected(lambda: a.invoke(action,node,identifier))
        canonical = '395378da-4f31-4996-9f01-48cad8f96ba6'
        for identifier in (canonical.upper(), canonical+'\n', canonical.replace('-',''), '{'+canonical+'}'):
            rejected(lambda: a.invoke('drain','amd103',identifier))
        assert not calls
        payload = {'expected_revision':'a'*64,'config':{'literal':'$(id); `id`'}}
        request = '395378da-4f31-4996-9f01-48cad8f96ba6'
        a.invoke('bgp-apply','amd103',request,payload)
        args, kwargs = calls.pop()
        assert args[:3] == ['/usr/bin/ssh','-F','/dev/null']
        assert 'StrictHostKeyChecking=yes' in args and 'IdentitiesOnly=yes' in args
        assert args[-1] == '/usr/bin/python3 /opt/secdns-persistent-20261021/candidate_status.py bgp-apply amd103 '+request
        assert not kwargs.get('shell',False) and json.loads(kwargs['input']) == payload
    finally:
        a.subprocess.run, a.verify_private_path = original_run, original_verify
    original_invoke, original_paths, original_argv = a.invoke, a.platform_paths, sys.argv
    actions = []
    a.platform_paths = lambda: dict(original_paths(), state=state)
    a.invoke = lambda action, *args, **kwargs: actions.append(action) or dict(stale=False, daemon={'active':True}, maintenance={'withdraw':True}, profiles=[])
    sys.argv = ['adapter', 'drain', 'amd103', '395378da-4f31-4996-9f01-48cad8f96ba6']
    try:
        rejected(a.main)
        assert actions == ['status','status'], actions
    finally:
        a.invoke, a.platform_paths, sys.argv = original_invoke, original_paths, original_argv
    (state / 'mutation.lock').unlink()
    target.unlink()
    state.rmdir()
    root.rmdir()
    print('PASS native Linux: cross-process flock contention/release, exception cleanup, unsafe state/lock/credential paths, missing config before spawn, fixed hosts/argv, stdin payload and last-provider drain guard; no SSH executed')
    return 0


if __name__ == '__main__':
    sys.exit(main())
