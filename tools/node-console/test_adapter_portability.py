"""Disposable portability contracts; all SSH execution is mocked.

Run with native Windows and Linux Python. Cross-process tests only acquire a
temporary local lock; no keys, trust files, candidate hosts or services are used.
"""
import importlib.util
import json
import os
import pathlib
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location('portable_adapter', pathlib.Path(__file__).with_name('adapter.py'))
a = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(a)
REQUEST = '395378da-4f31-4996-9f01-48cad8f96ba6'


class PortabilityTests(unittest.TestCase):
    def test_platform_defaults_are_explicit(self):
        linux = a.platform_paths('linux')
        self.assertEqual(str(linux['ssh']), '/usr/bin/ssh')
        self.assertEqual(str(linux['null']), '/dev/null')
        self.assertEqual(str(linux['state']).replace('\\', '/'), '/var/lib/secdns-admin/adapter-state')
        self.assertEqual(str(linux['keys']).replace('\\', '/'), '/etc/secdns-admin/ssh/keys')
        self.assertEqual(str(linux['trust']).replace('\\', '/'), '/etc/secdns-admin/ssh/known-hosts')
        windows = a.platform_paths('win32')
        self.assertEqual(str(windows['ssh']).replace('\\', '/'), 'C:/Windows/System32/OpenSSH/ssh.exe')
        self.assertEqual(str(windows['null']), 'NUL')
        for platform in ('darwin', 'freebsd', 'cygwin', '', 'linux; whoami'):
            with self.subTest(platform=platform), self.assertRaises((ValueError, RuntimeError)):
                a.platform_paths(platform)

    def test_fixed_candidate_inventory_excludes_production(self):
        self.assertEqual(set(a.NODES), {'amd103', 'cix106', 'intel108'})
        self.assertEqual({row[0] for row in a.NODES.values()}, {'100.91.1.82', '100.91.1.83', '100.91.1.84'})

    def test_invoke_rejects_untrusted_command_parts_before_spawn(self):
        cases = [('shell', 'amd103', None), ('status; id', 'amd103', None), ('status', '100.91.1.47', None),
                 ('status', 'amd103; id', None), ('drain', 'amd103', '; id'), ('drain', 'amd103', REQUEST.upper()),
                 ('drain', 'amd103', REQUEST+'\n'), ('drain', 'amd103', REQUEST.replace('-', '')),
                 ('drain', 'amd103', '{'+REQUEST+'}'), ('resume', 'amd103', None), ('status', 'amd103', REQUEST)]
        for action, node, identifier in cases:
            with self.subTest(action=action, node=node, identifier=identifier), patch.object(a.subprocess, 'run') as run:
                with self.assertRaises((ValueError, RuntimeError)):
                    a.invoke(action, node, identifier)
                run.assert_not_called()

    def test_linux_transport_uses_argument_list_and_stdin_payload(self):
        response = subprocess.CompletedProcess([], 0, '{"schema":1,"node":"amd103"}', '')
        # Payload is intentionally hostile text: it must remain JSON on stdin.
        payload = {'expected_revision': 'a' * 64, 'config': {'literal': '$(touch /tmp/NEVER); `id` "quoted"'}}
        with patch.object(a, 'platform_paths', return_value=a.platform_paths('linux')), patch.object(a, 'verify_private_path'), patch.object(a.subprocess, 'run', return_value=response) as run:
            a.invoke('bgp-apply', 'amd103', REQUEST, payload)
        args = run.call_args.args[0]
        self.assertIsInstance(args, list)
        self.assertEqual(args[0], '/usr/bin/ssh')
        self.assertEqual(args[1:3], ['-F', '/dev/null'])
        for option in ('BatchMode=yes', 'StrictHostKeyChecking=yes', 'IdentitiesOnly=yes'):
            self.assertIn(option, args)
        self.assertIn('root@100.91.1.82', args)
        self.assertEqual(args[-1], '/usr/bin/python3 /opt/secdns-persistent-20261021/candidate_status.py bgp-apply amd103 ' + REQUEST)
        self.assertFalse(run.call_args.kwargs.get('shell', False))
        self.assertEqual(json.loads(run.call_args.kwargs['input']), payload)
        self.assertNotIn('NEVER', ' '.join(map(str, args)))

    def test_unknown_platform_never_spawns(self):
        with patch.object(a.sys, 'platform', 'unsupported'), patch.object(a.subprocess, 'run') as run:
            with self.assertRaises((ValueError, RuntimeError)):
                a.invoke('status', 'amd103')
            run.assert_not_called()

    @unittest.skipUnless(sys.platform in ('win32', 'linux'), 'requires native supported locking platform')
    def test_cross_process_contention_release_and_exception_cleanup(self):
        with tempfile.TemporaryDirectory() as temporary:
            state = pathlib.Path(temporary) / 'state'
            child = '''import importlib.util,pathlib,sys
spec=importlib.util.spec_from_file_location('adapter',sys.argv[1]);a=importlib.util.module_from_spec(spec);spec.loader.exec_module(a)
try:
 with a.mutation_lock(pathlib.Path(sys.argv[2])): print('acquired',flush=True)
except (OSError,RuntimeError,ValueError): print('blocked',flush=True);sys.exit(23)
'''
            def attempt():
                return subprocess.run([sys.executable, '-c', child, str(pathlib.Path(a.__file__).resolve()), str(state)], capture_output=True, text=True, timeout=8)
            with a.mutation_lock(state):
                result = attempt()
                self.assertEqual(result.returncode, 23, result.stderr)
                self.assertEqual(result.stdout.strip(), 'blocked')
            result = attempt()
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout.strip(), 'acquired')
            with self.assertRaisesRegex(RuntimeError, 'synthetic'):
                with a.mutation_lock(state):
                    raise RuntimeError('synthetic failure')
            self.assertEqual(attempt().returncode, 0)

    @unittest.skipUnless(sys.platform == 'linux', 'Linux symlink and permission contract')
    def test_linux_symlink_lock_is_rejected_without_changing_target(self):
        with tempfile.TemporaryDirectory() as temporary:
            state = pathlib.Path(temporary) / 'state'
            state.mkdir(mode=0o700)
            target = pathlib.Path(temporary) / 'innocent'
            target.write_text('unchanged')
            (state / 'mutation.lock').symlink_to(target)
            with self.assertRaises((ValueError, RuntimeError, OSError)):
                with a.mutation_lock(state):
                    self.fail('symlink lock accepted')
            self.assertEqual(target.read_text(), 'unchanged')

    @unittest.skipUnless(sys.platform == 'linux', 'Linux permission contract')
    def test_linux_unsafe_state_and_lock_permissions(self):
        with tempfile.TemporaryDirectory() as temporary:
            state = pathlib.Path(temporary) / 'state'
            state.mkdir(mode=0o700)
            for mode in (0o777, 0o755):
                state.chmod(mode)
                with self.assertRaises(PermissionError):
                    with a.mutation_lock(state): self.fail('unsafe directory accepted')
            state.chmod(0o700)
            lock = state / 'mutation.lock'
            lock.write_text('fixture')
            lock.chmod(0o644)
            with self.assertRaises(PermissionError):
                with a.mutation_lock(state): self.fail('unsafe lock accepted')
            lock.unlink()
            lock.mkdir()
            with self.assertRaises(OSError):
                with a.mutation_lock(state): self.fail('directory lock accepted')

    @unittest.skipUnless(sys.platform == 'linux', 'Linux path ancestry contract')
    def test_linux_credential_symlink_and_writable_ancestry(self):
        with tempfile.TemporaryDirectory() as temporary:
            parent = pathlib.Path(temporary) / 'credentials'
            parent.mkdir(mode=0o700)
            key = parent / 'dummy'
            key.write_text('disposable test data, not a credential')
            key.chmod(0o600)
            a.verify_private_path(key, secret=True)
            link = parent / 'link'
            link.symlink_to(key)
            with self.assertRaises(PermissionError): a.verify_private_path(link, secret=True)
            alias = pathlib.Path(temporary) / 'alias'
            alias.symlink_to(parent, target_is_directory=True)
            with self.assertRaises(PermissionError): a.verify_private_path(alias / 'dummy', secret=True)
            with self.assertRaises(PermissionError):
                with a.mutation_lock(alias): self.fail('symlink state accepted')
            parent.chmod(0o777)
            with self.assertRaises(PermissionError): a.verify_private_path(key, secret=True)


if __name__ == '__main__':
    unittest.main()
