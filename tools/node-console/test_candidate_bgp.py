import copy
import unittest
import sys
import types
import tempfile
import pathlib
from contextlib import contextmanager
from unittest.mock import patch
if sys.platform=='win32':sys.modules['fcntl']=types.SimpleNamespace()
import candidate_bgp as b
import health_controller as h

class BGPTests(unittest.TestCase):
    def test_stale_rollback_never_claims_restored(self):
        receipt=dict(node='amd103',action='bgp-apply',status='pending',old_bgp='old',old_config=b.default_config('amd103'),old_withdraw=False)
        with patch.object(b,'atomic_text'),patch.object(b.c,'atomic') as atomic,patch.object(b,'restart'),patch.object(b.c,'snapshot',return_value={'stale':True,'peers':[],'profiles':[]}),patch.object(b.time,'monotonic',side_effect=[0,41]):
            with self.assertRaises(RuntimeError):b.rollback_locked('amd103',receipt,b.c.BASE/'receipt')
            self.assertEqual(receipt['status'],'pending')
            self.assertTrue(all(call.args[0].name!='receipt' for call in atomic.call_args_list))

    def test_pending_transaction_blocks_new_apply(self):
        with tempfile.TemporaryDirectory() as folder:
            root=pathlib.Path(folder);receipts=root/'console-receipts';receipts.mkdir()
            (receipts/'old.json').write_text('{"action":"bgp-apply","status":"pending"}')
            @contextmanager
            def lock():
                with (root/'lock').open('w') as handle:yield handle
            fake=types.SimpleNamespace(flock=lambda *args:None,LOCK_EX=1,LOCK_NB=2)
            with patch.object(b.c,'BASE',root),patch.object(b.c,'identity'),patch.object(b.c,'secure'),patch.object(b.c,'fcntl',fake),patch.object(b,'lock_file',lock),patch.object(b,'read_request') as read_request,patch.object(b,'restart') as restart:
                with self.assertRaisesRegex(ValueError,'pending transaction'):
                    b.apply('amd103','11111111-1111-4111-8111-111111111111',{})
                read_request.assert_not_called();restart.assert_not_called()

    def test_reused_worker_pid_is_not_killed(self):
        receipt=dict(worker_pid=987654,worker_start='old')
        with patch.object(b,'worker_identity',return_value=('new',['python','other.py'])),patch.object(b.os,'kill') as kill:
            self.assertFalse(b.terminate_worker(receipt,'amd103','request'))
            kill.assert_not_called()
    def test_fixed_identity_and_bounded_edits(self):
        original=b.default_config('amd103')
        for mutate in (lambda c:c.update(local_asn=1),lambda c:c['peers'][0].update(address='100.91.1.47'),lambda c:c['peers'][0].update(remote_asn=1),lambda c:c['peers'][0].update(keepalive_seconds=0),lambda c:c['peers'][0].update(hold_seconds=999),lambda c:c['announcements'][0].update(prefix='0.0.0.0/0')):
            config=copy.deepcopy(original);mutate(config)
            with self.assertRaises(ValueError):b.validate('amd103',config)
        config=copy.deepcopy(original)
        for p in config['peers']:
            if p['family']==4:p['enabled']=False
        with self.assertRaises(ValueError):b.validate('amd103',config)

    def test_render_preserves_exact_filters_and_private_port(self):
        config=b.default_config('amd103');config['peers'][0]['enabled']=False
        config['peers'][1].update(keepalive_seconds=4,hold_seconds=12)
        text=b.render('amd103',config)
        self.assertIn('neighbor '+config['peers'][0]['address']+' shutdown',text)
        self.assertEqual(text.count(' port 1179'),4)
        self.assertNotIn('network ',text)
        self.assertNotIn('0.0.0.0/0',text)
        self.assertIn('match as-path LOCAL-ONLY',text)

    def test_upstream_failure_and_recovery_hysteresis(self):
        gate=h.UpstreamGate()
        self.assertFalse(gate.observe(True));self.assertTrue(gate.observe(True))
        self.assertTrue(gate.observe(False));self.assertFalse(gate.observe(False))
        self.assertFalse(gate.observe(True));self.assertTrue(gate.observe(True))

if __name__=='__main__':unittest.main()
