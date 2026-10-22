import copy
import pathlib
import sys
import types
import unittest
from unittest.mock import patch
import health_settings as s
import health_controller as h
if sys.platform=='win32':sys.modules.setdefault('fcntl',types.SimpleNamespace())
import candidate_health as c

class SettingsTests(unittest.TestCase):
    def test_bounds_and_budget(self):
        good=dict(interval_seconds=3,probe_timeout_ms=1000,failure_threshold=2,recovery_threshold=2)
        self.assertEqual(s.stale_seconds(good),9)
        self.assertEqual(s.validate(good),good)
        for key,value in [('interval_seconds',2),('probe_timeout_ms',1500),('failure_threshold',1),('recovery_threshold',6),('interval_seconds',True)]:
            bad=dict(good);bad[key]=value
            with self.assertRaises(ValueError):s.validate(bad)
        with self.assertRaises(ValueError):s.validate(dict(good,arbitrary_host='8.8.8.8'))
        self.assertEqual(s.revision(good),s.revision(dict(reversed(list(good.items())))))
    def test_hysteresis(self):
        gate=h.UpstreamGate(2,3)
        self.assertEqual([gate.observe(x) for x in [True,True,True,False,True,False,False,True,True,True]], [False,False,True,True,True,True,False,False,False,True])
    def test_round_revision_reset_no_overlap(self):
        old=dict(s.DEFAULT);new=dict(interval_seconds=3,probe_timeout_ms=1000,failure_threshold=2,recovery_threshold=2)
        fake_thread=types.SimpleNamespace(start=lambda:None)
        with patch.object(h.threading,'Thread',return_value=fake_thread):worker=h.UpstreamHealth({'entries':[]})
        # Actual round worker has eight serial-fallback tasks; stub each thread synchronously.
        class Thread:
            def __init__(self,target,args=(),daemon=False):self.target=target;self.args=args
            def start(self):self.target(*self.args)
            def join(self,*a):pass
            def is_alive(self):return False
        worker.config={'entries':[{'role':'normal'}]*4}
        observations=[]
        def sleep(_):
            observations.append(worker.snapshot())
            if len(observations)==3:raise StopIteration()
        with patch.object(h.threading,'Thread',Thread),patch.object(h.health_settings,'load',side_effect=[old,old,new]),patch.object(h,'probe',return_value=True) as probe,patch.object(h.time,'sleep',sleep):
            with self.assertRaises(StopIteration):worker.run()
        self.assertEqual(probe.call_count,24) # no fallback after successful first provider
        self.assertEqual(observations[0][0],[False]*4)
        self.assertEqual(observations[1][0],[True]*4)
        self.assertEqual(observations[2][0],[False]*4)
        self.assertEqual(observations[2][-1],s.revision(new))
    def test_stalled_round_stops_without_ack_or_next_round(self):
        with patch.object(h.threading,'Thread') as thread:
            worker=h.UpstreamHealth({'entries':[{'role':'normal'}]*4})
            thread.return_value.is_alive.return_value=True
            worker.run()
        self.assertIsNone(worker.settings_revision)
        self.assertIsNone(worker.observed)
    def test_ack_alone_is_not_apply_or_rollback_confirmation(self):
        baseline=[dict(role=r,family=f,healthy=True,advertised=True) for r in ['normal','dns64'] for f in [4,6]]
        warm=dict(stale=False,health_settings_revision='a',profiles=[dict(p,healthy=False,advertised=False) for p in baseline])
        ready=dict(stale=False,health_settings_revision='a',profiles=baseline)
        with patch.object(c.c,'snapshot',side_effect=[warm,ready]) as snap,patch.object(c.time,'sleep'):
            self.assertEqual(c.wait_ready('amd103','a',baseline,10),ready)
            self.assertEqual(snap.call_count,2)
        wrong=dict(ready,health_settings_revision='old')
        with patch.object(c.c,'snapshot',return_value=wrong),patch.object(c.time,'monotonic',side_effect=[0,2]):
            with self.assertRaises(RuntimeError):c.wait_ready('amd103','a',baseline,1)


class TransactionTests(unittest.TestCase):
    def test_pending_transaction_blocks_and_receipt_never_replays(self):
        import tempfile,json
        from contextlib import contextmanager
        with tempfile.TemporaryDirectory() as folder:
            root=pathlib.Path(folder);receipts=root/'console-receipts';receipts.mkdir();old=receipts/'old.json';old.write_text('{"action":"bgp-apply","status":"pending"}')
            @contextmanager
            def lock():
                with (root/'lock').open('w') as handle:yield handle
            fake=types.SimpleNamespace(flock=lambda *args:None,LOCK_EX=1,LOCK_NB=2)
            request='11111111-1111-4111-8111-111111111111'
            with patch.object(c.c,'BASE',root),patch.object(c.c,'identity'),patch.object(c.c,'secure'),patch.object(c.c,'fcntl',fake),patch.object(c.bgp,'lock_file',lock),patch.object(c,'read_request') as read,patch.object(c.c,'atomic') as atomic:
                with self.assertRaisesRegex(ValueError,'pending transaction'):c.apply('amd103',request,{})
                read.assert_not_called();atomic.assert_not_called()
                old.unlink();path=receipts/(request+'.json');path.write_text(json.dumps(dict(action='health-apply',node='amd103',request_id=request,status='pending',confirmed=False,payload_digest=c.hashlib.sha256(b'{}').hexdigest())))
                with patch.object(c.c,'snapshot',return_value={}),patch.object(c,'get',return_value={}):
                    result=c.apply('amd103',request,{})
                    self.assertEqual(result['operation']['status'],'pending');atomic.assert_not_called()
    def test_failed_ack_restores_old_config_and_never_confirms(self):
        receipt=dict(node='amd103',action='health-apply',status='pending',confirmed=False,old_config=dict(s.DEFAULT),old_profiles=[])
        with patch.object(c.c,'atomic') as atomic,patch.object(c.c,'snapshot',return_value={}),patch.object(c,'wait_ready',side_effect=RuntimeError('no acknowledgement')):
            with self.assertRaises(RuntimeError):c.rollback_locked('amd103',receipt,pathlib.Path('/receipt'))
            self.assertEqual(atomic.call_args_list[0].args[1],s.DEFAULT)
            self.assertEqual(receipt['status'],'pending');self.assertFalse(receipt['confirmed'])
            self.assertEqual(atomic.call_count,1)
    def test_stopped_worker_rollback_restarts_private_routing_then_verifies(self):
        receipt=dict(node='amd103',action='health-apply',status='pending',confirmed=False,old_config=dict(s.DEFAULT),old_profiles=[])
        with patch.object(c.c,'atomic'),patch.object(c.c,'snapshot',return_value={'upstream_worker_failed':True}),patch.object(c.bgp,'restart') as restart,patch.object(c,'wait_ready') as wait,patch.object(c,'get',return_value={'config':s.DEFAULT}):
            c.rollback_locked('amd103',receipt,pathlib.Path('/receipt'))
            restart.assert_called_once();wait.assert_called_once();self.assertEqual(receipt['status'],'rolled_back');self.assertFalse(receipt['confirmed'])
            receipt['status']='pending'
            c.rollback_locked('amd103',receipt,pathlib.Path('/receipt'))
            restart.assert_called_once() # watchdog cannot replay a restart intent

if __name__=='__main__':unittest.main()
