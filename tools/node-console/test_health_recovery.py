import json
import subprocess
import threading
import time
import types
import unittest
from unittest.mock import patch
import health_controller as h

class RecoveryTests(unittest.TestCase):
    def test_hedged_success_failure_combinations_and_names(self):
        for primary,fallback,delay,expected in [(True,False,.3,True),(False,True,0,True),(False,False,0,False),(True,False,0,True)]:
            names=[];active=[0];maximum=[0];lock=threading.Lock()
            def fake(c,e,transport,timeout,diagnostic):
                first='sslip.io' in e['query_name']
                with lock:
                    names.append(e['query_name']);active[0]+=1;maximum[0]=max(maximum[0],active[0])
                try:
                    if first:time.sleep(delay)
                    diagnostic.update(outcome='success' if (primary if first else fallback) else 'timeout')
                    return primary if first else fallback
                finally:
                    with lock:active[0]-=1
            with patch.object(h,'probe',side_effect=fake):
                healthy,sources,details=h.upstream_attempts({}, {'role':'dns64','family':4},'udp',.5)
            self.assertEqual(healthy,expected);self.assertEqual(active[0],0)
            self.assertLessEqual(maximum[0],2);self.assertEqual(len(names),len(set(names)))
            self.assertEqual(len(details),len(names))
            if delay==0 and primary:self.assertEqual(len(names),1)
    def test_stalled_teardown_is_not_published_as_completed_round(self):
        class Stalled:
            def __init__(self,*a,**kw):pass
            def start(self):pass
            def join(self,*a):pass
            def is_alive(self):return True
        with patch.object(h.threading,'Thread',Stalled),patch.object(h.threading.Event,'wait',return_value=False):
            with self.assertRaisesRegex(RuntimeError,'stalled'):h.upstream_attempts({}, {'role':'normal'},'tcp',1)
    def test_transient_recovers_and_sustained_failure_requires_second_round(self):
        gate=h.UpstreamGate(2,2)
        gate.observe(True);gate.observe(True)
        self.assertTrue(gate.observe(False))
        self.assertEqual(h.next_round_delay({'interval_seconds':3},1.25,[gate]),1)
        self.assertTrue(gate.observe(True)) # recovered before independent confirmation
        self.assertEqual(h.next_round_delay({'interval_seconds':3},.2,[gate]),2.8)
        self.assertTrue(gate.observe(False));self.assertFalse(gate.observe(False))
        self.assertFalse(gate.observe(True));self.assertTrue(gate.observe(True))
    def test_probe_diagnostic_preserves_rcode_timeout_without_payload(self):
        entry={'probe_address':'127.0.0.1','probe_port':53,'query_name':'x.test.','query_type':'A','expected':'1.1.1.1'}
        for response,expected in [(types.SimpleNamespace(stdout=json.dumps({'rcode':2,'question':[]})),'unexpected_answer'),(subprocess.TimeoutExpired('query',1),'timeout')]:
            detail={}
            kwargs={'side_effect':response} if isinstance(response,Exception) else {'return_value':response}
            with patch.object(h.subprocess,'run',**kwargs):self.assertFalse(h.probe({'fixture':'fixture'},entry,'udp',1,detail))
            self.assertEqual(detail['outcome'],expected);self.assertIn('duration_ms',detail)
            self.assertNotIn('query_name',detail)

if __name__=='__main__':unittest.main()
