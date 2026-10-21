import importlib.util
import pathlib
import sys
import types
import unittest
import tempfile
from unittest.mock import patch

# Host helper's pure snapshot logic is also tested on Windows.
if sys.platform == 'win32': sys.modules['fcntl'] = types.SimpleNamespace()
spec = importlib.util.spec_from_file_location('candidate_status', pathlib.Path(__file__).with_name('candidate_status.py'))
c = importlib.util.module_from_spec(spec)
spec.loader.exec_module(c)

class SnapshotTests(unittest.TestCase):
    def test_advertisement_schema_and_allowlist_fail_closed(self):
        for routes in ({}, [], {'advertisedRoutes':[]}, {'advertisedRoutes':{'0.0.0.0/0':{}}}, {'advertisedRoutes':{'2001:db8:53::53/128':{}}}):
            with self.assertRaises(ValueError): c.advertised_prefixes(routes, 4)
        self.assertEqual(c.advertised_prefixes({'advertisedRoutes':{}},4),[])
        self.assertEqual(c.advertised_prefixes({'advertisedRoutes':{'203.0.113.53/32':{}}},4),['203.0.113.53/32'])
    def test_health_is_not_advertisement_and_stale_health_is_unknown(self):
        entries = [{'role': r, 'family': f, 'prefix': p} for r, f, p in [('normal',4,'203.0.113.53/32'),('normal',6,'2001:db8:53::53/128'),('dns64',4,'203.0.113.64/32'),('dns64',6,'2001:db8:53::64/128')]]
        with patch.object(c, 'identity', return_value=({'unit':'test'}, {'entries':entries})), patch.object(c, 'read', return_value={'withdraw': True}), patch.object(c, 'run', side_effect=['ActiveState=active\nMainPID=123', '{"type":"health","observed_monotonic":1,"healthy":[true,true,true,true]}']), patch.object(c.time, 'monotonic', return_value=100), patch.object(c, 'vty', return_value={}):
            result = c.snapshot('amd103')
        self.assertTrue(result['stale'])
        self.assertTrue(result['maintenance']['withdraw'])
        self.assertTrue(all(p['healthy'] is None and not p['advertised'] for p in result['profiles']))

    def test_invalid_request_cannot_mutate(self):
        # UUID validation happens before filesystem operations.
        with self.assertRaises(ValueError): c.operate('amd103', 'drain', '../unsafe')

    def test_pending_receipt_is_not_replayed(self):
        request = '395378da-4f31-4996-9f01-48cad8f96ba6'
        with tempfile.TemporaryDirectory() as temp:
            base = pathlib.Path(temp)
            (base/'console-receipts').mkdir()
            (base/'console-receipts'/(request+'.json')).write_text('{}')
            old = {'node':'amd103','action':'drain','status':'pending','confirmed':False,'request_id':request}
            fake_fcntl = types.SimpleNamespace(flock=lambda *args: None, LOCK_EX=1, LOCK_NB=2)
            with patch.object(c,'BASE',base), patch.object(c,'fcntl',fake_fcntl), patch.object(c.os,'O_NOFOLLOW',0,create=True), patch.object(c,'identity'), patch.object(c,'secure'), patch.object(c,'read',return_value=old), patch.object(c,'snapshot',return_value={'node':'amd103'}), patch.object(c,'atomic') as atomic:
                result = c.operate('amd103','drain',request)
                atomic.assert_not_called()
                self.assertEqual(result['operation']['status'],'pending')
                with self.assertRaises(ValueError): c.operate('amd103','resume',request)

if __name__ == '__main__': unittest.main()
