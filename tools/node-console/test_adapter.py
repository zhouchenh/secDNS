import importlib.util
import pathlib
import unittest
import tempfile
import sys
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('adapter', pathlib.Path(__file__).with_name('adapter.py'))
a = importlib.util.module_from_spec(spec)
spec.loader.exec_module(a)

class AdapterTests(unittest.TestCase):
    @unittest.skipUnless(sys.platform == 'win32', 'Windows cohort serialization')
    def test_last_provider_guard_never_sends_drain(self):
        with tempfile.TemporaryDirectory() as temp:
            base = pathlib.Path(temp)
            (base/'secdns-node-console-20261021').mkdir()
            snapshot = {'stale':False,'daemon':{'active':True},'maintenance':{'withdraw':True},'profiles':[]}
            with patch.object(a,'BASE',base), patch.object(a.sys,'argv',['adapter','drain','amd103','395378da-4f31-4996-9f01-48cad8f96ba6']), patch.object(a,'invoke',return_value=snapshot) as invoke:
                with self.assertRaises(ValueError): a.main()
                self.assertEqual([call.args[0] for call in invoke.call_args_list], ['status','status'])
    def test_untrusted_arguments_never_execute(self):
        for args in [['adapter','status','100.91.1.47'],['adapter','shell','amd103'],['adapter','drain','amd103','; reboot'],['adapter','status','amd103','extra']]:
            with patch.object(a.sys,'argv',args), patch.object(a,'invoke') as invoke:
                with self.assertRaises(ValueError): a.main()
                invoke.assert_not_called()

    def test_strict_transport_and_fixed_command(self):
        class Response:
            returncode = 0
            stdout = '{"schema":1,"node":"amd103"}'
        with patch.object(a.subprocess,'run',return_value=Response()) as run:
            a.invoke('status','amd103')
        args = run.call_args.args[0]
        self.assertIn('StrictHostKeyChecking=yes',args)
        self.assertIn('BatchMode=yes',args)
        self.assertEqual(args[-1], '/usr/bin/python3 /opt/secdns-persistent-20261021/candidate_status.py status amd103')

if __name__ == '__main__': unittest.main()
