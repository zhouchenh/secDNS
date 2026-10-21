import importlib.util
import pathlib
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('adapter', pathlib.Path(__file__).with_name('adapter.py'))
a = importlib.util.module_from_spec(spec)
spec.loader.exec_module(a)

class AdapterTests(unittest.TestCase):
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
