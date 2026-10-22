import copy
import json
import pathlib
import sys
import tempfile
import types
import unittest
from contextlib import contextmanager
from unittest.mock import patch
if sys.platform == 'win32': sys.modules['fcntl'] = types.SimpleNamespace()
import candidate_external as e
import candidate_bgp as b


def policy():
    return dict(schema=1,node='amd103',peers=[dict(id='fixture-switch',address='2001:db8:85:1::1',transport_family=6,local_source='2001:db8:85:1::',local_asn=8505,remote_asn=8501,port=179,allowed_afis=[4,6],allowed_exports=sorted(e.c.PREFIXES))])


def entry():
    return dict(id='fixture-switch',name='Switch17.fixture@IPv6',enabled=False,afis=[4,6],keepalive_seconds=1,hold_seconds=5,exports=[])


class ExternalTests(unittest.TestCase):
    def test_policy_literals_and_collision(self):
        with tempfile.TemporaryDirectory() as folder:
            root=pathlib.Path(folder);(root/'external-policy.json').write_text('{}')
            with patch.object(e.c,'BASE',root),patch.object(e.c,'read',return_value=policy()),patch.object(b,'test_client',return_value=None):
                self.assertEqual(e.policy('amd103'),policy())
                for key,value in [('address','router.example'),('address','100.91.1.82'),('address','fe80::1'),('port',True),('remote_asn',0),('allowed_exports',['::/0']),('allowed_afis',[6,6])]:
                    bad=policy();bad['peers'][0][key]=value
                    with patch.object(e.c,'read',return_value=bad),self.assertRaises(ValueError):e.policy('amd103')

    def test_draft_cannot_change_authority_or_expand_exports(self):
        self.assertEqual(e.validate('amd103',[entry()],policy()),[entry()])
        for change in ({'id':'production'}, {'address':'100.91.1.47'}, {'exports':['0.0.0.0/0']}, {'afis':[4,4]}, {'name':'x\nrouter bgp 1'}, {'hold_seconds':2}, {'enabled':1}):
            bad=entry();bad.update(change)
            with self.assertRaises(ValueError):e.validate('amd103',[bad],policy())

    def test_render_dual_afi_alias_and_no_exports_default(self):
        config=b.default_config('amd103');config['external_peers']=[entry()]
        with patch.object(b,'test_client',return_value=None):text=b.render('amd103',config,policy())
        self.assertIn('router bgp 65101',text)
        self.assertEqual(text.count(' port 1179'),4)
        self.assertIn('local-as 8505 no-prepend replace-as',text)
        self.assertIn('capability extended-nexthop',text)
        self.assertIn('neighbor 2001:db8:85:1::1 shutdown',text)
        self.assertEqual(text.count('route-map EXTERNAL-DENY in'),2)
        self.assertIn('route-map EXT-fixture-switch-4 deny 10',text)
        config['external_peers'][0].update(enabled=True,exports=sorted(e.c.PREFIXES))
        with patch.object(b,'test_client',return_value=None):text=b.render('amd103',config,policy())
        self.assertEqual(text.count('match as-path LOCAL-ONLY'),4)
        self.assertNotIn(' le ',text);self.assertNotIn('redistribute ',text);self.assertNotIn(' network ',text)

    def test_policy_drift_changes_revision_and_rejects_old_preview(self):
        with tempfile.TemporaryDirectory() as folder,patch.object(b,'test_client',return_value=None):
            with patch.object(e.c,'BASE',pathlib.Path(folder)),patch.object(e,'policy',return_value=policy()):old=b.get('amd103')
            for key,value in [('port',1179),('local_source','2001:db8:85:1::2'),('local_asn',8506),('remote_asn',8502),('address','2001:db8:85:1::3'),('allowed_afis',[6])]:
                changed=policy();changed['peers'][0][key]=value
                with patch.object(e.c,'BASE',pathlib.Path(folder)),patch.object(e,'policy',return_value=changed):
                    self.assertNotEqual(old['revision'],b.get('amd103')['revision'])
                    with self.assertRaisesRegex(ValueError,'changed'):b.read_request('amd103',dict(expected_revision=old['revision'],config=old['config']))

    def test_unknown_advertisements_never_mean_empty(self):
        p=entry();p['enabled']=True
        for response in ({},{'advertisedRoutes':[]},{'advertisedRoutes':{'0.0.0.0/0':{}}}):
            def query(command,deadline):return json.dumps({'ipv%dUnicast'%f:{'peers':{'2001:db8:85:1::1':{'state':'Established'}}} for f in (4,6)}) if 'summary' in command else json.dumps(response)
            with patch.object(e,'query',side_effect=query),patch.object(e,'runtime_matches',return_value=True):
                self.assertTrue(all(not x['observed'] and x['prefixes'] is None for x in e.observe('amd103',[p],policy())))

    def test_runtime_removal_and_transport_drift(self):
        p=entry();pol,neighbors,afis=e.render('amd103',[p],policy())
        text='\n'.join(['bgp as-path access-list LOCAL-ONLY permit ^$']+pol+['router bgp 65101']+neighbors+['address-family ipv4 unicast']+afis[4]+['exit-address-family','address-family ipv6 unicast']+afis[6]+['exit-address-family'])
        with patch.object(e,'query',return_value=text):
            self.assertTrue(e.runtime_matches('amd103',[p],policy(),999))
            self.assertFalse(e.runtime_matches('amd103',[],policy(),999))
        for old,new in [('port 179','port 1179'),('local-as 8505','local-as 8506'),('timers 1 5','timers 1 9'),('shutdown','')]:
            with patch.object(e,'query',return_value=text.replace(old,new)):
                self.assertFalse(e.runtime_matches('amd103',[p],policy(),999))
        with patch.object(e,'query',return_value='bgp as-path access-list LOCAL-ONLY permit ^$\nrouter bgp 65101'):
            self.assertTrue(e.runtime_matches('amd103',[],policy(),999))

    def test_runtime_policy_tampering_is_not_verified(self):
        p=entry();p.update(enabled=True,exports=['203.0.113.53/32'])
        config=b.default_config('amd103');config['external_peers']=[p]
        with patch.object(b,'test_client',return_value=None):text=b.render('amd103',config,policy())
        with patch.object(e,'query',return_value=text):self.assertTrue(e.runtime_matches('amd103',[p],policy(),999))
        for old,new in [('route-map EXTERNAL-DENY deny 10','route-map EXTERNAL-DENY permit 10'),(' match as-path LOCAL-ONLY',''),('permit 203.0.113.53/32','permit 0.0.0.0/0 le 32')]:
            with patch.object(e,'query',return_value=text.replace(old,new)):
                self.assertFalse(e.runtime_matches('amd103',[p],policy(),999))

    def test_deadline_applies_to_every_subprocess(self):
        with patch.object(e.time,'monotonic',return_value=5),patch.object(e.subprocess,'run') as run:
            with self.assertRaises(RuntimeError):e.query('show bgp summary json',4)
            run.assert_not_called()
            run.return_value=types.SimpleNamespace(returncode=0,stdout='{}')
            e.query('show bgp summary json',5.25)
            self.assertEqual(run.call_args.kwargs['timeout'],.25)

    def test_revocation_removes_external_without_restoring_authority(self):
        config=b.default_config('amd103');config['external_peers']=[entry()]
        receipt=dict(node='amd103',action='bgp-apply',status='pending',old_config=config,old_withdraw=False,external_policy_digest='old')
        empty=dict(schema=1,node='amd103',peers=[])
        with patch.object(e,'policy',return_value=empty),patch.object(b,'test_client',return_value=None),patch.object(b.c,'atomic') as atomic,patch.object(b,'atomic_text') as text,patch.object(b,'restart'):
            with self.assertRaisesRegex(RuntimeError,'reconciliation'):b.rollback_locked('amd103',receipt,pathlib.Path('receipt'))
            self.assertEqual(receipt['status'],'pending')
            self.assertEqual(atomic.call_args_list[0].args[1],{'withdraw':True})
            self.assertNotIn('2001:db8:85:1::1',text.call_args.args[1])
            self.assertTrue(all(x.args[0].name!='external-policy.json' for x in atomic.call_args_list))

    def test_apply_policy_change_after_preflight_withdraws_and_never_commits_peer(self):
        with tempfile.TemporaryDirectory() as folder:
            root=pathlib.Path(folder);(root/'console-receipts').mkdir();(root/'bgp.conf').write_text('old mesh')
            enrolled=policy();current=[enrolled]
            @contextmanager
            def lock():
                with (root/'lock').open('w') as handle:yield handle
            fake=types.SimpleNamespace(flock=lambda *args:None,LOCK_EX=1,LOCK_NB=2)
            original=pathlib.Path.read_text
            def read_text(path,*args,**kwargs):
                if str(path).replace('\\','/')=='/proc/self/stat':return '1 (worker) '+' '.join(['1']*20)
                return original(path,*args,**kwargs)
            snapshot=dict(stale=False,maintenance={'withdraw':False},profiles=[])
            def preflight(*args):current[0]=dict(schema=1,node='amd103',peers=[])
            with patch.object(e.c,'BASE',root),patch.object(e,'policy',side_effect=lambda node:current[0]),patch.object(b,'test_client',return_value=None),patch.object(b.c,'identity'),patch.object(b.c,'secure'),patch.object(b.c,'fcntl',fake),patch.object(b,'lock_file',lock),patch.object(b.c,'snapshot',return_value=snapshot),patch.object(b,'preflight',side_effect=preflight),patch.object(b.c,'run'),patch.object(b.c,'atomic') as atomic,patch.object(b,'atomic_text') as text,patch.object(b,'restart'),patch.object(pathlib.Path,'read_text',read_text):
                old=b.get('amd103');proposed=copy.deepcopy(old['config']);proposed['external_peers']=[entry()]
                with self.assertRaisesRegex(RuntimeError,'reconciliation'):
                    b.apply('amd103','11111111-1111-4111-8111-111111111111',dict(expected_revision=old['revision'],config=proposed))
                self.assertTrue(all('2001:db8:85:1::1' not in call.args[1] for call in text.call_args_list))
                configs=[call.args[1] for call in atomic.call_args_list if call.args[0].name=='bgp-console.json']
                self.assertEqual(configs,[old['config']])
                receipts=[call.args[1] for call in atomic.call_args_list if call.args[0].parent.name=='console-receipts']
                self.assertEqual(receipts[0]['status'],'pending')
                self.assertEqual(receipts[0]['external_policy_digest'],e.digest(enrolled))
                self.assertEqual(atomic.call_args_list[-1].args[1],{'withdraw':False})

if __name__=='__main__':unittest.main()
