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

    def test_native_frr_as_path_sequence_is_semantically_exact(self):
        # Captured AMD FRR 10.3 rollback readback, 2026-10-22:
        native='bgp as-path access-list LOCAL-ONLY seq 5 permit ^$'
        with patch.object(e,'query',return_value=native):
            self.assertTrue(e.runtime_matches('amd103',[],policy(),999))
        for bad in (native.replace('permit','deny'),native.replace('^$','.*'),
                    native+'\n'+native.replace('seq 5','seq 10'),
                    native.replace('seq 5','seq 0'),native.replace('seq 5','seq 4294967296'),
                    native.replace('LOCAL-ONLY','OTHER')):
            with patch.object(e,'query',return_value=bad):
                self.assertFalse(e.runtime_matches('amd103',[],policy(),999))
        p=entry();p.update(enabled=True,exports=['203.0.113.53/32'])
        config=b.default_config('amd103');config['external_peers']=[p]
        with patch.object(b,'test_client',return_value=None):text=b.render('amd103',config,policy())
        text=text.replace('bgp as-path access-list LOCAL-ONLY permit ^$',native)
        with patch.object(e,'query',return_value=text):
            self.assertTrue(e.runtime_matches('amd103',[p],policy(),999))
        with patch.object(e,'query',return_value=text.replace('route-map EXTERNAL-DENY deny 10','route-map EXTERNAL-DENY permit 10')):
            self.assertFalse(e.runtime_matches('amd103',[p],policy(),999))

    def test_native_default_port_omission_only_equates_to_179(self):
        # AMD r4 failure_diagnostic recorded this as its sole missing line;
        # both AFIs were Established, exact exports present, imports zero.
        missing=' neighbor 2001:db8:85:1::1 port 179\n'
        fixture=json.loads((pathlib.Path(__file__).with_name('fixtures')/'amd-r4-default-port.json').read_text(encoding='utf-8'))
        config,enrolled=fixture['config'],fixture['policy'];p=config['external_peers'][0]
        diagnostic=fixture['failure_diagnostic']
        self.assertEqual(diagnostic['runtime']['missing_neighbors'],[[0,missing.strip()]])
        self.assertFalse(diagnostic['runtime']['unexpected_neighbors'])
        self.assertFalse(diagnostic['runtime']['missing_policy'])
        self.assertFalse(diagnostic['runtime']['unexpected_policy'])
        self.assertTrue(all(diagnostic['last_checks'].values()))
        with patch.object(b,'test_client',return_value=None):text=b.render('amd103',config,enrolled)
        native=text.replace(missing,'').replace('LOCAL-ONLY permit ^$','LOCAL-ONLY seq 5 permit ^$')
        for running in (text,native):
            with patch.object(e,'query',return_value=running):
                self.assertTrue(e.runtime_matches('amd103',[p],enrolled,999))
        for running in (text.replace('::1 port 179','::1 port 1179'),
                        native.replace(' neighbor 2001:db8:85:1::1 remote-as 8501\n',''),
                        native.replace('timers 1 5','timers 1 9'),
                        text+missing, text+missing.replace('179','1179')):
            with patch.object(e,'query',return_value=running):
                self.assertFalse(e.runtime_matches('amd103',[p],enrolled,999))
        nondefault=copy.deepcopy(enrolled);nondefault['peers'][0]['port']=1179
        with patch.object(e,'query',return_value=native):
            self.assertFalse(e.runtime_matches('amd103',[p],nondefault,999))
        with patch.object(e,'query',return_value=text):
            self.assertFalse(e.runtime_matches('amd103',[p],nondefault,999))

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

    def _exercise_apply_policy_change(self, failure_mode=None):
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
            def diagnostic(*args):
                if failure_mode=='read':raise OSError('synthetic read failure')
                return {'schema':1}
            def persist(path,value):
                if failure_mode=='write' and path.parent.name=='console-receipts' and 'failure_diagnostic' in value:raise OSError('synthetic write failure')
            def preflight(*args):current[0]=dict(schema=1,node='amd103',peers=[])
            with patch.object(e.c,'BASE',root),patch.object(e,'policy',side_effect=lambda node:current[0]),patch.object(b,'test_client',return_value=None),patch.object(b.c,'identity'),patch.object(b.c,'secure'),patch.object(b.c,'fcntl',fake),patch.object(b,'lock_file',lock),patch.object(b.c,'snapshot',return_value=snapshot),patch.object(b,'preflight',side_effect=preflight),patch.object(b.c,'run'),patch.object(b.c,'atomic',side_effect=persist) as atomic,patch.object(e,'failure_diagnostic',side_effect=diagnostic),patch.object(b,'atomic_text') as text,patch.object(b,'restart'),patch.object(pathlib.Path,'read_text',read_text):
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

    def test_apply_policy_change_after_preflight_withdraws_and_never_commits_peer(self):
        self._exercise_apply_policy_change()

    def test_diagnostic_read_and_persistence_failure_do_not_block_rollback(self):
        for mode in ('read','write'):
            with self.subTest(mode=mode):self._exercise_apply_policy_change(mode)

    def test_failure_diagnostic_is_bounded_and_redacts_unrelated_native_text(self):
        p=entry();p.update(enabled=True,exports=['203.0.113.53/32'])
        config=b.default_config('amd103');config['external_peers']=[p]
        with patch.object(b,'test_client',return_value=None):running=b.render('amd103',config,policy())
        running+='neighbor 2001:db8:85:1::1 password DO-NOT-RECORD-SECRET\n'
        def query(command,deadline):
            if command=='show running-config':return running
            if command=='show bgp summary json':return json.dumps({'ipv%dUnicast'%f:{'peers':{'2001:db8:85:1::1':{'state':'Established','remoteAs':8501,'description':'DO-NOT-RECORD-SECRET'}}} for f in (4,6)})
            return json.dumps({'advertisedRoutes':{'0.0.0.0/0':{}}}) if 'ipv4' in command else json.dumps({'advertisedRoutes':{}})
        with patch.object(e,'query',side_effect=query):result=e.failure_diagnostic('amd103',config,policy())
        self.assertNotIn('DO-NOT-RECORD-SECRET',json.dumps(result))
        self.assertFalse(result['runtime']['matches'])
        self.assertEqual(result['peers'][0]['advertised_prefixes'],['0.0.0.0/0'])
        self.assertEqual(result['peers'][0]['state'],'Established')
        with patch.object(e.time,'monotonic',side_effect=[0]+[4]*10),patch.object(e.subprocess,'run') as run:
            result=e.failure_diagnostic('amd103',config,policy())
            self.assertFalse(result['complete']);run.assert_not_called()

if __name__=='__main__':unittest.main()
