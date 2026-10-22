import copy,json,pathlib,tempfile,unittest
from unittest.mock import patch
import candidate_bgp as b

CLIENT=dict(schema=1,name='secdns-test-client109',asn=65109,ipv4='100.91.1.85',ipv6='2001:470:f9d1:9001::109')
class TestClientPeer(unittest.TestCase):
 def test_readonly_enrollment_survives_user_edits(self):
  config=b.default_config('amd103')
  config['peers'][0].update(keepalive_seconds=4,hold_seconds=12)
  with patch.object(b,'test_client',return_value=CLIENT):text=b.render('amd103',config)
  self.assertEqual(text.count(' port 1179'),6)
  self.assertIn('route-map TEST-CLIENT-DENY deny 10',text)
  for f in (4,6):
   address=CLIENT['ipv'+str(f)]
   self.assertIn('neighbor '+address+' route-map TEST-CLIENT-DENY in',text)
   self.assertIn('neighbor '+address+' route-map OUT-'+str(f)+' out',text)
  self.assertEqual(len(config['peers']),4)
  self.assertNotIn('network ',text)
 def test_browser_cannot_enroll_client(self):
  config=b.default_config('amd103');config['peers'].append(dict(address=CLIENT['ipv4'],family=4,remote_asn=65109,enabled=True,keepalive_seconds=3,hold_seconds=9))
  with self.assertRaises(ValueError):b.validate('amd103',config)
 def test_enrollment_is_part_of_revision(self):
  with tempfile.TemporaryDirectory() as folder,patch.object(b.c,'BASE',pathlib.Path(folder)),patch.object(b,'test_client',return_value=None):
   before=b.get('amd103')
   with patch.object(b,'test_client',return_value=CLIENT):after=b.get('amd103')
   self.assertEqual(before['config'],after['config']);self.assertNotEqual(before['revision'],after['revision'])
 def test_bad_enrollment_rejected(self):
  with tempfile.TemporaryDirectory() as folder,patch.object(b.c,'BASE',pathlib.Path(folder)),patch.object(b.c,'secure'):
   path=pathlib.Path(folder)/'test-client.json'
   for change in ({'schema':True},{'ipv4':'100.91.1.0'},{'ipv4':'100.91.1.255'},{'ipv6':'2001:470:f9d1:9001::'},{'asn':1},{'ipv4':'127.0.0.1'},{'ipv4':'100.91.1.82'},{'ipv6':'::1'},{'name':'other'},{'ipv4':'100.91.1.85; reboot'}):
    item=dict(CLIENT);item.update(change);path.write_text(json.dumps(item))
    with self.assertRaises(ValueError):b.test_client()
   path.write_text(json.dumps(CLIENT));self.assertEqual(b.test_client(),CLIENT)
 def test_status_excludes_only_enrolled_client(self):
  c=b.c;config=b.default_config('amd103')
  entries=[dict(role=a['role'],family=a['family'],prefix=('203.0.113.'+('53' if a['role']=='normal' else '64')+'/32') if a['family']==4 else ('2001:db8:53::'+('53' if a['role']=='normal' else '64')+'/128')) for a in config['announcements']]
  running='\n'.join('neighbor '+p['address']+' timers 3 9' for p in config['peers'])
  summary={'ipv'+str(f)+'Unicast':{'as':65101,'peers':dict([(p['address'],{'state':'Established'}) for p in config['peers'] if p['family']==f]+[(CLIENT['ipv'+str(f)],{'state':'Idle'})])} for f in (4,6)}
  def vty(command):
   if command=='show bgp summary json':return summary
   family=6 if 'ipv6' in command else 4
   return {'advertisedRoutes':{e['prefix']:{} for e in entries if e['family']==family}}
  for unexpected in (False,True):
   if unexpected:summary['ipv4Unicast']['peers']['100.91.1.86']={'state':'Established'}
   with patch.object(c,'identity',return_value=({'unit':'test'},{'entries':entries})),patch.object(c,'read',return_value={'withdraw':False}),patch.object(c,'run',side_effect=['ActiveState=active\nMainPID=123',json.dumps({'type':'health','observed_monotonic':99,'healthy':[True]*4}),running]),patch.object(c.time,'monotonic',return_value=100),patch.object(c,'vty',side_effect=vty),patch.object(b,'get',return_value={'config':config}),patch.object(b,'test_client',return_value=CLIENT):
    result=c.snapshot('amd103')
   self.assertEqual(result['stale'],unexpected)
   if not unexpected:
    self.assertEqual(len(result['peers']),4)
    self.assertTrue(all(p['advertised'] for p in result['profiles']))
    self.assertFalse(any(p['address'] in (CLIENT['ipv4'],CLIENT['ipv6']) for p in result['peers']))
if __name__=='__main__':unittest.main()
