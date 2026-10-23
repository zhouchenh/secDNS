import copy
import unittest
from unittest.mock import Mock
import managed_ospf as m


class EnrollmentTests(unittest.TestCase):
    def setUp(self):
        self.config={'interface':'ens18','management_ipv4':'100.91.1.82','local_link_local':'fe80::1',
            'identity_interface':'secdns-id','identity_addresses':['100.66.53.101/32','2001:db8::101/128','2001:db8::64:101/128'],
            'zebra_state':'/opt/candidate/state','files':{x:'a'*64 for x in ('ospfd.conf','ospf6d.conf','policy.conf')},
            'firewall_sha256':'b'*64}
        self.entries=[{'ifname':'ens18','flags':['UP'],'addr_info':[{'local':'100.91.1.82'},{'local':'fe80::1'}]},
            {'ifname':'secdns-id','flags':['UP'],'addr_info':[{'local':'100.66.53.101'},{'local':'2001:db8::101'},{'local':'2001:db8::64:101'}]}]

    def test_valid_enrollment(self):self.assertEqual(m.validate(self.config),self.config)
    def test_dhcp_lease_change_stops_readiness(self):
        self.entries[0]['addr_info'][0]['local']='100.91.1.83'
        self.assertFalse(m.address_ready(self.config,self.entries))
    def test_link_local_on_wrong_interface_rejected(self):
        self.entries[0]['addr_info'].pop();self.entries.append({'ifname':'other','flags':['UP'],'addr_info':[{'local':'fe80::1'}]})
        self.assertFalse(m.address_ready(self.config,self.entries))
    def test_unrelated_identity_vip_rejected(self):
        self.entries[1]['addr_info'].append({'local':'192.0.2.1'})
        self.assertFalse(m.address_ready(self.config,self.entries))
    def test_dad_failed_address_rejected(self):
        self.entries[0]['addr_info'][1]['dadfailed']=True
        self.assertFalse(m.address_ready(self.config,self.entries))
    def test_recovery_matches_without_changing_config(self):
        self.assertTrue(m.address_ready(self.config,self.entries))
        self.entries[0]['flags']=[];self.assertFalse(m.address_ready(self.config,self.entries))
        self.entries[0]['flags']=['UP'];self.assertTrue(m.address_ready(self.config,self.entries))
    def test_both_policy_families_required(self):
        self.assertTrue(m.policy_attached('ospf : SD_STAGE4','ospf6 : SD_STAGE6'))
        self.assertFalse(m.policy_attached('ospf : SD_STAGE4','ospf6 : none'))
    def test_loader_runs_only_after_unowned_readback(self):
        order=[]
        def read():order.append('read');return 'ospf : none','ospf6 : none',''
        m.load_when_unowned(read,lambda:order.append('load'))
        self.assertEqual(order,['read','load'])
    def test_foreign_attachment_is_never_overwritten(self):
        loader=Mock()
        with self.assertRaises(RuntimeError):m.load_when_unowned(lambda:('ospf : OTHER','ospf6 : none',''),loader)
        loader.assert_not_called()
    def test_existing_owned_name_is_not_assumed_ours(self):
        loader=Mock()
        with self.assertRaises(RuntimeError):m.load_when_unowned(lambda:('ospf : none','ospf6 : none','route-map SD_STAGE4'),loader)
        loader.assert_not_called()
    def test_all_children_attempted_when_one_stop_fails(self):
        bad=Mock();bad.poll.return_value=None;bad.terminate.side_effect=OSError('failed')
        good=Mock();good.poll.return_value=None
        children={'ospfd':bad,'ospf6d':good}
        with self.assertRaises(RuntimeError):m.stop(children,('ospfd','ospf6d'))
        good.terminate.assert_called_once();good.wait.assert_called_once()
        self.assertEqual(children,{'ospfd':bad})
    def test_failed_wait_retains_ownership(self):
        child=Mock();child.poll.return_value=None;child.wait.side_effect=OSError('wait failed')
        children={'mgmtd':child}
        with self.assertRaises(RuntimeError):m.stop(children,('mgmtd',))
        self.assertIs(children['mgmtd'],child)
    def test_policy_body_change_detected(self):
        text='route-map SD_STAGE4 permit 10\n match ip address prefix-list SD_ALLOW4\n!\nroute-map SD_STAGE4 deny 100\n!'
        self.assertNotEqual(m.managed_policy(text),m.managed_policy(text.replace('deny 100','permit 100')))
        self.assertNotEqual(m.managed_policy(text),m.managed_policy(text.replace(' match ip address prefix-list SD_ALLOW4\n','')))
    def test_additional_dhcp_ipv4_rejected(self):
        self.entries[0]['addr_info'].append({'local':'100.91.1.83'})
        self.assertFalse(m.address_ready(self.config,self.entries))
    def test_nonhost_identity_rejected(self):
        self.config['identity_addresses'][0]='100.66.53.101/24'
        with self.assertRaises(ValueError):m.validate(self.config)
    def test_firewall_handle_reallocation_stable(self):
        original={'nftables':[{'metainfo':{'version':'1'}},{'rule':{'handle':1,'expr':[{'drop':None}]}}]}
        changed=copy.deepcopy(original);changed['nftables'][1]['rule']['handle']=9
        self.assertEqual(m.firewall_digest(original),m.firewall_digest(changed))
        changed['nftables'][1]['rule']['expr']=[{'accept':None}]
        self.assertNotEqual(m.firewall_digest(original),m.firewall_digest(changed))


if __name__=='__main__':unittest.main()

