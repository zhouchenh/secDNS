import json
import subprocess
import unittest
from unittest.mock import Mock, patch
import supervisor as s


def beat(seq=1, observed=10):
    return json.dumps(dict(type='health', sequence=seq, observed_monotonic=observed, healthy=[True]*4, advertised=[False]*4))


class Tests(unittest.TestCase):
    CONFIG = 'router bgp 65102\n bgp router-id 100.91.1.83\n address-family ipv4 unicast\n address-family ipv6 unicast\n'

    def test_identity_requires_both_families_and_one_instance(self):
        expected = s.bgp_identity(self.CONFIG)
        self.assertEqual(len(expected), 4)
        for config in (self.CONFIG.replace('address-family ipv6 unicast', ''),
                       self.CONFIG + 'router bgp 8506\n',
                       self.CONFIG.replace('bgp router-id 100.91.1.83', '')):
            with self.assertRaises(ValueError):
                s.bgp_identity(config)

    def test_auto_ra_guard_is_required_when_configured(self):
        expected = s.bgp_identity(self.CONFIG + ' no bgp ipv6-auto-ra\n')
        self.assertIn('no bgp ipv6-auto-ra', expected)
        child = Mock(); child.poll.return_value = None
        with patch.object(s.subprocess, 'run', return_value=Mock(returncode=0, stdout=self.CONFIG, stderr='')), patch.object(s.time, 'sleep'), patch.object(s.time, 'monotonic', side_effect=[1, 2, 4]):
            with self.assertRaisesRegex(RuntimeError, 'deadline'):
                s.wait_bgp_ready('/owned/state', expected, {'bgpd':child}, 4)

    def test_socket_ready_but_config_loading_does_not_start_checker(self):
        child = Mock(); child.poll.return_value = None
        responses = [Mock(returncode=0, stdout='', stderr=''),
                     Mock(returncode=0, stdout=self.CONFIG.replace('address-family ipv6 unicast', ''), stderr=''),
                     Mock(returncode=0, stdout=self.CONFIG, stderr='')]
        with patch.object(s.subprocess, 'run', side_effect=responses) as run, patch.object(s.time, 'sleep'), patch.object(s.time, 'monotonic', return_value=1):
            s.wait_bgp_ready('/owned/state', s.bgp_identity(self.CONFIG), {'bgpd':child}, 4)
        self.assertEqual(run.call_count, 3)
        self.assertIn('show running-config', run.call_args.args[0])

    def test_wrong_identity_errors_and_timeout_are_not_readiness(self):
        child = Mock(); child.poll.return_value = None
        bad = [Mock(returncode=1, stdout=self.CONFIG, stderr=''),
               Mock(returncode=0, stdout=self.CONFIG, stderr='VTY failure'),
               Mock(returncode=0, stdout=self.CONFIG + '% failed', stderr=''),
               Mock(returncode=0, stdout=self.CONFIG.replace('65102', '8506'), stderr=''),
               Mock(returncode=0, stdout=self.CONFIG.replace('100.91.1.83', '100.91.1.84'), stderr=''),
               subprocess.TimeoutExpired('vtysh', .5)]
        for result in bad:
            with self.subTest(result=result), patch.object(s.subprocess, 'run', side_effect=[result]), patch.object(s.time, 'sleep'), patch.object(s.time, 'monotonic', side_effect=[1, 2, 4]):
                with self.assertRaisesRegex(RuntimeError, 'deadline'):
                    s.wait_bgp_ready('/owned/state', s.bgp_identity(self.CONFIG), {'bgpd':child}, 4)

    def test_child_exit_before_or_during_readiness_is_fatal(self):
        for polls in ([1], [None, 1, 1]):
            child = Mock(); child.poll.side_effect = polls
            with patch.object(s.subprocess, 'run', return_value=Mock(returncode=0, stdout=self.CONFIG, stderr='')), patch.object(s.time, 'sleep'), patch.object(s.time, 'monotonic', return_value=1):
                with self.assertRaisesRegex(RuntimeError, 'owned child exited'):
                    s.wait_bgp_ready('/owned/state', s.bgp_identity(self.CONFIG), {'bgpd':child}, 4)

    def test_readiness_cannot_extend_original_deadline(self):
        child = Mock(); child.poll.return_value = None
        with patch.object(s.subprocess, 'run', return_value=Mock(returncode=0, stdout=self.CONFIG, stderr='')) as run, patch.object(s.time, 'sleep'), patch.object(s.time, 'monotonic', side_effect=[3.9, 4.01, 4.02, 4.03]):
            with self.assertRaisesRegex(RuntimeError, 'deadline'):
                s.wait_bgp_ready('/owned/state', s.bgp_identity(self.CONFIG), {'bgpd':child}, 4)
        self.assertAlmostEqual(run.call_args.kwargs['timeout'], .1)

    def test_progress_replay_and_stale(self):
        h = s.Heartbeat(10)
        h.accept(beat(), 10.5)
        with self.assertRaises(ValueError):
            h.accept(beat(), 11)
        for timestamp in (0, 100, float('nan')):
            with self.assertRaises(ValueError):
                h.accept(beat(2, timestamp), 20)
        h.accept(beat(2, 11), 12)
        h.check(24)
        with self.assertRaises(RuntimeError):
            h.check(24.01)

    def test_stalled_checker_even_without_exit(self):
        h = s.Heartbeat(0)
        with self.assertRaises(RuntimeError):
            h.check(12.01)

    def test_bad_states_do_not_refresh_deadline(self):
        h = s.Heartbeat(0)
        v = json.loads(beat())
        v['healthy'] = [1]*4
        with self.assertRaises(ValueError):
            h.accept(json.dumps(v), 10)
        self.assertEqual(h.last_progress, 0)

    def test_cleanup_order_and_stopped_child_escalation(self):
        events=[]
        children={}
        for name in ('checker','zebra','bgpd'):
            p=Mock()
            p.poll.return_value=None
            p.terminate.side_effect=lambda n=name: events.append(('term',n))
            p.kill.side_effect=lambda n=name: events.append(('kill',n))
            children[name]=p
        children['checker'].wait.side_effect=[subprocess.TimeoutExpired('checker',2),0]
        s.stop(children)
        self.assertEqual(events,[('term','bgpd'),('term','zebra'),('term','checker'),('kill','checker')])

    def test_already_dead_child_is_not_signalled(self):
        p=Mock();p.poll.return_value=-9
        s.stop({'bgpd':p})
        p.terminate.assert_not_called()


if __name__=='__main__':
    unittest.main()
