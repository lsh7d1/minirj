import os
import signal
import time
import tempfile
import unittest
from contextlib import redirect_stdout, redirect_stderr
from io import StringIO
from pathlib import Path
from unittest.mock import Mock, patch

from minirj.core.network_config import NetworkConfig
from minirj.core.session_guard import SessionGuard, detect_competitors
from minirj.main import main
import test_state_machine as session_tests
from test_state_machine import request, result, CHALLENGE_1


class TestNetworkConfig(unittest.TestCase):
    @patch('minirj.core.network_config.subprocess.Popen')
    def test_external_never_launches_process(self, popen):
        config = NetworkConfig()
        report = Mock()
        config.start('test0', report)
        config.poll(report)
        config.close(report)
        popen.assert_not_called()

    def test_script_requires_explicit_backend_and_valid_timeout(self):
        for kwargs in ({'script': '/script'}, {'backend': 'script'},
                       {'timeout': 0}, {'timeout': float('nan')}):
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                NetworkConfig(**kwargs)

    @patch('minirj.core.network_config.subprocess.Popen')
    def test_script_result_and_single_launch(self, popen):
        self.addCleanup(patch.stopall)
        patch("minirj.core.network_config.os.waitid", side_effect=[None, object()]).start()
        patch("minirj.core.network_config.os.killpg").start()
        popen.return_value.wait.return_value = 7
        config = NetworkConfig('script', '/script', monotonic=lambda: 0)
        report = Mock()
        config.start('test0', report)
        config.start('test0', report)
        config.poll(report)
        self.assertIsNotNone(config.process)
        config.poll(report)
        self.assertEqual(config.result, 'network script exited with code 7')
        self.assertIsNone(config.process)
        self.assertEqual(popen.call_args.args, (['/script', 'test0'],))
        popen.assert_called_once()

    @patch('minirj.core.network_config.subprocess.Popen')
    def test_timeout_terminates_only_owned_child(self, popen):
        self.addCleanup(patch.stopall)
        exited = patch("minirj.core.network_config.os.waitid", return_value=None).start()
        killpg = patch("minirj.core.network_config.os.killpg").start()
        clock = Mock(return_value=0)
        child = popen.return_value
        config = NetworkConfig('script', '/script', timeout=1, monotonic=clock)
        report = Mock()
        config.start('test0', report)
        clock.return_value = 1
        config.poll(report)
        killpg.assert_called_once_with(child.pid, signal.SIGTERM)
        clock.return_value = 2
        config.poll(report)
        killpg.assert_called_with(child.pid, signal.SIGKILL)
        exited.return_value = object()
        child.wait.return_value = -9
        config.poll(report)
        self.assertIsNone(config.process)

    @patch('minirj.core.network_config.os.waitid', return_value=object())
    @patch('minirj.core.network_config.os.killpg')
    @patch('minirj.core.network_config.subprocess.Popen')
    def test_cleanup_waits_for_reap_while_interface_is_locked(self, popen, killpg, waitid):
        def reap():
            with self.assertRaises(RuntimeError):
                with SessionGuard('test-owned-cleanup'):
                    pass
            return -9
        popen.return_value.wait.side_effect = reap
        config = NetworkConfig('script', '/script')
        with SessionGuard('test-owned-cleanup'):
            config.start('test0', Mock())
            config.close(Mock())
        popen.return_value.wait.assert_called_once_with()
        with SessionGuard('test-owned-cleanup'):
            pass

    @patch('minirj.core.network_config.os.waitid', return_value=object())
    @patch('minirj.core.network_config.os.killpg')
    @patch('minirj.core.network_config.subprocess.Popen')
    def test_late_zero_exit_remains_failed(self, popen, killpg, waitid):
        clock = Mock(return_value=0)
        popen.return_value.wait.return_value = 0
        config = NetworkConfig('script', '/script', timeout=1, monotonic=clock)
        report = Mock()
        config.start('test0', report)
        clock.return_value = 2
        config.poll(report)
        self.assertTrue(config.failed)
        self.assertEqual(config.exit_code, 0)
        self.assertIsNone(config.process)
        self.assertTrue(any('deadline' in call.args[0] for call in report.call_args_list))

    @patch('minirj.core.network_config.subprocess.Popen', side_effect=OSError)
    def test_launch_failure_reported(self, popen):
        config = NetworkConfig('script', '/script')
        config.start('test0', Mock())
        self.assertEqual(config.result, 'script launch failed')


class TestScriptProcessGroup(unittest.TestCase):
    def test_timeout_cleans_wrapper_and_child_without_network(self):
        with tempfile.TemporaryDirectory() as directory:
            script = Path(directory) / 'wrapper'
            pid_file = Path(directory) / 'child.pid'
            script.write_text('#!/bin/sh\nsleep 60 &\nchild=$!\nprintf "%s" "$child" > "$1"\nwait\n')
            script.chmod(0o700)
            clock = Mock(return_value=0)
            config = NetworkConfig('script', str(script), timeout=1, monotonic=clock)
            config.start(str(pid_file), lambda message: None)
            leader = config.process
            try:
                deadline = time.monotonic() + 3
                while (not pid_file.exists() or not pid_file.read_text()) and time.monotonic() < deadline:
                    time.sleep(0.01)
                child_pid = int(pid_file.read_text())
                self.assertEqual(os.getpgid(child_pid), leader.pid)
                self.assertNotEqual(leader.pid, os.getpgrp())
                clock.return_value = 2
                config.poll(lambda message: None)
            finally:
                config.close(lambda message: None)
            self.assertIsNotNone(leader.returncode)
            deadline = time.monotonic() + 3
            while time.monotonic() < deadline:
                try:
                    state = Path(f'/proc/{child_pid}/stat').read_text().split(') ', 1)[1][0]
                except FileNotFoundError:
                    break
                if state == 'Z':
                    break
                time.sleep(0.01)
            else:
                self.fail('owned wrapper child is still running')


class TestSessionGuard(unittest.TestCase):
    def test_same_interface_excluded_and_released(self):
        with SessionGuard('unittest-no-real-interface'):
            with self.assertRaisesRegex(RuntimeError, 'another local session'):
                with SessionGuard('unittest-no-real-interface'):
                    pass
            with SessionGuard('unittest-other-interface'):
                pass
        with SessionGuard('unittest-no-real-interface'):
            pass

    def test_competitor_scan_redacts_argv_and_filters_interfaces(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for pid in ('self', '123456789', '123456790'):
                (root / pid / 'ns').mkdir(parents=True)
                (root / pid / 'ns/net').symlink_to('net:[123]')
            (root / '123456789/cmdline').write_bytes(b'/bin/rjsupplicant\0-n\0test0\0-p\0SECRET\0')
            (root / '123456790/cmdline').write_bytes(b'/bin/minieap\0-iother0\0')
            conflicts, incomplete = detect_competitors('test0', root)
            self.assertEqual(conflicts, ['rjsupplicant (PID 123456789)'])
            self.assertFalse(incomplete)
            self.assertNotIn('SECRET', str(conflicts))

    def test_missing_proc_is_explicitly_incomplete(self):
        self.assertEqual(detect_competitors('test0', '/nonexistent-proc-fixture'), ([], True))


class TestExitPolicy(unittest.TestCase):
    def run_session(self, explicit=False, reauth=False):
        frames = [request(1, 1), request(4, 2, b'\x10' + CHALLENGE_1), result(3, 2)]
        if reauth:
            frames.append(request(1, 3))
        machine, network = session_tests.TestStateMachine().make_machine(frames)
        machine.logoff_on_exit = explicit
        network.stop_when_empty = True
        self.assertTrue(machine.authenticate(log_callback=lambda message: None))
        return machine, network

    def test_default_stop_does_not_send_logoff(self):
        _, network = self.run_session()
        self.assertFalse(any(frame[15] == 2 for frame in network.sent))
        self.assertFalse(network.opened)

    def test_explicit_logoff_including_reauth_is_sent_once(self):
        for reauth in (False, True):
            with self.subTest(reauth=reauth):
                machine, network = self.run_session(True, reauth)
                self.assertEqual(sum(frame[15] == 2 for frame in network.sent), 1)
                self.assertIn('server confirmation unavailable', machine.logoff_result)

    def test_exception_exit_obeys_explicit_logoff_policy(self):
        for explicit in (False, True):
            frames = [request(1, 1), request(4, 2, b'\x10' + CHALLENGE_1), result(3, 2)]
            machine, network = session_tests.TestStateMachine().make_machine(frames)
            machine.logoff_on_exit = explicit
            receive = network.recv_frame

            def failing_receive(timeout=0):
                if network.frames:
                    return receive(timeout)
                raise OSError('test receive failure')

            network.recv_frame = failing_receive
            with self.subTest(explicit=explicit), self.assertRaises(OSError):
                machine.authenticate(log_callback=lambda message: None)
            self.assertEqual(sum(frame[15] == 2 for frame in network.sent), int(explicit))
            self.assertFalse(network.opened)

    @patch('minirj.main.detect_competitors', return_value=(['rjsupplicant (PID 1)'], False))
    @patch('minirj.main.signal.signal')
    @patch('minirj.main.StateMachine')
    def test_competitor_blocks_before_authentication(self, machine, signal, scan):
        with redirect_stdout(StringIO()), redirect_stderr(StringIO()):
            self.assertEqual(main(['-i', 'test0', '-u', 'student', '-p', 'test-secret']), 1)
        machine.return_value.authenticate.assert_not_called()
        machine.return_value.logoff.assert_not_called()

    @patch('minirj.main.detect_competitors', return_value=([], False))
    @patch('minirj.main.signal.signal')
    @patch('minirj.main.StateMachine')
    def test_signal_requests_stop_not_direct_logoff(self, machine, signal, scan):
        def authenticate():
            signal.call_args_list[0].args[1](2, None)
            return True
        machine.return_value.authenticate.side_effect = authenticate
        with redirect_stdout(StringIO()):
            self.assertEqual(main(['-i', 'test0', '-u', 'student', '-p', 'test-secret']), 0)
        machine.return_value.stop.assert_called_once()
        machine.return_value.logoff.assert_not_called()

    @patch('minirj.main.StateMachine')
    def test_invalid_backend_combination_rejected_before_auth(self, machine):
        with redirect_stderr(StringIO()), self.assertRaises(SystemExit):
            main(['-i', 'test0', '-u', 'student', '-p', 'test-secret', '--dhcp-script', '/script'])
        machine.assert_not_called()
