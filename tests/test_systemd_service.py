"""Tests for the small deployment adapter, not original SuConfig/fileReg loading."""
import contextlib
import io
import os
from pathlib import Path
from types import SimpleNamespace
import socket
import tempfile
import threading
import time
import unittest
from unittest.mock import Mock, patch

from minirj import service
from minirj.core.state_machine import AuthState

ROOT = Path(__file__).resolve().parents[1]
UUID = "9ec06cf5-6945-40ad-966a-8c908fdf6c8d"


class FakeSock:
    def __init__(self, local="192.0.2.10"):
        self.local = local
        self.closed = False
        self.timeout = None

    def getsockname(self):
        return (self.local, 0)

    def close(self):
        self.closed = True

    def settimeout(self, value):
        self.timeout = value


class FakeTLS(FakeSock):
    def __init__(self, response=b"HTTP/1.1 200 OK\r\n\r\n"):
        super().__init__()
        self.response = response
        self.request = b""

    def sendall(self, data):
        self.request = data

    def recv(self, size):
        data, self.response = self.response, b""
        return data


class FakeClock:
    def __init__(self):
        self.now = 100.0

    def monotonic(self):
        return self.now


class FakeStop:
    def __init__(self, clock):
        self.clock, self.stopped = clock, False
        self.waits, self.on_wait = [], None

    def is_set(self):
        return self.stopped

    def set(self):
        self.stopped = True

    def wait(self, seconds):
        if self.stopped:
            return True
        self.waits.append(seconds)
        if len(self.waits) > 500:
            raise AssertionError("health loop did not terminate")
        self.clock.now += seconds
        if self.on_wait is not None:
            self.on_wait(seconds)
        return self.stopped


class ServiceAdapterTests(unittest.TestCase):
    def test_credentials_are_single_line_and_preserve_spaces(self):
        with tempfile.TemporaryDirectory() as tmp, patch.dict(os.environ, {"CREDENTIALS_DIRECTORY": tmp}):
            p = Path(tmp) / "password"
            p.write_text(" synthetic password \r\n")
            self.assertEqual(service.credential("password"), " synthetic password ")
            for value in ("", "one\ntwo\n", "bad\0value"):
                p.write_text(value)
                with self.assertRaises(ValueError):
                    service.credential("password")

    def test_wrong_interface_profile_is_not_touched(self):
        with patch.object(service, "nmcli", return_value="internal0\nno\nauto") as nm:
            with self.assertRaises(RuntimeError):
                service.network("campus0", UUID)
            self.assertEqual(nm.call_count, 1)

    def test_other_connection_is_not_touched(self):
        with patch.object(service, "nmcli", side_effect=["campus0\nno\nauto", "other-uuid"]) as nm:
            with self.assertRaises(RuntimeError):
                service.network("campus0", UUID)
            self.assertEqual(nm.call_count, 2)

    def test_cleanup_is_idempotent_and_only_downs_own_uuid(self):
        for active, calls in (("", 2), ("--", 2), (UUID, 3)):
            with self.subTest(active=active), patch.object(service, "nmcli", side_effect=["campus0\nno\nauto", active, ""]) as nm:
                service.network("campus0", UUID)
                self.assertEqual(nm.call_count, calls)
                if active == UUID:
                    nm.assert_called_with("connection", "down", "uuid", UUID)

    def test_dhcp_up_uses_only_configured_uuid_and_interface(self):
        with patch.object(service, "nmcli", side_effect=["campus0\nno\nauto", "", ""]) as nm:
            service.network("campus0", UUID, up=True)
            nm.assert_called_with("connection", "up", "uuid", UUID, "ifname", "campus0")

    def test_probe_uses_interface_source_and_verifying_tls(self):
        sock = FakeSock()
        with patch.object(service, "_resolve", return_value=("192.0.2.20", 443)) as resolve, \
                patch.object(service, "_connect", return_value=sock) as connect, \
                patch.object(service, "_tls_wrap") as tls, \
                patch.object(service, "_head", return_value=200) as head:
            self.assertEqual(service.probe("campus0", "192.0.2.10", "https://example.com/path?q=1"), 200)
        resolve.assert_called_once()
        self.assertEqual(connect.call_args.args[:3], ("campus0", "192.0.2.10", ("192.0.2.20", 443)))
        tls.assert_called_once()
        self.assertEqual(head.call_args.args[1:5], ("example.com", 443, "/path", "q=1"))

    def test_connect_binds_device_and_source(self):
        sock = Mock()
        with patch.object(service.socket, "socket", return_value=sock):
            result = service._connect("campus0", "192.0.2.10", ("192.0.2.20", 443), time.monotonic() + 1)
        self.assertIs(result, sock)
        sock.setsockopt.assert_called_once_with(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, b"campus0\0")
        sock.bind.assert_called_once_with(("192.0.2.10", 0))
        sock.connect.assert_called_once_with(("192.0.2.20", 443))

    def test_tls_wrap_uses_default_verifying_context(self):
        sock = Mock()
        wrapped = Mock()
        context = Mock()
        context.wrap_socket.return_value = wrapped
        with patch.object(service.ssl, "create_default_context", return_value=context):
            self.assertIs(service._tls_wrap(sock, "example.com", time.monotonic() + 1), wrapped)
        context.wrap_socket.assert_called_once_with(sock, server_hostname="example.com")

    def test_head_parses_status_line(self):
        tls = FakeTLS(b"HTTP/1.1 204 No Content\r\n\r\n")
        self.assertEqual(service._head(tls, "example.com", 443, "/", "", time.monotonic() + 1), 204)
        self.assertTrue(tls.request.startswith(b"HEAD / HTTP/1.1\r\n"))
        self.assertIn(b"Host: example.com\r\n", tls.request)
        for response in (b"", b"garbage\r\n"):
            with self.subTest(response=response), self.assertRaises(service.HealthFailure) as raised:
                service._head(FakeTLS(response), "example.com", 443, "/", "", time.monotonic() + 1)
            self.assertEqual(raised.exception.reason, "transfer_failed")

    def test_resolve_uses_ipv4_and_classifies_errors(self):
        answer = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.0.2.20", 443))]
        with patch.object(service.socket, "getaddrinfo", return_value=answer) as lookup:
            self.assertEqual(service._resolve("example.com", 443, time.monotonic() + 1), ("192.0.2.20", 443))
        lookup.assert_called_once_with("example.com", 443, socket.AF_INET, socket.SOCK_STREAM)
        with patch.object(service.socket, "getaddrinfo", side_effect=socket.gaierror()):
            with self.assertRaises(service.HealthFailure) as raised:
                service._resolve("example.com", 443, time.monotonic() + 1)
        self.assertEqual(raised.exception.reason, "dns_failure")

    def test_insecure_probe_url_fails_before_execution(self):
        with patch.object(service, "_resolve") as resolve:
            for url in ("http://example.com/", "https://user:pass@example.com/"):
                with self.assertRaises(ValueError):
                    service.probe("campus0", "192.0.2.10", url)
            resolve.assert_not_called()

    def test_notify_supports_abstract_systemd_socket(self):
        with patch.dict(os.environ, {"NOTIFY_SOCKET": "@test-notify"}), patch.object(service.socket, "socket") as factory:
            service.notify("READY=1")
            factory.assert_called_with(socket.AF_UNIX, socket.SOCK_DGRAM)
            factory.return_value.__enter__.return_value.sendto.assert_called_with(b"READY=1", "\0test-notify")

    def test_success_marks_ready_and_feeds_watchdog(self):
        machine = SimpleNamespace(state=AuthState.ONLINE, post_auth_status="complete", stop=Mock())
        stopped, failed = threading.Event(), threading.Event()
        def notified(message):
            self.assertIn("READY=1", message)
            self.assertIn("WATCHDOG=1", message)
            stopped.set()
        with patch("minirj.network.snapshot.LinuxIPv4SnapshotProvider.read", return_value=SimpleNamespace(ready=True, ip="192.0.2.10")), patch.object(service, "probe", return_value=200), patch.object(service, "notify", side_effect=notified), contextlib.redirect_stdout(io.StringIO()):
            service.health_loop(machine, SimpleNamespace(progress=time.monotonic()), "campus0", "https://example.com/", stopped, failed)
        self.assertFalse(failed.is_set())
        machine.stop.assert_not_called()

    def test_health_error_exits_without_ready_or_secret_log(self):
        machine = SimpleNamespace(state=AuthState.ONLINE, post_auth_status="complete", stop=Mock())
        stopped, failed = threading.Event(), threading.Event()
        output = io.StringIO()
        with patch("minirj.network.snapshot.LinuxIPv4SnapshotProvider.read", return_value=SimpleNamespace(ready=True, ip="192.0.2.10")), patch.object(service, "probe", side_effect=RuntimeError("synthetic-secret")), patch.object(service, "notify") as notify, contextlib.redirect_stdout(output):
            service.health_loop(machine, SimpleNamespace(progress=time.monotonic()), "campus0", "https://example.com/", stopped, failed)
        self.assertTrue(failed.is_set())
        machine.stop.assert_called_once()
        notify.assert_not_called()
        self.assertNotIn("synthetic-secret", output.getvalue())

    def test_stalled_auth_loop_does_not_feed_watchdog(self):
        machine = SimpleNamespace(state=AuthState.ONLINE, stop=Mock())
        failed = threading.Event()
        with patch.object(service, "probe") as probe, patch.object(service, "notify") as notify, contextlib.redirect_stdout(io.StringIO()):
            service.health_loop(machine, SimpleNamespace(progress=time.monotonic()-120), "campus0", "https://example.com/", threading.Event(), failed)
        self.assertTrue(failed.is_set())
        probe.assert_not_called()
        notify.assert_not_called()

    def test_server_text_not_forwarded(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            service.session_log("Authentication failed: synthetic-secret")
            service.session_log("EAP Notification: synthetic-secret")
        self.assertNotIn("synthetic-secret", output.getvalue())
        self.assertIn("authentication rejected", output.getvalue())

    def test_unit_has_one_restart_policy_and_no_extra_units(self):
        files = list((ROOT / "deploy/systemd").glob("*.service"))
        self.assertEqual(len(files), 1)
        text = files[0].read_text()
        for directive in ("Restart=always", "RestartSec=30s", "WatchdogSec=90s",
                          "TimeoutStartSec=75s", "TimeoutStopSec=20s", "StartLimitIntervalSec=0",
                          "KillMode=control-group", "Wants=NetworkManager.service", "LoadCredential=password:",
                          "User=minirj", "AmbientCapabilities=CAP_NET_RAW",
                          "CapabilityBoundingSet=CAP_NET_RAW",
                          "ExecStart=/usr/bin/python3 -I -u /opt/minirj/minirj.pyz"):
            self.assertIn(directive, text)
        self.assertNotIn("OnFailure=", text)
        self.assertNotIn("Requires=", text)
        self.assertNotIn("BindsTo=", text)
        self.assertFalse(list((ROOT / "deploy/systemd").glob("*.timer")))
        self.assertFalse(list((ROOT / "deploy/systemd").glob("*.socket")))


class ProbeDiagnosticTests(unittest.TestCase):
    def probe_result(self, **overrides):
        sock = overrides.pop("sock", FakeSock())
        values = {"_resolve": ("192.0.2.20", 443), "_connect": sock,
                  "_tls_wrap": FakeTLS(), "_head": 200}
        values.update(overrides)
        with contextlib.ExitStack() as stack:
            for name, value in values.items():
                if isinstance(value, Exception):
                    stack.enter_context(patch.object(service, name, side_effect=value))
                else:
                    stack.enter_context(patch.object(service, name, return_value=value))
            try:
                return service.probe("campus0", "192.0.2.10", "https://example.com/")
            except service.HealthFailure as exc:
                return exc

    def test_success_returns_http_status(self):
        self.assertEqual(self.probe_result(), 200)

    def test_dns_failure_is_retryable_and_sanitized(self):
        failure = self.probe_result(_resolve=service.HealthFailure("dns_failure", stage="dns"))
        self.assertEqual((failure.reason, failure.stage), ("dns_failure", "dns"))
        self.assertTrue(failure.retryable)
        with patch.object(service, "resolver_servers", return_value="192.0.2.53"):
            diagnostic = failure.diagnostic()
        self.assertIn("dns_s=", diagnostic)
        self.assertIn("dns_servers=192.0.2.53", diagnostic)
        self.assertNotIn("curl_exit", diagnostic)
        self.assertNotIn("synthetic-secret", diagnostic)

    def test_timeout_stages(self):
        cases = (
            ({"_resolve": service.HealthFailure("dns_timeout", stage="dns")}, "dns_timeout", "dns"),
            ({"_connect": service.HealthFailure("connection_timeout", stage="connect")},
             "connection_timeout", "connect"),
            ({"_tls_wrap": service.HealthFailure("tls_timeout", stage="tls")}, "tls_timeout", "tls"),
            ({"_head": service.HealthFailure("transfer_timeout", stage="transfer")},
             "transfer_timeout", "transfer"),
        )
        for overrides, reason, stage in cases:
            with self.subTest(reason=reason):
                failure = self.probe_result(**overrides)
                self.assertEqual((failure.reason, failure.stage), (reason, stage))
                self.assertTrue(failure.retryable)

    def test_hard_failures_are_not_retried(self):
        cases = (
            ({"_tls_wrap": service.HealthFailure("tls_verification_failed", stage="tls")},
             "tls_verification_failed"),
            ({"_head": 403}, "http_status"),
            ({"sock": FakeSock(local="192.0.2.11")}, "source_mismatch"),
        )
        for overrides, reason in cases:
            with self.subTest(reason=reason):
                failure = self.probe_result(**overrides)
                self.assertEqual(failure.reason, reason)
                self.assertFalse(failure.retryable)

    def test_transient_connection_and_transfer_errors_are_classified(self):
        for reason in ("connection_failed", "transfer_failed"):
            with self.subTest(reason=reason):
                key = "_connect" if reason == "connection_failed" else "_head"
                failure = self.probe_result(**{key: service.HealthFailure(reason)})
                self.assertEqual(failure.reason, reason)
                self.assertTrue(failure.retryable)

    def test_resolver_summary_accepts_only_addresses_and_at_most_three_servers(self):
        text = ("# synthetic-secret\nnameserver synthetic-secret\nnameserver 192.0.2.53\n"
                "nameserver 192.0.2.53\nnameserver 192.0.2.54 # synthetic-secret\n"
                "nameserver 2001:db8::53\nnameserver 192.0.2.55\n")
        with patch.object(service.Path, "read_text", return_value=text):
            self.assertEqual(service.resolver_servers(), "192.0.2.53,192.0.2.54,2001:db8::53")
        with patch.object(service.Path, "read_text", side_effect=OSError("synthetic-secret")):
            self.assertEqual(service.resolver_servers(), "unavailable")

    def test_timeout_budget_fits_watchdog(self):
        self.assertLess(service.PROBE_CONNECT_TIMEOUT, service.PROBE_TOTAL_TIMEOUT)
        self.assertLess(service.PROBE_TOTAL_TIMEOUT, service.PROBE_PROCESS_TIMEOUT)
        self.assertLess(service.PROBE_INTERVAL + service.HEALTH_CYCLE_TIMEOUT, 90)
        self.assertGreater(service.REAUTH_GRACE, 12)


class HealthPolicyTests(unittest.TestCase):
    def setUp(self):
        self.clock = FakeClock()
        self.stopped = FakeStop(self.clock)
        self.failed = threading.Event()
        self.machine = SimpleNamespace(state=AuthState.ONLINE, post_auth_status="complete", stop=Mock())
        self.engine = SimpleNamespace(progress=self.clock.now)
        self.snapshot = SimpleNamespace(ready=True, ip="192.0.2.10")
        self.output = io.StringIO()
        self.messages = []
        self.success_count = 1

    def notified(self, message):
        self.messages.append(message)
        if len(self.messages) == self.success_count:
            self.stopped.set()

    def check_health(self, effect, *, reader=None, notifier=None):
        with patch.object(service.time, "monotonic", side_effect=self.clock.monotonic), \
                patch("minirj.network.snapshot.LinuxIPv4SnapshotProvider.read",
                      side_effect=reader, return_value=self.snapshot), \
                patch.object(service, "probe", side_effect=effect) as probe, \
                patch.object(service, "notify", side_effect=notifier or self.notified) as notify, \
                patch.object(service, "resolver_servers", return_value="192.0.2.53"), \
                contextlib.redirect_stdout(self.output):
            service.health_loop(self.machine, self.engine, "campus0", "https://example.com/", self.stopped, self.failed)
        return probe, notify

    def assert_failed(self, reason):
        self.assertTrue(self.failed.is_set())
        self.machine.stop.assert_called_once()
        self.assertIn(f"reason={reason}", self.output.getvalue())
        self.assertNotIn("synthetic-secret", self.output.getvalue())

    def test_transient_failure_is_retried_once_before_ready(self):
        probe, _ = self.check_health([service.HealthFailure("dns_timeout", stage="dns"), 200])
        self.assertEqual(probe.call_count, 2)
        self.assertEqual(len(self.messages), 1)
        self.assertIn("READY=1", self.messages[0])
        self.assertEqual(self.stopped.waits, [service.PROBE_RETRY_DELAY])
        self.assertIn("health retry: reason=dns_timeout", self.output.getvalue())
        self.assertIn("dns_servers=192.0.2.53", self.output.getvalue())
        self.assertFalse(self.failed.is_set())

    def test_second_transient_failure_exits_without_any_watchdog_update(self):
        probe, notify = self.check_health([service.HealthFailure("dns_timeout"), service.HealthFailure("dns_timeout")])
        self.assertEqual(probe.call_count, 2)
        notify.assert_not_called()
        self.assert_failed("dns_timeout")
        self.assertIn("attempt=2", self.output.getvalue())

    def test_hard_failures_and_unclassified_errors_do_not_retry(self):
        for reason in ("tls_verification_failed", "http_status", "source_mismatch", "probe_execution"):
            with self.subTest(reason=reason):
                self.setUp()
                probe, notify = self.check_health([service.HealthFailure(reason)])
                self.assertEqual(probe.call_count, 1)
                notify.assert_not_called()
                self.assert_failed(reason)
        self.setUp()
        probe, notify = self.check_health([RuntimeError("synthetic-secret")])
        self.assertEqual(probe.call_count, 1)
        notify.assert_not_called()
        self.assert_failed("internal_error")

    def test_stopping_during_retry_wait_does_not_mark_failure(self):
        self.stopped.on_wait = lambda seconds: self.stopped.set()
        probe, notify = self.check_health([service.HealthFailure("dns_failure")])
        self.assertEqual(probe.call_count, 1)
        notify.assert_not_called()
        self.assertFalse(self.failed.is_set())
        self.machine.stop.assert_not_called()

    def test_stopping_during_probe_does_not_mark_failure_or_ready(self):
        def checked(*_):
            self.stopped.set()
            return 200
        probe, notify = self.check_health(checked)
        self.assertEqual(probe.call_count, 1)
        notify.assert_not_called()
        self.assertFalse(self.failed.is_set())

    def test_cancelled_probe_failure_does_not_retry(self):
        def checked(*_):
            self.stopped.set()
            raise service.HealthFailure("dns_failure")
        probe, notify = self.check_health(checked)
        self.assertEqual(probe.call_count, 1)
        notify.assert_not_called()
        self.assertFalse(self.failed.is_set())

    def test_state_and_progress_are_rechecked_after_successful_probe(self):
        for reason in ("auth_unavailable", "auth_stalled", "phase2_unavailable", "address_unavailable"):
            with self.subTest(reason=reason):
                self.setUp()
                def checked(*_):
                    if reason == "auth_unavailable":
                        self.machine.state = AuthState.FAILED
                    elif reason == "auth_stalled":
                        self.engine.progress = self.clock.now - 120
                    elif reason == "phase2_unavailable":
                        self.machine.post_auth_status = "address_pending"
                    else:
                        self.snapshot.ready = False
                    return 200
                _, notify = self.check_health(checked)
                notify.assert_not_called()
                self.assert_failed(reason)

    def test_source_address_change_during_probe_is_fatal(self):
        def checked(*_):
            self.snapshot.ip = "192.0.2.11"
            return 200
        _, notify = self.check_health(checked)
        notify.assert_not_called()
        self.assert_failed("address_changed")

    def test_snapshot_exception_is_sanitized(self):
        probe, notify = self.check_health([200], reader=OSError("synthetic-secret"))
        probe.assert_not_called()
        notify.assert_not_called()
        self.assert_failed("address_unavailable")

    def test_notification_error_does_not_report_health_ok(self):
        _, notify = self.check_health([200], notifier=OSError("synthetic-secret"))
        notify.assert_called_once()
        self.assert_failed("notify_failed")
        self.assertNotIn("health OK", self.output.getvalue())

    def test_ready_is_sent_once_and_watchdog_only_after_each_fresh_success(self):
        self.success_count = 2
        probe, _ = self.check_health([200, 200])
        self.assertEqual(probe.call_count, 2)
        self.assertIn("READY=1", self.messages[0])
        self.assertNotIn("READY=1", self.messages[1])
        self.assertTrue(all("WATCHDOG=1" in msg for msg in self.messages))
        self.assertEqual(self.stopped.waits, [service.PROBE_INTERVAL])
        self.assertFalse(self.failed.is_set())

    def test_completed_session_gets_bounded_reauth_grace(self):
        for state in (AuthState.WAIT_MD5_REQ, AuthState.WAIT_RESULT):
            with self.subTest(state=state):
                self.setUp()
                self.success_count = 2
                def waited(seconds):
                    self.machine.state = state if seconds == service.PROBE_INTERVAL else AuthState.ONLINE
                    self.engine.progress = self.clock.now
                self.stopped.on_wait = waited
                probe, _ = self.check_health([200, 200])
                self.assertEqual(probe.call_count, 2)
                self.assertEqual(len(self.messages), 2)
                self.assertIn("reason=reauthentication", self.output.getvalue())
                self.assertFalse(self.failed.is_set())

    def test_reauth_grace_never_extends_for_new_requests(self):
        self.success_count = 2
        def waited(seconds):
            self.machine.state = (AuthState.WAIT_RESULT if self.machine.state == AuthState.WAIT_MD5_REQ
                                  else AuthState.WAIT_MD5_REQ)
            self.engine.progress = self.clock.now
        self.stopped.on_wait = waited
        probe, _ = self.check_health([200])
        self.assertEqual(probe.call_count, 1)
        self.assertEqual(len(self.messages), 1)
        self.assert_failed("reauth_timeout")
        self.assertLessEqual(self.clock.now, 100 + service.PROBE_INTERVAL + service.REAUTH_GRACE + 0.21)

    def test_reauth_during_probe_requires_another_fresh_probe(self):
        self.success_count = 2
        calls = []
        def checked(*_):
            calls.append(self.clock.now)
            if len(calls) == 2:
                self.machine.state = AuthState.WAIT_RESULT
            return 200
        def waited(seconds):
            if seconds != service.PROBE_INTERVAL:
                self.machine.state = AuthState.ONLINE
            self.engine.progress = self.clock.now
        self.stopped.on_wait = waited
        probe, _ = self.check_health(checked)
        self.assertEqual(probe.call_count, 3)
        self.assertEqual(len(self.messages), 2)
        self.assertFalse(self.failed.is_set())

    def test_repeated_reauth_during_both_attempts_cannot_keep_watchdog_alive(self):
        self.success_count = 2
        calls = []
        def checked(*_):
            calls.append(self.clock.now)
            if len(calls) > 1:
                self.machine.state = AuthState.WAIT_RESULT
            return 200
        self.stopped.on_wait = lambda seconds: setattr(self.machine, "state", AuthState.ONLINE)
        probe, _ = self.check_health(checked)
        self.assertEqual(probe.call_count, 3)
        self.assertEqual(len(self.messages), 1)
        self.assert_failed("reauth_probe_stale")

    def test_no_reauth_grace_before_first_verified_health(self):
        def checked(*_):
            self.machine.state = AuthState.WAIT_RESULT
            return 200
        _, notify = self.check_health(checked)
        notify.assert_not_called()
        self.assert_failed("auth_unavailable")

    def test_failed_disconnected_or_address_pending_session_gets_no_grace(self):
        for state in (AuthState.FAILED, AuthState.DISCONNECTED, AuthState.WAIT_ADDRESS, AuthState.WAIT_ID_REQ):
            with self.subTest(state=state):
                self.setUp()
                self.success_count = 2
                self.stopped.on_wait = lambda seconds: setattr(self.machine, "state", state)
                probe, _ = self.check_health([200])
                self.assertEqual(probe.call_count, 1)
                self.assertEqual(len(self.messages), 1)
                self.assert_failed("auth_unavailable")

    def test_stopping_during_reauth_grace_does_not_mark_failure(self):
        self.success_count = 2
        def waited(seconds):
            if seconds == service.PROBE_INTERVAL:
                self.machine.state = AuthState.WAIT_RESULT
            else:
                self.stopped.set()
        self.stopped.on_wait = waited
        probe, _ = self.check_health([200])
        self.assertEqual(probe.call_count, 1)
        self.assertEqual(len(self.messages), 1)
        self.assertFalse(self.failed.is_set())
        self.machine.stop.assert_not_called()

    def test_auth_stall_during_retry_prevents_second_probe(self):
        def waited(seconds):
            self.engine.progress = self.clock.now - 120
        self.stopped.on_wait = waited
        probe, notify = self.check_health([service.HealthFailure("dns_failure")])
        self.assertEqual(probe.call_count, 1)
        notify.assert_not_called()
        self.assert_failed("auth_stalled")

    def test_health_cycle_deadline_prevents_late_watchdog_notification(self):
        def checked(*_):
            self.clock.now += service.HEALTH_CYCLE_TIMEOUT + 1
            self.engine.progress = self.clock.now
            return 200
        _, notify = self.check_health(checked)
        notify.assert_not_called()
        self.assert_failed("health_cycle_timeout")


if __name__ == "__main__":
    unittest.main()
