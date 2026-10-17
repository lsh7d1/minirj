"""Offline snapshot tests: all socket, ioctl and filesystem reads are fixtures."""

from dataclasses import FrozenInstanceError
from ipaddress import IPv4Address
import socket
import struct
import sys
import unittest
from unittest.mock import MagicMock, Mock, patch

from minirj.network.snapshot import (
    IPv4Snapshot, LinuxIPv4SnapshotProvider, RESOLV_PATH, ROUTE_PATH,
    SIOCGIFADDR, SIOCGIFNETMASK, IF_INET6_PATH, IPV6_ROUTE_PATH,
)


def response(address):
    return b"\0" * 16 + struct.pack("H", socket.AF_INET) + b"\0\0" + IPv4Address(address).packed + b"\0" * 232


def route(ifname="test0", gateway="192.0.2.1", metric=10,
          flags="0003", destination="00000000", mask="00000000"):
    gw = int.from_bytes(IPv4Address(gateway).packed, sys.byteorder)
    return f"{ifname} {destination} {gw:08X} {flags} 0 0 {metric} {mask} 0 0 0\n"


class TestIPv4Snapshot(unittest.TestCase):
    def test_defaults_and_immutability(self):
        snapshot = IPv4Snapshot()
        self.assertFalse(snapshot.ready)
        for field in ("ip", "netmask", "gateway", "dns", "secondary_dns"):
            self.assertEqual(getattr(snapshot, field), "0.0.0.0")
        with self.assertRaises(FrozenInstanceError):
            snapshot.ip = "192.0.2.2"
        warnings = ["fixture"]
        frozen = IPv4Snapshot(warnings=warnings)
        warnings.append("changed")
        self.assertEqual(frozen.warnings, ("fixture",))

    def test_ready_checks_only_ip_and_gateway(self):
        self.assertTrue(IPv4Snapshot(ip="192.0.2.2", gateway="192.0.2.1").ready)
        for invalid in ("", "bad", "::1", "0.0.0.0", "169.254.0.1", "169.254.255.254"):
            for field in ("ip", "gateway"):
                values = dict(ip="192.0.2.2", gateway="192.0.2.1")
                values[field] = invalid
                with self.subTest(field=field, invalid=invalid):
                    self.assertFalse(IPv4Snapshot(**values).ready)


class TestLinuxIPv4SnapshotProvider(unittest.TestCase):
    def setUp(self):
        # Fail closed if implementation accidentally bypasses fixture injection.
        for target in ("socket.socket", "fcntl.ioctl", "pathlib.Path.read_text",
                       "builtins.open", "subprocess.Popen", "os.system"):
            guard = patch(target, side_effect=AssertionError("unexpected host I/O"))
            guard.start()
            self.addCleanup(guard.stop)
        self.files = {ROUTE_PATH: route(), RESOLV_PATH: "nameserver 192.0.2.53\nnameserver 198.51.100.53\n"}
        self.reader = Mock(side_effect=lambda path: self.files[path])
        self.sock = MagicMock()
        self.sock.__enter__.return_value = self.sock
        self.sock.fileno.return_value = 42
        self.factory = Mock(return_value=self.sock)
        self.ioctl = Mock(side_effect=lambda fd, op, request: response(
            "192.0.2.2" if op == SIOCGIFADDR else "255.255.255.0"))
        self.provider = LinuxIPv4SnapshotProvider(
            read_text=self.reader, socket_factory=self.factory, ioctl=self.ioctl)

    def test_default_dependencies_obey_host_io_guard(self):
        with self.assertRaisesRegex(AssertionError, "unexpected host I/O"):
            LinuxIPv4SnapshotProvider().read('test0')
        with self.assertRaisesRegex(AssertionError, "unexpected host I/O"):
            LinuxIPv4SnapshotProvider(read_text=self.reader, socket_factory=self.factory).read('test0')

    def test_primary_address_and_read_only_operations(self):
        self.factory.assert_not_called()
        self.reader.assert_not_called()
        snapshot = self.provider.read("test0")
        self.assertEqual((snapshot.ip, snapshot.netmask, snapshot.gateway,
                          snapshot.dns, snapshot.secondary_dns),
                         ("192.0.2.2", "255.255.255.0", "192.0.2.1", "192.0.2.53", "198.51.100.53"))
        self.assertTrue(snapshot.ready)
        self.factory.assert_called_once_with(socket.AF_INET, socket.SOCK_DGRAM)
        self.assertEqual([call.args[1] for call in self.ioctl.call_args_list],
                         [SIOCGIFADDR, SIOCGIFNETMASK])
        for call in self.ioctl.call_args_list:
            self.assertEqual(call.args[0], 42)
            self.assertEqual(call.args[2][:16], b"test0" + b"\0" * 11)
        self.sock.__exit__.assert_called_once()
        self.sock.send.assert_not_called()
        self.sock.sendto.assert_not_called()
        self.sock.connect.assert_not_called()
        self.assertEqual([call.args[0] for call in self.reader.call_args_list],
                         [ROUTE_PATH, RESOLV_PATH, IF_INET6_PATH, IPV6_ROUTE_PATH])
        self.assertIn("global", " ".join(snapshot.warnings))

    def test_route_selection_and_tie_order(self):
        self.files[ROUTE_PATH] = (
            "Iface Destination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT\n"
            + route("other0", metric=0)
            + route(gateway="192.0.2.20", metric=20)
            + route(gateway="192.0.2.10", metric=10)
            + route(gateway="192.0.2.11", metric=10)
            + route(metric=0, flags="0002")
            + route(metric=0, flags="0203")
            + route(metric=0, flags="0001")
            + route(metric=0, destination="00000001")
            + route(metric=0, mask="00FFFFFF")
            + "test0 malformed\n")
        snapshot = self.provider.read("test0")
        self.assertEqual(snapshot.gateway, "192.0.2.10")
        self.assertIn("malformed route", " ".join(snapshot.warnings))

    def test_missing_interface_does_not_borrow_address_or_route(self):
        self.ioctl.side_effect = OSError("fixture no such interface")
        self.files[ROUTE_PATH] = route("other0")
        snapshot = self.provider.read("test0")
        self.assertEqual((snapshot.ip, snapshot.netmask, snapshot.gateway), ("0.0.0.0",) * 3)
        self.assertFalse(snapshot.ready)
        self.assertEqual(snapshot.dns, "192.0.2.53")
        self.assertIn("interface association", " ".join(snapshot.warnings))
        self.sock.__exit__.assert_called_once()

    def test_ioctl_fields_fail_independently(self):
        for bad in (OSError("fixture"), b"short", b"\0" * 256):
            with self.subTest(bad=bad):
                self.ioctl.side_effect = [bad, response("255.255.255.0")]
                snapshot = self.provider.read("test0")
                self.assertEqual(snapshot.ip, "0.0.0.0")
                self.assertEqual(snapshot.netmask, "255.255.255.0")
                self.assertIn("ip unavailable", " ".join(snapshot.warnings))

    def test_unavailable_sources_return_zero_and_warnings(self):
        self.factory.side_effect = OSError("fixture")
        self.reader.side_effect = PermissionError("fixture")
        snapshot = self.provider.read("test0")
        self.assertFalse(snapshot.ready)
        self.assertEqual(snapshot.gateway, "0.0.0.0")
        self.assertEqual(snapshot.dns, "0.0.0.0")
        self.assertEqual(snapshot.secondary_dns, "0.0.0.0")
        self.assertIn(ROUTE_PATH, " ".join(snapshot.warnings))
        self.assertIn(RESOLV_PATH, " ".join(snapshot.warnings))
        self.ioctl.assert_not_called()

    def test_dns_comments_ipv6_duplicates_and_stub_provenance(self):
        self.files[RESOLV_PATH] = (
            "# nameserver 203.0.113.1\nsearch example.invalid\n"
            "nameserver ::1\nnameserver garbage\nnameserver\n"
            "nameserver 127.0.0.53 # stub\nnameserver 127.0.0.53\n"
            "nameserver 192.0.2.53 ; resolver\nnameserver 198.51.100.53\n")
        snapshot = self.provider.read("test0")
        self.assertEqual((snapshot.dns, snapshot.secondary_dns), ("127.0.0.53", "192.0.2.53"))
        self.assertIn("not a verified upstream", " ".join(snapshot.warnings))
        self.assertIn(RESOLV_PATH, " ".join(snapshot.warnings))

    def test_stub_only_does_not_invent_upstream(self):
        self.files[RESOLV_PATH] = "nameserver 127.0.0.53\n"
        snapshot = self.provider.read("test0")
        self.assertEqual(snapshot.dns, "127.0.0.53")
        self.assertEqual(snapshot.secondary_dns, "0.0.0.0")
        self.assertIn("stub", " ".join(snapshot.warnings))

    def test_fresh_reads_leave_previous_snapshot_unchanged(self):
        before = self.provider.read("test0")
        self.files[ROUTE_PATH] = route(gateway="192.0.2.254")
        after = self.provider.read("test0")
        self.assertEqual(before.gateway, "192.0.2.1")
        self.assertEqual(after.gateway, "192.0.2.254")

    def test_invalid_names_rejected_before_io(self):
        for name in ("", "x" * 16, "a\0b", "界" * 6, None):
            with self.subTest(name=name), self.assertRaises(ValueError):
                self.provider.read(name)
        self.factory.assert_not_called()
        self.reader.assert_not_called()

    def test_ipv6_parsing_from_proc_net(self):
        self.files[IF_INET6_PATH] = (
            "fe80000000000000d85ed34fe0350000 03 40 20 80 test0\n"
            "20010da8900602120000000000000053 03 40 00 00 test0\n"
            "fe800000000000000000000000000001 02 40 20 80 other0\n"
        )
        self.files[IPV6_ROUTE_PATH] = (
            "20010da8900602120000000000000000 40 00000000000000000000000000000000 00 00000000000000000000000000000000 00000100 00000001 00000000 00000001 test0\n"
            "00000000000000000000000000000000 00 00000000000000000000000000000000 00 20010da8900602120000000000000001 00000200 00000001 00000000 00000001 test0\n"
        )
        snapshot = self.provider.read("test0")
        self.assertEqual(snapshot.ipv6_address, "2001:da8:9006:212::53")
        self.assertEqual(snapshot.ipv6_link_local, "fe80::d85e:d34f:e035:0")
        self.assertEqual(snapshot.ipv6_gateway, "2001:da8:9006:212::1")
        self.assertEqual(snapshot.ipv6_prefix_len, 64)


class TestSnapshotObservationStatus(unittest.TestCase):
    setUp = TestLinuxIPv4SnapshotProvider.setUp

    def event_with_warnings(self, warnings):
        from dataclasses import replace
        from minirj.network.events import LinuxNetworkEventSource
        # Exercise real provider -> immutable snapshot -> production watcher.
        provider = Mock(read=lambda name: replace(self.provider.read(name), warnings=warnings))
        source = LinuxNetworkEventSource("test0", read_link=Mock(return_value=(2, True)),
                                        snapshot_provider=provider)
        return source.poll(0)[0]

    def test_provider_failures_stay_closed_when_diagnostics_change(self):
        import errno
        for failure in ("ip", "mask", "malformed_ioctl", "socket", "route_read", "route_format"):
            for warnings in ((), ("诊断文案已翻译",), ("all looks fine",)):
                with self.subTest(failure=failure, warnings=warnings):
                    self.factory.side_effect = PermissionError("fixture") if failure == "socket" else None
                    def ioctl(fd, operation, request):
                        if (failure == "ip" and operation == SIOCGIFADDR or
                                failure == "mask" and operation == SIOCGIFNETMASK):
                            raise OSError(errno.EPERM, "fixture")
                        if failure == "malformed_ioctl":
                            return b"short"
                        return response("192.0.2.2" if operation == SIOCGIFADDR else "255.255.255.0")
                    self.ioctl.side_effect = ioctl
                    def reader(path):
                        if path == ROUTE_PATH:
                            if failure == "route_read":
                                raise PermissionError("fixture")
                            return "test0 malformed\n" if failure == "route_format" else route()
                        return "nameserver 192.0.2.53\n"
                    self.reader.side_effect = reader
                    event = self.event_with_warnings(warnings)
                    self.assertEqual(event.status, "unknown")
                    self.assertFalse(event.link_up)
                    self.assertIsNone(event.snapshot)

    def test_warning_words_alone_do_not_invalidate_known_observation(self):
        event = self.event_with_warnings(("/proc/net/route: unavailable",
                                          "test0: IPv4 ioctl socket unavailable"))
        self.assertTrue(event.link_up)

    def test_eaddrnotavail_and_no_gateway_are_known_empty(self):
        import errno
        self.ioctl.side_effect = OSError(errno.EADDRNOTAVAIL, "fixture")
        self.files[ROUTE_PATH] = route("other0")
        snapshot = self.provider.read("test0")
        self.assertEqual(snapshot.observation_errors, ())
        self.assertFalse(snapshot.ready)
        self.assertTrue(self.event_with_warnings(()).link_up)

    def test_dns_read_failure_does_not_poison_interface_observation(self):
        def reader(path):
            if path == RESOLV_PATH:
                raise PermissionError("fixture")
            return route()
        self.reader.side_effect = reader
        snapshot = self.provider.read("test0")
        self.assertEqual(snapshot.observation_errors, ())
        self.assertTrue(snapshot.ready)
        self.assertTrue(self.event_with_warnings(()).link_up)

    def test_status_is_immutable_and_old_construction_remains_valid(self):
        errors = ["route_unavailable"]
        snapshot = IPv4Snapshot(ip="192.0.2.2", gateway="192.0.2.1", observation_errors=errors)
        errors.clear()
        self.assertEqual(snapshot.observation_errors, ("route_unavailable",))
        self.assertFalse(snapshot.ready)
        self.assertEqual(IPv4Snapshot().observation_errors, ())
        self.assertTrue(IPv4Snapshot(ip="192.0.2.2", gateway="192.0.2.1").ready)


if __name__ == "__main__":
    unittest.main()
