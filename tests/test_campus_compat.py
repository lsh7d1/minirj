"""Campus wire contract, implemented independently; no MiniEAP code or live I/O.

Parameters: successful MiniEAP deployment (service 校外, version 6.84.0.0,
Ruijie multicast, DHCP double authentication). Wire facts: legacy VSA 0x63
is 1 before address acquisition and 2 throughout the lease-bearing exchange.
These synthetic conversations are regressions, NOT campus acceptance evidence.
"""
import binascii
import ipaddress
from io import StringIO
from contextlib import redirect_stdout
import unittest
from unittest.mock import Mock, patch

from minirj.core.state_machine import AuthState, StateMachine
from minirj.main import build_parser, main, resolve_runtime_config
from minirj.network.events import NetworkEvent
from minirj.network.snapshot import IPv4Snapshot
from minirj.protocol.tlv import ClientTLVEncoder
from test_client_tlv import DummyV3
from test_legacy_tx import legacy_fields
from test_state_machine import (CLIENT, SERVER, FakeClock, FakeNetwork, TimedNetwork,
                                CHALLENGE_1, CHALLENGE_2, request, result, hello_policy)

RUIJIE_START = bytes.fromhex("01d0f8000003")
READY = IPv4Snapshot("192.0.2.20", "255.255.255.0", "192.0.2.1", "192.0.2.53",
                     alternate_dns=("203.0.113.53",))
PENDING = IPv4Snapshot(dns="192.0.2.53", alternate_dns=READY.alternate_dns)


def exchange(identity=1, md5=2, server=SERVER, *, success=True):
    frames = [request(1, identity), request(4, md5, b"\x10" + CHALLENGE_1)]
    if success:
        frames.append(result(3, md5, hello_policy(0x10, 30)))
    return [raw[:6] + server + raw[12:] for raw in frames]


def plain_prefix(tail):
    plain = bytes(int(f"{value ^ 255:08b}"[::-1], 2) for value in tail[:23])
    assert int.from_bytes(plain[21:23], "big") == binascii.crc_hqx(plain[:21], 0)
    return plain


class CampusWireTests(unittest.TestCase):
    def machine(self, net, clock, **kwargs):
        machine = StateMachine(
            "test0", "synthetic-user", "synthetic-password", net_engine=net,
            monotonic=clock, service_name="校外", client_version=(6, 84, 0, 0),
            protocol_profile="ruijie", start_destination=RUIJIE_START,
            snapshot_provider=kwargs.pop("snapshot_provider", Mock(read=Mock(return_value=READY))),
            hello_rand=lambda: 0, **kwargs)
        net.machine = machine
        return machine

    def assert_wire(self, raw, phase, *, ready=False):
        tail, fields = legacy_fields(raw)
        self.assertEqual(fields[0x63], bytes((phase,)))
        self.assertEqual(tail[59:63], bytes((6, 84, 0, 0)))
        self.assertEqual(tail[63], 0, "header byte 63 is Logoff reason, not DHCP phase")
        self.assertEqual(fields[0x39], "校外".encode("gb18030").ljust(32, b"\0"))
        self.assertEqual(fields[0x6f], b"RG_SU_For_Windows 6.84\0")
        self.assertEqual(fields[0x18], b"\0\0\0\1")
        self.assertEqual(fields[0x2d], CLIENT)
        self.assertEqual(fields[0x76], b"203.0.113.53" if ready else b"")
        prefix = plain_prefix(tail)
        self.assertEqual(prefix[:5], b"\0\0\x13\x11\1")
        addresses = b"".join(ipaddress.IPv4Address(value).packed for value in
                             (READY.ip, READY.netmask, READY.gateway))
        self.assertEqual(prefix[5:17], addresses if ready else bytes(12))
        self.assertEqual(prefix[17:21], ipaddress.IPv4Address(READY.dns).packed)
        self.assertEqual(int.from_bytes(tail[68:70], "big"), len(tail) - 70)
        cursor, records = 70, []
        while cursor < len(tail):
            size = tail[cursor + 1]
            records.append(tail[cursor:cursor + size])
            cursor += size
        phases = [record for record in records if record[6] == 0x63]
        self.assertEqual(phases, [b"\x1a\x09\0\0\x13\x11\x63\x03" + bytes((phase,))])
        kinds = [record[6] for record in records]
        self.assertEqual(kinds.index(0x63), kinds.index(0x2d) + 1)

    def test_phase_attribute_is_in_legacy_vsa_not_eap_body(self):
        for phase in (1, 2):
            encoder = ClientTLVEncoder("u", "p", dhcp_auth_phase=phase,
                                       v3_generator=DummyV3())
            tail = encoder.encode_legacy()
            # Decode independently of the encoder; each phase adds one 9-byte VSA.
            from minirj.protocol.eapol import EAPOLPacket
            raw = EAPOLPacket.build_eap_start(CLIENT, RUIJIE_START, vendor_data=tail)
            self.assertEqual(raw[16:18], b"\0\0")
            self.assertEqual(legacy_fields(raw)[1][0x63], bytes((phase,)))
            self.assertEqual(tail[63], 0)

    def test_static_and_unselected_phase_do_not_emit_double_auth_property(self):
        from minirj.protocol.eapol import EAPOLPacket
        for dhcp, phase in ((0, 0), (0, 2), (1, 0)):
            encoder = ClientTLVEncoder("u", "p", dhcp_mode=dhcp, dhcp_auth_phase=phase,
                                       v3_generator=DummyV3())
            raw = EAPOLPacket.build_eap_start(CLIENT, vendor_data=encoder.encode_legacy())
            self.assertNotIn(0x63, legacy_fields(raw)[1])

    def test_invalid_legacy_phase_is_not_truncated_to_a_byte(self):
        for phase in (-1, 3, 257, True, "1"):
            with self.subTest(phase=phase), self.assertRaises(ValueError):
                ClientTLVEncoder("u", "p", dhcp_auth_phase=phase,
                                 v3_generator=DummyV3()).encode_legacy()

    @patch("minirj.core.network_config.subprocess.Popen")
    def test_delayed_address_then_full_second_exchange_before_online_or_hello(self, popen):
        clock = FakeClock()

        class Network(TimedNetwork):
            def send_frame(self, frame):
                if frame[15] == 1:
                    if not self.sent:
                        self.frames.extend(exchange())
                    else:
                        # Time spent awaiting an address may exceed the EAP timeout.
                        self.frames.extend(exchange(3, 4))
                        self.phase2_time = clock()
                return super().send_frame(frame)

            def recv_frame(self, timeout=0):
                if self.machine.state == AuthState.ONLINE:
                    self.machine.stop()
                    return None
                if self.machine.state == AuthState.WAIT_ADDRESS:
                    assert not any(raw[15] == 0xbf for raw in self.sent)
                return super().recv_frame(timeout)

        net = Network([], clock, stop_at=12)
        provider = Mock(read=lambda _: READY if clock() >= 5 else PENDING)
        m = self.machine(net, clock, snapshot_provider=provider, request_timeout=1)
        self.assertTrue(m.authenticate(lambda _: None))
        self.assertGreaterEqual(net.phase2_time, 5)
        self.assertEqual([raw[15] for raw in net.sent], [1, 0, 0, 1, 0, 0, 0xbf])
        for index, raw in enumerate(net.sent[:6]):
            with self.subTest(index=index):
                self.assert_wire(raw, 1 if index < 3 else 2, ready=index >= 3)
        self.assertEqual(m.post_auth_status, "complete")
        popen.assert_not_called()

    def test_address_wait_never_sends_phase2_while_script_running_or_failed(self):
        for failed in (False, True):
            with self.subTest(failed=failed):
                net, clock = FakeNetwork([]), FakeClock()
                m = self.machine(net, clock)
                m.state = AuthState.WAIT_ID_REQ
                for raw in exchange():
                    m._handle_packet(raw, CLIENT, lambda _: None)
                self.assertEqual(m.state, AuthState.WAIT_ADDRESS)
                m.network_config.process = Mock()
                count = len(net.sent)
                self.assertIsNone(m._poll_address(clock()))
                self.assertEqual(len(net.sent), count)
                m.network_config.process = None
                m.network_config.failed = failed
                clock.value = 2
                if failed:
                    self.assertEqual(m._poll_address(clock()), "failure")
                    self.assertEqual(len(net.sent), count)
                    self.assertEqual(m.post_auth_status, "network_script_failed")
                else:
                    self.assertEqual(m._poll_address(clock()), "restart")
                    self.assertEqual(legacy_fields(net.sent[-1])[1][0x63], b"\x02")

    def test_address_ready_at_deadline_cannot_skip_timeout(self):
        net, clock = FakeNetwork([]), FakeClock()
        m = self.machine(net, clock, address_timeout=1)
        m.state = AuthState.WAIT_ID_REQ
        for raw in exchange():
            m._handle_packet(raw, CLIENT, lambda _: None)
        count = len(net.sent)
        clock.value = 1
        self.assertEqual(m._poll_address(clock()), "failure")
        self.assertEqual(m.post_auth_status, "address_timeout")
        self.assertEqual(len(net.sent), count)
        self.assertFalse(any(raw[15] == 0xbf for raw in net.sent))

    def test_phase2_timeout_restarts_phase1_even_on_same_nas(self):
        for new_server in (SERVER, bytes.fromhex("020000000099")):
            with self.subTest(new_server=new_server.hex()):
                clock = FakeClock()

                class Network(TimedNetwork):
                    starts = 0

                    def send_frame(self, frame):
                        if frame[15] == 1:
                            self.starts += 1
                            if self.starts == 1:
                                self.frames.extend(exchange())
                            elif self.starts == 2:
                                self.frames.extend(exchange(3, 4, success=False))
                            elif self.starts == 3:
                                # A late previous phase2 result must not restore ONLINE.
                                self.frames.append(result(3, 4, hello_policy(0x10, 30)))
                                self.frames.extend(exchange(server=new_server))
                            elif self.starts == 4:
                                self.frames.extend(exchange(5, 6, new_server))
                        return super().send_frame(frame)

                    def recv_frame(self, timeout=0):
                        if self.machine.state == AuthState.ONLINE:
                            self.machine.stop()
                            return None
                        return super().recv_frame(timeout)

                net = Network([], clock, stop_at=5)
                m = self.machine(net, clock, request_timeout=.3,
                                 retransmit_interval=1, max_retries=2)
                self.assertTrue(m.authenticate(lambda _: None))
                self.assertEqual(net.starts, 4)
                starts = [raw for raw in net.sent if raw[15] == 1]
                for index, raw in enumerate(starts):
                    self.assert_wire(raw, 1 if index % 2 == 0 else 2, ready=index % 2 == 1)
                self.assertEqual(sum(raw[15] == 0xbf for raw in net.sent), 1)
                self.assertEqual(m.server_mac, new_server)

    def test_link_recovery_starts_phase1_not_old_phase2(self):
        net, clock = FakeNetwork([]), FakeClock()
        m = self.machine(net, clock)
        m.tlv_encoder.mac_address = CLIENT
        m._read_network_snapshot()
        m.state, m.server_mac = AuthState.ONLINE, SERVER
        m.dhcp_auth_phase = m.tlv_encoder.dhcp_auth_phase = 2
        m.inject_network_event(NetworkEvent("test0", False), 0)
        m.inject_network_event(NetworkEvent("test0", True, READY), 1)
        self.assertEqual(m._poll_network_events(m._recovery_due), "restart")
        self.assert_wire(net.sent[-1], 1)

    def test_retransmitted_phase1_and_phase2_responses_remain_identical(self):
        net, clock = FakeNetwork([]), FakeClock()
        m = self.machine(net, clock)
        m.tlv_encoder.mac_address = CLIENT
        m._read_network_snapshot(before_dhcp=True)
        m.state = AuthState.WAIT_ID_REQ
        for identity, md5, phase in ((1, 2, 1), (3, 4, 2)):
            for frame in (request(1, identity), request(4, md5, b"\x10" + CHALLENGE_2)):
                self.assertEqual(m._handle_packet(frame, CLIENT, lambda _: None), "request")
                self.assertEqual(m._handle_packet(frame, CLIENT, lambda _: None), "request")
                self.assertEqual(net.sent[-1], net.sent[-2])
                self.assert_wire(net.sent[-1], phase, ready=phase == 2)
            m._handle_packet(result(3, md5), CLIENT, lambda _: None)
            if phase == 1:
                self.assertEqual(m.state, AuthState.WAIT_ADDRESS)
                self.assertEqual(m._poll_address(clock()), "restart")
        self.assertEqual(m.state, AuthState.ONLINE)


class CampusPresetTests(unittest.TestCase):
    def resolve(self, extra=()):
        return resolve_runtime_config(build_parser().parse_args(["--campus-profile", *extra]), StringIO())

    def test_named_profile_selects_parameters_not_credentials_or_network_owner(self):
        config = self.resolve()
        self.assertEqual(config.service, "校外")
        self.assertEqual(config.binary_version, (6, 84, 0, 0))
        self.assertEqual(config.client_version, "RG_SU_For_Windows 6.84")
        self.assertEqual(config.protocol_profile, "ruijie")
        self.assertEqual(config.start_destination, RUIJIE_START)
        self.assertEqual(config.dhcp, 1)
        self.assertEqual(config.network_backend, "external")
        self.assertEqual((config.interface, config.username, config.password), ("", "", ""))

    def test_explicit_options_can_override_site_defaults(self):
        config = self.resolve(["--service", "test-service", "--binary-version", "1.2.3.4",
                               "--client-release", "test release", "--dhcp", "0"])
        self.assertEqual(config.service, "test-service")
        self.assertEqual(config.binary_version, (1, 2, 3, 4))
        self.assertEqual(config.client_version, "test release")
        self.assertEqual(config.dhcp, 0)

    @patch("minirj.main.detect_competitors", return_value=([], False))
    @patch("minirj.main.SessionGuard")
    @patch("minirj.main.signal.signal")
    @patch("minirj.main.StateMachine")
    def test_cli_profile_reaches_runner_without_live_io(self, machine, *_):
        with redirect_stdout(StringIO()):
            main(["--campus-profile", "-i", "test0", "-u", "synthetic-user",
                  "--password-stdin", "--no-network-monitor"], StringIO("synthetic-pass\n"))
        values = machine.call_args.kwargs
        self.assertEqual(values["service_name"], "校外")
        self.assertEqual(values["client_version"], (6, 84, 0, 0))
        self.assertEqual(values["protocol_profile"], "ruijie")
        self.assertEqual(values["start_destination"], RUIJIE_START)
        self.assertEqual(values["network_backend"], "external")
        self.assertEqual(values["dhcp_mode"], 1)
        self.assertIsNone(values["event_source"])

    def test_generic_defaults_are_not_changed_to_site_specific_values(self):
        config = resolve_runtime_config(build_parser().parse_args([]))
        self.assertEqual(config.service, "internet")
        self.assertEqual(config.binary_version, (6, 84, 0, 0))
        self.assertEqual(config.protocol_profile, "auto")
        self.assertEqual(config.start_destination, bytes.fromhex("0180c2000003"))

    def test_external_dns_cli_option_and_validation(self):
        config1 = resolve_runtime_config(build_parser().parse_args(["--external-dns", "114.114.114.114,8.8.8.8"]))
        self.assertEqual(config1.external_dns, ("114.114.114.114", "8.8.8.8"))

        config2 = resolve_runtime_config(build_parser().parse_args(["--dns", "223.5.5.5"]))
        self.assertEqual(config2.external_dns, ("223.5.5.5",))

        with self.assertRaises(ValueError):
            resolve_runtime_config(build_parser().parse_args(["--external-dns", "999.999.999.999"]))

    def test_network_config_reset_lifecycle(self):
        from minirj.core.network_config import NetworkConfig
        cfg = NetworkConfig(backend="script", script="/bin/true")
        mock_proc = Mock(pid=12345)
        mock_proc.wait = Mock(return_value=0)
        cfg.process = mock_proc
        cfg.started = True
        cfg.failed = True
        with patch("os.killpg"), patch.object(cfg, "_exited", return_value=True):
            cfg.reset()
        self.assertFalse(cfg.started)
        self.assertFalse(cfg.failed)
        self.assertIsNone(cfg.process)

    def test_phase2_real_ip_and_windows_684_vsa_fields(self):
        from minirj.protocol.eapol import EAPOLPacket
        # Phase 1 encodes 0.0.0.0
        enc1 = ClientTLVEncoder("u", "p", dhcp_mode=1, dhcp_auth_phase=1, fake_ip="192.0.2.10")
        self.assertEqual(enc1._ipv4_payload()[:4], bytes(4))

        # Phase 2 encodes real IP 192.0.2.10
        enc2 = ClientTLVEncoder("u", "p", dhcp_mode=1, dhcp_auth_phase=2, fake_ip="192.0.2.10")
        self.assertEqual(enc2._ipv4_payload()[:4], bytes((192, 0, 2, 10)))

        # VSA attributes for Windows 6.84
        tail = enc2.encode_legacy(CHALLENGE_1)
        raw = EAPOLPacket.build_eap_start(CLIENT, vendor_data=tail)
        tail, fields = legacy_fields(raw)
        self.assertEqual(fields[0x54][:15], b"Static:AB45A862")
        self.assertEqual(len(fields[0x54]), 64)
        self.assertEqual(fields[0x62], b"\x01")
        self.assertEqual(fields[0x6b], b"\x00")
        self.assertEqual(fields[0x7e], bytes((0, 0, 1, 0, 0, 4, 0, 0)))
        self.assertEqual(fields[0x70], b"\x40")
        self.assertEqual(fields[0x6f], b"RG_SU_For_Windows 6.84\x00")

