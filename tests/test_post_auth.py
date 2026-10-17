"""Static-spec and fake-clock post-authentication tests; no lease operations."""

import unittest
from unittest.mock import Mock, patch

from minirj.core.state_machine import AuthState, StateMachine
from minirj.network.snapshot import IPv4Snapshot
from minirj.protocol.eapol import EAPOLPacket
from test_legacy_tx import legacy_fields
from test_state_machine import (FakeClock, FakeNetwork, TimedNetwork, request,
                                result, hello_policy, CHALLENGE_1, CHALLENGE_2)

RUIJIE = bytes.fromhex('00d0f8010203')
READY = IPv4Snapshot('192.0.2.20', '255.255.255.0', '192.0.2.1', '192.0.2.53')


def from_ruijie(frame):
    return frame[:6] + RUIJIE + frame[12:]


def phase1():
    return [from_ruijie(frame) for frame in (
        request(1, 1), request(4, 2, b'\x10' + CHALLENGE_1),
        result(3, 2, hello_policy(0x10, 30)))]


def phase2():
    return [from_ruijie(frame) for frame in (
        request(1, 3), request(4, 4, b'\x10' + CHALLENGE_2),
        result(3, 4, hello_policy(0x20, 30)))]


class TestPostAuthentication(unittest.TestCase):
    def make_machine(self, frames, snapshots=None, *, clock=None, **kwargs):
        network = FakeNetwork(frames)
        provider = Mock(read=Mock(return_value=READY))
        if snapshots is not None:
            provider.read.side_effect = snapshots
        machine = StateMachine('test0', 'student', 'secret', net_engine=network,
                               snapshot_provider=provider,
                               monotonic=clock or FakeClock(), hello_rand=lambda: 0,
                               **kwargs)
        network.machine = machine
        network.stop_when_empty = True
        return machine, network, provider

    @patch('minirj.core.network_config.subprocess.Popen')
    def test_external_two_eap_phases_without_dhcp_process(self, popen):
        machine, network, provider = self.make_machine(phase1() + phase2())
        self.assertTrue(machine.authenticate(log_callback=lambda _: None))
        self.assertEqual(machine.dhcp_auth_phase, 2)
        self.assertEqual(machine.post_auth_status, 'complete')
        self.assertEqual(machine.address_status, 'ready')
        self.assertEqual(provider.read.call_count, 2)
        popen.assert_not_called()
        self.assertEqual(sum(frame[15] == 1 for frame in network.sent), 2)
        self.assertEqual(sum(frame[15] == 0xbf for frame in network.sent), 1)
        md5 = [frame for frame in network.sent if frame[15] == 0 and frame[22] == 4]
        first, first_fields = legacy_fields(md5[0])
        second, second_fields = legacy_fields(md5[1])
        # Legacy TX carries IPv4 in encoded21+CRC, not flat 50/63 attributes.
        decode = lambda p: bytes(int(format(x ^ 255, "08b")[::-1], 2) for x in p[:23])
        first, second = decode(first), decode(second)
        self.assertEqual(first_fields[0x18], b"\x00\x00\x00\x01")
        self.assertEqual(second_fields[0x18], b"\x00\x00\x00\x01")
        self.assertEqual(first[5:17], bytes(12))
        self.assertEqual(first[17:21], bytes([192, 0, 2, 53]))
        self.assertEqual(second[5:9], bytes([192,0,2,20]))
        self.assertEqual(second[9:17], bytes([255,255,255,0,192,0,2,1]))

    def test_phase1_stop_is_not_full_session_success_and_does_not_start_hello(self):
        machine, network, _ = self.make_machine(phase1(), snapshots=[READY, IPv4Snapshot()])
        self.assertFalse(machine.authenticate(log_callback=lambda _: None))
        self.assertEqual(machine.post_auth_status, 'address_pending')
        self.assertFalse(any(frame[15] == 0xbf for frame in network.sent))

    @patch('minirj.core.network_config.subprocess.Popen')
    def test_address_timeout_has_no_lease_side_effect(self, popen):
        clock = FakeClock()
        network = TimedNetwork(phase1(), clock, stop_at=10)
        machine = StateMachine('test0', 'student', 'secret', net_engine=network,
                               snapshot_provider=Mock(read=Mock(return_value=IPv4Snapshot())),
                               monotonic=clock, address_timeout=1)
        network.machine = machine
        self.assertFalse(machine.authenticate(log_callback=lambda _: None))
        self.assertEqual(machine.state, AuthState.FAILED)
        self.assertEqual(machine.post_auth_status, 'address_timeout')
        self.assertGreaterEqual(clock.value, 1)
        popen.assert_not_called()

    def test_unknown_nas_does_not_claim_management_postauth_success(self):
        frames = [request(1, 1), request(4, 2, b'\x10' + CHALLENGE_1), result(3, 2)]
        frames = [frame[:6] + bytes.fromhex('66778899aabb') + frame[12:] for frame in frames]
        machine, network, _ = self.make_machine(frames)
        self.assertFalse(machine.authenticate(log_callback=lambda _: None))
        self.assertEqual(machine.post_auth_status, 'unsupported_management')
        self.assertFalse(machine.network_config.started)
        self.assertEqual(machine.state, AuthState.FAILED)

    @patch('minirj.core.network_config.subprocess.Popen')
    def test_dhcp_zero_bypasses_script_and_uses_static_snapshot(self, popen):
        machine, network, provider = self.make_machine(phase1(), dhcp_mode=0,
            network_backend='script', dhcp_script='/never-run')
        self.assertTrue(machine.authenticate(log_callback=lambda _: None))
        self.assertEqual(machine.post_auth_status, 'not_required')
        self.assertEqual(machine.tlv_encoder.fake_ip, READY.ip)
        self.assertEqual(machine.tlv_encoder.fake_gw, READY.gateway)
        self.assertEqual(machine.tlv_encoder.dhcp_auth_phase, 0)
        self.assertEqual(provider.read.call_count, 1)
        popen.assert_not_called()

    @patch('minirj.core.network_config.subprocess.Popen', side_effect=OSError)
    def test_script_failure_does_not_accept_stale_ready_address(self, popen):
        machine, network, provider = self.make_machine(phase1(),
            network_backend='script', dhcp_script='/test-failure')
        self.assertFalse(machine.authenticate(log_callback=lambda _: None))
        self.assertEqual(machine.post_auth_status, 'network_script_failed')
        self.assertEqual(provider.read.call_count, 1)
        self.assertEqual(sum(frame[15] == 1 for frame in network.sent), 1)

    def test_phase2_requires_correlated_success(self):
        frames = phase1() + [from_ruijie(frame) for frame in (
            request(1, 3), request(4, 4, b'\x10' + CHALLENGE_2), result(3, 2))]
        machine, network, _ = self.make_machine(frames)
        self.assertFalse(machine.authenticate(log_callback=lambda _: None))
        self.assertEqual(machine.post_auth_status, 'eap_phase2_pending')
        self.assertFalse(any(frame[15] == 0xbf for frame in network.sent))

    def test_phase2_retry_on_new_nas_restarts_its_own_phase1(self):
        clock = FakeClock()
        nas_b = bytes.fromhex('001aa9010203')
        b_frames = [frame[:6] + nas_b + frame[12:] for frame in phase1() + phase2()]

        class RetryNetwork(FakeNetwork):
            switched = False

            def recv_frame(self, timeout=0):
                if self.frames:
                    return super().recv_frame(timeout)
                if not self.switched and sum(frame[15] == 1 for frame in self.sent) >= 3:
                    self.switched = True
                    self.frames = list(b_frames)
                    return super().recv_frame(timeout)
                if self.switched:
                    self.machine.stop()
                else:
                    clock.value += timeout
                return None

        network = RetryNetwork(phase1())
        provider = Mock(read=Mock(return_value=READY))
        machine = StateMachine('test0', 'student', 'secret', net_engine=network,
                               snapshot_provider=provider, monotonic=clock,
                               request_timeout=0.5, retransmit_interval=1, max_retries=2)
        network.machine = machine
        self.assertTrue(machine.authenticate(log_callback=lambda _: None))
        self.assertEqual(machine.server_mac, nas_b)
        self.assertEqual(provider.read.call_count, 4)
        md5 = []
        for raw in network.sent:
            parsed = EAPOLPacket.parse_frame(raw)
            eap = parsed.get('eap') if parsed else None
            if eap and eap['type'] == 4:
                tail, _ = legacy_fields(raw)
                decoded = bytes(int(format(x ^ 255, "08b")[::-1], 2) for x in tail[:23])
                md5.append(decoded[5:9])
        self.assertEqual(md5, [bytes(4), bytes(4), bytes([192,0,2,20])])
        self.assertEqual(machine.post_auth_status, 'complete')

    def test_non_ruijie_static_success_does_not_start_ruijie_hello(self):
        frames = [frame[:6] + bytes.fromhex('66778899aabb') + frame[12:] for frame in phase1()]
        machine, network, _ = self.make_machine(frames, dhcp_mode=0)
        self.assertTrue(machine.authenticate(log_callback=lambda _: None))
        self.assertFalse(any(frame[15] == 0xbf for frame in network.sent))

    def test_nas_oui_classification_matches_static_branches(self):
        for oui in ('00d0f8', '001aa9', '14144b', '58696c'):
            machine, _, _ = self.make_machine([])
            self.assertTrue(machine._accept_server(bytes.fromhex(oui + '010203')))
            self.assertEqual(machine.dhcp_auth_phase, 1)
        machine, _, _ = self.make_machine([])
        machine._accept_server(bytes.fromhex('00d0f9010203'))
        self.assertEqual(machine.dhcp_auth_phase, 0)
