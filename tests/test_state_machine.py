import struct
import unittest
from unittest.mock import Mock

from minirj.core.state_machine import AuthState, StateMachine
from minirj.protocol.eapol import EAPOLPacket
from minirj.protocol.hello import HelloCodec
from test_success_wire import private_wire
from minirj.network.snapshot import IPv4Snapshot


CLIENT = bytes.fromhex("001122334455")
SERVER = bytes.fromhex("00d0f899aabb")
CHALLENGE_1 = bytes(range(16))
CHALLENGE_2 = bytes(range(16, 32))


def request(eap_type, identifier, type_data=b""):
    body = struct.pack("!BBHB", 1, identifier, 5 + len(type_data), eap_type) + type_data
    return EAPOLPacket.build_ethernet_frame(SERVER, CLIENT, 0, body)


def result(code, identifier, private_data=b""):
    body = struct.pack("!BBH", code, identifier, 4) + private_data
    return EAPOLPacket.build_ethernet_frame(SERVER, CLIENT, 0, body)


def hello_policy(offset, seconds):
    """Synthetic static-spec wire, not an observed target output."""
    plain = bytes.fromhex("000013110a01") + struct.pack("!II", offset, seconds) + b"\x00"
    encoded = bytes(int(f"{value ^ 0xff:08b}"[::-1], 2) for value in plain)
    return private_wire(hello=encoded)


class FakeClock:
    def __init__(self):
        self.value = 0.0

    def __call__(self):
        return self.value


class FakeNetwork:
    def __init__(self, frames):
        self.frames = list(frames)
        self.mac_addr = CLIENT
        self.sent = []
        self.opened = False
        self.machine = None
        self.stop_when_empty = False

    def open(self):
        self.opened = True

    def close(self):
        self.opened = False

    def send_frame(self, frame):
        self.sent.append(frame)
        return len(frame)

    def recv_frame(self, timeout=0):
        if self.frames:
            return self.frames.pop(0)
        if self.stop_when_empty and self.machine is not None:
            self.machine.stop()
        return None


class TimedNetwork(FakeNetwork):
    def __init__(self, frames, clock, stop_at):
        super().__init__(frames)
        self.clock = clock
        self.stop_at = stop_at
        self.state_before_stop = None

    def recv_frame(self, timeout=0):
        if self.frames:
            return self.frames.pop(0)
        self.clock.value += timeout
        if self.clock.value >= self.stop_at and self.machine is not None:
            self.state_before_stop = self.machine.state
            self.machine.stop()
        return None


class TestStateMachine(unittest.TestCase):
    def make_machine(self, frames):
        network = FakeNetwork(frames)
        machine = StateMachine(
            "test0",
            "student",
            "secret",
            net_engine=network,
            dhcp_mode=0,
            snapshot_provider=Mock(read=Mock(return_value=IPv4Snapshot())),
            request_timeout=0.01,
            retransmit_interval=0.001,
            hello_rand=lambda: 0,
        )
        network.machine = machine
        machine.run_dhcp = Mock()
        return machine, network

    def test_success_keeps_receiving_and_online_failure_is_observed(self):
        frames = [
            request(1, 1),
            request(4, 2, b"\x10" + CHALLENGE_1),
            result(3, 2),
            result(4, 2),
        ]
        machine, network = self.make_machine(frames)

        self.assertFalse(machine.authenticate(log_callback=lambda _message: None))
        self.assertEqual(machine.state, AuthState.FAILED)
        machine.run_dhcp.assert_called_once_with()
        self.assertEqual(len(network.sent), 3)

    def test_duplicate_md5_request_replays_byte_identical_response(self):
        md5_request = request(4, 2, b"\x10" + CHALLENGE_1)
        frames = [request(1, 1), md5_request, md5_request, result(3, 2), result(4, 2)]
        machine, network = self.make_machine(frames)

        self.assertFalse(machine.authenticate(log_callback=lambda _message: None))
        self.assertEqual(network.sent[2], network.sent[3])

    def test_reauthentication_stays_on_locked_server_and_dhcp_runs_once(self):
        frames = [
            request(1, 1),
            request(4, 2, b"\x10" + CHALLENGE_1),
            result(3, 2),
            request(1, 3),
            request(4, 4, b"\x10" + CHALLENGE_2),
            result(3, 4),
            result(4, 4),
        ]
        machine, _network = self.make_machine(frames)

        self.assertFalse(machine.authenticate(log_callback=lambda _message: None))
        machine.run_dhcp.assert_called_once_with()
        self.assertEqual(machine.server_mac, SERVER)

    def test_delayed_identity_does_not_invalidate_pending_md5_result(self):
        machine, _network = self.make_machine([])
        machine.state = AuthState.WAIT_ID_REQ
        machine._handle_packet(request(1, 1), CLIENT, lambda _message: None)
        machine._handle_packet(request(4, 2, b"\x10" + CHALLENGE_1), CLIENT, lambda _message: None)
        machine._handle_packet(request(1, 1), CLIENT, lambda _message: None)

        self.assertEqual(machine.state, AuthState.WAIT_RESULT)
        self.assertEqual(machine._handle_packet(result(3, 2), CLIENT, lambda _message: None), "success")
        self.assertEqual(machine.state, AuthState.ONLINE)

    def test_failure_without_matching_md5_exchange_is_ignored(self):
        machine, _network = self.make_machine([])
        machine.state = AuthState.WAIT_ID_REQ
        machine._handle_packet(request(1, 7), CLIENT, lambda _message: None)

        self.assertIsNone(machine._handle_packet(result(4, 99), CLIENT, lambda _message: None))
        self.assertEqual(machine.state, AuthState.WAIT_MD5_REQ)

    def test_incomplete_online_reauthentication_times_out_to_online(self):
        clock = FakeClock()
        policy = hello_policy(0x10, 1)
        frames = [
            request(1, 1),
            request(4, 2, b"\x10" + CHALLENGE_1),
            result(3, 2, policy),
            request(1, 3),
        ]
        network = TimedNetwork(frames, clock, stop_at=4.0)
        machine = StateMachine(
            "test0",
            "student",
            "secret",
            net_engine=network,
            dhcp_mode=0,
            snapshot_provider=Mock(read=Mock(return_value=IPv4Snapshot())),
            request_timeout=2.0,
            retransmit_interval=0.5,
            monotonic=clock,
            hello_rand=lambda: 0,
        )
        network.machine = machine
        machine.run_dhcp = Mock()

        self.assertTrue(machine.authenticate(log_callback=lambda _message: None))
        self.assertEqual(network.state_before_stop, AuthState.ONLINE)
        hello_frames = [frame for frame in network.sent if len(frame) >= 16 and frame[15] == 0xBF]
        self.assertGreaterEqual(len(hello_frames), 4)

    def test_server_hello_policy_sends_real_frame_immediately(self):
        policy = hello_policy(0x10, 30)
        frames = [
            request(1, 1),
            request(4, 2, b"\x10" + CHALLENGE_1),
            result(3, 2, policy),
        ]
        machine, network = self.make_machine(frames)
        network.stop_when_empty = True

        self.assertTrue(machine.authenticate(log_callback=lambda _message: None))
        hello_frame = network.sent[3]
        self.assertEqual(hello_frame[:6], SERVER)
        self.assertEqual(hello_frame[6:12], CLIENT)
        self.assertEqual(hello_frame[12:18], bytes.fromhex("888e01bf001e"))
        plain = HelloCodec.decode(hello_frame[18:])
        self.assertEqual(struct.unpack("!I", plain[6:10])[0], 0x1012)
        self.assertEqual(struct.unpack("!I", plain[16:20])[0], 0x1002)

    def test_hello_scheduler_continues_during_reauthentication(self):
        machine, network = self.make_machine([])
        machine.state = AuthState.WAIT_MD5_REQ
        machine._session_authenticated = True
        machine._hello_codec = HelloCodec(CLIENT, sequence=0x1001, offset=0, dst_mac=SERVER)
        machine._hello_interval = 30.0
        machine._next_hello = 100.0

        machine._send_due_hello(99.9)
        self.assertEqual(network.sent, [])
        machine._send_due_hello(100.0)
        self.assertEqual(len(network.sent), 1)
        self.assertEqual(machine._next_hello, 130.0)

    def test_truncated_success_cannot_authenticate_or_start_network(self):
        machine, network = self.make_machine([])
        machine.state = AuthState.WAIT_MD5_REQ
        machine.server_mac = SERVER
        machine._handle_packet(request(4, 2, b"\x10" + CHALLENGE_1), CLIENT, lambda _: None)
        raw = result(3, 2, hello_policy(0x10, 30))[:-1]
        self.assertIsNone(machine._handle_packet(raw, CLIENT, lambda _: None))
        self.assertEqual(machine.state, AuthState.WAIT_RESULT)
        self.assertFalse(machine._session_authenticated)
        machine.run_dhcp.assert_not_called()

    def test_old_internal_hello_layout_is_not_accepted_as_wire(self):
        machine, _ = self.make_machine([])
        machine.state = AuthState.WAIT_MD5_REQ
        machine.server_mac = SERVER
        machine._handle_packet(request(4, 2, b"\x10" + CHALLENGE_1), CLIENT, lambda _: None)
        internal = struct.pack("<IBB2xII", 0x1311, 0x0a, 1, 0x10, 30)
        self.assertIsNone(machine._handle_packet(result(3, 2, internal), CLIENT, lambda _: None))
        self.assertIsNone(machine._hello_codec)
        machine.run_dhcp.assert_not_called()

    def test_complete_success_uses_eapol_private_tail_and_millisecond_interval(self):
        machine, network = self.make_machine([])
        machine.state = AuthState.WAIT_MD5_REQ
        machine.server_mac = SERVER
        machine._handle_packet(request(4, 2, b"\x10" + CHALLENGE_1), CLIENT, lambda _: None)
        self.assertEqual(machine._handle_packet(result(3, 2, hello_policy(0x10, 30)), CLIENT, lambda _: None), 'success')
        self.assertEqual(machine._hello_interval, 30.0)
        self.assertEqual(machine.last_private_properties['hello']['interval_ms'], 30000)
        self.assertEqual(network.sent[-1][15], 0xbf)

    def test_hello_update_zero_values_keep_parameters_and_preserve_cursor(self):
        machine, network = self.make_machine([])
        machine.server_mac = SERVER
        machine._hello_codec = HelloCodec(CLIENT, sequence=10, offset=0x1234,
                                           history_index=7, hello_ids=[0x75] * 16)
        machine._hello_interval = 30.0
        machine.last_private_properties = EAPOLPacket.parse_frame(result(3, 2, hello_policy(0, 0)))['eap']['private_properties']
        machine._configure_hello(CLIENT)
        self.assertEqual(machine._hello_codec.offset, 0x1234)
        self.assertEqual(machine._hello_codec.sequence, 11)
        self.assertEqual(machine._hello_codec.history_index, 8)
        self.assertEqual(machine._hello_codec.hello_ids, [0x74] * 16)
        self.assertEqual(machine._hello_interval, 30.0)
        self.assertEqual(len(network.sent), 1)

    def test_bf_packet_does_not_update_hello_history(self):
        machine, network = self.make_machine([])
        machine.server_mac = SERVER
        machine._hello_codec = HelloCodec(CLIENT, sequence=10, offset=0x1234)
        packet = HelloCodec(SERVER, dst_mac=CLIENT, sequence=0, offset=0).build()
        self.assertIsNone(machine._handle_packet(packet, CLIENT, lambda _: None))
        self.assertEqual(machine._hello_codec.hello_ids, [0x74] * 16)
        self.assertEqual(machine._hello_codec.sequence, 10)
        self.assertEqual(network.sent, [])

    def test_zero_initial_hello_interval_sends_once_without_periodic_loop(self):
        machine, network = self.make_machine([])
        machine.server_mac = SERVER
        machine._session_authenticated = True
        machine.last_private_properties = EAPOLPacket.parse_frame(result(3, 2, hello_policy(0x10, 0)))['eap']['private_properties']
        machine._configure_hello(CLIENT)
        self.assertEqual(len(network.sent), 1)
        self.assertIsNotNone(machine._hello_codec)
        self.assertIsNone(machine._hello_interval)
        self.assertIsNone(machine._next_hello)
        machine._send_due_hello(99999)
        self.assertEqual(len(network.sent), 1)

    def test_clean_stop_after_success_returns_true(self):
        frames = [
            request(1, 1),
            request(4, 2, b"\x10" + CHALLENGE_1),
            result(3, 2),
        ]
        machine, network = self.make_machine(frames)
        network.stop_when_empty = True

        self.assertTrue(machine.authenticate(log_callback=lambda _message: None))
        self.assertEqual(machine.tlv_encoder.mac_address, CLIENT)
        self.assertEqual(machine.state, AuthState.DISCONNECTED)


if __name__ == "__main__":
    unittest.main()
