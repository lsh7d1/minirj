"""Session review regressions: synthetic frames and injected I/O only."""
import unittest
import test_network_events as events
import test_vlan as vlan
from test_state_machine import CLIENT, SERVER, CHALLENGE_1, CHALLENGE_2, request, result
from minirj.core.state_machine import AuthState
from minirj.network.events import NetworkEvent
from minirj.network.snapshot import IPv4Snapshot
from minirj.protocol.eapol import EAPOLPacket

FOREIGN = bytes.fromhex("020000000099")


def from_foreign(frame):
    return frame[:6] + FOREIGN + frame[12:]


def owned_state(m, net):
    return (m.state, m.server_mac, m._phase_server_mac, m.dhcp_auth_phase,
            m.tlv_encoder.dhcp_auth_phase, m._last_request_key, m._last_response,
            m._last_md5_identifier, m._last_md5_challenge,
            m._session_authenticated, m._hello_codec, m._next_hello,
            m.post_auth_status, m.tlv_encoder.fake_ip, tuple(net.sent))


class SessionReviewTests(unittest.TestCase):
    def test_invalid_md5_does_not_block_legitimate_identity(self):
        m, net, _ = events.EventTests().make()
        m.state = AuthState.WAIT_ID_REQ
        self.assertIsNone(m._handle_packet(from_foreign(request(4, 77, b"\x10")), CLIENT, lambda _: None))
        self.assertEqual(m._handle_packet(request(1, 1), CLIENT, lambda _: None), "request")
        self.assertEqual(m.server_mac, SERVER)

    def test_complete_md5_in_wrong_state_preserves_server_phase_cache(self):
        for state in (AuthState.DISCONNECTED, AuthState.SEND_START, AuthState.WAIT_ID_REQ,
                      AuthState.WAIT_ADDRESS, AuthState.FAILED):
            for bound in (None, SERVER):
                with self.subTest(state=state, bound=bound):
                    m, net, _ = events.EventTests().make()
                    m.state, m.server_mac, m._phase_server_mac = state, bound, SERVER
                    m.dhcp_auth_phase = m.tlv_encoder.dhcp_auth_phase = 2
                    m._last_request_key, m._last_response = ("previous",), b"cached"
                    before = owned_state(m, net)
                    self.assertIsNone(m._handle_packet(from_foreign(request(4, 77, b"\x10" + CHALLENGE_1)), CLIENT, lambda _: None))
                    self.assertEqual(owned_state(m, net), before)

    def test_malformed_md5_in_allowed_states_preserves_server_phase_cache(self):
        for state in (AuthState.WAIT_MD5_REQ, AuthState.WAIT_RESULT, AuthState.ONLINE):
            for data in (b"", b"\x10", b"\x10" + CHALLENGE_1[:-1],
                         b"\x0f" + CHALLENGE_1, b"\x11" + CHALLENGE_1 + b"x"):
                for bound in (None, SERVER):
                    with self.subTest(state=state, data=data, bound=bound):
                        m, net, _ = events.EventTests().make()
                        m.state, m.server_mac, m._phase_server_mac = state, bound, SERVER
                        m.dhcp_auth_phase = m.tlv_encoder.dhcp_auth_phase = 2
                        m._last_request_key, m._last_response = ("previous",), b"cached"
                        before = owned_state(m, net)
                        self.assertIsNone(m._handle_packet(from_foreign(request(4, 77, data)), CLIENT, lambda _: None))
                        self.assertEqual(owned_state(m, net), before)

    def test_valid_online_reauth_direct_and_identity_with_reused_identifier(self):
        for identity in (False, True):
            with self.subTest(identity=identity):
                m, net, _ = events.EventTests().make()
                events.EventTests().online(m)
                if identity:
                    self.assertEqual(m._handle_packet(request(1, 1), CLIENT, lambda _: None), "request")
                frame = request(4, 2, b"\x10" + CHALLENGE_2)
                self.assertEqual(m._handle_packet(frame, CLIENT, lambda _: None), "request")
                response = net.sent[-1]
                self.assertEqual(m._handle_packet(frame, CLIENT, lambda _: None), "request")
                self.assertEqual(net.sent[-1], response)
                self.assertEqual(m._handle_packet(result(3, 2), CLIENT, lambda _: None), "success")
                self.assertEqual(m.state, AuthState.ONLINE)
                self.assertEqual(m.server_mac, SERVER)
                self.assertTrue(m._session_authenticated)

    def test_tagged_runner_ignores_invalid_md5_before_valid_exchange(self):
        good = [request(1, 1), request(4, 2, b"\x10" + CHALLENGE_1), result(3, 2)]
        for tci, tpid in ((0, 0x8100), (123, 0x8100), (0xa123, 0x88a8)):
            with self.subTest(tci=tci, tpid=tpid):
                frames = [from_foreign(request(4, 77, b"\x10"))] + good
                m, net, _ = vlan.VLANTests().make([vlan.tag(f, tci, tpid) for f in frames], tci, tpid)
                self.assertTrue(m.authenticate(lambda _: None))
                self.assertEqual(m.server_mac, SERVER)
                self.assertTrue(all(EAPOLPacket.parse_frame(f)["vlan_tci"] == tci for f in net.sent))

    def test_link_restart_refreshes_provider_without_up_snapshot(self):
        for down_snapshot in (None, events.A, IPv4Snapshot()):
            with self.subTest(down_snapshot=down_snapshot):
                m, net, _ = events.EventTests().make()
                m.inject_network_event(NetworkEvent("fake0", True, events.A), 0)
                m.inject_network_event(NetworkEvent("fake0", False, down_snapshot), 1)
                m.snapshot_provider.read.return_value = events.B
                m.snapshot_provider.read.reset_mock()
                count = len(net.sent)
                self.assertIsNone(m._poll_network_events(100))
                self.assertEqual(len(net.sent), count)
                m.inject_network_event(NetworkEvent("fake0", True), 101)
                self.assertEqual(m._poll_network_events(m._recovery_due), "restart")
                self.assertEqual(m.tlv_encoder.fake_ip, events.B.ip)
                m.snapshot_provider.read.assert_called_once_with("fake0")

