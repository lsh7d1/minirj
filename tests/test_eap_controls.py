"""Synthetic RFC 3748 vectors, not observations of Ruijie target behavior."""
import struct
import unittest
from unittest.mock import Mock
from minirj.core.state_machine import StateMachine, AuthState
from minirj.network.events import NetworkEvent
from minirj.protocol.eapol import EAPOLPacket
import test_state_machine as helpers
from test_state_machine import CLIENT, SERVER, CHALLENGE_1, request, result


class EAPControlTests(unittest.TestCase):
    make_machine = helpers.TestStateMachine.make_machine

    def make(self):
        m, net = self.make_machine([])
        m.state = AuthState.WAIT_ID_REQ
        return m, net

    def receive(self, m, frame):
        return m._handle_packet(frame, CLIENT, lambda _: None)

    def md5(self, m):
        self.receive(m, request(1, 1))
        self.receive(m, request(4, 2, b"\x10" + CHALLENGE_1))

    def exchange(self, m):
        return (m.state, m.server_mac, m._phase_server_mac, m._last_request_key,
                m._last_response, m._last_md5_identifier, m._last_md5_challenge,
                m._session_authenticated, m.dhcp_auth_phase, m._hello_codec)

    def test_wire_vectors_response_code_id_length_and_only_md5(self):
        nak = EAPOLPacket.build_eap_response_nak(CLIENT, SERVER, 0x91)
        note = EAPOLPacket.build_eap_response_notification(CLIENT, SERVER, 0x92)
        self.assertEqual(nak, SERVER+CLIENT+bytes.fromhex('888e01000006029100060304'))
        self.assertEqual(note, SERVER+CLIENT+bytes.fromhex('888e010000050292000502'))

    def test_nak_unimplemented_types_before_method_selection(self):
        for kind, data in ((5,b''), (6,b''), (13,b'\x20'), (25,b'\x20'),
                           (99,b''), (253,b''), (255,b''),
                           (254,bytes.fromhex('0000000000000d'))):
            with self.subTest(kind=kind):
                m, net = self.make()
                before = self.exchange(m)
                self.assertEqual(self.receive(m, request(kind,7,data)), 'nak')
                self.assertEqual(self.exchange(m), before)
                parsed = EAPOLPacket.parse_frame(net.sent[-1])['eap']
                self.assertEqual((parsed['code'],parsed['req_id'],parsed['type'],parsed['type_data']), (2,7,3,b'\x04'))

    def test_nak_after_identity_then_md5_without_identity_requery(self):
        m, net = self.make()
        self.receive(m, request(1,1))
        self.assertEqual(self.receive(m, request(25,2)), 'nak')
        self.assertEqual(self.receive(m, request(4,3,b'\x10'+CHALLENGE_1)), 'request')
        self.assertEqual(self.receive(m, result(3,3)), 'success')
        self.assertEqual(m.state, AuthState.ONLINE)

    def test_initial_nak_then_initial_md5_is_supported(self):
        m, net = self.make()
        self.receive(m, request(13,1))
        self.assertEqual(self.receive(m, request(4,2,b'\x10'+CHALLENGE_1)), 'request')
        self.assertEqual(self.receive(m, result(3,2)), 'success')

    def test_duplicate_nak_is_identical_and_does_not_repeat_log(self):
        m, net = self.make()
        log = Mock()
        packet = request(25,9,b'\x20')
        self.assertEqual(m._handle_packet(packet,CLIENT,log), 'nak')
        self.assertEqual(m._handle_packet(packet,CLIENT,log), 'duplicate')
        self.assertEqual(net.sent[0], net.sent[1])
        log.assert_called_once()
        self.assertIsNone(self.receive(m,request(13,9,b'\x20')))
        self.assertIsNone(self.receive(m,request(25,9,b'\x21')))
        self.assertEqual(len(net.sent),2)

    def test_reserved_response_only_expanded_special_and_malformed_requests_drop(self):
        for kind,data in ((0,b''),(3,b'\x04'),(4,b''),(254,b'bad'),
                          (254,bytes(7)),(254,bytes.fromhex('00000000000003')),
                          (254,bytes.fromhex('00000000000001'))):
            m,net=self.make()
            before=self.exchange(m)
            self.assertIsNone(self.receive(m,request(kind,1,data)))
            self.assertEqual(net.sent,[])
            self.assertEqual(self.exchange(m),before)
            self.assertIsNone(m._control_server)

    def test_never_respond_to_responses_success_failure_or_unknown_code(self):
        for code in (2,3,4,5):
            m,net=self.make()
            body=struct.pack('!BBHB',code,7,5,25)
            self.assertIsNone(self.receive(m,EAPOLPacket.build_ethernet_frame(SERVER,CLIENT,0,body)))
            self.assertEqual(net.sent,[])

    def test_wrong_states_link_loss_and_recovery_cannot_bind_or_send(self):
        for state in (AuthState.DISCONNECTED,AuthState.SEND_START,AuthState.WAIT_ADDRESS,AuthState.FAILED,AuthState.ONLINE):
            for packet in (request(25,1),request(2,1,b'notice')):
                m,net=self.make();m.state=state
                before=self.exchange(m)
                self.assertIsNone(self.receive(m,packet))
                self.assertEqual(net.sent,[])
                self.assertEqual(self.exchange(m),before)
        for attr,value in (('_recovering',True),('_link_up',False)):
            m,net=self.make();setattr(m,attr,value)
            self.assertIsNone(self.receive(m,request(25,1)))
            self.assertEqual(net.sent,[])

    def test_cross_server_and_vlan_cannot_influence_negotiation_or_md5(self):
        for established in (False,True):
            m,net=self.make()
            self.receive(m,request(1,1) if established else request(25,1))
            before=self.exchange(m);sent=len(net.sent)
            for packet in (request(13,2),request(2,2,b'notice'),request(1,2),request(4,2,b'\x10'+CHALLENGE_1)):
                foreign=packet[:6]+bytes.fromhex('00d0f8000001')+packet[12:]
                self.assertIsNone(self.receive(m,foreign))
                tagged=packet[:12]+bytes.fromhex('81000001')+packet[12:]
                self.assertIsNone(self.receive(m,tagged))
            self.assertEqual(len(net.sent),sent)
            self.assertEqual(self.exchange(m),before)

    def test_unknown_method_after_md5_is_silently_discarded_without_cache_pollution(self):
        m,net=self.make();self.md5(m)
        before=self.exchange(m);sent=len(net.sent)
        for kind in (5,13,25,254,255):
            self.assertIsNone(self.receive(m,request(kind,3,bytes.fromhex('0000000000000d'))))
        self.assertEqual(len(net.sent),sent)
        self.assertEqual(self.exchange(m),before)
        self.assertEqual(self.receive(m,result(3,2)), 'success')

    def test_notification_response_empty_preserves_pending_md5_and_duplicate_cache(self):
        m,net=self.make();self.md5(m)
        before=self.exchange(m)
        self.assertEqual(self.receive(m,request(2,3,b'password expires soon')), 'notification')
        self.assertEqual(self.exchange(m),before)
        self.assertEqual(self.receive(m,request(2,3,b'password expires soon')), 'duplicate')
        self.assertEqual(net.sent[-1],net.sent[-2])
        self.assertEqual(EAPOLPacket.parse_frame(net.sent[-1])['eap']['type_data'],b'')
        self.receive(m,request(4,2,b'\x10'+CHALLENGE_1))
        self.assertEqual(net.sent[-1],before[4])
        self.assertEqual(self.receive(m,result(3,2)), 'success')

    def test_notification_validation_and_id_collision(self):
        for data in (b'',b'bad\0',b'\xff',b'a'*1016):
            m,net=self.make()
            self.assertIsNone(self.receive(m,request(2,1,data)))
            self.assertEqual(net.sent,[])
            self.assertIsNone(m._control_server)
        m,net=self.make();self.md5(m)
        self.assertIsNone(self.receive(m,request(2,2,b'new request reused MD5 id')))
        self.assertEqual(self.receive(m,request(2,3,b'notice')), 'notification')
        sent=len(net.sent)
        self.assertIsNone(self.receive(m,request(2,3,b'changed')))
        self.assertIsNone(self.receive(m,request(4,3,b'\x10'+CHALLENGE_1)))
        self.assertEqual(len(net.sent),sent)

    def test_notification_log_is_escaped_and_credentials_redacted(self):
        m,net=self.make();log=Mock()
        m._handle_packet(request(2,1,b'student secret\n\x1b[31m'),CLIENT,log)
        message=log.call_args.args[0]
        self.assertNotIn('student',message);self.assertNotIn('secret',message)
        self.assertNotIn('\n',message);self.assertNotIn('\x1b',message)

    def test_failure_matching_nak_is_diagnostic_but_success_cannot_authenticate(self):
        m,net=self.make();self.receive(m,request(25,7))
        self.assertIsNone(self.receive(m,result(3,7)))
        self.assertIsNone(self.receive(m,result(4,8)))
        self.assertEqual(self.receive(m,result(4,7)), 'failure')
        self.assertEqual(m.post_auth_status,'unsupported_method')
        self.assertFalse(m._session_authenticated)

    def test_notification_does_not_authorize_success_or_failure(self):
        m,net=self.make();self.receive(m,request(2,7,b'notice'))
        self.assertIsNone(self.receive(m,result(3,7)))
        self.assertIsNone(self.receive(m,result(4,7)))
        self.assertEqual(m.state,AuthState.WAIT_ID_REQ)

    def test_network_invalidation_clears_control_peer_and_cache(self):
        m,net=self.make();self.receive(m,request(25,7))
        m.inject_network_event(NetworkEvent('test0',False))
        self.assertIsNone(m._control_key)
        self.assertIsNone(m._control_server)
        self.assertIsNone(m._nak_identifier)
        self.assertFalse(m._method_started)

    def test_tagged_profile_replies_tagged_and_rejects_changed_tci_tpid(self):
        m=StateMachine('test0','student','secret',net_engine=Mock(),dhcp_mode=0,vlan_tci=0xa123)
        m.net.send_frame.return_value=32
        m.state=AuthState.WAIT_ID_REQ
        frame=request(25,1)
        tagged=frame[:12]+bytes.fromhex('8100a123')+frame[12:]
        self.assertEqual(self.receive(m,tagged),'nak')
        response=m.net.send_frame.call_args.args[0]
        self.assertEqual(response[12:18],bytes.fromhex('8100a123888e'))
        for header in ('88a8a123','81000123'):
            self.assertIsNone(self.receive(m,frame[:12]+bytes.fromhex(header)+frame[12:]))
        m.net.send_frame.assert_called_once()

    def test_runner_nak_notification_md5_and_failure_paths(self):
        for frames,expected in (([request(25,1),result(4,1)],False),
                                ([request(25,1),request(2,2,b'notice'),request(4,3,b'\x10'+CHALLENGE_1),result(3,3)],True)):
            m,net=self.make_machine(frames);net.stop_when_empty=True
            self.assertEqual(m.authenticate(lambda _:None),expected)
            self.assertEqual(EAPOLPacket.parse_frame(net.sent[1])['eap']['type'],3)


    def test_notification_after_nak_cannot_match_stale_nak_failure(self):
        m,net=self.make();self.receive(m,request(25,7))
        self.receive(m,request(2,8,b'notice'))
        self.assertIsNone(self.receive(m,result(4,7)))
        self.assertIsNone(self.receive(m,result(3,8)))

    def test_notification_redacts_control_containing_password_before_escaping(self):
        m,net=self.make();m.password='hidden\npassword';log=Mock()
        m._handle_packet(request(2,1,b'hidden\npassword'),CLIENT,log)
        message=log.call_args.args[0]
        self.assertNotIn('hidden',message)
        self.assertNotIn('password',message)


    def test_identity_id_reused_after_notification_gets_nak(self):
        m, net = self.make()
        self.assertEqual(self.receive(m, request(1, 7)), "request")
        # A different request cannot reuse the immediately preceding ID.
        self.assertIsNone(self.receive(m, request(13, 7, b"\x20")))
        self.assertEqual(self.receive(m, request(2, 8, b"notice")), "notification")
        self.assertEqual(self.receive(m, request(13, 7, b"\x20")), "nak")
        nak = net.sent[-1]
        self.assertEqual(nak, EAPOLPacket.build_eap_response_nak(CLIENT, SERVER, 7))
        self.assertEqual(self.receive(m, request(13, 7, b"\x20")), "duplicate")
        self.assertEqual(net.sent[-1], nak)
        sent = len(net.sent)
        self.assertIsNone(self.receive(m, request(1, 7)))  # Do not replay stale Identity.
        self.assertIsNone(self.receive(m, request(2, 7, b"conflict")))
        self.assertEqual(len(net.sent), sent)
        self.assertIsNone(self.receive(m, result(3, 7)))
        self.assertEqual(self.receive(m, result(4, 7)), "failure")
        self.assertEqual(m.post_auth_status, "unsupported_method")

    def test_identity_id_wrap_after_notifications_gets_nak(self):
        m, net = self.make()
        self.assertEqual(self.receive(m, request(1, 0)), "request")
        for identifier in range(1, 256):
            self.assertEqual(self.receive(m, request(2, identifier, b"notice")), "notification")
        self.assertEqual(self.receive(m, request(13, 0, b"\x20")), "nak")
        self.assertEqual(net.sent[-1], EAPOLPacket.build_eap_response_nak(CLIENT, SERVER, 0))
        self.assertIsNone(self.receive(m, result(3, 0)))
        self.assertEqual(self.receive(m, request(4, 1, b"\x10" + CHALLENGE_1)), "request")
        self.assertEqual(self.receive(m, result(3, 1)), "success")


    def test_id_reuse_keeps_pending_md5_challenge_failure_and_replay_guards(self):
        m, net = self.make()
        self.md5(m)
        md5_response = net.sent[-1]
        self.assertEqual(self.receive(m, request(2, 3, b"notice")), "notification")
        notification = net.sent[-1]
        before = self.exchange(m)
        sent = len(net.sent)
        for frame in (request(2, 2, b"pending MD5 ID"),
                      request(4, 2, b"\x10" + bytes(16)),
                      request(2, 4, b"\xff"),
                      request(2, 3, b"changed"), result(4, 3)):
            self.assertIsNone(self.receive(m, frame))
        self.assertEqual(len(net.sent), sent)
        self.assertEqual(self.exchange(m), before)
        self.assertEqual(self.receive(m, request(2, 3, b"notice")), "duplicate")
        self.assertEqual(net.sent[-1], notification)
        self.assertEqual(self.receive(m, request(4, 2, b"\x10" + CHALLENGE_1)), "request")
        self.assertEqual(net.sent[-1], md5_response)
        self.assertIsNone(self.receive(m, request(2, 2, b"conflict after replay")))
        self.assertEqual(self.receive(m, result(4, 2)), "failure")
        self.assertFalse(m._session_authenticated)

    def test_replayed_identity_becomes_latest_request_without_id_blacklist(self):
        m, net = self.make()
        self.receive(m, request(1, 7))
        identity = net.sent[-1]
        self.receive(m, request(2, 8, b"notice"))
        self.assertEqual(self.receive(m, request(1, 7)), "request")
        self.assertEqual(net.sent[-1], identity)
        sent = len(net.sent)
        self.assertIsNone(self.receive(m, request(13, 7, b"\x20")))
        self.assertIsNone(self.receive(m, request(2, 8, b"\xff")))
        self.assertIsNone(self.receive(m, request(13, 7, b"\x20")))
        self.assertEqual(len(net.sent), sent)
        self.assertEqual(self.receive(m, request(2, 8, b"notice")), "notification")
        self.assertEqual(self.receive(m, request(13, 7, b"\x20")), "nak")
