"""Synthetic VLAN sessions only; no interfaces or sockets are opened."""
import socket
import struct
import unittest
from unittest.mock import Mock, patch
from minirj.core.state_machine import StateMachine, AuthState
from minirj.network.raw_socket import RawSocketEngine, restore_vlan
from minirj.network.events import NetworkEvent
from minirj.network.snapshot import IPv4Snapshot
from minirj.protocol.eapol import EAPOLPacket
from test_state_machine import (CLIENT, CHALLENGE_1, FakeClock, TimedNetwork,
                                request, result, hello_policy)


def tag(frame, tci=123, tpid=0x8100):
    return frame[:12] + struct.pack("!HH", tpid, tci) + frame[12:]


class VLANTests(unittest.TestCase):
    def make(self, frames=(), tci=123, tpid=0x8100, dhcp=0):
        clock = FakeClock()
        net = TimedNetwork(frames, clock, 2.2)
        m = StateMachine("fake0", "synthetic", "synthetic", net_engine=net,
                         snapshot_provider=Mock(read=Mock(return_value=IPv4Snapshot(
                             "192.0.2.2", "255.255.255.0", "192.0.2.1"))),
                         vlan_tci=tci, vlan_ethertype=tpid, dhcp_mode=dhcp,
                         monotonic=clock, hello_rand=lambda: 0, logoff_on_exit=True,
                         request_timeout=3, retransmit_interval=.5)
        net.machine = m
        return m, net, clock

    def exchange(self, m, tci=123, tpid=0x8100, ident=2, policy=b""):
        for f in (request(1, ident-1), request(4, ident, b"\x10"+CHALLENGE_1),
                  result(3, ident, policy)):
            m._handle_packet(tag(f, tci, tpid), CLIENT, lambda _: None)

    def test_whole_session_reauth_hello_logoff_and_duplicate(self):
        for tci, tpid in ((123,0x8100), (0,0x8100), (0xa123,0x88a8)):
            with self.subTest(tci=tci,tpid=tpid):
                md5=request(4,2,b"\x10"+CHALLENGE_1)
                frames=[request(1,1),md5,md5,result(3,2,hello_policy(1,1)),
                        request(1,3),request(4,4,b"\x10"+CHALLENGE_1),result(3,4)]
                m,net,_=self.make([tag(f,tci,tpid) for f in frames],tci,tpid)
                self.assertTrue(m.authenticate(lambda _: None))
                parsed=[EAPOLPacket.parse_frame(f) for f in net.sent]
                self.assertTrue(all(p["vlan_tci"]==tci and p["outer_ethertype"]==tpid for p in parsed))
                self.assertEqual(parsed[0]["eapol_type"],1)
                self.assertEqual(parsed[-1]["eapol_type"],2)
                self.assertGreaterEqual(sum(p["eapol_type"]==0xbf for p in parsed),3)
                self.assertEqual(net.sent[2],net.sent[3])
                self.assertIn("sent locally",m.logoff_result)

    def test_foreign_tags_never_bind_or_change_exchange_cache(self):
        m,net,_=self.make()
        m.state=AuthState.WAIT_ID_REQ
        foreign=lambda f: (f,tag(f,124),tag(f,123,0x88a8),tag(f,123|0x2000),tag(tag(f)))
        for f in foreign(request(1,1)):
            self.assertIsNone(m._handle_packet(f,CLIENT,lambda _: None))
        self.assertIsNone(m.server_mac)
        m._handle_packet(tag(request(1,1)),CLIENT,lambda _: None)
        m._handle_packet(tag(request(4,2,b"\x10"+CHALLENGE_1)),CLIENT,lambda _: None)
        before=(m.state,m._last_request_key,m._last_response,len(net.sent))
        for base in (request(1,9),request(4,2,b"\x10"+CHALLENGE_1),result(3,2),result(4,2)):
            for f in foreign(base):
                self.assertIsNone(m._handle_packet(f,CLIENT,lambda _: None))
                self.assertEqual((m.state,m._last_request_key,m._last_response,len(net.sent)),before)
        m._handle_packet(tag(result(3,2)),CLIENT,lambda _: None)
        for f in foreign(result(4,99)):
            m._handle_packet(f,CLIENT,lambda _: None)
        self.assertEqual(m.state,AuthState.ONLINE)
        self.assertEqual(m._handle_packet(tag(result(4,99)),CLIENT,lambda _: None),"failure")

    def test_untagged_profile_rejects_tagged_request(self):
        m,net,_=self.make(tci=None)
        self.assertIsNone(m._handle_packet(tag(request(1,1)),CLIENT,lambda _: None))
        self.assertEqual(net.sent,[])
        self.assertIsNone(m.server_mac)

    def test_start_retransmission_phase2_and_recovery(self):
        m,net,_=self.make()
        self.assertFalse(m.authenticate(lambda _: None))
        self.assertGreater(len(net.sent),1)
        self.assertTrue(all(f==net.sent[0] for f in net.sent))
        m,net,clock=self.make(dhcp=1)
        m.state=AuthState.WAIT_ID_REQ
        self.exchange(m)
        self.assertEqual(m.state,AuthState.WAIT_ADDRESS)
        self.assertEqual(m._poll_address(0),"restart")
        self.assertEqual(EAPOLPacket.parse_frame(net.sent[-1])["vlan_tci"],123)
        self.exchange(m,ident=4,policy=hello_policy(1,1))
        self.assertEqual(m.state,AuthState.ONLINE)
        m.inject_network_event(NetworkEvent("fake0",False),0)
        self.assertIsNone(m._last_response)
        m.inject_network_event(NetworkEvent("fake0",True),1)
        self.assertEqual(m._poll_network_events(2),"restart")
        self.assertEqual(EAPOLPacket.parse_frame(net.sent[-1])["vlan_tci"],123)

    def test_profile_validation_immutability_and_short_send(self):
        for tci in (-1,65536,4095,0xafff,True,1.5):
            with self.assertRaises(ValueError): self.make(tci=tci)
        with self.assertRaises(ValueError): self.make(tpid=0x0800)
        m,net,_=self.make()
        with self.assertRaises(AttributeError): m.vlan_tci=124
        with self.assertRaises(AttributeError): m.vlan_ethertype=0x88a8
        m.state=AuthState.WAIT_ID_REQ
        self.exchange(m)
        net.send_frame=Mock(return_value=1)
        self.assertIn("incomplete",m.logoff(lambda _: None))

    def test_auxdata_restores_offload_and_rejects_ambiguous_metadata(self):
        f=request(1,1)
        aux=lambda status,tci=123,tpid=0x8100: [(263,8,struct.pack("=IIIHHHH",status,len(f),len(f),0,14,tci,tpid))]
        self.assertEqual(restore_vlan(f,aux(16)),tag(f))
        self.assertEqual(restore_vlan(f,aux(16,0)),tag(f,0))
        self.assertEqual(restore_vlan(f,aux(80,123,0x88a8)),tag(f,123,0x88a8))
        self.assertEqual(restore_vlan(tag(f),[]),tag(f))
        self.assertEqual(restore_vlan(f,aux(0)),f)
        for data,anc,flags in ((tag(f),aux(16),0),(f,aux(16)*2,0),
                               (f,[(263,8,b"x")],0),(f,aux(80,1,0x800),0),
                               (f,[],socket.MSG_CTRUNC),(f,[],socket.MSG_TRUNC),
                               (tag(tag(f)),[],0),(f[:13],[],0)):
            self.assertIsNone(restore_vlan(data,anc,flags))

    def test_raw_engine_uses_all_protocols_and_mandatory_auxdata(self):
        engine=RawSocketEngine("fake0")
        with patch("minirj.network.raw_socket.socket.socket") as factory:
            sock=factory.return_value
            engine.get_interface_mac=Mock(return_value=CLIENT)
            engine.open()
            factory.assert_called_once_with(socket.AF_PACKET,socket.SOCK_RAW,socket.htons(3))
            sock.setsockopt.assert_called_once_with(263,8,1)
            sock.bind.assert_called_once_with(("fake0",0))
            sock.recvmsg.return_value=(tag(request(1,1)),[],0,None)
            self.assertEqual(engine.recv_frame(),tag(request(1,1)))
            engine.close()
        with patch("minirj.network.raw_socket.socket.socket") as factory:
            factory.return_value.setsockopt.side_effect=OSError("unsupported")
            with self.assertRaises(OSError): engine.open()
            factory.return_value.close.assert_called_once()
            self.assertIsNone(engine.sock)
