"""Static specification plus redacted old TX shape; synthetic bytes are not oracle bytes."""
import unittest
import local_data
from minirj.protocol.eapol import EAPOLPacket
from minirj.protocol.tlv import ClientTLVEncoder
from minirj.core.state_machine import StateMachine, AuthState
from test_client_tlv import DummyV3, radius_unhide
from test_state_machine import FakeNetwork, CLIENT, SERVER, request, CHALLENGE_1


def legacy_fields(frame):
    end = 18 + int.from_bytes(frame[16:18], "big")
    tail = frame[end:]
    records = []
    offset = 70
    while offset < len(tail):
        outer, length = tail[offset:offset+2]
        assert outer == 26 and length >= 8
        assert tail[offset+2:offset+6] == bytes.fromhex("00001311")
        kind, inner_length = tail[offset+6:offset+8]
        assert inner_length == length - 6
        records.append((kind, tail[offset+8:offset+length]))
        offset += length
    assert offset == len(tail)
    return tail, dict(records)


class LegacyTXTests(unittest.TestCase):
    def encoder(self, **kwargs):
        return ClientTLVEncoder("testuser", "testpass", mac_address=CLIENT,
                                v3_generator=DummyV3(), **kwargs)

    def test_observed_tx_shapes_against_independent_spec(self):
        fixture = local_data.load("f3.json")
        for observation in fixture["frames"]:
            with self.subTest(length=observation["length"]):
                kind = observation["eapol_type"]
                method = observation.get("method")
                encoder = self.encoder(client_version=(6, 84, 0, 0))
                dns_length = next(r["inner_length"]-2 for r in observation["vendor_wrappers"] if r["inner_type"] == 0x76)
                encoder.alternate_dns = b"D" * dns_length
                vendor = encoder.encode_legacy(CHALLENGE_1 if method == 4 else None)
                if kind == 1:
                    raw = EAPOLPacket.build_eap_start(CLIENT, vendor_data=vendor)
                elif kind == 2:
                    raw = EAPOLPacket.build_eap_logoff(CLIENT, SERVER, vendor_data=vendor)
                elif method == 1:
                    raw = EAPOLPacket.build_eap_response_identity(CLIENT, SERVER, observation["id"], "testuser", vendor_data=vendor)
                else:
                    raw = EAPOLPacket.build_eap_response_md5(CLIENT, SERVER, observation["id"], b"d"*16, vendor, username="testuser")
                self.assertEqual(len(raw), observation["length"])
                self.assertEqual(int.from_bytes(raw[16:18], "big"), observation["eapol_length"])
                if kind == 0:
                    self.assertEqual(int.from_bytes(raw[20:22], "big"), observation["eap_length"])
                    self.assertEqual(raw[23:31] if method == 1 else raw[40:48], b"testuser")
                tail, fields = legacy_fields(raw)
                self.assertEqual(tail[23:27], bytes.fromhex("00001311"))
                self.assertEqual(tail[64:68], bytes.fromhex("00001311"))
                self.assertEqual(tail[59:63], bytes.fromhex("06540000"))
                self.assertEqual(int.from_bytes(tail[68:70], "big"), len(tail)-70)
                self.assertEqual([(t, len(p)+2) for t,p in fields.items()],
                                 [(r["inner_type"], r["inner_length"]) for r in observation["vendor_wrappers"]])
                self.assertEqual(fields[0x6f], b"RG_SU_For_Windows 6.84\x00")
                if method == 4:
                    self.assertEqual(radius_unhide(fields[0x2f], CHALLENGE_1, b"testuser"), b"testpass")
                else:
                    self.assertEqual(fields[0x2f], b"")

    def test_state_machine_actual_response_producer(self):
        net = FakeNetwork([])
        machine = StateMachine("test0", "testuser", "testpass", net_engine=net,
                               client_version=(6,84,0,0))
        machine.tlv_encoder.v3_gen = DummyV3()
        machine.tlv_encoder.mac_address = CLIENT
        machine.state = AuthState.WAIT_ID_REQ
        machine._handle_packet(request(1,1), CLIENT, lambda _: None)
        machine._handle_packet(request(4,2,b"\x10"+CHALLENGE_1), CLIENT, lambda _: None)
        # The campus double-auth profile adds one 9-byte phase VSA; the old
        # observed TX fixture above still tests its original unselected profile.
        self.assertEqual([len(f) for f in net.sent], [572,605])
        tail, fields = legacy_fields(net.sent[-1])
        self.assertEqual(tail[59:63], bytes.fromhex("06540000"))
        self.assertEqual(fields[0x2d], CLIENT)
        self.assertEqual(fields[0x63], b"\x01")
        self.assertEqual(net.sent[-1][40:48], b"testuser")

    def test_explicit_four_component_version_and_compatibility_default(self):
        self.assertEqual(self.encoder()._client_version_payload()[-4:], bytes((6,84,0,0)))
        for release in ("RG_SU_For_Windows 6.84", "independent release"):
            self.assertEqual(self.encoder(client_ver=release, client_version=(6,84,0,0))._client_version_payload()[-4:], bytes((6,84,0,0)))
        for bad in ((6,84,0), (6,84,0,256), (6,84,-1,0), "6.84.0.0", (True,84,0,0)):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                self.encoder(client_version=bad)

    def test_md5_rejects_non_16_byte_digest(self):
        for digest in (b"", b"a"*15, b"a"*17):
            with self.assertRaises(ValueError):
                EAPOLPacket.build_eap_response_md5(CLIENT, SERVER, 1, digest)

    def test_crc_encoded_prefix_and_phase2_ip(self):
        enc = self.encoder(dhcp_mode=1, fake_ip="192.0.2.10", fake_mask="255.255.255.0",
                           fake_gw="192.0.2.1", fake_dns="192.0.2.53")
        tail = enc.encode_legacy(None)
        plain = bytes(int(format(x ^ 255, "08b")[::-1], 2) for x in tail[:23])
        self.assertEqual(plain[:21], bytes.fromhex("0000131101c000020affffff00c0000201c0000235"))
        import binascii
        self.assertEqual(int.from_bytes(plain[21:], "big"), binascii.crc_hqx(plain[:21],0))
        enc.encode_legacy(CHALLENGE_1)
        self.assertEqual(enc.v3_gen.challenges, [bytes(16), CHALLENGE_1])

    def test_explicit_profile_unknown_oui_keeps_association_checks(self):
        nas = bytes.fromhex("2c58b9010203")
        net = FakeNetwork([])
        machine = StateMachine("test0", "testuser", "testpass", net_engine=net,
                               protocol_profile="ruijie", client_version=(6,84,0,0),
                               start_destination=bytes.fromhex("01d0f8000003"))
        machine.tlv_encoder.v3_gen = DummyV3()
        machine.state = AuthState.WAIT_ID_REQ
        identity = request(1,1)
        identity = identity[:6] + nas + identity[12:]
        machine._handle_packet(identity, CLIENT, lambda _: None)
        self.assertEqual(len(net.sent[-1]),572)
        self.assertEqual(machine.dhcp_auth_phase,1)
        md5 = request(4,2,b"\x10"+CHALLENGE_1)
        before = (len(net.sent),machine.server_mac,machine._last_request_key)
        machine._handle_packet(md5, CLIENT, lambda _: None)  # another NAS
        self.assertEqual((len(net.sent),machine.server_mac,machine._last_request_key),before)
        md5 = md5[:6] + nas + md5[12:]
        machine._handle_packet(md5, CLIENT, lambda _: None)
        self.assertEqual(len(net.sent[-1]),605)
        machine._handle_packet(md5, CLIENT, lambda _: None)
        self.assertEqual(net.sent[-1],net.sent[-2])
        # Profile must not make malformed EAP or stale results acceptable.
        from test_state_machine import result
        stale = result(3,99)
        stale = stale[:6]+nas+stale[12:]
        self.assertIsNone(machine._handle_packet(stale,CLIENT,lambda _: None))
        self.assertEqual(machine.state,AuthState.WAIT_RESULT)
        for bad in ("unknown", None, True):
            with self.assertRaises(ValueError):
                StateMachine("test0","testuser","testpass",net_engine=net,protocol_profile=bad)

    def test_legacy_start_vlan_phase2_and_logoff(self):
        from test_vlan import tag
        from test_state_machine import result, FakeClock
        from minirj.network.snapshot import IPv4Snapshot
        from unittest.mock import Mock
        net = FakeNetwork([])
        m = StateMachine("test0","testuser","testpass",net_engine=net,
                         start_destination=bytes.fromhex("01d0f8000003"),
                         protocol_profile="ruijie", vlan_tci=123, monotonic=FakeClock(),
                         snapshot_provider=Mock(read=Mock(return_value=IPv4Snapshot("192.0.2.20","255.255.255.0","192.0.2.1"))))
        m.tlv_encoder.v3_gen=DummyV3()
        m._send_frame(m._build_start())
        self.assertEqual(len(net.sent[-1]),563)  # VLAN + explicit phase1 VSA
        self.assertEqual(net.sent[-1][:6],bytes.fromhex("01d0f8000003"))
        self.assertEqual(int.from_bytes(net.sent[-1][20:22],"big"),0)
        m.state=AuthState.WAIT_ID_REQ
        for raw in (request(1,1),request(4,2,b"\x10"+CHALLENGE_1),result(3,2)):
            m._handle_packet(tag(raw),CLIENT,lambda _: None)
        self.assertEqual(m.state,AuthState.WAIT_ADDRESS)
        self.assertEqual(m._poll_address(0),"restart")
        raw=net.sent[-1][:12]+net.sent[-1][16:]
        tail, fields=legacy_fields(raw)
        plain=bytes(int(format(x^255,"08b")[::-1],2) for x in tail[:23])
        self.assertEqual(plain[5:9],bytes((192,0,2,20)))
        self.assertEqual(fields[0x63], b"\x02")
        m._session_authenticated=True
        m.logoff(lambda _: None)
        raw=net.sent[-1][:12]+net.sent[-1][16:]
        tail,fields=legacy_fields(raw)
        self.assertEqual(raw[15:18],b"\x02\x00\x00")
        self.assertEqual(tail[63],1)
        self.assertEqual(fields[0x2f],b"")

    def test_non_ruijie_flat_branch_is_preserved(self):
        net=FakeNetwork([])
        m=StateMachine("test0","testuser","testpass",net_engine=net)
        m.tlv_encoder.v3_gen=DummyV3()
        m.state=AuthState.WAIT_ID_REQ
        nas=bytes.fromhex("66778899aabb")
        for raw in (request(1,1),request(4,2,b"\x10"+CHALLENGE_1)):
            m._handle_packet(raw[:6]+nas+raw[12:],CLIENT,lambda _: None)
        parsed=EAPOLPacket.parse_frame(net.sent[-1])
        self.assertEqual(parsed["trailing"],b"")
        self.assertEqual(parsed["eap"]["type_data"][17:19],bytes((0x11,36)))

    def test_vsa_length_limits_and_zero_password_padding(self):
        enc=self.encoder()
        enc.alternate_dns=b"a"*248
        with self.assertRaises(ValueError): enc.encode_legacy()
        enc.alternate_dns=b""
        enc.password=""
        raw=EAPOLPacket.build_eap_start(CLIENT,vendor_data=enc.encode_legacy(CHALLENGE_1))
        self.assertEqual(len(legacy_fields(raw)[1][0x2f]),16)
        enc.ipv6_tlvs=b"\x36\x01x"
        with self.assertRaises(ValueError): enc.encode_legacy()

    def test_real_snapshot_alternate_dns_reaches_phase2_tx(self):
        from minirj.network.snapshot import IPv4Snapshot, LinuxIPv4SnapshotProvider
        from unittest.mock import Mock
        provider=LinuxIPv4SnapshotProvider(read_text=lambda _: "nameserver 192.0.2.53\nnameserver 203.0.113.101\nnameserver 203.0.113.102\n")
        primary,secondary,alternates=provider._dns([],with_alternates=True)
        self.assertEqual(primary,"192.0.2.53")
        self.assertEqual(secondary,"203.0.113.101")
        snapshot=IPv4Snapshot("192.0.2.20","255.255.255.0","192.0.2.1",primary,secondary,alternate_dns=alternates)
        net=FakeNetwork([])
        m=StateMachine("test0","testuser","testpass",net_engine=net,protocol_profile="ruijie",
                       start_destination=bytes.fromhex("01d0f8000003"),
                       snapshot_provider=Mock(read=Mock(return_value=snapshot)))
        m.tlv_encoder.v3_gen=DummyV3()
        m.state=AuthState.WAIT_ADDRESS
        m._address_deadline=10
        m._next_address_poll=0
        self.assertEqual(m._poll_address(0),"restart")
        raw=net.sent[-1]
        self.assertEqual(len(raw),586)
        self.assertEqual(legacy_fields(raw)[1][0x76],b"203.0.113.101;203.0.113.102")
        # A subsequent empty observation removes stale resolver data.
        m.snapshot_provider.read.return_value=IPv4Snapshot()
        m._read_network_snapshot(before_dhcp=True)
        self.assertEqual(m.tlv_encoder.alternate_dns,b"")

    def _machine_with_residual_global_dns(self, dhcp_mode):
        """Real provider.read/parse paths; only OS I/O and Ethernet transport fake."""
        import ipaddress
        import socket
        import struct
        import sys
        from unittest.mock import Mock
        from minirj.network.snapshot import LinuxIPv4SnapshotProvider, SIOCGIFADDR, RESOLV_PATH, ROUTE_PATH
        from test_state_machine import FakeClock, result
        resolver = "nameserver 192.0.2.53\nnameserver 203.0.113.101\nnameserver 203.0.113.102\n"
        gateway = int.from_bytes(ipaddress.IPv4Address("192.0.2.1").packed, sys.byteorder)
        texts = {RESOLV_PATH: resolver,
                 ROUTE_PATH: f"test0 00000000 {gateway:08X} 0003 0 0 10 00000000\n"}
        def ioctl(fd, operation, request_bytes):
            address = "192.0.2.20" if operation == SIOCGIFADDR else "255.255.255.0"
            return bytes(16) + struct.pack("H", socket.AF_INET) + bytes(2) + ipaddress.IPv4Address(address).packed
        sock = Mock()
        sock.__enter__ = Mock(return_value=sock)
        sock.__exit__ = Mock(return_value=False)
        provider = LinuxIPv4SnapshotProvider(read_text=texts.__getitem__,
                                            socket_factory=Mock(return_value=sock), ioctl=ioctl)
        frames = [request(1,1), request(4,2,b"\x10"+CHALLENGE_1)]
        if dhcp_mode:
            frames += [result(3,2), request(1,3), request(4,4,b"\x10"+CHALLENGE_1), result(4,4)]
        else:
            frames += [result(4,2)]
        net = FakeNetwork(frames)
        m = StateMachine("test0","testuser","testpass",net_engine=net,
                         snapshot_provider=provider, monotonic=FakeClock(), dhcp_mode=dhcp_mode,
                         protocol_profile="ruijie", start_destination=bytes.fromhex("01d0f8000003"))
        m.tlv_encoder.v3_gen = DummyV3()
        net.machine = m
        net.stop_when_empty = True
        return m, net

    def test_residual_global_dns_delayed_until_dhcp_phase2_actual_session(self):
        m, net = self._machine_with_residual_global_dns(1)
        self.assertFalse(m.authenticate(lambda _: None))
        self.assertEqual([len(raw) for raw in net.sent], [559,572,605,586,599,632])
        for index,raw in enumerate(net.sent):
            with self.subTest(index=index):
                tail, fields = legacy_fields(raw)
                self.assertEqual(fields[0x63], b"\x01" if index < 3 else b"\x02")
                self.assertEqual(fields[0x76], b"" if index < 3 else b"203.0.113.101;203.0.113.102")
                plain = bytes(int(format(x ^ 255,"08b")[::-1],2) for x in tail[:23])
                self.assertEqual(plain[17:21], bytes((192,0,2,53)))  # primary DNS unchanged
                self.assertEqual(plain[5:9], bytes(4) if index < 3 else bytes((192,0,2,20)))
        self.assertFalse(m.network_config.process)  # external backend never launches a lease command

    def test_dhcp_zero_preserves_global_alternate_dns_actual_session(self):
        m, net = self._machine_with_residual_global_dns(0)
        self.assertFalse(m.authenticate(lambda _: None))
        self.assertEqual([len(raw) for raw in net.sent], [577,590,623])
        for raw in net.sent:
            self.assertEqual(legacy_fields(raw)[1][0x76], b"203.0.113.101;203.0.113.102")
        # Even an explicit before_dhcp observation must not strip DHCP0 DNS.
        m._read_network_snapshot(before_dhcp=True)
        self.assertEqual(m.tlv_encoder.alternate_dns, b"203.0.113.101;203.0.113.102")

    def test_dhcp_restart_clears_previous_phase2_and_secondary_fallback_dns(self):
        from minirj.network.snapshot import IPv4Snapshot
        from unittest.mock import Mock
        m, net = self._machine_with_residual_global_dns(1)
        m.snapshot_provider = Mock(read=Mock(return_value=IPv4Snapshot(
            "192.0.2.20","255.255.255.0","192.0.2.1","192.0.2.53","203.0.113.101")))
        m._read_network_snapshot()
        self.assertEqual(m.tlv_encoder.alternate_dns,b"203.0.113.101")
        m._read_network_snapshot(before_dhcp=True)
        self.assertEqual(m.tlv_encoder.alternate_dns,b"")
        self.assertEqual(legacy_fields(m._build_start())[1][0x76],b"")
        m._read_network_snapshot()
        self.assertEqual(m.tlv_encoder.alternate_dns,b"203.0.113.101")
