import struct
import unittest

from minirj.protocol.eapol import (
    EAPOL_EAPPACKET,
    EAPOL_RUIJIE,
    EAPOLPacket,
    EAP_CODE_REQUEST,
    EAP_CODE_SUCCESS,
    EAP_TYPE_IDENTITY,
)


SRC = b"\x00\x11\x22\x33\x44\x55"
DST = b"\x66\x77\x88\x99\xaa\xbb"


class TestEAPOLFraming(unittest.TestCase):
    def test_single_vlan_is_parsed(self):
        eap = struct.pack("!BBHB", EAP_CODE_REQUEST, 7, 5, EAP_TYPE_IDENTITY)
        frame = EAPOLPacket.build_ethernet_frame(
            SRC, DST, EAPOL_EAPPACKET, eap, vlan_tci=0xA123
        )
        parsed = EAPOLPacket.parse_frame(frame)
        self.assertEqual(parsed["vlan"]["tci"], 0xA123)
        self.assertEqual(parsed["vlan"]["pcp"], 5)
        self.assertEqual(parsed["vlan"]["vid"], 0x123)
        self.assertEqual(parsed["eap"]["type"], EAP_TYPE_IDENTITY)

    def test_eapol_length_separates_ethernet_trailing(self):
        frame = EAPOLPacket.build_eap_start(SRC, DST) + b"padding"
        parsed = EAPOLPacket.parse_frame(frame)
        self.assertEqual(parsed["eapol_body"], b"")
        self.assertEqual(parsed["trailing"], b"padding")

    def test_eap_length_separates_eap_trailing(self):
        eap = struct.pack("!BBHB", EAP_CODE_REQUEST, 9, 5, EAP_TYPE_IDENTITY)
        frame = EAPOLPacket.build_ethernet_frame(
            SRC, DST, EAPOL_EAPPACKET, eap + b"not-eap"
        )
        parsed = EAPOLPacket.parse_frame(frame)
        self.assertEqual(parsed["eap"]["type_data"], b"")
        self.assertEqual(parsed["eap"]["trailing"], b"not-eap")

    def test_success_has_private_data_not_type(self):
        private = b"\x00\x00\x13\x11\x00\x02ok"
        eap = struct.pack("!BBH", EAP_CODE_SUCCESS, 3, 4 + len(private)) + private
        parsed = EAPOLPacket.parse_frame(
            EAPOLPacket.build_ethernet_frame(SRC, DST, EAPOL_EAPPACKET, eap)
        )
        self.assertIsNone(parsed["eap"]["type"])
        self.assertEqual(parsed["eap"]["private_data"], private)

    def test_ruijie_bf_body_is_recognized(self):
        body = b"\x00\x00\x13\x11\x00\x02ok"
        parsed = EAPOLPacket.parse_frame(
            EAPOLPacket.build_ethernet_frame(SRC, DST, EAPOL_RUIJIE, body)
        )
        self.assertEqual(parsed["eapol_type"], 0xBF)
        self.assertEqual(parsed["private_data"], body)

    def test_malformed_lengths_warn_without_index_error(self):
        ethernet = DST + SRC + struct.pack("!H", EAPOLPacket.ETHERTYPE_8021X)
        cases = [
            ethernet,
            ethernet + b"\x01",
            ethernet + b"\x01\x00\x00\x08\x01",
            ethernet + b"\x01\x00\x00\x04\x01\x01\x00\x05",
        ]
        for frame in cases:
            with self.subTest(frame=frame):
                parsed = EAPOLPacket.parse_frame(frame)
                self.assertIsNotNone(parsed)
                self.assertTrue(parsed["warnings"])

    def test_static_hello_tx_length_exception_is_narrow(self):
        # Static constructor specification, NOT a binary dynamic oracle.
        body = bytes.fromhex(
            "ffff37777f9fffffffff ffff37777f9fffffffff ffff37777f3fff"
        )
        ethernet = DST + SRC + b"\x88\x8e"
        raw = ethernet + b"\x01\xbf\x00\x1e" + body
        self.assertEqual(len(raw), 45)
        for padding in (b"", bytes(15)):
            parsed = EAPOLPacket.parse_frame(raw + padding)
            self.assertTrue(parsed["framing_valid"])
            self.assertFalse(parsed["state_valid"])
            self.assertEqual(parsed["framing_kind"], "ruijie_hello_tx")
            self.assertEqual(parsed["eapol_body"], body)
            self.assertEqual(parsed["trailing"], padding)
            self.assertNotIn("private_properties", parsed)
        for broken in (raw[:-1], raw[:-1] + b"\x00",
                       ethernet + b"\x01\x00\x00\x1e" + body,
                       ethernet + b"\x02\xbf\x00\x1e" + body):
            parsed = EAPOLPacket.parse_frame(broken)
            self.assertFalse(parsed["framing_valid"])
            self.assertFalse(parsed["state_valid"])

    def test_non_eapol_and_truncated_vlan_are_rejected(self):
        self.assertIsNone(EAPOLPacket.parse_frame(DST + SRC + b"\x08\x00"))
        self.assertIsNone(
            EAPOLPacket.parse_frame(DST + SRC + b"\x81\x00\x00")
        )


if __name__ == "__main__":
    unittest.main()
