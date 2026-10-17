"""Synthetic STATIC-SPEC fixtures; not captures or a binary dynamic oracle.

Bytes follow the historical target instruction mapping preserved in the research workspace.
No production builder/encoder computes expected Hello bytes or fields.
"""
import unittest

from minirj.protocol.eapol import EAPOLPacket
from minirj.protocol.private_property import parse_private_properties

ETH = bytes.fromhex("66778899aabb001122334455888e")
# decode gives 00001311 0a 01 11223344 0000001e 00 (15 bytes).
HELLO = bytes.fromhex("ffff3777af7f77bb33ddffffff87ff")
FLAGS = bytes.fromhex("000013110100000013110101")


def private_wire(message=b"", count=0, hello=HELLO):
    return (bytes.fromhex("00001311") + len(message).to_bytes(2, "big")
            + message + bytes.fromhex("00001311") + bytes(106)
            + bytes([count]) + bytes(32 * count) + FLAGS + hello)


def frame(private, eap_length=4):
    body = b"\x03\x07" + eap_length.to_bytes(2, "big") + private
    return ETH + b"\x01\x00" + len(body).to_bytes(2, "big") + body


class TestSuccessWire(unittest.TestCase):
    def test_complete_wire_to_hello_policy(self):
        for message, count in ((b"", 0), (b"ok", 2), ("成功".encode("gbk"), 1)):
            p = private_wire(message, count)
            for length in (4, 4 + len(p)):
                raw = frame(p, length) + b"ethernet-padding"
                parsed = EAPOLPacket.parse_frame(raw)
                self.assertTrue(parsed["state_valid"])
                self.assertEqual(parsed["framing_errors"], [])
                self.assertEqual(parsed["raw"], raw)
                self.assertEqual(parsed["trailing"], b"ethernet-padding")
                self.assertEqual(parsed["eap"]["private_data"], p)
                props = parsed["eap"]["private_properties"]
                hello = props["hello"]
                self.assertEqual(hello["offset"], len(message) + 129 + count * 32)
                self.assertEqual(hello["id"], 0x11223344)
                self.assertEqual(hello["interval_ms"], 30000)
                self.assertEqual(hello["interval"], 30000)
                self.assertEqual(hello["interval_seconds_wire"], 30)
                self.assertEqual(hello["raw"], HELLO)
                self.assertEqual(hello["decoded_raw"], bytes.fromhex("000013110a01112233440000001e00"))

    def test_disabled_does_not_expose_stale_values(self):
        disabled = HELLO[:5] + b"\xff" + HELLO[6:]
        parsed = parse_private_properties(private_wire(hello=disabled))
        self.assertTrue(parsed["policy_valid"])
        self.assertFalse(parsed["hello"]["enabled"])
        self.assertIsNone(parsed["hello"]["id"])
        self.assertIsNone(parsed["hello"]["interval_ms"])

    def test_all_capture_truncations_are_fatal(self):
        raw = frame(private_wire())
        for end in range(14, len(raw)):
            with self.subTest(end=end):
                parsed = EAPOLPacket.parse_frame(raw[:end])
                self.assertFalse(parsed["state_valid"])
                self.assertTrue(parsed["framing_errors"])
                self.assertEqual(parsed["raw"], raw[:end])

    def test_structural_errors_do_not_become_framing_errors(self):
        p = private_wire()
        for offset, value in ((6, 1), (116, 1), (121, 2), (122, 2),
                              (127, 2), (128, 2), (129, 0), (133, 0)):
            with self.subTest(offset=offset):
                broken = p[:offset] + bytes([value]) + p[offset + 1:]
                parsed = EAPOLPacket.parse_frame(frame(broken))
                self.assertTrue(parsed["framing_valid"])
                self.assertFalse(parsed["state_valid"])
                self.assertTrue(parsed["eap"]["private_properties"]["errors"])

    def test_hello_cannot_be_scanned_or_relocated(self):
        for p in (HELLO, bytes.fromhex("000013110000") + HELLO):
            props = parse_private_properties(p)
            self.assertIsNone(props["hello"])
            self.assertFalse(props["policy_valid"])

    def test_unknown_extension_is_preserved_without_rejecting_success(self):
        p = private_wire() + bytes.fromhex("00001311fe0378")
        parsed = EAPOLPacket.parse_frame(frame(p))
        props = parsed["eap"]["private_properties"]
        self.assertTrue(parsed["framing_valid"])
        self.assertTrue(parsed["state_valid"])
        self.assertFalse(props["policy_complete"])
        self.assertEqual(props["unsupported"][0]["type"], 0xFE)
        self.assertEqual(props["errors"], [])
        self.assertEqual(props["raw_remainder"], bytes.fromhex("00001311fe0378"))
        self.assertEqual(props["hello"]["id"], 0x11223344)

    def test_malformed_extension_is_not_merely_unsupported(self):
        for tail in (b"\x00", bytes.fromhex("00001311fe01"),
                     bytes.fromhex("00001311fe0478"), bytes.fromhex("00001312fe0278")):
            parsed = EAPOLPacket.parse_frame(frame(private_wire() + tail))
            self.assertTrue(parsed["framing_valid"])
            self.assertFalse(parsed["state_valid"])
            self.assertTrue(parsed["eap"]["private_properties"]["errors"])

    def test_private_bytes_outside_eapol_are_not_used(self):
        parsed = EAPOLPacket.parse_frame(frame(b"") + private_wire())
        self.assertTrue(parsed["state_valid"])
        self.assertEqual(parsed["eap"]["private_data"], b"")
        self.assertNotIn("private_properties", parsed["eap"])

    def test_bad_eap_lengths_are_fatal(self):
        p = private_wire()
        for length in (0, 1, 3, len(p) + 5):
            parsed = EAPOLPacket.parse_frame(frame(p, length))
            self.assertFalse(parsed["state_valid"])
            self.assertTrue(parsed["framing_errors"])

    def test_invalid_text_warning_does_not_block_valid_wire(self):
        parsed = EAPOLPacket.parse_frame(frame(private_wire(b"\xff")))
        self.assertTrue(parsed["warnings"])
        self.assertTrue(parsed["state_valid"])
        self.assertEqual(parsed["framing_errors"], [])


if __name__ == "__main__":
    unittest.main()
