import struct
import unittest

from minirj.protocol.private_property import (
    PRIVATE_PROPERTY_MAGIC,
    parse_private_properties,
)


class TestPrivateProperty(unittest.TestCase):
    def test_first_message_is_bounded_and_decoded_as_gbk(self):
        message = "认证成功".encode("gbk")
        raw = struct.pack("!IH", PRIVATE_PROPERTY_MAGIC, len(message)) + message
        parsed = parse_private_properties(raw)
        self.assertEqual(parsed["magic"], PRIVATE_PROPERTY_MAGIC)
        self.assertEqual(parsed["message"], "认证成功")
        self.assertEqual(parsed["message_raw"], message)
        self.assertEqual(parsed["raw_remainder"], b"")

    def test_magic_and_lengths_are_network_byte_order(self):
        message = "欢迎".encode("gbk")
        raw = struct.pack("<IH", PRIVATE_PROPERTY_MAGIC, len(message)) + message
        parsed = parse_private_properties(raw)
        self.assertIsNone(parsed["magic"])
        self.assertEqual(parsed["raw_remainder"], raw)

    def test_message_length_does_not_consume_remainder(self):
        raw = struct.pack("!IH", PRIVATE_PROPERTY_MAGIC, 2) + b"ok" + b"tail"
        parsed = parse_private_properties(raw)
        self.assertEqual(parsed["message"], "ok")
        self.assertEqual(parsed["raw_remainder"], b"tail")
        self.assertEqual(parsed["unknown"][0]["raw"], b"tail")

    def test_truncated_message_warns_and_keeps_available_raw(self):
        raw = struct.pack("!IH", PRIVATE_PROPERTY_MAGIC, 10) + b"abc"
        parsed = parse_private_properties(raw)
        self.assertEqual(parsed["message_raw"], b"abc")
        self.assertIn("truncated private message", parsed["warnings"])

    def test_hello_result_is_reserved_and_unknown_remainder_is_kept(self):
        raw = struct.pack("!IH", PRIVATE_PROPERTY_MAGIC, 2) + b"ok" + b"encoded-hello"
        parsed = parse_private_properties(raw)
        self.assertIn("hello", parsed)
        self.assertIsNone(parsed["hello"])
        self.assertEqual(parsed["raw_remainder"], b"encoded-hello")
        self.assertEqual(parsed["unknown"][0]["raw"], b"encoded-hello")

    def test_native_object_layout_is_not_wire(self):
        # Historical fixture represented native +0x648, not wire evidence.
        for enabled in (0, 1):
            native = struct.pack("<IBB2xII", PRIVATE_PROPERTY_MAGIC, 0x0A,
                                 enabled, 0x11223344, 30)
            for prefix in (b"", bytes.fromhex("000013110000")):
                parsed = parse_private_properties(prefix + native)
                self.assertIsNone(parsed["hello"])
                self.assertFalse(parsed["policy_valid"])
                self.assertEqual(parsed["raw"], prefix + native)

    def test_invalid_gbk_is_diagnostic_not_policy_error(self):
        parsed = parse_private_properties(bytes.fromhex("000013110001ff"))
        self.assertTrue(parsed["warnings"])
        self.assertEqual(parsed["errors"], [])
        self.assertTrue(parsed["policy_valid"])

    def test_embedded_nul_preserves_wire_and_ends_display(self):
        parsed = parse_private_properties(bytes.fromhex("000013110004") + b"a\x00bc")
        self.assertEqual(parsed["message"], "a")
        self.assertEqual(parsed["message_raw"], b"a\x00bc")

    def test_unknown_and_bad_magic_are_preserved(self):
        parsed = parse_private_properties(b"\xde\xad\xbe\xefunknown")
        self.assertIsNone(parsed["magic"])
        self.assertEqual(parsed["raw_remainder"], b"\xde\xad\xbe\xefunknown")
        self.assertEqual(parsed["unknown"][0]["raw"], parsed["raw"])

    def test_short_inputs_never_raise_index_error(self):
        for size in range(6):
            with self.subTest(size=size):
                parsed = parse_private_properties(b"\x11" * size)
                self.assertTrue(parsed["warnings"])


if __name__ == "__main__":
    unittest.main()
