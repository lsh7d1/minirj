import struct
import unittest

from minirj.protocol.hello import HelloCodec


SRC = b"\x00\x11\x22\x33\x44\x55"

# GDB oracle at main, calling encode(0x00..0x1a, 27) @ 0x45d560.
ENCODE_ORACLE = bytes.fromhex(
    "ff 7f bf 3f df 5f 9f 1f ef 6f af 2f cf 4f 8f 0f "
    "f7 77 b7 37 d7 57 97 17 e7 67 a7"
)

# GDB oracle for CreateHelloPacket @ 0x4452a0 with:
#   CtrlThread+0x550 = 01:d0:f8:00:00:03
#   CtrlThread+0x2b0 = 00:11:22:33:44:55
#   sequence(+0x1f0) = 0x01020304, offset(+0x1d8) = 0x10203040
#   history_index(+0x1ec) = 0, e_pHelloID[0:16] = 0x74
HELLO_ORACLE = bytes.fromhex(
    "01 d0 f8 00 00 03 00 11 22 33 44 55 88 8e 01 bf 00 1e "
    "ff ff 37 77 7f 9f 77 bb 33 5d ff ff 37 77 7f 9f 7f bf "
    "3f 5f ff ff 37 77 7f 3f ff"
)


class TestHelloCodec(unittest.TestCase):
    def test_encode_matches_controlled_gdb_oracle(self):
        plain = bytes(range(27))
        self.assertEqual(HelloCodec.encode(plain), ENCODE_ORACLE)
        self.assertEqual(HelloCodec.decode(ENCODE_ORACLE), plain)

    def test_create_packet_matches_controlled_gdb_oracle(self):
        codec = HelloCodec(SRC, sequence=0x01020304, offset=0x10203040)
        self.assertEqual(codec.build(), HELLO_ORACLE)
        self.assertEqual(codec.sequence, 0x01020305)
        self.assertEqual(codec.history_index, 1)

    def test_fixed_header_and_plain_dynamic_fields(self):
        codec = HelloCodec(SRC, sequence=0x01020304, offset=0x10203040)
        frame = codec.build()

        self.assertEqual(len(frame), 45)
        self.assertEqual(frame[:6], HelloCodec.INITIAL_DST_MAC)
        self.assertEqual(frame[6:12], SRC)
        self.assertEqual(frame[12:18], bytes.fromhex("88 8e 01 bf 00 1e"))

        plain = HelloCodec.decode(frame[18:45])
        self.assertEqual(len(plain), 27)
        self.assertEqual(plain[:6], bytes.fromhex("00 00 13 11 01 06"))
        self.assertEqual(struct.unpack("!I", plain[6:10])[0], 0x11223345)
        self.assertEqual(plain[10:16], bytes.fromhex("00 00 13 11 01 06"))
        self.assertEqual(struct.unpack("!I", plain[16:20])[0], 0x01020305)
        self.assertEqual(plain[20:], bytes.fromhex("00 00 13 11 01 03 00"))

    def test_destination_models_target_global_and_can_be_overridden(self):
        learned_peer = bytes.fromhex("66 77 88 99 aa bb")
        frame = HelloCodec(
            SRC,
            dst_mac=learned_peer,
            sequence=0,
            offset=0,
        ).build()
        self.assertEqual(frame[:6], learned_peer)

    def test_non_sentinel_history_value_is_propagated_and_affects_counter(self):
        hello_ids = [0x75] + [HelloCodec.HELLO_ID_SENTINEL] * 15
        codec = HelloCodec(
            SRC,
            sequence=0x1000,
            offset=0,
            hello_ids=hello_ids,
        )
        plain = HelloCodec.decode(codec.build()[18:45])

        self.assertEqual(struct.unpack("!I", plain[6:10])[0], 0x1001)
        self.assertEqual(struct.unpack("!I", plain[16:20])[0], 0x1000)
        self.assertEqual(codec.hello_ids, [0x75] * 16)

    def test_sequence_seed_matches_initinstance_formula(self):
        self.assertEqual(HelloCodec.sequence_seed_from_rand(0), 0x1001)
        self.assertEqual(HelloCodec.sequence_seed_from_rand(0x1001), 0x1001)
        self.assertEqual(HelloCodec.sequence_seed_from_rand(0x1000), 0x2001)

    def test_state_inputs_are_validated_instead_of_guessed(self):
        with self.assertRaises(ValueError):
            HelloCodec(b"short", sequence=0, offset=0)
        with self.assertRaises(ValueError):
            HelloCodec(SRC, sequence=-1, offset=0)
        with self.assertRaises(ValueError):
            HelloCodec(SRC, sequence=0, offset=0, hello_ids=[0x74])
        with self.assertRaises(ValueError):
            HelloCodec(SRC, sequence=0, offset=0, history_index=16)


if __name__ == "__main__":
    unittest.main()
