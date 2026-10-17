import struct
import unittest

from minirj.protocol.tlv import (
    RC4_STATIC_KEY,
    ServerTLVDecoder,
    _rc4_crypt,
)


def tlv(tlv_type, payload):
    return bytes((tlv_type, len(payload))) + payload


class TestServerTLV(unittest.TestCase):
    def test_rc4_matches_independent_published_fixed_vector(self):
        # Standard RC4 vector: key "Key", plaintext "Plaintext".
        self.assertEqual(_rc4_crypt(b"Plaintext", b"Key").hex(), "bbf316e8d940af0ad3")
        self.assertEqual(RC4_STATIC_KEY, b"com.ruijie.www")
        self.assertEqual(ServerTLVDecoder.RC4_STATIC_KEY, b"com.ruijie.www")

    def test_decodes_all_read_rg_vendor_seg_properties_in_network_order(self):
        upgrade_url = b"https://upgrade.example/rg".ljust(0xF7, b"\x00")
        encrypted_key = bytes.fromhex("0011223344556677")
        encrypted_iv = bytes.fromhex("8899aabbccddeeff")
        packet = b"".join(
            (
                tlv(0x05, struct.pack("!I", 0x01020304)),
                tlv(0x14, struct.pack("!I", 1)),
                tlv(0x15, struct.pack("!I", 2)),
                tlv(0x37, upgrade_url),
                tlv(0x3C, "账户信息".encode("gb18030")),
                tlv(0x3D, "个人信息".encode("gb18030")),
                tlv(0x52, "广播".encode("gb18030")),
                tlv(0x53, "系统".encode("gb18030")),
                tlv(0x56, struct.pack("!I", 300)),
                tlv(0x59, struct.pack("!I", 30)),
                tlv(0x5A, struct.pack("!I", 3850)),
                tlv(0x5B, bytes((192, 0, 2, 7))),
                tlv(0x5C, encrypted_key),
                tlv(0x5D, encrypted_iv),
                tlv(0x5E, bytes.fromhex("0102030405060708")),
                tlv(0x61, b"\x09"),
                tlv(0x66, "联通@电信@校园网".encode("gb18030")),
                tlv(0x68, b"https://login.example/"),
                tlv(0x6E, struct.pack("!I", 61440)),
                tlv(0x72, "https://utrust.example/".encode("gb18030")),
                tlv(0x74, struct.pack("!I", 0xAABBCCDD)),
                tlv(0x77, b"\x01" + struct.pack("!H", 513)),
                tlv(0x79, b"\x02"),
                tlv(0x80, struct.pack("!I", 0x80000001)),
            )
        )

        decoded = ServerTLVDecoder.decode(packet)
        self.assertEqual(decoded["newest_version"], 0x01020304)
        self.assertEqual(decoded["proxy_avoid"], 1)
        self.assertEqual(decoded["dialup_avoid"], 2)
        self.assertEqual(decoded["upgrade_url"], "https://upgrade.example/rg")
        self.assertEqual(decoded["account_info"], "账户信息")
        self.assertEqual(decoded["personal_info"], "个人信息")
        self.assertEqual(decoded["broadcast_info"], "广播")
        self.assertEqual(decoded["system_info"], "系统")
        self.assertEqual(decoded["reauth_interval"], 300)
        self.assertEqual(decoded["hello_interval"], 30)
        self.assertEqual(decoded["heartbeat_interval"], 30)
        self.assertEqual(decoded["indicate_port"], 3850)
        self.assertEqual(decoded["indicate_server_ip"], "192.0.2.7")
        self.assertEqual(decoded["encrypt_key"], _rc4_crypt(encrypted_key, RC4_STATIC_KEY))
        self.assertEqual(decoded["encrypt_iv"], _rc4_crypt(encrypted_iv, RC4_STATIC_KEY))
        self.assertEqual(decoded["server_utc_time"], bytes.fromhex("0102030405060708"))
        self.assertEqual(decoded["radius_server_type"], 9)
        self.assertEqual(decoded["server_list"], ["联通", "电信", "校园网"])
        self.assertEqual(decoded["user_login_url"], "https://login.example/")
        self.assertEqual(decoded["message_client_port"], 61440)
        self.assertEqual(decoded["utrust_url"], "https://utrust.example/")
        self.assertEqual(decoded["proxy_detect_kinds"], 0xAABBCCDD)
        self.assertEqual(decoded["utrust_display"], {"show": 1, "delay_seconds": 513})
        self.assertEqual(decoded["direct_communication_highest_version"], 2)
        self.assertEqual(decoded["direct_communication_heartbeat_flags"], 0x80000001)

    def test_unknown_and_duplicate_tlvs_are_preserved(self):
        packet = b"".join(
            (
                tlv(0x14, struct.pack("!I", 1)),
                tlv(0x90, b"first"),
                tlv(0x14, struct.pack("!I", 2)),
                tlv(0x90, b"second"),
            )
        )
        decoded = ServerTLVDecoder.decode(packet)
        self.assertEqual(decoded["proxy_avoid"], 2)
        self.assertEqual(decoded.getall("proxy_avoid"), [1, 2])
        self.assertEqual(decoded.getall(0x90), [b"first", b"second"])
        self.assertEqual([record.payload for record in decoded.unknown], [b"first", b"second"])
        self.assertEqual([record.type for record in decoded.records], [0x14, 0x90, 0x14, 0x90])

    def test_rejects_truncation_and_invalid_known_lengths(self):
        packets = (
            b"\x14",
            b"\x14\x04\x00\x00",
            tlv(0x05, b"\x00"),
            tlv(0x37, b"short"),
            tlv(0x5C, b"1234567"),
            tlv(0x61, b""),
            tlv(0x77, b"\x01\x00"),
            tlv(0x79, b"\x01\x02"),
            tlv(0x80, b"\x00\x00\x00"),
        )
        for packet in packets:
            with self.subTest(packet=packet), self.assertRaises(ValueError):
                ServerTLVDecoder.decode(packet)

    def test_terminators_stop_without_consuming_following_bytes(self):
        prefix = tlv(0x59, struct.pack("!I", 15))
        self.assertEqual(
            ServerTLVDecoder.decode(prefix + b"\x00\x00garbage")["hello_interval"], 15
        )
        self.assertEqual(
            ServerTLVDecoder.decode(prefix + b"\x99\xffgarbage")["hello_interval"], 15
        )

    def test_rejects_oversized_server_segment(self):
        with self.assertRaisesRegex(ValueError, "exceeds"):
            ServerTLVDecoder.decode(b"\x01\x00" * ((0x578 // 2) + 1))


if __name__ == "__main__":
    unittest.main()
