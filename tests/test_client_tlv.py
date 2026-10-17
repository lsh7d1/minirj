import hashlib
import unittest

from minirj.protocol.tlv import ClientTLVEncoder, PEAP_CHALLENGE


class DummyV3:
    def __init__(self, old_api=False):
        self.old_api = old_api
        self.challenges = []

    def generate(self, challenge):
        self.challenges.append(challenge)
        payload = b"a" * 128
        return b"\x00\x00" + payload if self.old_api else payload


def parse_tlvs(data):
    records = []
    offset = 0
    while offset < len(data):
        tlv_type, length = data[offset : offset + 2]
        payload = data[offset + 2 : offset + 2 + length]
        if len(payload) != length:
            raise AssertionError("truncated test TLV")
        records.append((tlv_type, payload))
        offset += length + 2
    return records


def radius_unhide(ciphertext, authenticator, secret):
    plaintext = bytearray()
    previous = authenticator
    for offset in range(0, len(ciphertext), 16):
        block = ciphertext[offset : offset + 16]
        stream = hashlib.md5(secret + previous).digest()
        plaintext.extend(a ^ b for a, b in zip(block, stream))
        previous = block
    return bytes(plaintext).rstrip(b"\x00")


def make_encoder(v3, **overrides):
    arguments = dict(
        username="student",
        password="secret",
        service_name="campus",
        client_ver="RG_SU_For_Windows 6.84",
        client_version=(6, 84, 0, 0),
        program_name="8021x.exe",
        fake_ip="192.0.2.10",
        fake_mask="255.255.255.0",
        fake_gw="192.0.2.1",
        fake_dns="192.0.2.53",
        dhcp_mode=0,
        mac_address="00:11:22:33:44:55",
        hard_disk_sn="DISK-1",
        security_check_result=1,
        v3_generator=v3,
    )
    arguments.update(overrides)
    return ClientTLVEncoder(**arguments)


class TestClientTLV(unittest.TestCase):
    def test_normal_profile_order_and_payload_only_v3_compatibility(self):
        challenge = bytes(range(16))
        v3 = DummyV3(old_api=True)
        encoder = make_encoder(v3)
        records = parse_tlvs(encoder.encode(challenge))

        self.assertEqual(
            [tlv_type for tlv_type, _ in records],
            [0x11, 0x50, 0x2D, 0x39, 0x2F, 0x76, 0x4D, 0x54,
             0x62, 0x6B, 0x7E, 0x70, 0x6F, 0x79],
        )
        by_type = dict(records)
        self.assertEqual(len(by_type[0x11]), 0x24)
        self.assertEqual(by_type[0x11][:32], b"8021x.exe".ljust(32, b"\x00"))
        self.assertEqual(by_type[0x11][-4:], bytes((6, 84, 0, 0)))
        self.assertEqual(len(by_type[0x50]), 0x11)
        self.assertEqual(by_type[0x2D], bytes.fromhex("001122334455"))
        self.assertEqual(len(by_type[0x39]), 0x20)
        self.assertEqual(radius_unhide(by_type[0x2F], challenge, b"student"), b"secret")
        self.assertEqual(by_type[0x4D], b"a" * 128)
        self.assertEqual(by_type[0x62], b"\x01")
        self.assertEqual(by_type[0x6B], b"\x00")
        self.assertEqual(by_type[0x7E], bytes.fromhex("0000010000040000"))
        self.assertEqual(by_type[0x70], b"\x40")
        self.assertEqual(by_type[0x6F], b"RG_SU_For_Windows 6.84\x00")
        self.assertEqual(by_type[0x79], b"\x02")
        self.assertEqual(v3.challenges, [challenge])

    def test_normal_optional_fields_stay_in_decompiled_order(self):
        encoder = make_encoder(
            DummyV3(),
            dhcp_auth_phase=2,
            ipv6_tlvs=b"\x35\x01\x01\x36\x10" + b"\x00" * 16,
            security_domain="secure.example",
        )
        types = [tlv_type for tlv_type, _ in parse_tlvs(encoder.encode(bytes(range(16))))]
        self.assertEqual(
            types,
            [0x11, 0x50, 0x2D, 0x63, 0x35, 0x36, 0x39, 0x2F, 0x76,
             0x4D, 0x54, 0x55, 0x62, 0x6B, 0x7E, 0x70, 0x6F, 0x79],
        )

    def test_peap_has_independent_5f_60_profile_and_fixed_challenge(self):
        v3 = DummyV3()
        encoder = make_encoder(v3)
        records = parse_tlvs(encoder.encode_peap())
        types = [tlv_type for tlv_type, _ in records]

        self.assertEqual(
            types,
            [0x11, 0x50, 0x2D, 0x39, 0x76, 0x5F, 0x60, 0x54, 0x62, 0x79],
        )
        self.assertNotIn(0x2F, types)
        self.assertNotIn(0x4D, types)
        self.assertNotIn(0x70, types)
        self.assertNotIn(0x6F, types)
        by_type = dict(records)
        self.assertEqual(radius_unhide(by_type[0x5F], PEAP_CHALLENGE, b"student"), b"secret")
        self.assertEqual(by_type[0x60], b"a" * 128)
        self.assertEqual(v3.challenges, [PEAP_CHALLENGE])


if __name__ == "__main__":
    unittest.main()
