"""Synthetic wire fixtures; ELF ParsePrivateProperty dispatch is the authority.

No captured server values. 0x463738 subtracts two from the wire length.
Known dispatch entries: 3c=46386d, 3d=46391e, 56=4639f2, 5a=463b46,
5b=463b97, 5c=463be2, 5d=463cb4, 5e=463d86, 66=463f37,
6e=46420a, 79=46424c, 80=46429f. 98 skips at 4644ba.
"""
import unittest

from minirj.protocol.eapol import EAPOLPacket
from minirj.protocol.tlv import ServerTLVDecoder
from test_success_wire import private_wire, frame

MAGIC = bytes.fromhex("00001311")


def extension(kind, payload):
    return MAGIC + bytes((kind, len(payload) + 2)) + payload


# Public, invented fixtures, never a real endpoint, key, or account.
FIELDS = (
    (60, b"account"), (61, b"person"), (86, bytes.fromhex("0000003c")),
    (90, bytes.fromhex("0000181b")), (91, bytes((192, 0, 2, 1))),
    (92, b"fixtureK"), (93, b"fixtureI"),
    (94, bytes.fromhex("0102030405060708")),
    (102, b"a@b"), (110, bytes.fromhex("00000050")),
    (121, bytes((2,))), (128, bytes.fromhex("00000001")),
)


def parsed_fields(fields=FIELDS):
    private = private_wire() + b"".join(extension(k, v) for k, v in fields)
    return EAPOLPacket.parse_frame(frame(private, 4 + len(private)))


class TestSuccessLegacyExtensions(unittest.TestCase):
    def test_known_wire_fields_reach_existing_server_decoder(self):
        parsed = parsed_fields()
        props = parsed["eap"]["private_properties"]
        self.assertTrue(parsed["state_valid"])
        self.assertTrue(props["policy_complete"])
        self.assertEqual(props["unsupported"], [])
        self.assertEqual(props["unknown"], [])
        self.assertEqual(props["raw_remainder"], b"")
        values = props["server_tlvs"]
        self.assertEqual(values["account_info"], "account")
        self.assertEqual(values["personal_info"], "person")
        self.assertEqual(values["reauth_interval"], 60)
        self.assertEqual(values["indicate_port"], 6171)
        self.assertEqual(values["indicate_server_ip"], "192.0.2.1")
        self.assertEqual(values["server_utc_time"], bytes.fromhex("0102030405060708"))
        self.assertEqual(values["server_list"], ["a", "b"])
        self.assertEqual(values["message_client_port"], 80)
        self.assertEqual(values["direct_communication_highest_version"], 2)
        self.assertEqual(values["direct_communication_heartbeat_flags"], 1)
        # Existing independently specified decoder is the adapter oracle,
        # including RC4. Production wire builder is never used for expectations.
        expected = ServerTLVDecoder.decode(b"".join(bytes((k, len(v))) + v for k, v in FIELDS))
        self.assertEqual(values, expected)
        self.assertEqual([(r.type, r.payload) for r in values.records], list(FIELDS))
        self.assertEqual(props["message"], "")
        self.assertEqual(props["hello"]["interval_ms"], 30000)

    def test_442_byte_shape_decodes_twelve_and_retains_unknown_152(self):
        # Only type/offset/length match the reported observation. All values
        # below are invented, including the message and variable-length text.
        fields = list(FIELDS)
        fields[0] = (60, b"A" * 117)
        fields[1] = (61, b"B" * 9)
        fields[8] = (102, b"a@b@c@d@e")
        fields.append((152, b"????"))
        private = private_wire(b"synthetic-only") + b"".join(extension(k, v) for k, v in fields)
        raw = frame(private, 424)
        self.assertEqual(len(raw), 442)
        self.assertEqual(raw[16:18], bytes.fromhex("01a8"))
        parsed = EAPOLPacket.parse_frame(raw)
        props = parsed["eap"]["private_properties"]
        self.assertTrue(parsed["state_valid"])
        self.assertEqual(props["errors"], [])
        self.assertFalse(props["policy_complete"])
        self.assertEqual([(r["type"], r["offset"]) for r in props["unsupported"]], [(152, 410)])
        self.assertEqual([(r["type"], r["offset"]) for r in props["unknown"]], [(152, 410)])
        self.assertEqual(props["unknown"][0]["raw"], extension(152, b"????"))
        self.assertEqual(props["raw_remainder"], extension(152, b"????"))
        extensions = [r for r in props["properties"] if r["kind"] == "server_tlv"]
        self.assertEqual([r["offset"] for r in extensions],
                         [158, 281, 296, 306, 316, 326, 340, 354, 368, 383, 393, 400])
        self.assertEqual([r.type for r in props["server_tlvs"].records],
                         [60, 61, 86, 90, 91, 92, 93, 94, 102, 110, 121, 128])

    def test_unknown_does_not_hide_following_known_or_mean_complete(self):
        for kind in (0, 5, 152, 254):
            with self.subTest(kind=kind):
                fields = ((kind, b"?"), (90, bytes.fromhex("0000181b")))
                parsed = parsed_fields(fields)
                props = parsed["eap"]["private_properties"]
                self.assertTrue(parsed["state_valid"])
                self.assertFalse(props["policy_complete"])
                self.assertEqual(props["server_tlvs"]["indicate_port"], 6171)
                self.assertEqual(len(props["unknown"]), 1)
                self.assertEqual(props["unknown"][0]["raw"], extension(kind, b"?"))

    def test_bad_known_lengths_are_errors_not_unsupported(self):
        for kind, payload in FIELDS:
            if kind in (60, 61, 102):
                continue
            for bad in (payload[:-1], payload + b"x"):
                with self.subTest(kind=kind, length=len(bad)):
                    parsed = parsed_fields(((kind, bad),))
                    props = parsed["eap"]["private_properties"]
                    self.assertFalse(parsed["state_valid"])
                    self.assertFalse(props["policy_valid"])
                    self.assertFalse(props["policy_complete"])
                    self.assertTrue(props["errors"])
                    self.assertEqual(props["unsupported"], [])
                    self.assertEqual(props["server_tlvs"].records, [])

    def test_tail_is_atomic_on_error_and_never_scans_for_magic(self):
        valid = extension(90, bytes.fromhex("0000181b"))
        for bad in (b"x", MAGIC + bytes((90, 1)),
                    MAGIC + bytes((90, 6)) + b"x", b"BAD!" + bytes((90, 2))):
            parsed = EAPOLPacket.parse_frame(frame(private_wire() + valid + bad))
            props = parsed["eap"]["private_properties"]
            self.assertFalse(parsed["state_valid"])
            self.assertFalse(props["policy_complete"])
            self.assertEqual(props["server_tlvs"].records, [])
            self.assertFalse(any(r["kind"] == "server_tlv" for r in props["properties"]))
