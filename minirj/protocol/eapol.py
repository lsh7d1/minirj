"""
802.1X / EAPOL / EAP packet encapsulation and parser.

The parser deliberately keeps bytes outside each protocol's declared length.  A
capture can therefore be inspected without accidentally treating Ethernet
padding, a following packet, or malformed input as EAP data.
"""

import struct
from typing import NamedTuple, Optional

# EAPOL Types
EAPOL_EAPPACKET = 0
EAPOL_START = 1
EAPOL_LOGOFF = 2
EAPOL_KEY = 3
EAPOL_ASF_ALERT = 4
EAPOL_RUIJIE = 0xBF

# EAP Codes
EAP_CODE_REQUEST = 1
EAP_CODE_RESPONSE = 2
EAP_CODE_SUCCESS = 3
EAP_CODE_FAILURE = 4

# EAP Types
EAP_TYPE_IDENTITY = 1
EAP_TYPE_NOTIFICATION = 2
EAP_TYPE_NAK = 3
EAP_TYPE_MD5 = 4
EAP_TYPE_OTP = 5
EAP_TYPE_GTC = 6


class EAPHeader(NamedTuple):
    code: int
    req_id: int
    length: int
    type: Optional[int]
    type_data: bytes


class EAPOLPacket:
    """Encapsulates and parses 802.1X EAPOL Ethernet frames."""

    ETHERTYPE_8021X = 0x888E
    ETHERTYPE_VLAN = 0x8100
    ETHERTYPE_QINQ = 0x88A8
    VLAN_ETHERTYPES = (ETHERTYPE_VLAN, ETHERTYPE_QINQ)

    @classmethod
    def build_ethernet_frame(
        cls,
        src_mac: bytes,
        dst_mac: bytes,
        eapol_type: int,
        eap_payload: bytes = b"",
        vlan_tci: Optional[int] = None,
        vlan_ethertype: int = ETHERTYPE_VLAN,
    ) -> bytes:
        """Construct an Ethernet II frame, optionally with one VLAN tag.

        The original five positional parameters remain unchanged; VLAN support
        is exposed through optional trailing parameters.
        """
        if len(src_mac) != 6 or len(dst_mac) != 6:
            raise ValueError("source and destination MAC addresses must be 6 bytes")
        if not 0 <= eapol_type <= 0xFF:
            raise ValueError("EAPOL type must fit in one byte")
        if len(eap_payload) > 0xFFFF:
            raise ValueError("EAPOL payload is too large")

        eth_header = dst_mac + src_mac
        if vlan_tci is None:
            eth_header += struct.pack("!H", cls.ETHERTYPE_8021X)
        else:
            if not 0 <= vlan_tci <= 0xFFFF:
                raise ValueError("VLAN TCI must fit in two bytes")
            if vlan_ethertype not in cls.VLAN_ETHERTYPES:
                raise ValueError("unsupported VLAN EtherType")
            eth_header += struct.pack(
                "!HHH", vlan_ethertype, vlan_tci, cls.ETHERTYPE_8021X
            )

        eapol_header = struct.pack("!BBH", 1, eapol_type, len(eap_payload))
        return eth_header + eapol_header + eap_payload

    @classmethod
    def build_eap_start(
        cls,
        src_mac: bytes,
        dst_mac: bytes = b"\x01\x80\xc2\x00\x00\x03",
        *, vendor_data: bytes = b"",
    ) -> bytes:
        """Build an EAPOL-Start frame."""
        return cls.build_ethernet_frame(src_mac, dst_mac, EAPOL_START) + vendor_data

    @classmethod
    def build_eap_logoff(cls, src_mac: bytes, dst_mac: bytes, *, vendor_data: bytes = b"") -> bytes:
        """Build an EAPOL-Logoff frame."""
        return cls.build_ethernet_frame(src_mac, dst_mac, EAPOL_LOGOFF) + vendor_data

    @classmethod
    def build_eap_response_identity(
        cls, src_mac: bytes, dst_mac: bytes, req_id: int, username: str,
        *, vendor_data: bytes = b"",
    ) -> bytes:
        """Build an EAP-Response/Identity frame."""
        identity_bytes = username.encode("gb18030")
        eap_len = 5 + len(identity_bytes)
        eap_data = struct.pack(
            "!BBHB", EAP_CODE_RESPONSE, req_id, eap_len, EAP_TYPE_IDENTITY
        ) + identity_bytes
        return cls.build_ethernet_frame(
            src_mac, dst_mac, EAPOL_EAPPACKET, eap_data
        ) + vendor_data

    @classmethod
    def build_eap_response_nak(cls, src_mac: bytes, dst_mac: bytes, req_id: int) -> bytes:
        """RFC 3748 §5.3.1: legacy Nak; MD5 is our only implemented method."""
        payload = struct.pack("!BBHBB", EAP_CODE_RESPONSE, req_id, 6, EAP_TYPE_NAK, EAP_TYPE_MD5)
        return cls.build_ethernet_frame(src_mac, dst_mac, EAPOL_EAPPACKET, payload)

    @classmethod
    def build_eap_response_notification(cls, src_mac: bytes, dst_mac: bytes, req_id: int) -> bytes:
        """RFC 3748 §5.2: same Identifier, Type 2, zero octets of Type-Data."""
        payload = struct.pack("!BBHB", EAP_CODE_RESPONSE, req_id, 5, EAP_TYPE_NOTIFICATION)
        return cls.build_ethernet_frame(src_mac, dst_mac, EAPOL_EAPPACKET, payload)

    @classmethod
    def build_eap_response_md5(
        cls,
        src_mac: bytes,
        dst_mac: bytes,
        req_id: int,
        md5_digest: bytes,
        vendor_data: bytes = b"",
        *, username: str = "", vendor_in_eap: bool = False,
    ) -> bytes:
        """Build MD5 Value+Name; private trailer is outside EAP/EAPOL lengths."""
        if len(md5_digest) != 16:
            raise ValueError("EAP-MD5 digest must contain exactly 16 bytes")
        if vendor_in_eap:
            # ChangeToUChar@462b8c: non-Ruijie flat branch, 22+flat length,
            # no username. It is intentionally separate from legacy trailers.
            type_data = b"\x10" + md5_digest + vendor_data
            vendor_data = b""
        else:
            type_data = b"\x10" + md5_digest + username.encode("gb18030")
        eap_len = 5 + len(type_data)
        eap_data = struct.pack(
            "!BBHB", EAP_CODE_RESPONSE, req_id, eap_len, EAP_TYPE_MD5
        ) + type_data
        return cls.build_ethernet_frame(
            src_mac, dst_mac, EAPOL_EAPPACKET, eap_data
        ) + vendor_data

    @staticmethod
    def _parse_eap(body: bytes, warnings: list[str]) -> Optional[dict]:
        if len(body) < 4:
            warnings.append("truncated EAP header")
            return None

        code, req_id, declared_length = struct.unpack("!BBH", body[:4])
        if declared_length < 4:
            warnings.append("invalid EAP length below header size")
            packet = body[:4]
        else:
            packet = body[: min(declared_length, len(body))]
            if declared_length > len(body):
                warnings.append("truncated EAP packet")

        # Bytes after the EAP length are still inside the EAPOL body, but are
        # not part of EAP and must not be interpreted as type/private data.
        trailing = body[declared_length:] if declared_length <= len(body) else b""
        eap_type = None
        type_data = b""
        private_data = b""

        if code in (EAP_CODE_REQUEST, EAP_CODE_RESPONSE):
            if declared_length < 5:
                warnings.append("EAP Request/Response is missing its type byte")
            elif len(packet) >= 5:
                eap_type = packet[4]
                type_data = packet[5:]
        elif code in (EAP_CODE_SUCCESS, EAP_CODE_FAILURE):
            # ChangeToEAPOLFrame@0x42501b passes wire+22, EAPOL length-4.
            # EAP raw/trailing remain diagnostic views of the EAP declaration;
            # private_data intentionally includes EAP trailing, never Ethernet
            # trailing. This is not a general Request/Response exception.
            private_data = body[4:]
        else:
            warnings.append("unknown EAP code")

        if code in (EAP_CODE_REQUEST, EAP_CODE_RESPONSE) and declared_length != len(body):
            warnings.append("EAP and EAPOL lengths disagree")

        result = {
            "code": code,
            "req_id": req_id,
            "length": declared_length,
            "type": eap_type,
            "type_data": type_data,
            "private_data": private_data,
            "trailing": trailing,
            "raw": packet,
        }

        if private_data:
            try:
                from .private_property import parse_private_properties

                result["private_properties"] = parse_private_properties(private_data)
            except (ImportError, ValueError):
                # Framing remains useful even if an optional private decoder is
                # unavailable or the bytes are not a private-property stream.
                result["private_properties"] = None

        return result

    @classmethod
    def parse_frame(cls, raw_frame: bytes) -> Optional[dict]:
        """Parse one Ethernet/EAPOL frame without reading past declared lengths.

        Non-EAPOL Ethernet frames return ``None``.  Once an EAPOL EtherType is
        identified, malformed/truncated data is returned with ``warnings`` so
        callers retain MAC/VLAN metadata and all available bytes.
        """
        if len(raw_frame) < 14:
            return None

        dst_mac = raw_frame[0:6]
        src_mac = raw_frame[6:12]
        outer_eth_type = struct.unpack("!H", raw_frame[12:14])[0]
        eth_type = outer_eth_type
        eapol_offset = 14
        vlan = None

        if outer_eth_type in cls.VLAN_ETHERTYPES:
            if len(raw_frame) < 18:
                return None
            vlan_tci, eth_type = struct.unpack("!HH", raw_frame[14:18])
            vlan = {
                "ethertype": outer_eth_type,
                "tci": vlan_tci,
                "pcp": (vlan_tci >> 13) & 0x07,
                "dei": (vlan_tci >> 12) & 0x01,
                "vid": vlan_tci & 0x0FFF,
            }
            eapol_offset = 18

        if eth_type != cls.ETHERTYPE_8021X:
            return None

        warnings: list[str] = []
        result = {
            "dst_mac": dst_mac,
            "src_mac": src_mac,
            "ethertype": eth_type,
            "outer_ethertype": outer_eth_type,
            "vlan": vlan,
            "vlan_tci": vlan["tci"] if vlan else None,
            "eapol_ver": None,
            "eapol_type": None,
            "eapol_length": None,
            "eapol_body": b"",
            "private_data": b"",
            "eap": None,
            "trailing": b"",
            "warnings": warnings,
            "raw": bytes(raw_frame),
            "framing_errors": [],
            "framing_valid": False,
            "state_valid": False,
            "framing_kind": "standard",
        }

        if len(raw_frame) < eapol_offset + 4:
            warnings.append("truncated EAPOL header")
            result["framing_errors"] = list(warnings)
            result["trailing"] = raw_frame[eapol_offset:]
            return result

        eapol_ver, eapol_type, eapol_len = struct.unpack(
            "!BBH", raw_frame[eapol_offset : eapol_offset + 4]
        )
        body_start = eapol_offset + 4
        available = raw_frame[body_start:]
        body = available[:eapol_len]
        trailing = available[eapol_len:] if eapol_len <= len(available) else b""
        # Constructor@0x4452a0 emits 27 encoded bytes but declares 30.
        # Recognize its exact static shape, not arbitrary short 0xBF traffic.
        if eapol_ver == 1 and eapol_type == EAPOL_RUIJIE and eapol_len == 30 and len(available) >= 27:
            from .hello import HelloCodec

            plain = HelloCodec.decode(available[:27])
            prefix = b"\x00\x00\x13\x11\x01\x06"
            if (plain[:6] == prefix and plain[10:16] == prefix
                    and plain[20:] == b"\x00\x00\x13\x11\x01\x03\x00"):
                result["framing_kind"] = "ruijie_hello_tx"
                result["hello_tx_decoded"] = plain
                body, trailing = available[:27], available[27:]
        if eapol_len > len(available) and result["framing_kind"] == "standard":
            warnings.append("truncated EAPOL body")

        result.update(
            {
                "eapol_ver": eapol_ver,
                "eapol_type": eapol_type,
                "eapol_length": eapol_len,
                "eapol_body": body,
                "trailing": trailing,
            }
        )

        if eapol_type == EAPOL_EAPPACKET:
            result["eap"] = cls._parse_eap(body, warnings)
        elif eapol_type == EAPOL_RUIJIE:
            # The 0xBF receive branch is not ParsePrivateProperty. In particular
            # a transmitted Hello body must never become Success policy.
            result["private_data"] = body

        result["framing_errors"] = list(warnings)
        result["framing_valid"] = not result["framing_errors"]
        eap = result["eap"]
        private = (eap or {}).get("private_properties")
        if private:
            warnings.extend(private["warnings"])
        result["state_valid"] = bool(
            result["framing_valid"] and eap is not None
            and (not eap["private_data"] or (private and private["policy_valid"]))
        )
        return result
