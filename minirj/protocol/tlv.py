"""Ruijie private TLV encoder/decoder.

The wire format is a sequence of ``type:u8, length:u8, payload:length``
records.  The client layout follows ``EncapRGVerdorSeg*`` and the server
layout follows ``ReadRGVendorSeg`` from the bundled client.
"""

from __future__ import annotations

import ipaddress
import re
import struct
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional, Tuple, Union

from ..crypto.radius_pwd import encrypt_ruijie_password, hide_radius_password
from ..crypto.v3 import V3Generator


PEAP_CHALLENGE = b"!jierui9002pmsus"
RC4_STATIC_KEY = b"com.ruijie.www"


def _rc4_crypt(data: bytes, key: bytes) -> bytes:
    """Apply the standard RC4 KSA/PRGA transform."""
    if not key:
        raise ValueError("RC4 key must not be empty")

    state = list(range(256))
    j = 0
    for i in range(256):
        j = (j + state[i] + key[i % len(key)]) & 0xFF
        state[i], state[j] = state[j], state[i]

    i = j = 0
    output = bytearray()
    for byte in data:
        i = (i + 1) & 0xFF
        j = (j + state[i]) & 0xFF
        state[i], state[j] = state[j], state[i]
        output.append(byte ^ state[(state[i] + state[j]) & 0xFF])
    return bytes(output)


def _tlv(tlv_type: int, payload: bytes) -> bytes:
    if not 0 < tlv_type <= 0xFF:
        raise ValueError(f"invalid TLV type: {tlv_type!r}")
    if len(payload) > 0xFE:
        # 0xff is the terminator/error length in ReadRGVendorSeg.
        raise ValueError(f"TLV 0x{tlv_type:02x} payload is too long: {len(payload)}")
    return bytes((tlv_type, len(payload))) + payload


def _encode_text(value: Union[str, bytes], encoding: str = "gb18030") -> bytes:
    return value if isinstance(value, bytes) else value.encode(encoding)


class ClientTLVEncoder:
    """Build the normal EAP-MD5 or PEAP Ruijie client profile.

    ``encode(challenge)`` remains compatible with the current state machine.
    Additional constructor arguments expose fields that the state machine does
    not yet collect, without requiring changes outside this module.
    """

    def __init__(
        self,
        username: str,
        password: str,
        service_name: str = "internet",
        client_ver: str = "RG_SU_For_Windows 6.84",
        fake_ip: str = "0.0.0.0",
        fake_mask: str = "0.0.0.0",
        fake_gw: str = "0.0.0.0",
        fake_dns: str = "0.0.0.0",
        dhcp_mode: int = 1,
        *,
        mac_address: Union[str, bytes] = b"\x00" * 6,
        dhcp_auth_phase: int = 0,
        alternate_dns: Union[str, bytes] = b"",
        ipv6_tlvs: bytes = b"",
        ipv6_address: str = "",
        ipv6_link_local: str = "",
        ipv6_gateway: str = "",
        ipv6_prefix_len: int = 0,
        hard_disk_sn: Union[str, bytes] = "Static:AB45A862",
        security_domain: Union[str, bytes] = b"",
        security_check_result: Union[bool, int] = 1,
        security_probe: int = 0,
        os_code: int = 4,
        os_bits: int = 64,
        direct_communication_version: int = 2,
        program_name: str = "8021x.exe",
        v3_generator: Optional[Any] = None,
        client_version: Optional[Tuple[int, int, int, int]] = (6, 84, 0, 0),
    ) -> None:
        self.username = username
        self.password = password
        self.service_name = service_name
        self.client_ver = client_ver
        if client_version is not None and (
            not isinstance(client_version, (tuple, list)) or len(client_version) != 4
            or any(type(v) is not int or not 0 <= v <= 255 for v in client_version)
        ):
            raise ValueError("client_version must contain four integer bytes")
        self.client_version = tuple(client_version) if client_version is not None else None
        self.fake_ip = fake_ip
        self.fake_mask = fake_mask
        self.fake_gw = fake_gw
        self.fake_dns = fake_dns
        self.dhcp_mode = dhcp_mode
        self.mac_address = mac_address
        self.dhcp_auth_phase = dhcp_auth_phase
        self.alternate_dns = alternate_dns
        self.ipv6_tlvs = bytes(ipv6_tlvs)
        self.ipv6_address = ipv6_address
        self.ipv6_link_local = ipv6_link_local
        self.ipv6_gateway = ipv6_gateway
        self.ipv6_prefix_len = int(ipv6_prefix_len)
        self.hard_disk_sn = hard_disk_sn
        self.security_domain = security_domain
        self.security_check_result = int(bool(security_check_result))
        self.security_probe = int(security_probe) & 0xFF
        self.os_code = int(os_code) & 0xFF
        self.os_bits = os_bits
        self.direct_communication_version = direct_communication_version
        self.program_name = program_name
        self.v3_gen = v3_generator if v3_generator is not None else V3Generator()

    @staticmethod
    def _ip_to_bytes(value: str) -> bytes:
        try:
            return ipaddress.IPv4Address(value).packed
        except ipaddress.AddressValueError as exc:
            raise ValueError(f"invalid IPv4 address: {value!r}") from exc

    @staticmethod
    def _ip6_to_bytes(value: str) -> bytes:
        if not value:
            return bytes(16)
        try:
            return ipaddress.IPv6Address(value).packed
        except ValueError:
            return bytes(16)

    @staticmethod
    def _prefix_to_mask_bytes(prefix_len: int) -> bytes:
        if not (0 <= prefix_len <= 128) or prefix_len == 0:
            return bytes(16)
        val = ((1 << 128) - 1) ^ ((1 << (128 - prefix_len)) - 1)
        return val.to_bytes(16, "big")

    def _mac_payload(self) -> bytes:
        if isinstance(self.mac_address, bytes):
            value = self.mac_address
        else:
            compact = self.mac_address.replace(":", "").replace("-", "")
            try:
                value = bytes.fromhex(compact)
            except ValueError as exc:
                raise ValueError(f"invalid MAC address: {self.mac_address!r}") from exc
        if len(value) != 6:
            raise ValueError(f"MAC address must contain 6 bytes, got {len(value)}")
        return value

    def _client_version_payload(self) -> bytes:
        # GetClientVersion reserves 32 bytes for the program name followed by
        # four one-byte version components.
        name = self.program_name.encode("ascii", errors="replace")[:32].ljust(32, b"\x00")
        if self.client_version is not None:
            return name + bytes(self.client_version)
        match = re.search(r"[Vv]?(\d+)(?:\.(\d+))?", self.client_ver)
        major = int(match.group(1)) if match else 6
        minor = int(match.group(2) or 0) if match else 84
        return name + bytes((major & 0xFF, minor & 0xFF, 0x00, 0x00))

    def _ipv4_payload(self) -> bytes:
        is_phase1 = self.dhcp_mode and (self.dhcp_auth_phase != 2)
        ip = b"\x00" * 4 if is_phase1 else self._ip_to_bytes(self.fake_ip)
        return b"".join(
            (
                ip,
                self._ip_to_bytes(self.fake_mask),
                self._ip_to_bytes(self.fake_gw),
                self._ip_to_bytes(self.fake_dns),
                bytes((1 if self.dhcp_mode else 0,)),
            )
        )

    def _service_payload(self) -> bytes:
        # GetServiceName always allocates a 0x20-byte property when non-empty.
        return _encode_text(self.service_name)[:32].ljust(32, b"\x00")

    def _password_payload(self, challenge: bytes, peap_mode: bool) -> bytes:
        if len(challenge) < 16:
            raise ValueError(f"challenge must contain at least 16 bytes, got {len(challenge)}")
        return encrypt_ruijie_password(
            self.password,
            self.username,
            challenge[:16],
            peap=peap_mode,
        )

    def _v3_payload(self, challenge: bytes) -> bytes:
        """Adapt both the intended 128-byte API and the old 130-byte API."""
        generator = self.v3_gen
        if hasattr(generator, "generate_payload"):
            payload = generator.generate_payload(challenge[:16])
        else:
            payload = generator.generate(challenge[:16])
        payload = bytes(payload)

        if len(payload) == 130 and payload[:2] in (b"\x00\x00", b"\x4d\x80", b"\x60\x80"):
            payload = payload[2:]
        if len(payload) != 128:
            raise ValueError(f"V3 generator must return a 128-byte payload, got {len(payload)}")
        return payload

    def encode(self, challenge: bytes, peap_mode: bool = False) -> bytes:
        """Encode a complete normal or PEAP profile.

        Normal order:
        11, 50, 2d, [63], [IPv6], 39, 2f, 76, 4d, 54, [55],
        62, 70, 6f, 79.

        PEAP uses its independent profile: password 5f and V3 60, and omits
        the normal-only OS-bits/release-version properties.
        """
        effective_challenge = PEAP_CHALLENGE if peap_mode else challenge
        if len(effective_challenge) < 16:
            raise ValueError(f"challenge must contain at least 16 bytes, got {len(effective_challenge)}")
        effective_challenge = effective_challenge[:16]

        fields: List[bytes] = [
            _tlv(0x11, self._client_version_payload()),
            _tlv(0x50, self._ipv4_payload()),
            _tlv(0x2D, self._mac_payload()),
        ]
        if self.dhcp_auth_phase > 0:
            fields.append(_tlv(0x63, bytes((self.dhcp_auth_phase & 0xFF,))))

        # GetIPv6Info emits zero or more already-framed nested properties.
        fields.append(self.ipv6_tlvs)

        if self.service_name:
            fields.append(_tlv(0x39, self._service_payload()))

        if peap_mode:
            fields.extend(
                (
                    _tlv(0x76, _encode_text(self.alternate_dns)),
                    _tlv(0x5F, self._password_payload(effective_challenge, True)),
                    _tlv(0x60, self._v3_payload(effective_challenge)),
                )
            )
        else:
            fields.extend(
                (
                    _tlv(0x2F, self._password_payload(effective_challenge, False)),
                    _tlv(0x76, _encode_text(self.alternate_dns)),
                    _tlv(0x4D, self._v3_payload(effective_challenge)),
                )
            )

        fields.append(_tlv(0x54, _encode_text(self.hard_disk_sn or "Static:AB45A862", "ascii")[:64].ljust(64, b"\x00")))
        if self.security_domain:
            fields.append(_tlv(0x55, _encode_text(self.security_domain)))
        fields.append(_tlv(0x62, bytes((self.security_check_result,))))

        if not peap_mode:
            fields.append(_tlv(0x6B, bytes((self.security_probe & 0xFF,))))
            fields.append(_tlv(0x7E, bytes((0, 0, 1, 0, 0, self.os_code & 0xFF, 0, 0))))
            os_value = 0x40 if self.os_bits == 64 else 0x20
            fields.append(_tlv(0x70, bytes((os_value,))))
            release = self.client_ver.encode("ascii", errors="replace") + b"\x00"
            fields.append(_tlv(0x6F, release))

        fields.append(_tlv(0x79, bytes((self.direct_communication_version & 0xFF,))))
        return b"".join(fields)

    def encode_legacy(self, challenge: Optional[bytes] = None, *, logoff_reason: int = 0) -> bytes:
        """AppendPrivateProperty@0x4615f0, NOT the flat EncapRGVerdorSeg profile.

        Returned bytes belong after the declared EAPOL body. None selects the
        Start/Identity/Logoff profile (empty password VSA, zero V3 challenge).
        Header +63 is the txLogOff reason, not the DHCP authentication phase.
        Double authentication uses its own vendor-wrapped 0x63 property (1/2),
        after the MAC property. Phase 0 leaves the original profile unchanged.
        Uninitialized legacy reason memory is deliberately not reproduced.
        """
        if challenge is not None and len(challenge) != 16:
            raise ValueError("legacy MD5 challenge must contain 16 bytes")
        if type(logoff_reason) is not int or not 0 <= logoff_reason <= 255:
            raise ValueError("logoff reason must fit in one byte")
        if type(self.dhcp_auth_phase) is not int or self.dhcp_auth_phase not in (0, 1, 2):
            raise ValueError("legacy DHCP authentication phase must be 0, 1 or 2")
        magic = b"\x00\x00\x13\x11"
        # DhcpIpInfoToUChar@45de30 copies these four addresses verbatim.
        prefix = magic + bytes((int(self.dhcp_mode == 1),)) + b"".join(
            self._ip_to_bytes(value) for value in
            (self.fake_ip, self.fake_mask, self.fake_gw, self.fake_dns)
        )
        # xcrc16@424aa0: MSB-first polynomial 0x1021, init 0, no xorout.
        crc = 0
        for value in prefix:
            crc ^= value << 8
            for _ in range(8):
                crc = ((crc << 1) ^ (0x1021 if crc & 0x8000 else 0)) & 0xffff
        prefix += struct.pack("!H", crc)
        encoded = bytes(int(f"{value:08b}"[::-1], 2) ^ 255 for value in prefix)

        def vsa(kind, payload):
            if len(payload) > 247:
                raise ValueError("legacy VSA payload exceeds one-byte outer length")
            return bytes((0x1a, len(payload)+8)) + magic + bytes((kind, len(payload)+2)) + payload

        # IPv6 fields are always present on this path, unlike flat GetIPv6Info.
        ipv6 = {0x35: bytes(1), 0x36: bytes(16), 0x38: bytes(16), 0x4e: bytes(16)}
        if self.ipv6_address:
            ipv6[0x35] = bytes((1,))
            ipv6[0x36] = self._ip6_to_bytes(self.ipv6_address)
            ipv6[0x38] = self._ip6_to_bytes(self.ipv6_gateway or self.ipv6_link_local)
            ipv6[0x4e] = self._prefix_to_mask_bytes(self.ipv6_prefix_len)
        offset = 0
        while offset < len(self.ipv6_tlvs):
            if len(self.ipv6_tlvs)-offset < 2:
                raise ValueError("truncated legacy IPv6 property")
            kind, size = self.ipv6_tlvs[offset:offset+2]
            payload = self.ipv6_tlvs[offset+2:offset+2+size]
            if kind not in ipv6 or len(payload) != size or size != len(ipv6[kind]):
                raise ValueError("unsupported legacy IPv6 property shape")
            ipv6[kind] = payload
            offset += size+2
        cipher = b"" if challenge is None else hide_radius_password(
            _encode_text(self.password), challenge, _encode_text(self.username), pad_empty=True
        )
        fields = [
            (0x18, struct.pack("!I", int(bool(self.dhcp_mode)))),
            (0x2d, self._mac_payload()),
        ]
        if self.dhcp_mode and self.dhcp_auth_phase:
            fields.append((0x63, bytes((self.dhcp_auth_phase,))))
        fields.extend([
            (0x2f, cipher),
            (0x76, _encode_text(self.alternate_dns)),
            *ipv6.items(),
            (0x4d, self._v3_payload(bytes(16) if challenge is None else challenge)),
            (0x39, self._service_payload()),
            (0x54, _encode_text(self.hard_disk_sn or "Static:AB45A862")[:64].ljust(64, b"\x00")),
            (0x55, _encode_text(self.security_domain)),
            (0x62, bytes((self.security_check_result if challenge is not None else 0,))),
            (0x6b, bytes((self.security_probe & 0xFF,))),
            (0x7e, bytes((0, 0, 1, 0, 0, self.os_code & 0xFF, 0, 0))),
            (0x70, bytes((0x40 if self.os_bits == 64 else 0x20,))),
            (0x6f, self.client_ver.encode("ascii", errors="replace") + b"\x00"),
            (0x79, bytes((self.direct_communication_version & 255,))),
        ])
        properties = b"".join(vsa(kind, payload) for kind, payload in fields)
        # AppendPrivateProperty@462362: VSA bytes only, excluding the length word.
        return (encoded + magic + self._client_version_payload()
                + bytes((logoff_reason,)) + magic
                + struct.pack("!H", len(properties)) + properties)

    def encode_peap(self) -> bytes:
        """Encode the PEAP profile using its fixed challenge."""
        return self.encode(PEAP_CHALLENGE, peap_mode=True)


@dataclass(frozen=True)
class TLVRecord:
    type: int
    payload: bytes
    name: Optional[str] = None
    value: Any = None


class DecodedTLVs(dict):
    """Dictionary-compatible decode result that also preserves wire records."""

    def __init__(self) -> None:
        super().__init__()
        self.records: List[TLVRecord] = []
        self.unknown: List[TLVRecord] = []
        self.by_type: Dict[int, List[TLVRecord]] = {}

    def add(self, record: TLVRecord) -> None:
        self.records.append(record)
        self.by_type.setdefault(record.type, []).append(record)
        if record.name is None:
            self.unknown.append(record)
        else:
            # Keep the last value at the compatibility dictionary key while
            # retaining every occurrence in records/by_type/getall().
            self[record.name] = record.value

    def getall(self, key: Union[int, str]) -> List[Any]:
        if isinstance(key, int):
            records = self.by_type.get(key, ())
        else:
            records = (record for record in self.records if record.name == key)
        return [record.value if record.name is not None else record.payload for record in records]


class ServerTLVDecoder:
    """Strict decoder for ``CRGPrivateProc::ReadRGVendorSeg`` properties."""

    RC4_STATIC_KEY = RC4_STATIC_KEY
    MAX_SEGMENT_LENGTH = 0x578

    _U32_FIELDS = {
        0x05: "newest_version",
        0x14: "proxy_avoid",
        0x15: "dialup_avoid",
        0x56: "reauth_interval",
        0x59: "hello_interval",
        0x5A: "indicate_port",
        0x6E: "message_client_port",
        0x74: "proxy_detect_kinds",
        0x80: "direct_communication_heartbeat_flags",
    }
    _TEXT_FIELDS = {
        0x37: "upgrade_url",
        0x3C: "account_info",
        0x3D: "personal_info",
        0x52: "broadcast_info",
        0x53: "system_info",
        0x68: "user_login_url",
        0x72: "utrust_url",
    }

    @staticmethod
    def _text(payload: bytes, encoding: str = "gb18030") -> str:
        return payload.split(b"\x00", 1)[0].decode(encoding, errors="replace")

    @classmethod
    def _decode_known(cls, tlv_type: int, payload: bytes) -> Tuple[Optional[str], Any]:
        length = len(payload)

        if tlv_type in cls._U32_FIELDS:
            if length != 4:
                raise ValueError(f"TLV 0x{tlv_type:02x} requires length 4, got {length}")
            return cls._U32_FIELDS[tlv_type], struct.unpack("!I", payload)[0]

        if tlv_type == 0x37:
            if length != 0xF7:
                raise ValueError(f"TLV 0x37 requires length 247, got {length}")
            return "upgrade_url", cls._text(payload)

        if tlv_type in cls._TEXT_FIELDS:
            encoding = "ascii" if tlv_type == 0x68 else "gb18030"
            return cls._TEXT_FIELDS[tlv_type], cls._text(payload, encoding)

        if tlv_type == 0x5B:
            if length != 4:
                raise ValueError(f"TLV 0x5b requires length 4, got {length}")
            return "indicate_server_ip", str(ipaddress.IPv4Address(payload))

        if tlv_type == 0x5C:
            if length != 8:
                raise ValueError(f"TLV 0x5c requires length 8, got {length}")
            return "encrypt_key", _rc4_crypt(payload, cls.RC4_STATIC_KEY)

        if tlv_type == 0x5D:
            if length != 8:
                raise ValueError(f"TLV 0x5d requires length 8, got {length}")
            return "encrypt_iv", _rc4_crypt(payload, cls.RC4_STATIC_KEY)

        if tlv_type == 0x5E:
            if length != 8:
                raise ValueError(f"TLV 0x5e requires length 8, got {length}")
            return "server_utc_time", payload

        if tlv_type == 0x61:
            if length != 1:
                raise ValueError(f"TLV 0x61 requires length 1, got {length}")
            return "radius_server_type", payload[0]

        if tlv_type == 0x66:
            text = cls._text(payload)
            return "server_list", [item for item in text.split("@") if item]

        if tlv_type == 0x77:
            if length != 3:
                raise ValueError(f"TLV 0x77 requires length 3, got {length}")
            return "utrust_display", {
                "show": payload[0],
                "delay_seconds": struct.unpack("!H", payload[1:])[0],
            }

        if tlv_type == 0x79:
            if length != 1:
                raise ValueError(f"TLV 0x79 requires length 1, got {length}")
            return "direct_communication_highest_version", payload[0]

        return None, payload

    @classmethod
    def decode(cls, data: bytes) -> DecodedTLVs:
        if not isinstance(data, (bytes, bytearray, memoryview)):
            raise TypeError("data must be bytes-like")
        data = bytes(data)
        if len(data) > cls.MAX_SEGMENT_LENGTH:
            raise ValueError(
                f"server TLV segment exceeds 0x{cls.MAX_SEGMENT_LENGTH:x} bytes: {len(data)}"
            )

        result = DecodedTLVs()
        offset = 0
        while offset < len(data):
            if len(data) - offset < 2:
                raise ValueError(f"truncated TLV header at offset {offset}")

            tlv_type = data[offset]
            length = data[offset + 1]
            if tlv_type == 0 or length == 0xFF:
                break

            payload_start = offset + 2
            payload_end = payload_start + length
            if payload_end > len(data):
                raise ValueError(
                    f"truncated TLV 0x{tlv_type:02x} at offset {offset}: "
                    f"declared {length}, available {len(data) - payload_start}"
                )

            payload = data[payload_start:payload_end]
            name, value = cls._decode_known(tlv_type, payload)
            result.add(TLVRecord(tlv_type, payload, name, value))
            offset = payload_end

        # Compatibility aliases used by the existing state machine and older
        # callers; they refer to real ReadRGVendorSeg fields.
        if "hello_interval" in result:
            result["heartbeat_interval"] = result["hello_interval"]
        if "encrypt_key" in result:
            result["des_key"] = result["encrypt_key"]
        if "encrypt_iv" in result:
            result["des_iv"] = result["encrypt_iv"]
        for message_field in ("account_info", "personal_info", "broadcast_info", "system_info"):
            if message_field in result:
                result.setdefault("message", result[message_field])
                break

        return result
