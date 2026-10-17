"""Ruijie V3 check-code generator backed by Windows 8021x.exe V6.84.0.0 five branches."""

from __future__ import annotations

from .des import hash_des, des_ecb_encrypt
from .md5_vz import hash_md5_vz_ascii
from .ripemd128 import hash_ripemd128
from .whirlpool import V3_STATE, whirlpool_hash

# Keys extracted from 8021x.exe:
# 0x006d0530: b"v*$!1d3V" (Selector 1 & 2 challenge encryption)
KEY_SEL12 = bytes.fromhex("762a242131643356")
# 0x006d0524: b"{?^9*~!o" (Selector 4 Whirlpool digest encryption)
KEY_SEL4 = bytes.fromhex("7b3f5e392a7e216f")

# Digests of the target app-data slice, used as selector inputs.
APP_SHA = bytes.fromhex("bb9ed25c67218983bafdd692cf6d906c6c599fb8")
APP_ARX = bytes.fromhex("a5925fe1e0c79e213801b9e53945adf6")
APP_TIGER = bytes.fromhex("4a885b751b2e2a903ded859d250550da1f67eaa42474b171")


def select_mode(challenge: bytes) -> int:
    """Windows 8021x.exe dispatcher formula at 0x0056fe00."""
    if len(challenge) < 16:
        raise ValueError(f"challenge must contain at least 16 bytes, got {len(challenge)}")
    signed = lambda value: value if value < 0x80 else value - 0x100
    return ((signed(challenge[1]) + signed(challenge[4])) & 0xFFFFFFFF) % 5


class V3Generator:
    """Generate the 128-byte lowercase ASCII payload used by V3 TLV 0x4D in Windows 6.84."""

    def _selector_0(self, challenge: bytes) -> tuple[bytes, bytes]:
        c = bytes(challenge[:16])
        md5_hex = hash_md5_vz_ascii(c)[:20]
        buf = bytearray(md5_hex + c[0:6] + APP_SHA + c[6:16])
        # 7 in-place byte rewrites at 0x005761e0..0x005762b8
        buf[1] = (buf[3] + 1) & 0xFF
        buf[3] = (buf[5] - 3) & 0xFF
        buf[7] = (buf[11] + 5) & 0xFF
        buf[11] = (buf[13] - 7) & 0xFF
        buf[13] = (buf[17] + 11) & 0xFF
        buf[17] = (buf[19] - 13) & 0xFF
        buf[23] = (buf[27] + 17) & 0xFF
        intermediate = bytes(buf)
        digest = whirlpool_hash(intermediate, initial_state=V3_STATE)
        # 0..16 forward, then 63..17 reverse
        fwd = "".join(f"{digest[i]:02x}" for i in range(17))
        rev = "".join(f"{digest[i]:02x}" for i in range(63, 16, -1))
        return intermediate, (fwd + rev).encode("ascii")

    def _selector_1(self, challenge: bytes) -> tuple[bytes, bytes]:
        c = bytes(challenge[:16])
        arx_out = APP_ARX
        des_out = des_ecb_encrypt(KEY_SEL12, c)
        str1 = "".join(f"{arx_out[i]:02x}" for i in [15, 14, 13, 12, 11, 10, 9, 8])
        str1 += "".join(f"{arx_out[i]:02x}" for i in [0, 1, 2, 3, 4, 5])
        str2 = ""
        for i in range(15, -1, -1):
            val = des_out[i]
            signed_val = val if val < 0x80 else val | 0xFFFFFF00
            temp = f"{signed_val:02x}"
            if i % 2 == 0:
                str2 += temp
            else:
                str1 += temp
        intermediate = (str1 + str2)[:64].encode("ascii")
        digest = whirlpool_hash(intermediate, initial_state=V3_STATE)
        # Strict reverse 63..0
        payload = "".join(f"{digest[i]:02x}" for i in range(63, -1, -1)).encode("ascii")
        return intermediate, payload

    def _selector_2(self, challenge: bytes) -> tuple[bytes, bytes]:
        c = bytes(challenge[:16])
        arx_out = APP_ARX
        des_out = des_ecb_encrypt(KEY_SEL12, c)
        intermediate = arx_out[10:16] + des_out[0:16] + arx_out[0:10] + c
        digest = whirlpool_hash(intermediate, initial_state=V3_STATE)
        top = "".join(f"{(digest[i] - i) & 0xFF:02x}" for i in range(63, 31, -1))
        bot = "".join(f"{digest[i]:02x}" for i in range(32))
        return intermediate, (top + bot).encode("ascii")

    def _selector_3(self, challenge: bytes) -> tuple[bytes, bytes]:
        c = bytes(challenge[:16])
        tiger_out = APP_TIGER
        sha1_out = hash_des(c)
        intermediate = tiger_out[0:24] + c[0:9] + b"\x00" + sha1_out[0:20] + c[8:14]
        digest = whirlpool_hash(intermediate, initial_state=V3_STATE)
        top = "".join(f"{(digest[i] - i) & 0xFF:02x}" for i in range(63, 47, -1))
        bot = "".join(f"{digest[i]:02x}" for i in range(48))
        return intermediate, (top + bot).encode("ascii")

    def _selector_4(self, challenge: bytes) -> tuple[bytes, bytes]:
        c = bytes(challenge[:16])
        tiger_out = APP_TIGER
        arx_out = hash_ripemd128(c)
        intermediate = tiger_out[0:16] + c[0:9] + b"\x48" + arx_out[0:16] + c[10:16]
        digest = whirlpool_hash(intermediate, initial_state=V3_STATE)
        des_out = des_ecb_encrypt(KEY_SEL4, digest)
        bot = "".join(f"{des_out[i]:02x}" for i in range(32))
        top = "".join(f"{(des_out[i] + (i & 1)) & 0xFF:02x}" for i in range(63, 31, -1))
        return intermediate, (bot + top).encode("ascii")

    def prepare_intermediate(self, challenge: bytes, *, mode: int | None = None) -> tuple[int, bytes]:
        """Compute the selector and intermediate buffer."""
        selected = select_mode(challenge)
        if mode is None:
            mode = selected
        elif type(mode) is not int or mode not in range(5):
            raise ValueError("explicit PrepareData mode must be an integer in 0..4")

        handlers = (
            self._selector_0,
            self._selector_1,
            self._selector_2,
            self._selector_3,
            self._selector_4,
        )
        intermediate, _ = handlers[mode](challenge)
        expected_lengths = (56, 64, 48, 60, 48)
        if len(intermediate) != expected_lengths[mode]:
            raise AssertionError(
                f"V3 mode {mode} intermediate must be {expected_lengths[mode]} bytes, got {len(intermediate)}"
            )
        return mode, intermediate

    def generate_payload(self, challenge: bytes, *, mode: int | None = None) -> bytes:
        """Return 128 hex ASCII bytes; mode overrides the dispatcher selector."""
        selected = select_mode(challenge)
        if mode is None:
            mode = selected
        elif type(mode) is not int or mode not in range(5):
            raise ValueError("explicit PrepareData mode must be an integer in 0..4")

        handlers = (
            self._selector_0,
            self._selector_1,
            self._selector_2,
            self._selector_3,
            self._selector_4,
        )
        _, payload = handlers[mode](challenge)
        if len(payload) != 128:
            raise AssertionError(f"V3 payload must be 128 bytes, got {len(payload)}")
        return payload

    def generate(self, challenge: bytes) -> bytes:
        """Compatibility alias for :meth:`generate_payload`."""
        return self.generate_payload(challenge)
