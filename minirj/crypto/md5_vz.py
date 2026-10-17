"""Compatibility implementation of Ruijie's ``CMD5ForVz`` hash.

The implementation follows the x64 ``rjsupplicant`` ELF methods at:

* constructor: ``0x44b880``
* ``Transform``: ``0x44ad70``
* ``Update``: ``0x44b6b0``
* ``Final``: ``0x44b920``
* ``GetMD5``: ``0x44baa0``

It has MD5's block layout and padding, but it is not standard MD5.  The IV,
several constants, two rotation counts, the value added after each round's
rotation, and one message-dependent operation are modified.

``hash_md5_vz`` returns the raw 16-byte digest.  The ELF's ``GetMD5`` method
instead allocates and returns 32 lowercase hexadecimal ASCII characters;
``hash_md5_vz_ascii`` provides that representation without the trailing NUL.
"""

from __future__ import annotations

import struct

_MASK32 = 0xFFFFFFFF

_IV = (0x50137246, 0x8ACF9DBE, 0xC9EFACED, 0x25647013)

# MD5's sine constants with the six Transform-specific changes preserved.
_K = (
    0xD76AA478, 0xE8C7B756, 0x242070DB, 0xC1BDCEEE,
    0xF57C0FAF, 0x4787C62A, 0xA8304613, 0xFD469501,
    0x698098D8, 0x8B44F7AF, 0xFFFF5BB1, 0x895CD7BE,
    0x6B901122, 0xFD987163, 0xA679438E, 0x49B40821,
    0xF61E2562, 0xC040B340, 0x265E5A51, 0xE9B6C7AA,
    0xD62F105D, 0x02442453, 0xD8A1E681, 0xE7D3FBC8,
    0x21E1CDE6, 0xC33707D6, 0xF4D50D87, 0x455A14ED,
    0xA9E3E905, 0xFCEFA3F8, 0x676F02D9, 0x8D2A4C8A,
    0xFFFA3492, 0x8771F681, 0x6D9D6122, 0xFDE5380C,
    0xA4BEEA44, 0x4BDECFA9, 0xF6BB4B60, 0xBEBFBC70,
    0x289B7EC6, 0xEAA127FA, 0xD4EF3085, 0x04881D05,
    0xD9D4D039, 0xE6DB99E5, 0x1FA27CF8, 0xC4AC5665,
    0xF4292244, 0x432AFF97, 0xAB9423A7, 0xFC93A039,
    0x655659C3, 0x8F0CCC92, 0xFFEFF47D, 0x85845DD1,
    0x6FA87E4F, 0xFE2CE6E0, 0xA3014314, 0x4E0811A1,
    0xF7537E82, 0xBD3AF335, 0x2AD7D2BB, 0xEB866391,
)

_ROTATIONS = (
    (7, 12, 17, 22) * 4
    + (5, 9, 14, 20) * 4
    + (5, 11, 16, 23) * 4
    + (6, 10, 15, 19) * 4
)


def _rol32(value: int, count: int) -> int:
    value &= _MASK32
    return ((value << count) | (value >> (32 - count))) & _MASK32


def _transform(state: tuple[int, int, int, int], block: bytes) -> tuple[int, int, int, int]:
    """Compress one 64-byte block exactly as ``CMD5ForVz::Transform``."""
    words = struct.unpack("<16I", block)
    a, b, c, d = state

    for index in range(64):
        if index < 16:
            function = (b & c) | ((~b) & d)
            word_index = index
            post_add = 2
        elif index < 32:
            function = (d & b) | ((~d) & c)
            word_index = (5 * index + 1) & 0x0F
            post_add = -2
        elif index < 48:
            function = b ^ c ^ d
            word_index = (3 * index + 5) & 0x0F
            post_add = -1
        else:
            function = c ^ (b | (~d))
            word_index = (7 * index) & 0x0F
            post_add = 1

        # Transform step 43 adds input byte 9 separately in addition to X[6].
        extra = block[9] if index == 43 else 0
        mixed = (a + function + _K[index] + words[word_index] + extra) & _MASK32
        new_b = (b + post_add + _rol32(mixed, _ROTATIONS[index])) & _MASK32
        a, d, c, b = d, c, b, new_b

    return (
        (state[0] + a) & _MASK32,
        (state[1] + b) & _MASK32,
        (state[2] + c) & _MASK32,
        (state[3] + d) & _MASK32,
    )


def hash_md5_vz(data: bytes) -> bytes:
    """Return the raw 16-byte ``CMD5ForVz`` digest of *data*.

    Padding is MD5-style: ``0x80``, zero bytes to byte 56 modulo 64, then the
    original bit length as an unsigned 64-bit little-endian integer.
    """
    if not isinstance(data, bytes):
        raise TypeError("data must be bytes")

    bit_length = (len(data) * 8) & 0xFFFFFFFFFFFFFFFF
    padded = data + b"\x80"
    padded += b"\x00" * ((56 - len(padded)) % 64)
    padded += struct.pack("<Q", bit_length)

    state = _IV
    for offset in range(0, len(padded), 64):
        state = _transform(state, padded[offset : offset + 64])

    return struct.pack("<4I", *state)


def hash_md5_vz_ascii(data: bytes) -> bytes:
    """Return the ELF ``GetMD5`` representation: 32 lowercase ASCII bytes."""
    return hash_md5_vz(data).hex().encode("ascii")


__all__ = ["hash_md5_vz", "hash_md5_vz_ascii"]
