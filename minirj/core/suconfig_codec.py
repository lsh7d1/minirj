"""Strict byte codec for Ruijie ``SuConfig.dat`` containers."""

from __future__ import annotations

TABLE_SIZE = 0x8000
TABLE_INIT = 0x20
DEFAULT_MAX_PLAIN_SIZE = 0x100000


class SuConfigCodecError(ValueError):
    """Raised when a SuConfig container is empty, oversized, or non-canonical."""


def _invert(data: bytes) -> bytes:
    return bytes(byte ^ 0xFF for byte in data)


def _compress(plain: bytes) -> bytes:
    table = bytearray([TABLE_INIT]) * TABLE_SIZE
    output = bytearray()
    previous_2 = previous_1 = 0

    for group_start in range(0, len(plain), 8):
        flags = 0
        literals = bytearray()
        for bit, value in enumerate(plain[group_start : group_start + 8]):
            index = ((previous_2 & 0xFF) << 7) ^ (previous_1 & 0xFF)
            if table[index] == value:
                flags |= 1 << bit
            else:
                table[index] = value
                literals.append(value)
            previous_2, previous_1 = previous_1, value
        output.append(flags)
        output.extend(literals)

    return bytes(output)


def _decompress(compressed: bytes, max_plain_size: int) -> bytes:
    table = bytearray([TABLE_INIT]) * TABLE_SIZE
    output = bytearray()
    previous_2 = previous_1 = 0
    position = 0

    while position < len(compressed):
        flags = compressed[position]
        position += 1
        for bit in range(8):
            index = ((previous_2 & 0xFF) << 7) ^ (previous_1 & 0xFF)
            if flags & (1 << bit):
                value = table[index]
            else:
                if position >= len(compressed):
                    return bytes(output)
                value = compressed[position]
                position += 1
                table[index] = value

            output.append(value)
            if len(output) > max_plain_size:
                raise SuConfigCodecError(
                    f"decoded SuConfig exceeds {max_plain_size} bytes"
                )
            previous_2, previous_1 = previous_1, value

    return bytes(output)


def encode_suconfig(plain_ini: bytes) -> bytes:
    """Encode non-empty INI bytes into the canonical SuConfig representation."""
    if not isinstance(plain_ini, bytes):
        raise TypeError("plain_ini must be bytes")
    if not plain_ini:
        raise SuConfigCodecError("plain SuConfig data is empty")
    return _invert(_compress(plain_ini))


def decode_suconfig(
    raw_container: bytes,
    *,
    max_plain_size: int = DEFAULT_MAX_PLAIN_SIZE,
) -> bytes:
    """Decode and strictly validate a canonical, non-empty SuConfig container."""
    if not isinstance(raw_container, bytes):
        raise TypeError("raw_container must be bytes")
    if not raw_container:
        raise SuConfigCodecError("SuConfig container is empty")
    if max_plain_size <= 0:
        raise ValueError("max_plain_size must be positive")

    plain = _decompress(_invert(raw_container), max_plain_size)
    if not plain:
        raise SuConfigCodecError("SuConfig decoded to empty data")
    if encode_suconfig(plain) != raw_container:
        raise SuConfigCodecError("SuConfig container is truncated or non-canonical")
    return plain


class SuConfigCodec:
    """Namespace-style compatibility API for the single strict codec."""

    encode = staticmethod(encode_suconfig)
    decode = staticmethod(decode_suconfig)
