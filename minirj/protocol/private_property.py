"""Bounded Success/Failure wire decoder, not an EAPOLFrame memory decoder.

Static evidence and offsets: re/notes/success_wire_mapping.md. Unknown fields
remain opaque. ``policy_valid`` is a conservative integration gate, not a claim
that the original binary rejected the same input.
"""

import struct
from typing import Any, Dict

from .hello import HelloCodec
from .tlv import ServerTLVDecoder

PRIVATE_PROPERTY_MAGIC = 0x00001311
PRIVATE_PROPERTY_HELLO = 0x0A
_MAGIC = struct.pack("!I", PRIVATE_PROPERTY_MAGIC)
# Verified ParsePrivateProperty dispatches in this ELF, not every type known to
# ReadRGVendorSeg. Its different envelope must not confer support on wire types
# that the legacy Success path skips (including type zero).
_WIRE_SERVER_TYPES = frozenset((0x3C, 0x3D, 0x56, 0x5A, 0x5B, 0x5C, 0x5D,
                                0x5E, 0x66, 0x6E, 0x79, 0x80))


def _decode_gbk(raw: bytes, warnings: list[str]) -> str:
    # The target converts to UTF-8 and then uses strlen, so embedded NUL ends
    # display text; message_raw retains the entire length-delimited input.
    raw = raw.split(b"\x00", 1)[0]
    try:
        return raw.decode("gbk")
    except UnicodeDecodeError:
        warnings.append("private message contains invalid GBK bytes")
        return raw.decode("gbk", errors="replace")


def parse_private_properties(data: bytes) -> Dict[str, Any]:
    """Decode the private bytes bounded by EAPOL length minus four.

    No scanning for magic, no object-layout fallback, no guessed optional fields.
    ``hello.interval`` is the target's uint32 milliseconds (also interval_ms),
    NOT seconds. Callers must check policy_valid before using any result.
    """
    raw = bytes(data)
    warnings: list[str] = []
    errors: list[str] = []
    result: Dict[str, Any] = {
        "magic": None, "byte_order": None, "message": None,
        "message_raw": b"", "hello": None, "properties": [], "unknown": [],
        "raw_remainder": raw, "warnings": warnings, "errors": errors,
        "raw": raw, "policy_valid": False, "policy_complete": False,
        "unsupported": [],
        # Only verified wire types, with original wrapped payloads in records.
        # Consumers must also check policy_complete.
        "server_tlvs": ServerTLVDecoder.decode(b""),
    }

    def finish(offset: int, error: str | None = None, *, include_remainder: bool = True) -> Dict[str, Any]:
        if error:
            errors.append(error)
            warnings.append(error)
        result["raw_remainder"] = raw[offset:]
        if include_remainder and raw[offset:]:
            result["unknown"].append({"offset": offset, "raw": raw[offset:]})
        result["policy_valid"] = not errors
        result["policy_complete"] = not errors and not result["unknown"]
        return result

    if not raw.startswith(_MAGIC):
        return finish(0, "truncated private-property magic" if len(raw) < 4
                      else "unknown private-property magic")
    result.update(magic=PRIVATE_PROPERTY_MAGIC, byte_order="big")
    if len(raw) < 6:
        return finish(4, "truncated private message header")
    size = int.from_bytes(raw[4:6], "big")
    end = 6 + size
    message_raw = raw[6:end]
    result["message_raw"] = message_raw
    result["message"] = _decode_gbk(message_raw, warnings)
    result["properties"].append({
        "kind": "message", "length": size, "value": result["message"],
        "raw_value": message_raw, "raw": raw[:end], "offset": 0,
    })
    if end > len(raw):
        return finish(len(raw), "truncated private message")
    if end == len(raw):
        return finish(end)

    # 0x463334..0x463392: fixed 111-byte block after the message,
    # last byte counts 32-byte records. Only these structural facts are known.
    if len(raw) < size + 0x75:
        return finish(end, "truncated private fixed block")
    if raw[end:end + 4] != _MAGIC:
        return finish(end, "invalid private fixed-block magic")
    q = size + 0x75 + 32 * raw[size + 0x74]
    if len(raw) < q:
        return finish(end, "truncated private counted records")
    result["properties"].append({"kind": "opaque_fixed_block",
                                  "offset": end, "raw": raw[end:q]})
    for offset in (q, q + 6):
        if len(raw) < offset + 6:
            return finish(offset, "truncated private flag block")
        block = raw[offset:offset + 6]
        if block[:4] != _MAGIC or block[4] != 1 or block[5] > 1:
            return finish(offset, "invalid private flag block")
        result["properties"].append({"kind": "flag_block", "offset": offset,
                                      "raw": block})
    h = q + 12
    if len(raw) < h + 15:
        return finish(h, "truncated Hello private property")
    wire = raw[h:h + 15]
    decoded = HelloCodec.decode(wire)
    if decoded[:4] != _MAGIC or decoded[4] != PRIVATE_PROPERTY_HELLO:
        return finish(h, "invalid decoded Hello private property")
    enabled = decoded[5] != 0
    seconds = int.from_bytes(decoded[10:14], "big")
    milliseconds = (seconds * 1000) & 0xFFFFFFFF
    hello = {
        "enabled": enabled,
        "id": int.from_bytes(decoded[6:10], "big") if enabled else None,
        "interval": milliseconds if enabled else None,
        "interval_ms": milliseconds if enabled else None,
        "interval_seconds_wire": seconds,
        "raw": wire, "decoded_raw": decoded, "offset": h,
        # The target copies byte 14 to +0x658; no semantics inferred.
    }
    result["hello"] = hello
    result["properties"].append({"kind": "hello", **hello})
    # 0x463700..0x463738: BE magic, type, length including type+length.
    # 0x4644ba skips unknown types if bounded; unknown is NOT malformed.
    # Convert only proven wire types to ReadRGVendorSeg's payload-length form.
    # Decode each known record before publishing anything: malformed known data
    # is an error, never an unsupported-type fallback. Preserve duplicates for
    # strict downstream consumers.
    tail = h + 15
    cursor = tail
    first_unknown = None
    normalized = bytearray()
    properties = []
    while cursor < len(raw):
        if len(raw) < cursor + 6:
            return finish(cursor, "truncated private extension header")
        if raw[cursor:cursor + 4] != _MAGIC:
            return finish(cursor, "invalid private extension magic")
        kind, length = raw[cursor + 4:cursor + 6]
        if length < 2:
            return finish(cursor, "invalid private extension length")
        end = cursor + 4 + length
        if end > len(raw):
            return finish(cursor, "truncated private extension value")
        payload = raw[cursor + 6:end]
        if kind in _WIRE_SERVER_TYPES:
            inner = bytes((kind, length - 2)) + payload
            try:
                decoded = ServerTLVDecoder.decode(inner)
            except ValueError as exc:
                return finish(cursor, f"invalid private extension at offset {cursor}: {exc}")
            normalized.extend(inner)
            record = decoded.records[0]
            properties.append({"kind": "server_tlv", "type": kind,
                               "length": length, "offset": cursor,
                               "name": record.name, "value": record.value,
                               "raw_value": payload, "raw": raw[cursor:end]})
        else:
            record = {"type": kind, "offset": cursor, "raw": raw[cursor:end]}
            result["unsupported"].append(record)
            result["unknown"].append(dict(record))
            if first_unknown is None:
                first_unknown = cursor
        cursor = end
    try:
        result["server_tlvs"] = ServerTLVDecoder.decode(bytes(normalized))
    except ValueError as exc:
        return finish(tail, f"invalid private extension sequence: {exc}")
    result["properties"].extend(properties)
    if first_unknown is not None:
        warnings.append("uninterpreted private extension; policy incomplete")
    # raw_remainder remains a contiguous original suffix for compatibility;
    # unknown entries, unlike that diagnostic suffix, cover only unknown packets.
    return finish(cursor if first_unknown is None else first_unknown,
                  include_remainder=False)


def parse_private_property(data: bytes) -> Dict[str, Any]:
    """Compatibility alias; input is wire, never a native object."""
    return parse_private_properties(data)


class PrivatePropertyParser:
    @staticmethod
    def parse(data: bytes) -> Dict[str, Any]:
        return parse_private_properties(data)
