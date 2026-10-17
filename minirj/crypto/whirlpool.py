"""
Ruijie Custom Whirlpool Hash Implementation.
Reversed from WhirlPool::CoreTransform (0x4893e0) and WhirlPool::Hash (0x48a0a0).
"""

from ..resources import load_asset
import struct
from typing import List, Tuple

def _load_tables() -> Tuple[List[List[int]], List[int]]:
    data = load_asset("whirlpool_tables.bin")
    rc = list(struct.unpack("<11Q", data[:88]))
    tables = [list(struct.unpack("<256Q", data[88+i*2048:88+(i+1)*2048]))
              for i in range(8)]
    return tables, rc

C_TABLES, RC_CONSTANTS = _load_tables()

ZERO_STATE = (0, 0, 0, 0, 0, 0, 0, 0)
V3_STATE = (0, 3, 5, 2, 1, 7, 4, 6)


def _whirlpool_op(src: List[int], shift: int) -> int:
    res = 0
    res ^= C_TABLES[0][(src[shift & 7] >> 56) & 0xFF]
    res ^= C_TABLES[1][(src[(shift + 7) & 7] >> 48) & 0xFF]
    res ^= C_TABLES[2][(src[(shift + 6) & 7] >> 40) & 0xFF]
    res ^= C_TABLES[3][(src[(shift + 5) & 7] >> 32) & 0xFF]
    res ^= C_TABLES[4][(src[(shift + 4) & 7] >> 24) & 0xFF]
    res ^= C_TABLES[5][(src[(shift + 3) & 7] >> 16) & 0xFF]
    res ^= C_TABLES[6][(src[(shift + 2) & 7] >> 8) & 0xFF]
    res ^= C_TABLES[7][src[(shift + 1) & 7] & 0xFF]
    return res


def _core_transform(H: List[int], block_bytes: bytes) -> List[int]:
    assert len(block_bytes) == 64
    M = list(struct.unpack(">8Q", block_bytes))

    K = [H[i] for i in range(8)]
    S = [M[i] ^ H[i] for i in range(8)]

    for r in range(10):
        K_next = [0] * 8
        K_next[0] = (_whirlpool_op(K, 0) ^ RC_CONSTANTS[r + 1]) & 0xFFFFFFFFFFFFFFFF
        for i in range(1, 8):
            K_next[i] = _whirlpool_op(K, i) & 0xFFFFFFFFFFFFFFFF

        S_next = [0] * 8
        S_next[0] = (_whirlpool_op(S, 0) ^ K_next[0]) & 0xFFFFFFFFFFFFFFFF
        S_next[1] = (_whirlpool_op(S, 1) ^ K_next[1]) & 0xFFFFFFFFFFFFFFFF
        S_next[2] = ((_whirlpool_op(S, 2) ^ K_next[2]) + 1) & 0xFFFFFFFFFFFFFFFF
        S_next[3] = (_whirlpool_op(S, 3) ^ K_next[3]) & 0xFFFFFFFFFFFFFFFF
        S_next[4] = (_whirlpool_op(S, 4) ^ K_next[4]) & 0xFFFFFFFFFFFFFFFF
        S_next[5] = ((_whirlpool_op(S, 5) ^ K_next[5]) + 1) & 0xFFFFFFFFFFFFFFFF
        S_next[6] = ((_whirlpool_op(S, 6) ^ K_next[6]) + 1) & 0xFFFFFFFFFFFFFFFF
        S_next[7] = (_whirlpool_op(S, 7) ^ K_next[7]) & 0xFFFFFFFFFFFFFFFF

        K = K_next
        S = S_next

    H_new = [(S[i] ^ H[i] ^ M[i]) & 0xFFFFFFFFFFFFFFFF for i in range(8)]
    return H_new


def whirlpool_hash(data: bytes, initial_state=ZERO_STATE) -> bytes:
    """Compute the 64-byte Ruijie custom Whirlpool hash.

    ``ZERO_STATE`` reproduces a manually zeroed WhirlPool object. PrepareData
    initializes the object with ``V3_STATE`` before hashing its intermediate
    buffer, so V3 callers must pass that state explicitly.
    """
    if len(initial_state) != 8:
        raise ValueError("Whirlpool initial_state must contain eight words")
    H = [int(word) & 0xFFFFFFFFFFFFFFFF for word in initial_state]
    total_len = len(data)
    idx = 0
    while idx + 64 <= total_len:
        H = _core_transform(H, data[idx : idx + 64])
        idx += 64

    rem = data[idx:]
    msg = bytearray(rem)
    msg.append(0x80)

    bit_len = total_len * 8

    if len(msg) > 32:
        msg.extend(b"\x00" * (64 - len(msg)))
        H = _core_transform(H, bytes(msg))
        msg = bytearray(b"\x00" * 56)
        msg.extend(struct.pack(">Q", bit_len))
        H = _core_transform(H, bytes(msg))
    else:
        msg.extend(b"\x00" * (56 - len(msg)))
        msg.extend(struct.pack(">Q", bit_len))
        H = _core_transform(H, bytes(msg))

    out = b"".join(struct.pack(">Q", w) for w in H)
    return out
