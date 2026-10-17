#!/usr/bin/env python3
"""
Ruijie custom RIPEMD-128 variant, faithfully ported from x64/rjsupplicant
RipeMD128::CoreTransform @ 0x487f00 (size 0xcfc) and the inline hashing loop
inside CVz_APIApp::PrepareData @ 0x485790 (mode 2/3).

Algorithm family:  RIPEMD-128 (two parallel 4-round lines, 64-bit block
compression), BUT with a custom IV, custom per-step round constants, and a
custom final state combination.  It is NOT standard RIPEMD-128:
  * IV      = [0x10257436, 0xa8bd9cfe, 0x9efcad8b, 0x12375460]
  * Round-1 line constant is 2 instead of 0x00000000
  * The 4 line constants are {2, 0x325b99a1, 0x1baed69c, 0xbcdcb1f9}
    (left) and {0x5a82798a, 0x41d42d5d, 0x30ed3f68, 2} (right)
  * A handful of individual steps use a constant borrowed from another
    round (see the step() calls with explicit constants) -- this is exactly
    what the binary does (verified per-step against a GDB black-box oracle).
  * The final combination adds a stray "+1" into h2.

Message block is read as 16 little-endian uint32 words.  Merkle-Damgard
padding is 0x80 + 0x00* + 64-bit little-endian bit-length (matching the
inline code in PrepareData mode 2/3).  Digest is the 4 state words written
little-endian (16 bytes).

Validation summary (see repo notes):
  * CoreTransform: matches a GDB oracle of 0x487f00 on 21 inputs
    (1 specific + 20 random) -- 21/21 PASS.
"""

from __future__ import annotations

import struct

MASK32 = 0xFFFFFFFF

# --------------------------------------------------------------------------
# Working state layout used by CoreTransform: 16-byte state + 64-byte block,
# i.e. 80 bytes at `this`.  The four boolean functions are the standard
# RIPEMD-128 F1..F4.
# --------------------------------------------------------------------------

def _rol(x: int, s: int) -> int:
    x &= MASK32
    return ((x << s) | (x >> (32 - s))) & MASK32


def _f1(x: int, y: int, z: int) -> int:
    return (x ^ y ^ z) & MASK32


def _f2(x: int, y: int, z: int) -> int:
    return ((x & y) | ((~x) & z)) & MASK32


def _f3(x: int, y: int, z: int) -> int:
    return ((x | (~y)) ^ z) & MASK32


def _f4(x: int, y: int, z: int) -> int:
    return ((x & z) | (y & (~z))) & MASK32


# Nominal per-round constants (the "+K" folded into each round function).
# left line rounds: r1..r4 ; right line rounds: r5..r8
_K = {
    1: 0x00000002,      # F1 + 2
    2: 0x325b99a1,      # F2 + 0x325b99a1
    3: 0x1baed69c,      # F3 + 0x1baed69c
    4: 0xbcdcb1f9,      # F4 + 0xbcdcb1f9   ( = -0x43234e07 )
    5: 0x5a82798a,      # F4 + 0x5a82798a
    6: 0x41d42d5d,      # F3 + 0x41d42d5d
    7: 0x30ed3f68,      # F2 + 0x30ed3f68
    8: 0x00000002,      # R8 == R1 (F1 + 2)
}


def _step(wv, dst, fn, xi, yi, zi, msg, k, rot):
    """One RIPEMD step: wv[dst] = rol(wv[dst] + fn(wv[xi],wv[yi],wv[zi]) + k + msg, rot)."""
    wv[dst] = _rol(wv[dst] + fn(wv[xi], wv[yi], wv[zi]) + k + msg, rot)


def core_transform(h, x):
    """Compress one 64-byte block.
    h: 4-tuple state; x: 16-tuple message words. Returns new 4-tuple.

    Faithful transcription of RipeMD128::CoreTransform @ 0x487f00.  Steps
    marked with an explicit constant (instead of _K[round]) are the steps the
    binary computes with a constant borrowed from a different round -- this is
    a real quirk of the binary, verified against GDB, not a transcription bug.
    """
    wv = list(h) + list(h)          # wv[0..3] left line, wv[4..7] right line

    # ---------------- left line, round 1  (F1, +2) ----------------
    _step(wv, 0, _f1, 1, 2, 3, x[ 0], _K[1], 11)
    _step(wv, 3, _f1, 0, 1, 2, x[ 1], _K[1], 14)
    _step(wv, 2, _f1, 3, 0, 1, x[ 2], _K[1], 15)
    _step(wv, 1, _f1, 2, 3, 0, x[ 3], _K[1], 12)
    _step(wv, 0, _f1, 1, 2, 3, x[ 4], _K[1],  5)
    _step(wv, 3, _f1, 0, 1, 2, x[ 5], _K[1],  8)
    _step(wv, 2, _f1, 3, 0, 1, x[ 6], _K[1],  7)
    _step(wv, 1, _f1, 2, 3, 0, x[ 7], _K[1],  9)
    _step(wv, 0, _f1, 1, 2, 3, x[ 8], _K[1], 11)
    _step(wv, 3, _f1, 0, 1, 2, x[ 9], _K[1], 13)
    _step(wv, 2, _f1, 3, 0, 1, x[10], _K[1], 14)
    _step(wv, 1, _f1, 2, 3, 0, x[11], _K[1], 15)
    _step(wv, 0, _f1, 1, 2, 3, x[12], _K[1],  6)
    _step(wv, 3, _f1, 0, 1, 2, x[13], _K[1],  7)
    _step(wv, 2, _f1, 3, 0, 1, x[14], _K[1],  9)
    _step(wv, 1, _f1, 2, 3, 0, x[15], _K[1],  8)

    # ---------------- left line, round 2  (F2) ----------------
    _step(wv, 0, _f2, 1, 2, 3, x[ 7], _K[2],  7)
    _step(wv, 3, _f2, 0, 1, 2, x[ 4], 0x2,        6)   # binary: +2
    _step(wv, 2, _f2, 3, 0, 1, x[13], _K[2],  8)
    _step(wv, 1, _f2, 2, 3, 0, x[ 1], _K[2], 13)
    _step(wv, 0, _f2, 1, 2, 3, x[10], _K[2], 11)
    _step(wv, 3, _f2, 0, 1, 2, x[ 6], _K[2],  9)
    _step(wv, 2, _f2, 3, 0, 1, x[15], _K[2],  7)
    _step(wv, 1, _f2, 2, 3, 0, x[ 3], 0xbcdcb1f9, 15)  # binary: -0x43234e07
    _step(wv, 0, _f2, 1, 2, 3, x[12], _K[2],  7)
    _step(wv, 3, _f2, 0, 1, 2, x[ 0], 0x2,       12)   # binary: +2
    _step(wv, 2, _f2, 3, 0, 1, x[ 9], _K[2], 15)
    _step(wv, 1, _f2, 2, 3, 0, x[ 5], _K[2],  9)
    _step(wv, 0, _f2, 1, 2, 3, x[ 2], _K[2], 11)
    _step(wv, 3, _f2, 0, 1, 2, x[14], _K[2],  7)
    _step(wv, 2, _f2, 3, 0, 1, x[11], _K[2], 13)
    _step(wv, 1, _f2, 2, 3, 0, x[ 8], 0x2,       12)   # binary: +2

    # ---------------- left line, round 3  (F3) ----------------
    _step(wv, 0, _f3, 1, 2, 3, x[ 3], _K[3], 11)
    _step(wv, 3, _f3, 0, 1, 2, x[10], _K[3], 13)
    _step(wv, 2, _f3, 3, 0, 1, x[14], _K[3],  6)
    _step(wv, 1, _f3, 2, 3, 0, x[ 4], _K[3],  7)
    _step(wv, 0, _f3, 1, 2, 3, x[ 9], _K[3], 14)
    _step(wv, 3, _f3, 0, 1, 2, x[15], _K[3],  9)
    _step(wv, 2, _f3, 3, 0, 1, x[ 8], _K[3], 13)
    _step(wv, 1, _f3, 2, 3, 0, x[ 1], _K[3], 15)
    _step(wv, 0, _f3, 1, 2, 3, x[ 2], _K[3], 14)
    _step(wv, 3, _f3, 0, 1, 2, x[ 7], _K[3],  8)
    _step(wv, 2, _f3, 3, 0, 1, x[ 0], _K[3], 13)
    _step(wv, 1, _f3, 2, 3, 0, x[ 6], 0x325b99a1, 6)   # binary: +0x325b99a1
    _step(wv, 0, _f3, 1, 2, 3, x[13], _K[3],  5)
    _step(wv, 3, _f3, 0, 1, 2, x[11], 0xbcdcb1fa, 12)  # binary: -0x43234e06
    _step(wv, 2, _f3, 3, 0, 1, x[ 5], _K[3],  7)
    _step(wv, 1, _f3, 2, 3, 0, x[12], _K[3],  5)

    # ---------------- left line, round 4  (F4) ----------------
    _step(wv, 0, _f4, 1, 2, 3, x[ 1], _K[4], 11)
    _step(wv, 3, _f4, 0, 1, 2, x[ 9], _K[4], 12)
    _step(wv, 2, _f4, 3, 0, 1, x[11], 0x325b99a1, 14)  # binary: +0x325b99a1
    _step(wv, 1, _f4, 2, 3, 0, x[10], _K[4], 15)
    _step(wv, 0, _f4, 1, 2, 3, x[ 0], _K[4], 14)
    _step(wv, 3, _f4, 0, 1, 2, x[ 8], 0xbcdcb1fb, 15)  # binary: +0xbcdcb1f9 + 2
    _step(wv, 2, _f4, 3, 0, 1, x[12], _K[4],  9)
    _step(wv, 1, _f4, 2, 3, 0, x[ 4], _K[4],  8)
    _step(wv, 0, _f4, 1, 2, 3, x[13], _K[4],  9)
    _step(wv, 3, _f4, 0, 1, 2, x[ 3], 0x1baed69c, 14)  # binary: +0x1baed69c
    _step(wv, 2, _f4, 3, 0, 1, x[ 7], _K[4],  5)
    _step(wv, 1, _f4, 2, 3, 0, x[15], 0x2,        6)   # binary: +2
    _step(wv, 0, _f4, 1, 2, 3, x[14], _K[4],  8)
    _step(wv, 3, _f4, 0, 1, 2, x[ 5], _K[4],  6)
    _step(wv, 2, _f4, 3, 0, 1, x[ 6], _K[4],  5)
    _step(wv, 1, _f4, 2, 3, 0, x[ 2], 0xbcdcb1fc, 12)  # binary: -0x43234e04

    # ---------------- right line, round 1  (F4) ----------------
    _step(wv, 4, _f4, 5, 6, 7, x[ 5], _K[5],  8)
    _step(wv, 7, _f4, 4, 5, 6, x[14], _K[5],  9)
    _step(wv, 6, _f4, 7, 4, 5, x[ 7], _K[5],  9)
    _step(wv, 5, _f4, 6, 7, 4, x[ 0], _K[5], 11)
    _step(wv, 4, _f4, 5, 6, 7, x[ 9], _K[5], 13)
    _step(wv, 7, _f4, 4, 5, 6, x[ 2], _K[5], 15)
    _step(wv, 6, _f4, 7, 4, 5, x[11], 0x325b99a1, 15)  # binary: +0x325b99a1
    _step(wv, 5, _f4, 6, 7, 4, x[ 4], _K[5],  5)
    _step(wv, 4, _f4, 5, 6, 7, x[13], _K[5],  7)
    _step(wv, 7, _f4, 4, 5, 6, x[ 6], _K[5],  7)
    _step(wv, 6, _f4, 7, 4, 5, x[15], 0xbcdcb1f9,  8)  # binary: -0x43234e07
    _step(wv, 5, _f4, 6, 7, 4, x[ 8], _K[5], 11)
    _step(wv, 4, _f4, 5, 6, 7, x[ 1], _K[5], 14)
    _step(wv, 7, _f4, 4, 5, 6, x[10], _K[5], 14)
    _step(wv, 6, _f4, 7, 4, 5, x[ 3], 0xbcdcb1fc, 12)  # binary: -0x43234e04
    _step(wv, 5, _f4, 6, 7, 4, x[12], _K[5],  6)

    # ---------------- right line, round 2  (F3) ----------------
    _step(wv, 4, _f3, 5, 6, 7, x[ 6], _K[6],  9)
    _step(wv, 7, _f3, 4, 5, 6, x[11], _K[6], 13)
    _step(wv, 6, _f3, 7, 4, 5, x[ 3], _K[6], 15)
    _step(wv, 5, _f3, 6, 7, 4, x[ 7], _K[6],  7)
    _step(wv, 4, _f3, 5, 6, 7, x[ 0], _K[6], 12)
    _step(wv, 7, _f3, 4, 5, 6, x[13], _K[6],  8)
    _step(wv, 6, _f3, 7, 4, 5, x[ 5], 0xbcdcb1f9,  9)  # binary: -0x43234e07
    _step(wv, 5, _f3, 6, 7, 4, x[10], 0xbcdcb1fd, 11)  # binary: -0x43234e03
    _step(wv, 4, _f3, 5, 6, 7, x[14], _K[6],  7)
    _step(wv, 7, _f3, 4, 5, 6, x[15], _K[6],  7)
    _step(wv, 6, _f3, 7, 4, 5, x[ 8], _K[6], 12)
    _step(wv, 5, _f3, 6, 7, 4, x[12], _K[6],  7)
    _step(wv, 4, _f3, 5, 6, 7, x[ 4], _K[6],  6)
    _step(wv, 7, _f3, 4, 5, 6, x[ 9], _K[6], 15)
    _step(wv, 6, _f3, 7, 4, 5, x[ 1], 0x325b99a1, 13)  # binary: +0x325b99a1
    _step(wv, 5, _f3, 6, 7, 4, x[ 2], _K[6], 11)

    # ---------------- right line, round 3  (F2) ----------------
    _step(wv, 4, _f2, 5, 6, 7, x[15], _K[7],  9)
    _step(wv, 7, _f2, 4, 5, 6, x[ 5], _K[7],  7)
    _step(wv, 6, _f2, 7, 4, 5, x[ 1], _K[7], 15)
    _step(wv, 5, _f2, 6, 7, 4, x[ 3], _K[7], 11)
    _step(wv, 4, _f2, 5, 6, 7, x[ 7], _K[7],  8)
    _step(wv, 7, _f2, 4, 5, 6, x[14], _K[7],  6)
    _step(wv, 6, _f2, 7, 4, 5, x[ 6], 0xbcdcb1fe,  6)  # binary: -0x43234e02
    _step(wv, 5, _f2, 6, 7, 4, x[ 9], _K[7], 14)
    _step(wv, 4, _f2, 5, 6, 7, x[11], _K[7], 12)
    _step(wv, 7, _f2, 4, 5, 6, x[ 8], 0x5a82798a, 13)  # binary: +0x5a82798a
    _step(wv, 6, _f2, 7, 4, 5, x[12], _K[7],  5)
    _step(wv, 5, _f2, 6, 7, 4, x[ 2], _K[7], 14)
    _step(wv, 4, _f2, 5, 6, 7, x[10], _K[7], 13)
    _step(wv, 7, _f2, 4, 5, 6, x[ 0], _K[7], 13)
    _step(wv, 6, _f2, 7, 4, 5, x[ 4], 0x41d42d5d,  7)  # binary: +0x41d42d5d
    _step(wv, 5, _f2, 6, 7, 4, x[13], _K[7],  5)

    # ---------------- right line, round 4  (F1, +2) ----------------
    _step(wv, 4, _f1, 5, 6, 7, x[ 8], _K[8], 15)
    _step(wv, 7, _f1, 4, 5, 6, x[ 6], 0xbcdcb1fe,  5)  # binary: -0x43234e02
    _step(wv, 6, _f1, 7, 4, 5, x[ 4], _K[8],  8)
    _step(wv, 5, _f1, 6, 7, 4, x[ 1], _K[8], 11)
    _step(wv, 4, _f1, 5, 6, 7, x[ 3], _K[8], 14)
    _step(wv, 7, _f1, 4, 5, 6, x[11], _K[8], 14)
    _step(wv, 6, _f1, 7, 4, 5, x[15], _K[8],  6)
    _step(wv, 5, _f1, 6, 7, 4, x[ 0], _K[8], 14)
    _step(wv, 4, _f1, 5, 6, 7, x[ 5], _K[8],  6)
    _step(wv, 7, _f1, 4, 5, 6, x[12], _K[8],  9)
    _step(wv, 6, _f1, 7, 4, 5, x[ 2], _K[8], 12)
    _step(wv, 5, _f1, 6, 7, 4, x[13], _K[8],  9)
    _step(wv, 4, _f1, 5, 6, 7, x[ 9], _K[8], 12)
    _step(wv, 7, _f1, 4, 5, 6, x[ 7], _K[8],  5)
    _step(wv, 6, _f1, 7, 4, 5, x[10], _K[8], 15)
    _step(wv, 5, _f1, 6, 7, 4, x[14], _K[8],  8)

    # ---------------- final combination (matches binary epilogue) ----------------
    # h0 = (left b) + (right b) + h1 ; h1 = left d + right a + h2
    # h2 = left a + right c + h3 + 1 ; h3 = left c + right d + h0
    wv[7] += wv[2] + h[1]                       # h0
    nh1 = h[2] + wv[3] + wv[4]
    nh2 = h[3] + wv[0] + wv[5] + 1              # the stray "+1" quirk
    nh3 = h[0] + wv[1] + wv[6]
    nh0 = wv[7]
    return (nh0 & MASK32, nh1 & MASK32, nh2 & MASK32, nh3 & MASK32)


# --------------------------------------------------------------------------
# Full hash: 0x80 + 0x00* + 64-bit LE bit-length padding, block by block.
# --------------------------------------------------------------------------

IV = (0x10257436, 0xa8bd9cfe, 0x9efcad8b, 0x12375460)


def hash_ripemd128(data: bytes) -> bytes:
    """Compute the Ruijie custom RIPEMD-128 digest of *data*.

    Returns 16 bytes (4 little-endian uint32 words), byte order identical to
    the inline PrepareData mode 2/3 usage.
    """
    h = list(IV)
    bitlen = len(data) * 8
    padded = data + b"\x80"
    while len(padded) % 64 != 56:
        padded += b"\x00"
    padded += struct.pack("<Q", bitlen)
    for off in range(0, len(padded), 64):
        words = struct.unpack("<16I", padded[off:off + 64])
        h = core_transform(tuple(h), words)
    return struct.pack("<4I", *h)


# --------------------------------------------------------------------------
# Self-tests (values captured from the binary via GDB).
# --------------------------------------------------------------------------

def _self_test() -> None:
    # 1) CoreTransform oracle vector: state=IV, msg words 0..15
    iv = (0x10257436, 0xa8bd9cfe, 0x9efcad8b, 0x12375460)
    out = core_transform(iv, tuple(range(16)))
    got = struct.pack("<4I", *out).hex()
    exp = "3a7433270d9dc27f28e60e622686acf0"
    if got != exp:
        raise AssertionError(f"core_transform oracle mismatch: {got} != {exp}")
    print("[PASS] CoreTransform(IV, X=0..15) == GDB oracle", got)

    # 2) empty / short input sanity (no external golden; just runs)
    hash_ripemd128(b"")
    hash_ripemd128(b"a")
    hash_ripemd128(b"abc" * 100)
    print("[PASS] empty / short / multi-block inputs run cleanly")


if __name__ == "__main__":
    _self_test()
