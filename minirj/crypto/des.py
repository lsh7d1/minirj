#!/usr/bin/env python3
"""Ruijie custom DES-named hash, transcribed from x64/rjsupplicant."""

M32 = 0xFFFFFFFF
INIT = [0x32075416, 0xF8DAE9BC, 0x73541260, 0x8ACB9DFE, 0xFD0C2E1B]
PADDING = b"\x80" + b"\x00" * 64


def u32(value):
    return value & M32


def ror32(value, bits):
    value &= M32
    return ((value >> bits) | (value << (32 - bits))) & M32


def des_transform(state, block):
    """Exact register-level transcription of DESTransform @ 0x459930."""
    if len(block) != 64:
        raise ValueError("DESTransform requires exactly 64 bytes")

    words = [int.from_bytes(block[i:i + 4], "big") for i in range(0, 64, 4)]
    words.extend([0] * 64)
    for index in range(16, 80):
        words[index] = ror32(
            words[index - 3] ^ words[index - 8] ^ words[index - 14] ^ words[index - 16],
            31,
        )

    input_first = block[0]
    r14 = state[0]
    r8 = u32(state[1])
    edi = u32(state[2])
    esi = u32(state[3])
    ecx = u32(state[4])
    r10 = u32(r14)

    # 0x4599f8..0x459a30, 20 iterations.
    for index in range(20):
        ecx = u32(ecx + words[index])
        eax = ror32(r10, 27)
        edx = u32(~r8) & esi
        r9 = ror32(r8, 2)
        eax = u32(ecx + eax + 0xA2955B2C)
        ecx = edi & r8
        r8 = r10
        edx = u32(edx | ecx)
        ecx = esi
        edx = u32(eax + edx)
        eax = edi
        if index != 19:
            r10 = edx
            edi = r9
            esi = eax

    # 0x459a32..0x459a80, 20 iterations.
    r11 = edx
    ebx = esi
    ebp = u32(input_first + 0x16AE9DEB)
    ecx = edi
    for index in range(20):
        eax = u32(ebp + words[20 + index])
        edx = ror32(r11, 27)
        r8 = ror32(r10, 2)
        eax = u32(eax + ebx)
        ebx = ecx
        eax = u32(eax + edx)
        edx = r9 ^ r10 ^ ecx
        r10 = r11
        eax = u32(eax + edx)
        edx = r9
        if index != 19:
            r11 = eax
            r9 = r8
            ecx = edx

    # 0x459a82..0x459ad4, 21 iterations.
    edi = eax
    r9 = r11
    esi = edx
    for index in range(21):
        ecx = u32(ecx + words[40 + index])
        eax = ror32(edi, 27)
        edx = (esi | r8) & r9
        r11 = ror32(r9, 2)
        r10 = r8
        r9 = edi
        eax = u32(ecx + eax + 0xCBFCD1B8)
        ecx = (esi & r8) | edx
        eax = u32(eax + ecx)
        ecx = esi
        if index != 20:
            edi = eax
            r8 = r11
            esi = r10

    # 0x459ad6..0x459b1e, 19 iterations.
    ecx = eax
    eax = esi
    for index in range(19):
        eax = u32(eax + words[61 + index])
        edx = ror32(ecx, 27)
        ebx = ror32(r9, 2)
        esi = r11
        edx = u32(eax + edx + 0xA32C616D)
        eax = r11 ^ r9 ^ r8
        r9 = ecx
        edx = u32(edx + eax)
        eax = r8
        if index != 18:
            ecx = edx
            r11 = ebx
            r8 = esi

    state[0] = (state[0] + u32(edx + 1)) & 0xFFFFFFFFFFFFFFFF
    state[1] = (state[1] + u32(ecx)) & 0xFFFFFFFFFFFFFFFF
    state[2] = (state[2] + u32(ebx)) & 0xFFFFFFFFFFFFFFFF
    state[3] = (state[3] + u32(r11)) & 0xFFFFFFFFFFFFFFFF
    state[4] = (state[4] + u32(r8)) & 0xFFFFFFFFFFFFFFFF


def _new_context():
    return {
        "state": list(INIT),
        "bit_length": 0,
        "buffer": bytearray(),
    }


def _update(context, data):
    context["bit_length"] = (context["bit_length"] + len(data) * 8) & ((1 << 128) - 1)
    context["buffer"].extend(data)
    while len(context["buffer"]) >= 64:
        block = bytes(context["buffer"][:64])
        del context["buffer"][:64]
        des_transform(context["state"], block)


def hash_des(data: bytes) -> bytes:
    """Run DESInit/DESUpdate/DESFinal and return the full 20-byte digest."""
    context = _new_context()
    _update(context, data)
    original_bits = context["bit_length"]
    pad_length = 56 - len(context["buffer"])
    if pad_length <= 0:
        pad_length += 64
    _update(context, PADDING[:pad_length])
    _update(context, original_bits.to_bytes(16, "big")[-8:])
    return b"".join(u32(word).to_bytes(4, "big") for word in context["state"])

# The obsolete 8-byte POC self-test was retired during repository migration.
# Full 20-byte hash behavior remains covered by PrepareData vectors.


# --------------------------------------------------------------------------
# Standard FIPS 46-3 Single-DES ECB encryption (zero third-party dependency)
# --------------------------------------------------------------------------

_PC1 = [
    57, 49, 41, 33, 25, 17, 9,
    1, 58, 50, 42, 34, 26, 18,
    10, 2, 59, 51, 43, 35, 27,
    19, 11, 3, 60, 52, 44, 36,
    63, 55, 47, 39, 31, 23, 15,
    7, 62, 54, 46, 38, 30, 22,
    14, 6, 61, 53, 45, 37, 29,
    21, 13, 5, 28, 20, 12, 4
]

_PC2 = [
    14, 17, 11, 24, 1, 5,
    3, 28, 15, 6, 21, 10,
    23, 19, 12, 4, 26, 8,
    16, 7, 27, 20, 13, 2,
    41, 52, 31, 37, 47, 55,
    30, 40, 51, 45, 33, 48,
    44, 49, 39, 56, 34, 53,
    46, 42, 50, 36, 29, 32
]

_SHIFTS = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]

_IP = [
    58, 50, 42, 34, 26, 18, 10, 2,
    60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6,
    64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17, 9, 1,
    59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5,
    63, 55, 47, 39, 31, 23, 15, 7
]

_FP = [
    40, 8, 48, 16, 56, 24, 64, 32,
    39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30,
    37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28,
    35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26,
    33, 1, 41, 9, 49, 17, 57, 25
]

_E = [
    32, 1, 2, 3, 4, 5,
    4, 5, 6, 7, 8, 9,
    8, 9, 10, 11, 12, 13,
    12, 13, 14, 15, 16, 17,
    16, 17, 18, 19, 20, 21,
    20, 21, 22, 23, 24, 25,
    24, 25, 26, 27, 28, 29,
    28, 29, 30, 31, 32, 1
]

_P = [
    16, 7, 20, 21,
    29, 12, 28, 17,
    1, 15, 23, 26,
    5, 18, 31, 10,
    2, 8, 24, 14,
    32, 27, 3, 9,
    19, 13, 30, 6,
    22, 11, 4, 25
]

_S_BOXES = [
    [
        14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7,
        0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8,
        4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0,
        15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13
    ],
    [
        15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10,
        3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5,
        0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15,
        13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9
    ],
    [
        10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8,
        13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1,
        13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7,
        1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12
    ],
    [
        7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15,
        13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9,
        10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4,
        3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14
    ],
    [
        2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9,
        14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6,
        4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14,
        11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3
    ],
    [
        12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11,
        10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8,
        9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6,
        4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13
    ],
    [
        4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1,
        13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6,
        1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2,
        6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12
    ],
    [
        13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7,
        1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2,
        7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8,
        2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11
    ]
]


def _permute(block, table):
    return [block[x - 1] for x in table]


def _bytes_to_bits(data):
    bits = []
    for b in data:
        for i in range(7, -1, -1):
            bits.append((b >> i) & 1)
    return bits


def _bits_to_bytes(bits):
    data = bytearray()
    for i in range(0, len(bits), 8):
        byte = 0
        for bit in bits[i:i+8]:
            byte = (byte << 1) | bit
        data.append(byte)
    return bytes(data)


def _des_key_schedule(key_bytes):
    key_bits = _bytes_to_bits(key_bytes)
    permuted = _permute(key_bits, _PC1)
    C = permuted[:28]
    D = permuted[28:]
    subkeys = []
    for shift in _SHIFTS:
        C = C[shift:] + C[:shift]
        D = D[shift:] + D[:shift]
        subkeys.append(_permute(C + D, _PC2))
    return subkeys


def _des_encrypt_block(block_bits, subkeys):
    permuted = _permute(block_bits, _IP)
    L = permuted[:32]
    R = permuted[32:]
    for round_key in subkeys:
        expanded_R = _permute(R, _E)
        xored = [a ^ b for a, b in zip(expanded_R, round_key)]
        s_output = []
        for i in range(8):
            chunk = xored[i*6 : (i+1)*6]
            row = (chunk[0] << 1) | chunk[5]
            col = (chunk[1] << 3) | (chunk[2] << 2) | (chunk[3] << 1) | chunk[4]
            val = _S_BOXES[i][row * 16 + col]
            for shift in (3, 2, 1, 0):
                s_output.append((val >> shift) & 1)
        f_res = _permute(s_output, _P)
        new_R = [a ^ b for a, b in zip(L, f_res)]
        L = R
        R = new_R
    return _permute(R + L, _FP)


def des_ecb_encrypt(key: bytes, data: bytes) -> bytes:
    """Standard Single-DES ECB encryption over multiple 8-byte blocks."""
    if len(key) != 8:
        raise ValueError(f"DES key must be exactly 8 bytes, got {len(key)}")
    if len(data) % 8 != 0:
        raise ValueError(f"DES ECB data length must be a multiple of 8 bytes, got {len(data)}")
    subkeys = _des_key_schedule(key)
    bits = _bytes_to_bits(data)
    out_bits = []
    for i in range(0, len(bits), 64):
        out_bits.extend(_des_encrypt_block(bits[i:i+64], subkeys))
    return _bits_to_bytes(out_bits)

