"""Clean-room codec for the Ruijie layer-2 Hello frame.

The wire layout and state transitions mirror ``CHelloThread::CreateHelloPacket``
from the reference client.  The reference constructor itself does not choose all
of the values needed here:

* the destination is copied from ``CtrlThread + 0x550``.  That field is initially
  ``01:d0:f8:00:00:03`` and may later be replaced with the learned peer MAC;
* ``offset`` is supplied to ``CHelloProcessor::ProcessorRun`` and stored at
  ``CHelloThread + 0x1d8``;
* ``sequence`` is stored at ``CHelloThread + 0x1f0`` and seeded by
  ``InitInstance`` from ``rand()``; it is incremented before each frame;
* ``hello_ids`` is the global 16-element ``e_pHelloID`` array, while
  ``history_index`` is the per-thread cursor at ``CHelloThread + 0x1ec``.

Consequently ``sequence`` and ``offset`` are mandatory deterministic inputs.
No protocol default is inferred for either field.
"""

from __future__ import annotations

import struct
from typing import Iterable


_U32_MASK = 0xFFFFFFFF


class HelloCodec:
    """Build stateful 45-byte Ruijie Hello Ethernet frames."""

    FRAME_LENGTH = 45
    BODY_LENGTH = 27
    ETHERTYPE = 0x888E
    EAPOL_VERSION = 1
    EAPOL_TYPE = 0xBF

    # CContextControlThread::BeginStart initializes both the start destination
    # and CtrlThread+0x550 to this address.  CreateHelloPacket reads the latter,
    # so callers must override dst_mac after the reference client learns a peer.
    INITIAL_DST_MAC = b"\x01\xd0\xf8\x00\x00\x03"

    HELLO_ID_SENTINEL = 0x74
    HELLO_ID_SLOTS = 16

    _FIRST_PREFIX = b"\x00\x00\x13\x11\x01\x06"
    _SECOND_PREFIX = b"\x00\x00\x13\x11\x01\x06"
    _TRAILER = b"\x00\x00\x13\x11\x01\x03\x00"

    def __init__(
        self,
        src_mac: bytes,
        *,
        sequence: int,
        offset: int,
        dst_mac: bytes = INITIAL_DST_MAC,
        hello_ids: Iterable[int] | None = None,
        history_index: int = 0,
    ) -> None:
        """Create a deterministic model of the target's Hello state.

        ``sequence`` is the value held before the next packet; ``build`` first
        increments it, exactly like ``GetCurCRCID``.  ``offset`` is added to that
        incremented value for the first dynamic field.  The second dynamic field
        is ``sequence + 0x74 - hello_ids[history_index]``, all modulo 2**32.
        """
        self.src_mac = self._mac(src_mac, "source")
        self.dst_mac = self._mac(dst_mac, "destination")
        self.sequence = self._u32(sequence, "sequence")
        self.offset = self._u32(offset, "offset")

        if hello_ids is None:
            self.hello_ids = [self.HELLO_ID_SENTINEL] * self.HELLO_ID_SLOTS
        else:
            self.hello_ids = [self._u32(value, "hello ID") for value in hello_ids]
            if len(self.hello_ids) != self.HELLO_ID_SLOTS:
                raise ValueError("hello_ids must contain exactly 16 unsigned values")

        if not 0 <= history_index < self.HELLO_ID_SLOTS:
            raise ValueError("history_index must be in range 0..15")
        self.history_index = history_index

    @staticmethod
    def _mac(value: bytes, name: str) -> bytes:
        value = bytes(value)
        if len(value) != 6:
            raise ValueError(f"{name} MAC address must be 6 bytes")
        return value

    @staticmethod
    def _u32(value: int, name: str) -> int:
        if not isinstance(value, int) or not 0 <= value <= _U32_MASK:
            raise ValueError(f"{name} must be an unsigned 32-bit integer")
        return value

    @staticmethod
    def sequence_seed_from_rand(rand_value: int) -> int:
        """Reproduce the sequence seed selected by target ``InitInstance``.

        The target computes ``rand() % 0x1001 + 0x1001``.  Accepting the rand
        result rather than generating one keeps the codec deterministic and
        avoids guessing the reference process's libc PRNG state.
        """
        if not isinstance(rand_value, int) or rand_value < 0:
            raise ValueError("rand_value must be a non-negative integer")
        return rand_value % 0x1001 + 0x1001

    @staticmethod
    def _reverse_bits(value: int) -> int:
        value = ((value & 0x55) << 1) | ((value >> 1) & 0x55)
        value = ((value & 0x33) << 2) | ((value >> 2) & 0x33)
        return ((value & 0x0F) << 4) | ((value >> 4) & 0x0F)

    @classmethod
    def encode(cls, data: bytes | bytearray | memoryview) -> bytes:
        """Apply target ``encode``: reverse each byte's bits, then complement."""
        return bytes(cls._reverse_bits(value) ^ 0xFF for value in bytes(data))

    @classmethod
    def decode(cls, data: bytes | bytearray | memoryview) -> bytes:
        """Decode bytes produced by ``encode`` (the transform is involutory)."""
        return cls.encode(data)

    def reset_hello_ids(self) -> None:
        """Mirror the target timer/init reset of global ``e_pHelloID``."""
        self.hello_ids[:] = [self.HELLO_ID_SENTINEL] * self.HELLO_ID_SLOTS

    def build(self) -> bytes:
        """Build one frame and advance the same counter/history state as target."""
        sampled_id = self.hello_ids[self.history_index]
        if sampled_id != self.HELLO_ID_SENTINEL:
            # GetCurCRCID propagates the selected non-sentinel value into every
            # slot that still contains 0x74.  Existing non-sentinel slots remain.
            self.hello_ids[:] = [
                sampled_id if value == self.HELLO_ID_SENTINEL else value
                for value in self.hello_ids
            ]

        self.sequence = (self.sequence + 1) & _U32_MASK
        offset_counter = (self.sequence + self.offset) & _U32_MASK
        history_counter = (
            self.sequence + self.HELLO_ID_SENTINEL - sampled_id
        ) & _U32_MASK
        self.history_index = (self.history_index + 1) % self.HELLO_ID_SLOTS

        plain_body = (
            self._FIRST_PREFIX
            + struct.pack("!I", offset_counter)
            + self._SECOND_PREFIX
            + struct.pack("!I", history_counter)
            + self._TRAILER
        )
        if len(plain_body) != self.BODY_LENGTH:
            raise AssertionError("internal Hello body length mismatch")

        frame = (
            self.dst_mac
            + self.src_mac
            + struct.pack(
                "!HBBH",
                self.ETHERTYPE,
                self.EAPOL_VERSION,
                self.EAPOL_TYPE,
                self.BODY_LENGTH + 3,
            )
            + self.encode(plain_body)
        )
        if len(frame) != self.FRAME_LENGTH:
            raise AssertionError("internal Hello frame length mismatch")
        return frame
