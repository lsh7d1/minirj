"""Ruijie RadiusEncrpytPwd and RFC 2865-style password hiding."""

import hashlib

PEAP_AUTHENTICATOR = b"!jierui9002pmsus"


class RadiusPasswordError(ValueError):
    pass


def hide_radius_password(password: bytes, authenticator: bytes, secret: bytes, *, pad_empty: bool = False) -> bytes:
    """Hide a byte string in 16-byte blocks.

    The target's ordinary GetUserPasswd uses GBK(password), a 16-byte
    challenge authenticator, and GBK(username) as the MD5 secret. Unlike the
    conventional RADIUS User-Password attribute, an empty target password is
    allowed to produce zero blocks.
    """
    if len(authenticator) != 16:
        raise RadiusPasswordError(f"authenticator must be 16 bytes, got {len(authenticator)}")

    password = bytes(password)
    if not password and not pad_empty:
        return b""
    padded_length = ((len(password) + 15) // 16) * 16
    if padded_length == 0:
        padded_length = 16
    padded = password.ljust(padded_length, b"\x00")

    output = bytearray()
    previous = authenticator
    for offset in range(0, len(padded), 16):
        mask = hashlib.md5(secret + previous).digest()
        block = bytes(left ^ right for left, right in zip(padded[offset:offset + 16], mask))
        output.extend(block)
        previous = block
    return bytes(output)


def encrypt_ruijie_password(
    password: str,
    username: str,
    challenge: bytes,
    *,
    peap: bool = False,
    encoding: str = "gb18030",
) -> bytes:
    """Apply the parameter binding used by GetUserPasswd/GetUserPasswd4Peap."""
    authenticator = PEAP_AUTHENTICATOR if peap else bytes(challenge)
    return hide_radius_password(
        password.encode(encoding),
        authenticator,
        username.encode(encoding),
        pad_empty=False,
    )
