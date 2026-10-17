"""Ruijie CEncryption, matched to CEncryption::{encrypt,decrypt}."""

import base64
import binascii

KEYSTREAM = b"~!:?$*<(qw2e5o7i8x12c6m67s98w43d2l45we82q3iuu1z4xle23rt4oxclle34e54u6r8m"


class CEncryptionError(ValueError):
    pass


def _c_string(data: bytes) -> bytes:
    """The target accepts C strings and stops at the first NUL."""
    return data.split(b"\x00", 1)[0]


def encrypt_bytes(plaintext: bytes) -> str:
    plaintext = _c_string(bytes(plaintext))
    encrypted = bytes(value ^ KEYSTREAM[index % len(KEYSTREAM)] for index, value in enumerate(plaintext))
    return base64.b64encode(encrypted).decode("ascii")


def decrypt_bytes(ciphertext: str) -> bytes:
    try:
        encoded = _c_string(ciphertext.encode("ascii"))
        encrypted = base64.b64decode(encoded, validate=True)
    except (UnicodeEncodeError, binascii.Error) as exc:
        raise CEncryptionError("invalid CEncryption Base64 text") from exc
    plaintext = bytes(value ^ KEYSTREAM[index % len(KEYSTREAM)] for index, value in enumerate(encrypted))
    return _c_string(plaintext)


def encrypt_text(plaintext: str, encoding: str = "gb18030") -> str:
    return encrypt_bytes(plaintext.encode(encoding))


def decrypt_text(ciphertext: str, encoding: str = "gb18030") -> str:
    try:
        return decrypt_bytes(ciphertext).decode(encoding)
    except UnicodeDecodeError as exc:
        raise CEncryptionError(f"decrypted data is not valid {encoding}") from exc


class CEncryption:
    """Compatibility facade for the previous class-based API."""

    @staticmethod
    def encrypt(plaintext: str, key_index=None) -> str:
        if key_index not in (None, 0):
            raise CEncryptionError("the target binary has one fixed keystream; key_index is unsupported")
        return encrypt_text(plaintext)

    @staticmethod
    def decrypt(ciphertext: str, key_index=None) -> str:
        if key_index not in (None, 0):
            raise CEncryptionError("the target binary has one fixed keystream; key_index is unsupported")
        return decrypt_text(ciphertext)
