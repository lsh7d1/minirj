"""Parser and writer for Ruijie's ``fileReg.ini`` credential bundle."""

from __future__ import annotations

import base64
from dataclasses import dataclass
from pathlib import Path

from ..crypto import cencryption as _cencryption

# Compatibility key used by the corrected CEncryption implementation.  Keep this
# fallback here only until all supported branches expose encrypt_text/decrypt_text.
_COMPAT_KEY = b"~!:?$*<(qw2e5o7i8x12c6m67s98w43d2l45we82q3iuu1z4xle23rt4oxclle34e54u6r8m"


def _encrypt_text(value: str) -> str:
    method = getattr(_cencryption, "encrypt_text", None)
    if method is None:
        method = getattr(getattr(_cencryption, "CEncryption", object), "encrypt_text", None)
    if method is not None:
        result = method(value)
        return result.decode("ascii") if isinstance(result, bytes) else result
    raw = value.encode("gb18030")
    encrypted = bytes(byte ^ _COMPAT_KEY[i % len(_COMPAT_KEY)] for i, byte in enumerate(raw))
    return base64.b64encode(encrypted).decode("ascii")


def _decrypt_text(value: str) -> str:
    method = getattr(_cencryption, "decrypt_text", None)
    if method is None:
        method = getattr(getattr(_cencryption, "CEncryption", object), "decrypt_text", None)
    if method is not None:
        result = method(value)
        return result.decode("gb18030") if isinstance(result, bytes) else result
    if not value:
        return ""
    try:
        raw = base64.b64decode(value.strip(), validate=True)
        plain = bytes(byte ^ _COMPAT_KEY[i % len(_COMPAT_KEY)] for i, byte in enumerate(raw))
        return plain.decode("gb18030")
    except (ValueError, UnicodeError) as exc:
        raise ValueError("invalid encrypted value in fileReg.ini") from exc


@dataclass
class FileRegConfig:
    """Meaningful view of the four obfuscated ``[pu32list]`` fields."""

    ed2e1: str = ""  # encrypted username
    gr2a1: str = ""  # encrypted saved password
    unl2t1: int = 0   # encrypted username length
    dcd2x: int = 0    # save-password flag

    @property
    def username(self) -> str:
        return _decrypt_text(self.ed2e1) if self.ed2e1 else ""

    @property
    def password_saved(self) -> bool:
        return bool(self.dcd2x and self.gr2a1)

    @property
    def password(self) -> str:
        return _decrypt_text(self.gr2a1) if self.password_saved else ""

    @classmethod
    def from_credentials(
        cls,
        username: str = "",
        password: str = "",
        *,
        save_password: bool = False,
    ) -> "FileRegConfig":
        encrypted_username = _encrypt_text(username) if username else ""
        encrypted_password = _encrypt_text(password) if password and save_password else ""
        return cls(
            ed2e1=encrypted_username,
            gr2a1=encrypted_password,
            unl2t1=len(encrypted_username),
            dcd2x=int(bool(encrypted_password)),
        )

    @classmethod
    def parse(cls, raw: bytes | str) -> "FileRegConfig":
        if isinstance(raw, str):
            raw = raw.encode("ascii")
        values: dict[str, str] = {}
        section = ""
        for raw_line in raw.splitlines():
            line = raw_line.strip()
            if not line or line.startswith((b"#", b";")):
                continue
            if line.startswith(b"[") and line.endswith(b"]"):
                section = line[1:-1].decode("ascii", errors="strict").lower()
                continue
            if section == "pu32list" and b"=" in line:
                key, value = line.split(b"=", 1)
                values[key.decode("ascii").lower()] = value.decode("ascii")

        def parse_int(key: str) -> int:
            value = values.get(key, "0") or "0"
            try:
                parsed = int(value)
            except ValueError as exc:
                raise ValueError(f"fileReg.ini {key} must be an integer") from exc
            if parsed < 0:
                raise ValueError(f"fileReg.ini {key} must not be negative")
            return parsed

        result = cls(
            ed2e1=values.get("ed2e1", ""),
            gr2a1=values.get("gr2a1", ""),
            unl2t1=parse_int("unl2t1"),
            dcd2x=parse_int("dcd2x"),
        )
        # Validate ciphertext eagerly instead of failing later during CLI merge.
        if result.ed2e1:
            result.username
        if result.gr2a1:
            _decrypt_text(result.gr2a1)
        return result

    @classmethod
    def load(cls, path: str | Path) -> "FileRegConfig":
        file_path = Path(path)
        if not file_path.is_file():
            raise FileNotFoundError(f"Credentials file not found: {file_path}")
        return cls.parse(file_path.read_bytes())

    def to_bytes(self) -> bytes:
        return (
            b"[pu32list]\n"
            + f"gr2a1={self.gr2a1}\n".encode("ascii")
            + f"ed2e1={self.ed2e1}\n".encode("ascii")
            + f"dcd2x={self.dcd2x}\n".encode("ascii")
            + f"unl2t1={self.unl2t1}\n".encode("ascii")
        )
