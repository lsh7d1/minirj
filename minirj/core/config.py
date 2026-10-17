"""Byte-preserving Ruijie configuration parsing and runtime loading."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Iterator

from .file_reg import FileRegConfig
from .suconfig_codec import decode_suconfig


def decode_config_text(value: bytes) -> str:
    """Decode one field without forcing a single encoding on the whole file."""
    for encoding in ("utf-8", "gb18030"):
        try:
            return value.decode(encoding)
        except UnicodeDecodeError:
            pass
    return value.decode("utf-8", errors="surrogateescape")


def encode_config_text(value: str, encoding: str = "utf-8") -> bytes:
    return value.encode(encoding)


def _header_name(line: bytes) -> bytes | None:
    stripped = line.rstrip(b"\r\n").strip()
    if len(stripped) >= 2 and stripped.startswith(b"[") and stripped.endswith(b"]"):
        return stripped[1:-1].strip().lower()
    return None


def _key_value(line: bytes) -> tuple[bytes, bytes] | None:
    stripped = line.rstrip(b"\r\n")
    if stripped.lstrip().startswith((b"#", b";")) or b"=" not in stripped:
        return None
    key, value = stripped.split(b"=", 1)
    key = key.strip()
    if not key:
        return None
    return key.lower(), value


class ByteIniDocument:
    """Minimal INI document that leaves untouched bytes and line endings intact."""

    def __init__(self, raw: bytes):
        self.lines = raw.splitlines(keepends=True)
        if raw and (not self.lines or raw[-1:] not in (b"\n", b"\r")):
            # splitlines already retains the unterminated last line.
            pass
        crlf = raw.count(b"\r\n")
        lf = raw.count(b"\n") - crlf
        self.eol = b"\r\n" if crlf > lf else b"\n"

    def to_bytes(self) -> bytes:
        return b"".join(self.lines)

    def _section_ranges(self, section: str) -> list[tuple[int, int]]:
        wanted = section.encode("ascii").lower()
        starts = [i for i, line in enumerate(self.lines) if _header_name(line) == wanted]
        ranges: list[tuple[int, int]] = []
        for start in starts:
            end = start + 1
            while end < len(self.lines) and _header_name(self.lines[end]) is None:
                end += 1
            ranges.append((start, end))
        return ranges

    def has_section(self, section: str) -> bool:
        return bool(self._section_ranges(section))

    def sections(self) -> list[str]:
        result: list[str] = []
        for line in self.lines:
            name = _header_name(line)
            if name is not None:
                result.append(name.decode("ascii", errors="replace"))
        return result

    def get_bytes(self, section: str, key: str, default: bytes = b"") -> bytes:
        wanted = key.encode("ascii").lower()
        for start, end in self._section_ranges(section):
            for line in self.lines[start + 1 : end]:
                parsed = _key_value(line)
                if parsed and parsed[0] == wanted:
                    return parsed[1]
        return default

    def get(self, section: str, key: str, default: str = "") -> str:
        value = self.get_bytes(section, key)
        return decode_config_text(value) if value else default

    def items(self, section: str) -> Iterator[tuple[str, str]]:
        ranges = self._section_ranges(section)
        if not ranges:
            return
        start, end = ranges[0]
        for line in self.lines[start + 1 : end]:
            parsed = _key_value(line)
            if parsed:
                yield parsed[0].decode("ascii", errors="replace"), decode_config_text(parsed[1])

    def _line(self, key: str, value: bytes) -> bytes:
        return key.encode("ascii") + b"=" + value + self.eol

    def set_bytes(self, section: str, key: str, value: bytes) -> None:
        ranges = self._section_ranges(section)
        if not ranges:
            self._append_section(section, [(key, value)])
            return

        start, end = ranges[0]
        wanted = key.encode("ascii").lower()
        matches = [
            index
            for index in range(start + 1, end)
            if (parsed := _key_value(self.lines[index])) and parsed[0] == wanted
        ]
        replacement = self._line(key, value)
        if matches:
            self.lines[matches[0]] = replacement
            for index in reversed(matches[1:]):
                del self.lines[index]
        else:
            self.lines.insert(end, replacement)

    def set(self, section: str, key: str, value: str, encoding: str = "utf-8") -> None:
        self.set_bytes(section, key, encode_config_text(value, encoding))

    def remove_key(self, section: str, key: str) -> None:
        wanted = key.encode("ascii").lower()
        indexes: list[int] = []
        for start, end in self._section_ranges(section):
            indexes.extend(
                index
                for index in range(start + 1, end)
                if (parsed := _key_value(self.lines[index])) and parsed[0] == wanted
            )
        for index in reversed(indexes):
            del self.lines[index]

    def remove_section(self, section: str) -> None:
        for start, end in reversed(self._section_ranges(section)):
            del self.lines[start:end]

    def replace_section(self, section: str, values: list[tuple[str, bytes]]) -> None:
        ranges = self._section_ranges(section)
        insertion = ranges[0][0] if ranges else len(self.lines)
        self.remove_section(section)
        block = [f"[{section}]".encode("ascii") + self.eol]
        block.extend(self._line(key, value) for key, value in values)
        if insertion and self.lines and not self.lines[insertion - 1].endswith((b"\n", b"\r")):
            block.insert(0, self.eol)
        self.lines[insertion:insertion] = block

    def ensure_section(self, section: str) -> None:
        if not self.has_section(section):
            self._append_section(section, [])

    def _append_section(self, section: str, values: list[tuple[str, bytes]]) -> None:
        if self.lines and not self.lines[-1].endswith((b"\n", b"\r")):
            self.lines[-1] += self.eol
        self.lines.append(f"[{section}]".encode("ascii") + self.eol)
        self.lines.extend(self._line(key, value) for key, value in values)


@dataclass(frozen=True)
class ServiceEntry:
    index: int
    name: str
    value: str


class SuConfigLoader:
    """Load runtime settings from SuConfig.dat and its sibling fileReg.ini."""

    def __init__(self, dat_path: str | Path, credentials_path: str | Path | None = None):
        self.dat_path = Path(dat_path)
        if not self.dat_path.is_file():
            raise FileNotFoundError(f"Configuration file not found: {self.dat_path}")
        self.raw_plain = decode_suconfig(self.dat_path.read_bytes())
        self.config = ByteIniDocument(self.raw_plain)

        if credentials_path is None:
            candidate = self.dat_path.with_name("fileReg.ini")
            credentials_path = candidate if candidate.is_file() else None
        self.credentials = (
            FileRegConfig.load(credentials_path) if credentials_path is not None else FileRegConfig()
        )

    def get_public_setting(self, key: str, default: str = "") -> str:
        return self.config.get("PUBLIC", key, default)

    def get_server_setting(self, section: str, key: str, default: str = "") -> str:
        return self.config.get(section, key, default)

    def get_services(self) -> list[ServiceEntry]:
        entries: list[ServiceEntry] = []
        for key, raw_value in self.config.items("SERVER"):
            if not key.startswith("name") or not key[4:].isdigit():
                continue
            index = int(key[4:])
            name, separator, value = raw_value.partition(">")
            entries.append(ServiceEntry(index, name, value if separator else name))
        return sorted(entries, key=lambda item: item.index)

    def get_auth_params(self, server_section: str = "") -> dict:
        """Extract real PUBLIC/NETDETECT fields and separately stored credentials."""
        del server_section  # Kept for compatibility with the previous public signature.
        username = self.credentials.username or self.config.get(
            "NETDETECT", "LastAuthUsername", self.get_public_setting("Name", "")
        )
        service = self.get_public_setting("Service", "")
        if not service:
            services = self.get_services()
            service = services[0].value if services else "internet"
        try:
            dhcp = int(self.get_public_setting("DHCP", "1"))
        except ValueError as exc:
            raise ValueError("PUBLIC.DHCP must be 0 or 1") from exc
        if dhcp not in (0, 1):
            raise ValueError("PUBLIC.DHCP must be 0 or 1")

        return {
            "username": username,
            "password": self.credentials.password,
            "password_saved": self.credentials.password_saved,
            "service_name": service,
            "services": self.get_services(),
            "dhcp": dhcp,
            "nic": self.get_public_setting("Adapter", ""),
        }
