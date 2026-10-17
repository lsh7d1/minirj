"""Pinned target-derived resources; packaging is not a redistribution grant."""
from importlib.resources import files
import hashlib

# Independent constants; never trust a manifest alongside changed bytes.
ASSETS = {
    "whirlpool_tables.bin": (16472, "ca991971e449c62799a6da92659f93a664a72250e1c004b5abb3ff181c047715"),
}


def load_asset(name: str) -> bytes:
    if name not in ASSETS:
        raise ValueError(f"unknown packaged asset: {name}")
    length, digest = ASSETS[name]
    try:
        data = files("minirj").joinpath("data", name).read_bytes()
    except FileNotFoundError as exc:
        raise FileNotFoundError(f"required packaged asset missing: {name}") from exc
    if len(data) != length or hashlib.sha256(data).hexdigest() != digest:
        raise ValueError(f"packaged asset integrity check failed: {name}")
    return data
