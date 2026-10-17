#!/usr/bin/env python3
"""Build the minirj zipapp with the standard library only."""
from __future__ import annotations

import argparse
import hashlib
from pathlib import Path
import shutil
import tempfile
import zipapp


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", required=True)
    parser.add_argument("--entry", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    source = Path(args.source).resolve()
    output = Path(args.output).resolve()
    with tempfile.TemporaryDirectory(prefix="minirj-zipapp-") as tmp:
        stage = Path(tmp) / "app"
        shutil.copytree(source, stage / source.name,
                        ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
        shutil.copy2(Path(args.entry).resolve(), stage / "__main__.py")
        zipapp.create_archive(stage, output, interpreter="/usr/bin/python3 -I", compressed=True)
    output.chmod(0o755)
    data = output.read_bytes()
    print(f"{output} {len(data)} bytes sha256={hashlib.sha256(data).hexdigest()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
