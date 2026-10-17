"""Regression inputs supplied outside the repository; absent inputs skip locally."""
import json
from pathlib import Path
import unittest

BASE = Path(__file__).resolve().parents[1] / ".local"


def load(name):
    path = BASE / name
    if not path.is_file():
        raise unittest.SkipTest("local regression input unavailable")
    return json.loads(path.read_text(encoding="utf-8"))
