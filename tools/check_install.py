"""Offline zipapp build -> isolated import acceptance. Python 3.10+, Linux.

Run as PID1 in an isolated user/net/PID namespace. For filesystem independence,
add a private mount/container boundary that hides the old research workspace.
No target execution, authentication, DHCP, or server interaction occurs here.
"""
import ast
import hashlib
import os
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
PACKAGE_FILES = frozenset("""
minirj/__init__.py
minirj/core/__init__.py
minirj/core/config.py
minirj/core/file_reg.py
minirj/core/network_config.py
minirj/core/session_guard.py
minirj/core/state_machine.py
minirj/core/suconfig_codec.py
minirj/crypto/__init__.py
minirj/crypto/cencryption.py
minirj/crypto/des.py
minirj/crypto/md5_vz.py
minirj/crypto/radius_pwd.py
minirj/crypto/ripemd128.py
minirj/crypto/tiger.py
minirj/crypto/v3.py
minirj/crypto/whirlpool.py
minirj/data/ASSET_PROVENANCE.txt
minirj/data/__init__.py
minirj/data/whirlpool_tables.bin
minirj/main.py
minirj/network/__init__.py
minirj/network/events.py
minirj/network/raw_socket.py
minirj/network/snapshot.py
minirj/protocol/__init__.py
minirj/protocol/eapol.py
minirj/protocol/hello.py
minirj/protocol/private_property.py
minirj/protocol/tlv.py
minirj/resources.py
minirj/service.py
""".split())


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def asset_pins():
    tree = ast.parse((ROOT / "minirj/resources.py").read_text())
    return next(ast.literal_eval(n.value) for n in tree.body if isinstance(n, ast.Assign)
                and any(isinstance(t, ast.Name) and t.id == "ASSETS" for t in n.targets))


def check_assets(read):
    for name, (length, digest) in asset_pins().items():
        data = read("minirj/data/" + name)
        require(len(data) == length and hashlib.sha256(data).hexdigest() == digest,
                f"changed packaged resource: {name}")


SMOKE = r"""
import pathlib, sys
sys.path.insert(0, sys.argv[1])
import minirj
from minirj.crypto.v3 import V3Generator
from minirj.resources import ASSETS, load_asset
base = pathlib.Path(sys.argv[1]).resolve()
p = pathlib.Path(minirj.__file__).resolve()
assert str(p).startswith(str(base) + "/"), (p, base)
V3Generator()
for name in ASSETS: load_asset(name)
print('INSTALLED GOLDEN PASS', len(ASSETS))
for name, module in list(sys.modules.items()):
    if name == 'minirj' or name.startswith('minirj.'):
        origin = getattr(module, '__file__', None)
        if origin:
            assert pathlib.Path(origin).resolve().is_relative_to(base), (name, origin)
print('PACKAGE', base)
"""


def main():
    if sys.version_info < (3, 10):
        raise SystemExit("check_install.py requires Python 3.10+")
    if not __debug__:
        raise SystemExit("acceptance must not run with -O/-OO")
    for name in PACKAGE_FILES:
        require((ROOT / name).is_file(), f"missing source file: {name}")
    check_assets(lambda name: (ROOT / name).read_bytes())
    with tempfile.TemporaryDirectory(prefix="rj-install-") as temporary:
        tmp = Path(temporary)
        env = {"PATH": os.defpath, "HOME": str(tmp), "TMPDIR": str(tmp), "LC_ALL": "C.UTF-8",
               "PYTHONNOUSERSITE": "1", "PYTHONDONTWRITEBYTECODE": "1"}
        def run(argv, check=True):
            result = subprocess.run([str(a) for a in argv], cwd=tmp, env=env, text=True,
                                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=240)
            print(result.stdout, end="", flush=True)
            if check and result.returncode:
                raise RuntimeError(f"command failed ({result.returncode}): {argv}")
            return result
        python = sys.executable
        pyz = tmp / "minirj.pyz"
        run([python, "-I", str(ROOT / "deploy/build_zipapp.py"),
             "--source", str(ROOT / "minirj"),
             "--entry", str(ROOT / "deploy/zipapp_main.py"),
             "--output", str(pyz)])
        run([python, "-I", str(pyz), "--version"])
        run([python, "-I", str(pyz), "--help"])
        observed = run([python, "-I", "-c", SMOKE, pyz])
        require(any(line.startswith("PACKAGE ") for line in observed.stdout.splitlines()),
                "smoke test did not report the package origin")
        extract = tmp / "extract"
        run([python, "-I", "-m", "zipfile", "-e", str(pyz), str(extract)])
        negative_count = 0
        probe = "import sys; sys.path.insert(0, sys.argv[1]); from minirj.crypto.v3 import V3Generator; V3Generator()"
        for name in asset_pins():
            path = extract / "minirj/data" / name
            original = path.read_bytes()
            try:
                path.unlink()
                result = run([python, "-I", "-c", probe, extract], check=False)
                require(result.returncode != 0 and "required packaged asset missing" in result.stdout,
                        f"missing asset did not fail: {name}")
                negative_count += 1
                path.write_bytes(bytes([original[0] ^ 1]) + original[1:])
                result = run([python, "-I", "-c", probe, extract], check=False)
                require(result.returncode != 0 and "integrity check failed" in result.stdout,
                        f"corrupt asset did not fail: {name}")
                negative_count += 1
            finally:
                path.write_bytes(original)
        run([python, "-I", "-c", SMOKE, extract])
        print("PASS: source -> zipapp -> isolated import", "asset failure cases", negative_count, flush=True)


if __name__ == "__main__":
    main()
