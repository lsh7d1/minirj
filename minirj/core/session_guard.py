"""Linux-only cooperative per-interface lock and best-effort read-only scan."""

import errno
import hashlib
import os
from pathlib import Path
import socket


class SessionGuard:
    def __init__(self, interface):
        self.address = "\0minirj-" + hashlib.sha256(interface.encode()).hexdigest()
        self.sock = None

    def __enter__(self):
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        try:
            sock.bind(self.address)
        except OSError as exc:
            sock.close()
            if exc.errno == errno.EADDRINUSE:
                raise RuntimeError("another local session owns this interface") from None
            raise
        self.sock = sock
        return self

    def __exit__(self, *args):
        if self.sock is not None:
            self.sock.close()
            self.sock = None


def detect_competitors(interface, proc_root="/proc"):
    """Return safe name/PID labels only; unknown interfaces are not conflicts.

    Only recognize explicit interface flags for known EAP clients. No argv,
    credentials, service changes, or signals are emitted.
    """
    root = Path(proc_root)
    conflicts = []
    incomplete = False
    known = {"rjsupplicant": ("-n", "--nic", "--interface"),
             "mentohust": ("-n",), "minieap": ("-i", "--interface"),
             "wpa_supplicant": ("-i",)}
    try:
        own_ns = (root / "self/ns/net").readlink()
        entries = list(root.iterdir())
    except OSError:
        return [], True
    for entry in entries:
        if not entry.name.isdigit() or int(entry.name) == os.getpid():
            continue
        try:
            if (entry / "ns/net").readlink() != own_ns:
                continue
            argv = (entry / "cmdline").read_bytes().decode(errors="replace").split("\0")
        except FileNotFoundError:
            continue  # process exited during the scan
        except PermissionError:
            continue  # other-uid process; unreadable without CAP_SYS_PTRACE
        except OSError:
            incomplete = True
            continue
        name = Path(argv[0]).name
        if name not in known:
            continue
        interfaces = []
        for i, arg in enumerate(argv[1:], 1):
            for flag in known[name]:
                if arg == flag and i + 1 < len(argv):
                    interfaces.append(argv[i + 1])
                elif flag.startswith("--") and arg.startswith(flag + "="):
                    interfaces.append(arg[len(flag) + 1:])
                elif len(flag) == 2 and arg.startswith(flag) and len(arg) > 2:
                    interfaces.append(arg[2:])
        if interface in interfaces:
            conflicts.append(f"{name} (PID {entry.name})")
        elif not interfaces:
            incomplete = True
    return conflicts, incomplete
