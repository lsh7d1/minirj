"""Read-only Linux link/IPv4 polling; never configure networking."""
from dataclasses import dataclass
import errno
import fcntl
import math
import socket
import struct
from .snapshot import IPv4Snapshot, LinuxIPv4SnapshotProvider


@dataclass(frozen=True)
class NetworkEvent:
    ifname: str
    link_up: bool
    snapshot: IPv4Snapshot | None = None
    status: str = "observed"
    ifindex: int | None = None

    def __post_init__(self):
        if not isinstance(self.link_up, bool):
            raise ValueError("link_up must be boolean")
        if self.snapshot is not None and not isinstance(self.snapshot, IPv4Snapshot):
            raise ValueError("snapshot must be IPv4Snapshot")
        if self.status not in ("observed", "missing", "unknown"):
            raise ValueError("invalid observation status")
        if self.status != "observed" and self.link_up:
            raise ValueError("unavailable observations cannot assert link up")


def snapshot_key(snapshot):
    """Global resolver DNS and warnings are not interface change evidence."""
    return (snapshot.ip, snapshot.netmask, snapshot.gateway)


def _strict_ioctl(fd, operation, request):
    try:
        response = fcntl.ioctl(fd, operation, request)
        if (not isinstance(response, bytes) or len(response) < 24
                or struct.unpack_from("H", response, 16)[0] != socket.AF_INET):
            raise RuntimeError("invalid IPv4 observation")
        return response
    except OSError as exc:
        if exc.errno == errno.EADDRNOTAVAIL:
            raise  # Known absence of IPv4, not an unknown read failure.
        raise RuntimeError("IPv4 observation unavailable") from None


def read_linux_link(ifname):
    """GETLINK to the local kernel only, not a wire packet or configuration.

    NETLINK_ROUTE observes the current network namespace, unlike inherited
    /sys/class/net mounts. Carrier AND administrative/operational state gate up.
    """
    try:
        index = socket.if_nametoindex(ifname)
    except OSError as exc:
        if exc.errno in (errno.ENODEV, errno.ENXIO):
            return None, False
        # CPython may omit errno for a missing interface name. Confirm via
        # another read-only kernel query rather than treating any error as down.
        if exc.errno is None and ifname not in dict(socket.if_nameindex()).values():
            return None, False
        raise
    with socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, socket.NETLINK_ROUTE) as sock:
        sock.settimeout(0.2)
        sock.bind((0, 0))
        body = struct.pack("=BBHiII", socket.AF_UNSPEC, 0, 0, index, 0, 0)
        sock.sendto(struct.pack("=IHHII", 32, 18, 1, 1, 0) + body, (0, 0))
        data, _, flags, sender = sock.recvmsg(65536)
        if sender[0] != 0 or flags & socket.MSG_TRUNC:
            raise ValueError("invalid link observation")
        offset = 0
        while offset + 16 <= len(data):
            length, kind, _, sequence, _ = struct.unpack_from("=IHHII", data, offset)
            if length < 16 or offset + length > len(data) or sequence != 1:
                raise ValueError("invalid link response")
            payload = data[offset + 16:offset + length]
            if kind == 2:
                error = struct.unpack_from("=i", payload)[0]
                if error in (-errno.ENODEV, -errno.ENXIO):
                    return None, False
                raise OSError("link query failed")
            if kind == 16:
                _, _, _, actual, link_flags, _ = struct.unpack_from("=BBHiII", payload)
                if actual != index:
                    raise ValueError("interface changed during observation")
                attrs = {}
                pos = 16
                while pos + 4 <= len(payload):
                    size, attr = struct.unpack_from("=HH", payload, pos)
                    if size < 4 or pos + size > len(payload):
                        raise ValueError("invalid link attribute")
                    attrs[attr] = payload[pos + 4:pos + size]
                    pos += (size + 3) & ~3
                carrier, state = attrs.get(33), attrs.get(16)
                if carrier not in (b"\x00", b"\x01") or state is None or len(state) != 1 or state[0] > 6:
                    raise ValueError("carrier/operstate unavailable")
                # UNKNOWN operstate occurs on virtual devices; require carrier.
                return index, bool(link_flags & 1 and carrier == b"\x01" and state[0] in (0, 6))
            offset += (length + 3) & ~3
    raise ValueError("link response missing")


class LinuxNetworkEventSource:
    """Bounded synchronous polling. Construction performs no I/O.

    Unknown observations fail closed but remain distinguishable from link down
    and interface absence. Duplicate snapshots refresh data without recovery.
    """
    def __init__(self, ifname, *, snapshot_provider=None, read_link=None, interval=0.5):
        if (not isinstance(ifname, str) or not ifname or len(ifname.encode()) >= 16
                or "\0" in ifname or "/" in ifname):
            raise ValueError("invalid network monitor interface")
        if not math.isfinite(interval) or interval <= 0:
            raise ValueError("invalid network monitor interval")
        self.ifname = ifname
        self.snapshot_provider = (snapshot_provider if snapshot_provider is not None
                                  else LinuxIPv4SnapshotProvider(ioctl=_strict_ioctl))
        self._read_link = read_linux_link if read_link is None else read_link
        self.interval = interval
        self._next_poll = None
        self.status = "unobserved"

    def poll(self, now):
        if self._next_poll is not None and now < self._next_poll:
            return ()
        self._next_poll = now + self.interval
        index = None
        try:
            index, up = self._read_link(self.ifname)
            if index is None:
                event = NetworkEvent(self.ifname, False, status="missing")
            elif not up:
                event = NetworkEvent(self.ifname, False, ifindex=index)
            else:
                snapshot = self.snapshot_provider.read(self.ifname)
                if not isinstance(snapshot, IPv4Snapshot):
                    raise ValueError("invalid snapshot")
                if snapshot.observation_errors:
                    raise ValueError("incomplete address observation")
                if self._read_link(self.ifname) != (index, up):
                    raise ValueError("link changed during snapshot")
                event = NetworkEvent(self.ifname, True, snapshot, ifindex=index)
        except Exception:
            # Never expose provider exception text, which may contain credentials.
            event = NetworkEvent(self.ifname, False, status="unknown", ifindex=index)
        self.status = event.status if event.status != "observed" else ("up" if event.link_up else "down")
        return (event,)
