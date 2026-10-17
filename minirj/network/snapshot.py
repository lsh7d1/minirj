"""Read-only Linux IPv4 observations, not DHCP or connectivity verification.

Only the selected interface's primary ioctl IPv4 address/netmask and lowest
metric active default gateway in /proc/net/route are used. Secondary addresses,
policy routing, other namespaces and per-link resolver configuration are not
queried. /etc/resolv.conf is a global resolver source, NOT evidence of DNS for
this interface or of an upstream DNS server; loopback stubs are retained and
explicitly warned about. Missing fields are "0.0.0.0", never borrowed from
another interface. Reads are sequential, not an atomic kernel snapshot.

This provider does not implement authentication lifecycle policy. Callers own
initial DHCP IP/netmask/gateway clearing (preserving DNS) and step-2 snapshot
retention. It never runs commands, sends packets or writes runtime files.
"""

from dataclasses import dataclass
import errno
import fcntl
from ipaddress import IPv4Address, IPv6Address, ip_address
from pathlib import Path
import socket
import struct
import sys
from typing import Callable


SIOCGIFADDR = 0x8915
SIOCGIFNETMASK = 0x891B
ROUTE_PATH = "/proc/net/route"
RESOLV_PATH = "/etc/resolv.conf"
IF_INET6_PATH = "/proc/net/if_inet6"
IPV6_ROUTE_PATH = "/proc/net/ipv6_route"


def _offered(value: str) -> bool:
    try:
        address = IPv4Address(value)
    except ValueError:
        return False
    return int(address) != 0 and not address.is_link_local


@dataclass(frozen=True)
class IPv4Snapshot:
    ip: str = "0.0.0.0"
    netmask: str = "0.0.0.0"
    gateway: str = "0.0.0.0"
    dns: str = "0.0.0.0"
    secondary_dns: str = "0.0.0.0"
    warnings: tuple[str, ...] = ()
    # Stable interface-observation errors; DNS diagnostics never enter this field.
    # Empty means known (possibly empty IPv4), not connectivity or DHCP success.
    observation_errors: tuple[str, ...] = ()
    # Legacy get_alternate_dns skips the first nameserver and joins the rest.
    # Preserve that list separately from the existing IPv4 primary/secondary view.
    alternate_dns: tuple[str, ...] = ()
    # Concrete uncoupled IPv6 properties (from /proc/net/if_inet6 and ipv6_route)
    ipv6_address: str = ""
    ipv6_link_local: str = ""
    ipv6_gateway: str = ""
    ipv6_prefix_len: int = 0

    def __post_init__(self):
        # Also freeze a caller-supplied list rather than retaining its alias.
        object.__setattr__(self, "warnings", tuple(self.warnings))
        object.__setattr__(self, "alternate_dns", tuple(self.alternate_dns))
        object.__setattr__(self, "observation_errors", tuple(self.observation_errors))

    @property
    def ready(self) -> bool:
        """IsGetDhcpIpp-style IP/GW check only; no reachability assertion."""
        return not self.observation_errors and _offered(self.ip) and _offered(self.gateway)


def _read_text(path: str) -> str:
    return Path(path).read_text(encoding="ascii")


class LinuxIPv4SnapshotProvider:
    """Inject read_text(path), socket_factory(family, type), and ioctl mocks.

    Construction performs no I/O. A read opens one AF_INET/SOCK_DGRAM socket
    solely for two GET ioctls, then closes it. Fixture injection needs no real
    interface, root access, file writes or network traffic.
    """

    def __init__(self, *, read_text: Callable[[str], str] | None = None,
                 socket_factory: Callable | None = None,
                 ioctl: Callable | None = None):
        self._read_text = _read_text if read_text is None else read_text
        self._socket_factory = socket.socket if socket_factory is None else socket_factory
        self._ioctl = fcntl.ioctl if ioctl is None else ioctl

    def read(self, ifname: str) -> IPv4Snapshot:
        if not isinstance(ifname, str):
            raise ValueError("interface name must be a string")
        encoded = ifname.encode("utf-8")
        if not encoded or len(encoded) >= 16 or b"\0" in encoded:
            raise ValueError("interface name must contain 1-15 bytes without NUL")
        warnings = []
        errors = []
        values = {"ip": "0.0.0.0", "netmask": "0.0.0.0"}
        request = struct.pack("256s", encoded)
        try:
            with self._socket_factory(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                for field, operation in (("ip", SIOCGIFADDR),
                                         ("netmask", SIOCGIFNETMASK)):
                    try:
                        response = self._ioctl(sock.fileno(), operation, request)
                        if len(response) < 24 or struct.unpack_from("H", response, 16)[0] != socket.AF_INET:
                            raise ValueError("invalid IPv4 ioctl response")
                        values[field] = str(IPv4Address(response[20:24]))
                    except (OSError, ValueError, TypeError) as exc:
                        warnings.append(f"{ifname}: {field} unavailable from ioctl")
                        if not isinstance(exc, OSError) or exc.errno != errno.EADDRNOTAVAIL:
                            errors.append(f"{field}_unavailable")
        except OSError:
            warnings.append(f"{ifname}: IPv4 ioctl socket unavailable")
            errors.append("ioctl_socket_unavailable")
        gateway = self._gateway(ifname, warnings, errors)
        dns, secondary_dns, alternate_dns = self._dns(warnings, with_alternates=True)
        ipv6_address, ipv6_link_local, ipv6_gateway, ipv6_prefix_len = self._ipv6(ifname, warnings)
        return IPv4Snapshot(**values, gateway=gateway, dns=dns,
                            secondary_dns=secondary_dns, warnings=tuple(warnings),
                            observation_errors=tuple(errors), alternate_dns=alternate_dns,
                            ipv6_address=ipv6_address, ipv6_link_local=ipv6_link_local,
                            ipv6_gateway=ipv6_gateway, ipv6_prefix_len=ipv6_prefix_len)

    def _text(self, path, warnings):
        try:
            return self._read_text(path)
        except (OSError, UnicodeError, KeyError):
            warnings.append(f"{path}: unavailable")
            return None

    def _ipv6(self, ifname: str, warnings: list[str]) -> tuple[str, str, str, int]:
        global_ip = ""
        link_local = ""
        prefix_len = 0
        gateway = ""

        # 1. Parse /proc/net/if_inet6
        text = self._text(IF_INET6_PATH, warnings)
        for line in (text or "").splitlines():
            parts = line.split()
            if len(parts) >= 6 and parts[5] == ifname:
                try:
                    addr_bytes = bytes.fromhex(parts[0])
                    if len(addr_bytes) != 16:
                        continue
                    formatted = str(IPv6Address(addr_bytes))
                    scope = int(parts[3], 16)
                    plen = int(parts[2], 16)
                    if scope == 0x20 and not link_local:
                        link_local = formatted
                    elif scope == 0x00 and not global_ip:
                        global_ip = formatted
                        prefix_len = plen
                except Exception:
                    continue

        # 2. Parse /proc/net/ipv6_route for default route ::/0
        route_text = self._text(IPV6_ROUTE_PATH, warnings)
        for line in (route_text or "").splitlines():
            parts = line.split()
            if len(parts) >= 10 and parts[9] == ifname:
                try:
                    dst = parts[0]
                    dst_len = parts[1]
                    gw_hex = parts[4]
                    if dst == "0" * 32 and dst_len == "00" and gw_hex != "0" * 32:
                        gw_bytes = bytes.fromhex(gw_hex)
                        if len(gw_bytes) == 16:
                            gateway = str(IPv6Address(gw_bytes))
                            break
                except Exception:
                    continue

        return global_ip, link_local, gateway, prefix_len

    def _gateway(self, ifname, warnings, errors):
        candidates = []
        text = self._text(ROUTE_PATH, warnings)
        if text is None:
            errors.append("route_unavailable")
        for line in (text or "").splitlines():
            fields = line.split()
            if not fields or fields[0] != ifname:
                continue
            try:
                destination, gateway, flags = (int(value, 16) for value in fields[1:4])
                metric = int(fields[6])
                mask = int(fields[7], 16)
                if destination != 0 or mask != 0 or flags & 3 != 3 or flags & 0x200:
                    continue  # Require UP + GATEWAY, exclude REJECT routes.
                if metric < 0:
                    raise ValueError("negative metric")
                address = str(IPv4Address(gateway.to_bytes(4, sys.byteorder)))
                candidates.append((metric, address))
            except (ValueError, IndexError, OverflowError):
                warnings.append(f"{ROUTE_PATH}: malformed route for {ifname}")
                errors.append("route_malformed")
        if not candidates:
            warnings.append(f"{ifname}: default gateway unavailable from {ROUTE_PATH}")
            return "0.0.0.0"
        # Stable min preserves file order when metrics tie.
        return min(candidates, key=lambda item: item[0])[1]

    def _parse_resolv_file(self, path, warnings, addresses, nameservers):
        try:
            content = self._text(path, warnings)
        except Exception:
            return
        if not content:
            return
        for line in content.splitlines():
            fields = line.split("#", 1)[0].split(";", 1)[0].split()
            if not fields or fields[0] != "nameserver":
                continue
            try:
                ip_address(fields[1])
                nameservers.append(fields[1])
                address = IPv4Address(fields[1])
            except (ValueError, IndexError):
                warnings.append(f"{path}: non-IPv4 or malformed nameserver ignored")
                continue
            text = str(address)
            if address.is_loopback:
                warnings.append(f"{path}: {text} is a loopback resolver/stub, not a verified upstream DNS server")
            if text not in addresses:
                addresses.append(text)

    def _dns(self, warnings, *, with_alternates=False):
        warnings.append(f"DNS source: {RESOLV_PATH} (global; interface association and upstream DNS unverified)")
        addresses = []
        nameservers = []
        self._parse_resolv_file(RESOLV_PATH, warnings, addresses, nameservers)
        if not addresses or all(IPv4Address(a).is_loopback for a in addresses if not a.startswith(":")):
            for alt_path in ("/run/systemd/resolve/resolv.conf", "/run/NetworkManager/resolv.conf"):
                alt_addresses = []
                self._parse_resolv_file(alt_path, warnings, alt_addresses, nameservers)
                valid = [a for a in alt_addresses if not IPv4Address(a).is_loopback]
                if valid:
                    addresses = valid
                    warnings.append(f"Upstream DNS recovered from {alt_path}")
                    break
        if not addresses:
            warnings.append(f"{RESOLV_PATH}: IPv4 DNS unavailable")
        primary, secondary = (addresses + ["0.0.0.0", "0.0.0.0"])[:2]
        if with_alternates:
            return primary, secondary, tuple(nameservers[1:])
        return primary, secondary
