#!/usr/bin/env python3
"""Command-line entry point for MiniRJ."""

from __future__ import annotations

import argparse
from dataclasses import dataclass, field
import ipaddress
import signal
import sys
from typing import Sequence, TextIO

from minirj import __version__
from minirj.core.config import SuConfigLoader
from minirj.core.file_reg import FileRegConfig
from minirj.core.state_machine import StateMachine
from minirj.core.network_config import NetworkConfig
from minirj.network.events import LinuxNetworkEventSource
from minirj.core.session_guard import SessionGuard, detect_competitors

DEFAULT_SERVICE = "internet"
DEFAULT_DHCP = 1
DEFAULT_CLIENT_VERSION = "RG_SU_For_Windows 6.84"


@dataclass(frozen=True)
class RuntimeConfig:
    interface: str
    username: str = field(repr=False)
    password: str = field(repr=False)
    service: str
    dhcp: int
    dhcp_script: str
    client_version: str
    network_backend: str
    script_timeout: float
    logoff_on_exit: bool
    vlan_tci: int | None = None
    vlan_ethertype: int = 0x8100
    network_monitor: bool = True
    binary_version: tuple[int, int, int, int] | None = None
    protocol_profile: str = "auto"
    start_destination: bytes = bytes.fromhex("0180c2000003")
    external_dns: tuple[str, ...] = ()


def _binary_version(value: str) -> tuple[int, int, int, int]:
    components = value.split(".")
    if (len(components) != 4 or any(not item or not item.isascii() or not item.isdecimal()
                                    or len(item) > 3 or int(item) > 255 for item in components)):
        raise argparse.ArgumentTypeError("binary version must be four decimal bytes (0..255)")
    return tuple(int(item) for item in components)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="minirj",
        description="MiniRJ: 802.1X/EAP-MD5 Client for Ruijie Networks",
    )
    parser.add_argument("--campus-profile", action="store_true",
                        help="Use this deployment's Ruijie double-auth parameters: "
                             "service 校外, binary version 6.84.0.0, Ruijie Start; "
                             "does not configure DHCP or supply credentials")
    parser.add_argument("-c", "--config", default=None, help="Path to SuConfig.dat")
    parser.add_argument(
        "--credentials",
        default=None,
        help="Path to fileReg.ini (defaults to the file beside SuConfig.dat)",
    )
    parser.add_argument("-i", "--interface", default=None, help="Network interface")
    parser.add_argument("--vlan-tci", type=lambda value: int(value, 0), default=None,
                        help="Explicit full VLAN TCI; default untagged only, no VLAN learning")
    parser.add_argument("--vlan-ethertype", type=lambda value: int(value, 0),
                        choices=(0x8100, 0x88a8), default=0x8100)
    parser.add_argument("-u", "--username", default=None, help="Authentication username")
    password_group = parser.add_mutually_exclusive_group()
    password_group.add_argument("-p", "--password", default=None, help="Authentication password")
    password_group.add_argument(
        "--password-stdin",
        action="store_true",
        help="Read the authentication password from standard input",
    )
    parser.add_argument("-s", "--service", default=None, help="Service name")
    parser.add_argument(
        "-d", "--dhcp", type=int, choices=(0, 1), default=None, help="Protocol DHCP mode; does not launch DHCP"
    )
    parser.add_argument("--dhcp-script", default=None, help="Foreground network script (script backend only)")
    parser.add_argument("--network-backend", choices=("external", "script"), default="external")
    parser.add_argument("--no-network-monitor", action="store_true",
                        help="Disable read-only link/IPv4 monitoring (external backend only)")
    parser.add_argument("--script-timeout", type=float, default=30.0)
    parser.add_argument("--logoff-on-exit", action="store_true",
                        help="Send Logoff on termination; default is local stop only")
    parser.add_argument(
        "--client-version", "--client-release", default=None,
        help="Release text (independent of four-byte binary version)"
    )
    parser.add_argument("--binary-version", type=_binary_version, default=None,
                        help="Explicit four-byte version, e.g. 6.84.0.0; legacy default unchanged")
    parser.add_argument("--protocol-profile", choices=("auto", "ruijie"), default=None,
                        help="Explicit Ruijie session profile; does not bypass server correlation")
    parser.add_argument("--ruijie-start", action="store_true",
                        help="Use Ruijie 01:d0:f8:00:00:03 Start instead of standard 802.1X multicast")
    parser.add_argument(
        "--external-dns", "--dns", default=None,
        help="Custom external DNS server(s), comma-separated (e.g. 114.114.114.114,223.5.5.5)"
    )
    parser.add_argument(
        "--version", action="version", version=f"%(prog)s {__version__}"
    )
    return parser


def _read_password(stdin: TextIO) -> str:
    password = stdin.readline()
    return password[:-2] if password.endswith("\r\n") else password.rstrip("\n")


def resolve_runtime_config(args: argparse.Namespace, stdin: TextIO = sys.stdin) -> RuntimeConfig:
    loaded: dict[str, object] = {}
    if args.config:
        loaded.update(
            SuConfigLoader(args.config, credentials_path=args.credentials).get_auth_params()
        )
    elif args.credentials:
        credentials = FileRegConfig.load(args.credentials)
        loaded.update(username=credentials.username, password=credentials.password)

    if args.vlan_tci is not None and (not 0 <= args.vlan_tci <= 65535
                                     or args.vlan_tci & 0xfff == 0xfff):
        raise ValueError("invalid VLAN TCI (VID 4095 reserved)")
    password = _read_password(stdin) if args.password_stdin else args.password
    external_dns = ()
    if getattr(args, "external_dns", None):
        try:
            parts = args.external_dns.split(",")
            if any(not part.strip() for part in parts):
                raise ValueError("empty DNS entry")
            addresses = [ipaddress.IPv4Address(value) for part in parts for value in part.split()]
            if not 1 <= len(addresses) <= 3 or len(set(addresses)) != len(addresses):
                raise ValueError("must specify 1 to 3 unique IPv4 addresses")
            zero_net = ipaddress.IPv4Network("0.0.0.0/8")
            if any(a in zero_net or a.is_unspecified or a.is_loopback or a.is_link_local
                   or a.is_multicast or a.is_reserved or str(a) == "255.255.255.255" for a in addresses):
                raise ValueError("must be unicast IPv4 addresses")
            external_dns = tuple(str(a) for a in addresses)
        except ValueError as exc:
            raise ValueError(f"invalid external DNS address: {args.external_dns}") from exc
    values = {
        "interface": args.interface if args.interface is not None else loaded.get("nic", ""),
        "username": args.username if args.username is not None else loaded.get("username", ""),
        "password": password if password is not None else loaded.get("password", ""),
        "service": (
            args.service
            if args.service is not None
            else "校外" if args.campus_profile else loaded.get("service_name", DEFAULT_SERVICE)
        ),
        "dhcp": (args.dhcp if args.dhcp is not None else
                 1 if args.campus_profile else loaded.get("dhcp", DEFAULT_DHCP)),
        "dhcp_script": args.dhcp_script if args.dhcp_script is not None else "",
        "network_backend": args.network_backend,
        "network_monitor": not args.no_network_monitor and args.network_backend == "external",
        "script_timeout": args.script_timeout,
        "logoff_on_exit": args.logoff_on_exit,
        "vlan_tci": args.vlan_tci,
        "vlan_ethertype": args.vlan_ethertype,
        "binary_version": (args.binary_version if args.binary_version is not None else
                           (6, 84, 0, 0)),
        "protocol_profile": (args.protocol_profile if args.protocol_profile is not None else
                             "ruijie" if args.campus_profile else "auto"),
        "start_destination": bytes.fromhex(
            "01d0f8000003" if args.ruijie_start or args.campus_profile else "0180c2000003"),
        "client_version": (
            args.client_version
            if args.client_version is not None
            else DEFAULT_CLIENT_VERSION
        ),
        "external_dns": external_dns,
    }
    return RuntimeConfig(**values)  # type: ignore[arg-type]


def main(argv: Sequence[str] | None = None, stdin: TextIO = sys.stdin) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        config = resolve_runtime_config(args, stdin)
        NetworkConfig(config.network_backend, config.dhcp_script, config.script_timeout)
    except (OSError, ValueError):
        parser.error("invalid or unreadable configuration")

    missing = [
        label
        for label, value in (
            ("username", config.username),
            ("password", config.password),
            ("network interface", config.interface),
        )
        if not value
    ]
    if missing:
        parser.error(
            "missing required "
            + ", ".join(missing)
            + " (use CLI options or a configuration bundle)"
        )

    print("=" * 60)
    print(" MiniRJ (Ruijie 802.1X/EAP-MD5 Client)")
    print(f" Interface   : {config.interface}")
    print(f" Service     : {config.service}")
    print(f" DHCP Mode   : {config.dhcp} (protocol field)")
    print(f" Network     : {config.network_backend}")
    print(f" Client Ver  : {config.client_version}")
    print("=" * 60)

    event_source = LinuxNetworkEventSource(config.interface) if config.network_monitor else None
    sm = StateMachine(
        ifname=config.interface,
        username=config.username,
        password=config.password,
        service_name=config.service,
        client_ver=config.client_version,
        client_version=config.binary_version,
        protocol_profile=config.protocol_profile,
        start_destination=config.start_destination,
        dhcp_mode=config.dhcp,
        dhcp_script=config.dhcp_script,
        network_backend=config.network_backend,
        script_timeout=config.script_timeout,
        logoff_on_exit=config.logoff_on_exit,
        vlan_tci=config.vlan_tci,
        vlan_ethertype=config.vlan_ethertype,
        event_source=event_source,
        external_dns=config.external_dns,
    )

    def sig_handler(signum, frame):
        del signum, frame
        sm.stop()
        print("[*] Local stop requested; cleanup follows the selected exit policy.")

    signal.signal(signal.SIGINT, sig_handler)
    signal.signal(signal.SIGTERM, sig_handler)

    try:
        with SessionGuard(config.interface):
            conflicts, incomplete = detect_competitors(config.interface)
            if conflicts:
                print("[!] Competing authentication client: " + ", ".join(conflicts), file=sys.stderr)
                return 1
            if incomplete:
                print("[*] Process scan incomplete; exclusive ownership is not guaranteed.")
            if not sm.authenticate():
                print("[-] Authentication session ended without a successful clean stop.")
                return 1
            return 0
    except KeyboardInterrupt:
        sig_handler(None, None)
    except PermissionError:
        print(
            "[!] Permission denied: Linux Raw Socket requires root privileges (Run with sudo).",
            file=sys.stderr,
        )
        return 1
    except Exception:
        print("[!] Runtime error; authentication session stopped.", file=sys.stderr)
        sm.stop()
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
