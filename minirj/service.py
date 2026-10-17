"""One session, bounded health checks, one recovery policy: let systemd restart.

No deployment daemon, socket unit, timer, protocol changes, or credential argv.
The executable is also the foreground DHCP hook (one interface argument).
"""
from __future__ import annotations

import ipaddress
from ipaddress import ip_address
import os
from pathlib import Path
import signal
import socket
import ssl
import subprocess
import sys
import threading
import time
from urllib.parse import urlsplit
from uuid import UUID

PROBE_INTERVAL = 30
PROGRESS_TIMEOUT = 60
PROBE_CONNECT_TIMEOUT = 6
PROBE_TOTAL_TIMEOUT = 8
PROBE_PROCESS_TIMEOUT = 10
PROBE_RETRY_DELAY = 1
REAUTH_GRACE = 15
HEALTH_CYCLE_TIMEOUT = 2 * PROBE_PROCESS_TIMEOUT + PROBE_RETRY_DELAY + REAUTH_GRACE + 1


class HealthFailure(RuntimeError):
    REASONS = {
        "dns_failure", "dns_timeout", "connection_failed", "connection_timeout",
        "tls_timeout", "transfer_timeout", "transfer_failed", "tls_failed",
        "tls_verification_failed", "http_status", "source_mismatch",
        "probe_execution", "auth_stalled", "auth_unavailable", "phase2_unavailable", "address_unavailable",
        "address_changed", "reauth_timeout", "reauth_probe_stale", "health_cycle_timeout",
        "notify_failed", "internal_error",
    }
    TRANSIENT = {
        "dns_failure", "dns_timeout", "connection_failed", "connection_timeout",
        "tls_timeout", "transfer_timeout", "transfer_failed",
    }

    def __init__(self, reason, *, stage="runtime", details=None):
        if reason not in self.REASONS or stage not in {"runtime", "dns", "connect", "tls", "transfer", "unknown"}:
            raise ValueError("invalid health failure category")
        super().__init__(reason)
        self.reason, self.stage = reason, stage
        self.details = details

    @property
    def retryable(self):
        return self.reason in self.TRANSIENT

    def diagnostic(self):
        fields = [f"reason={self.reason}", f"stage={self.stage}"]
        if self.details is not None:
            fields.append(f"http={self.details['http']}")
            fields += [f"{name}_s={self.details[name]:.3f}" for name in ("dns", "tcp", "tls", "total")]
        if self.reason in {"dns_failure", "dns_timeout"}:
            fields.append("resolver_source=resolv.conf")
            fields.append("dns_servers=" + resolver_servers())
        return " ".join(fields)


def resolver_servers():
    try:
        servers = []
        for line in Path("/etc/resolv.conf").read_text().splitlines():
            fields = line.split()
            if len(fields) >= 2 and fields[0] == "nameserver":
                try:
                    server = str(ip_address(fields[1]))
                except ValueError:
                    continue
                if server not in servers:
                    servers.append(server)
        return ",".join(servers[:3]) or "none"
    except (OSError, UnicodeError):
        return "unavailable"


def _remaining(deadline):
    return max(0.0, deadline - time.monotonic())


def _resolve(host, port, deadline):
    result = {}

    def work():
        try:
            result["addresses"] = socket.getaddrinfo(host, port, socket.AF_INET, socket.SOCK_STREAM)
        except OSError as exc:
            result["error"] = exc

    worker = threading.Thread(target=work, daemon=True)
    worker.start()
    worker.join(_remaining(deadline))
    if worker.is_alive():
        raise HealthFailure("dns_timeout", stage="dns")
    if "error" in result:
        raise HealthFailure("dns_failure", stage="dns")
    addresses = result.get("addresses")
    if not addresses:
        raise HealthFailure("dns_failure", stage="dns")
    return addresses[0][4]


def _connect(interface, source_ip, address, deadline):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, interface.encode() + b"\0")
        sock.bind((source_ip, 0))
        sock.settimeout(_remaining(deadline))
        sock.connect(address)
    except TimeoutError:
        sock.close()
        raise HealthFailure("connection_timeout", stage="connect") from None
    except OSError:
        sock.close()
        raise HealthFailure("connection_failed", stage="connect") from None
    return sock


def _tls_wrap(sock, host, deadline):
    context = ssl.create_default_context()
    sock.settimeout(_remaining(deadline))
    try:
        return context.wrap_socket(sock, server_hostname=host)
    except ssl.SSLCertVerificationError:
        raise HealthFailure("tls_verification_failed", stage="tls") from None
    except TimeoutError:
        raise HealthFailure("tls_timeout", stage="tls") from None
    except ssl.SSLError:
        raise HealthFailure("tls_failed", stage="tls") from None
    except OSError:
        raise HealthFailure("connection_failed", stage="connect") from None


def _head(tls_sock, host, port, path, query, deadline):
    target = path or "/"
    if query:
        target += "?" + query
    host_header = host if port == 443 else f"{host}:{port}"
    request = (
        f"HEAD {target} HTTP/1.1\r\n"
        f"Host: {host_header}\r\n"
        "Connection: close\r\n"
        "User-Agent: minirj\r\n\r\n"
    ).encode("ascii")
    tls_sock.settimeout(_remaining(deadline))
    try:
        tls_sock.sendall(request)
        response = b""
        while b"\r\n" not in response and len(response) < 65536:
            chunk = tls_sock.recv(4096)
            if not chunk:
                break
            response += chunk
    except TimeoutError:
        raise HealthFailure("transfer_timeout", stage="transfer") from None
    except OSError:
        raise HealthFailure("transfer_failed", stage="transfer") from None
    line = response.split(b"\r\n", 1)[0]
    parts = line.split(b" ", 2)
    if len(parts) < 2 or not parts[0].startswith(b"HTTP/") or not parts[1].isdigit():
        raise HealthFailure("transfer_failed", stage="transfer")
    return int(parts[1])


def probe(interface, source_ip, url):
    parsed = urlsplit(url)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username is not None or parsed.password is not None:
        raise ValueError("probe requires an HTTPS URL without credentials")
    host = parsed.hostname
    port = parsed.port or 443
    started = time.monotonic()
    deadline = started + PROBE_TOTAL_TIMEOUT
    dns_deadline = min(deadline, started + PROBE_CONNECT_TIMEOUT)
    timings = {"http": 0, "dns": 0.0, "tcp": 0.0, "tls": 0.0, "total": 0.0}
    try:
        address = _resolve(host, port, dns_deadline)
        timings["dns"] = time.monotonic() - started
        tcp_started = time.monotonic()
        sock = _connect(interface, source_ip, address, min(deadline, tcp_started + PROBE_CONNECT_TIMEOUT))
        timings["tcp"] = time.monotonic() - tcp_started
        local = sock.getsockname()[0]
        if local != source_ip:
            sock.close()
            raise HealthFailure("source_mismatch", stage="connect")
        tls_started = time.monotonic()
        try:
            tls_sock = _tls_wrap(sock, host, deadline)
        except BaseException:
            sock.close()
            raise
        timings["tls"] = time.monotonic() - tls_started
        try:
            status = _head(tls_sock, host, port, parsed.path, parsed.query, deadline)
        finally:
            tls_sock.close()
        timings["http"] = status
        timings["total"] = time.monotonic() - started
        if not 200 <= status < 400:
            raise HealthFailure("http_status", stage="transfer", details=timings)
        return status
    except HealthFailure as exc:
        exc.details = timings
        exc.details["total"] = time.monotonic() - started
        raise


def settings():
    interface = os.environ["MINIRJ_INTERFACE"]
    if not interface or len(interface.encode()) >= 16 or any(c in interface for c in "\0\n\r/"):
        raise ValueError("invalid interface")
    connection = str(UUID(os.environ["MINIRJ_NM_UUID"]))
    return interface, connection


def nmcli(*args):
    # Never forward output (connection descriptions may contain personal data).
    return subprocess.check_output(
        ["/usr/bin/nmcli", "--wait", "10", *args], text=True, stderr=subprocess.DEVNULL,
        timeout=12, env={**os.environ, "LC_ALL": "C"},
    ).strip()


def network(interface, connection, *, up=False):
    # Only the explicitly configured, dedicated, non-autoconnect DHCP profile.
    properties = nmcli("-g", "connection.interface-name,connection.autoconnect,ipv4.method",
                      "connection", "show", "uuid", connection).splitlines()
    if properties != [interface, "no", "auto"]:
        raise RuntimeError("requires a dedicated non-autoconnect DHCP profile")
    active = nmcli("-g", "GENERAL.CON-UUID", "device", "show", interface)
    if active not in ("", "--", connection):
        raise RuntimeError("another connection owns the interface")
    if up:
        nmcli("connection", "up", "uuid", connection, "ifname", interface)
    elif active == connection:
        nmcli("connection", "down", "uuid", connection)


def credential(name):
    value = (Path(os.environ["CREDENTIALS_DIRECTORY"]) / name).read_text(encoding="utf-8")
    value = value[:-2] if value.endswith("\r\n") else value.removesuffix("\n")
    if not value or any(c in value for c in "\r\n\0"):
        raise ValueError("credential must be one nonempty line")
    return value


def notify(message):
    address = os.environ["NOTIFY_SOCKET"]
    if address.startswith("@"):
        address = "\0" + address[1:]
    with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as sock:
        sock.settimeout(2)
        sock.sendto(message.encode("ascii"), address)


def health_loop(machine, engine, interface, url, stopped, failed):
    # Import only in run mode: --down must still work if the package cannot import.
    from minirj.core.state_machine import AuthState
    from minirj.network.snapshot import LinuxIPv4SnapshotProvider

    ready, online_ip, reauth_started = False, None, None
    attempt = 0

    def online_snapshot(deadline):
        nonlocal reauth_started
        waited = False
        while not stopped.is_set():
            now = time.monotonic()
            if now >= deadline:
                raise HealthFailure("health_cycle_timeout")
            if now - engine.progress > PROGRESS_TIMEOUT:
                raise HealthFailure("auth_stalled")
            if machine.post_auth_status != "complete":
                raise HealthFailure("phase2_unavailable")
            if machine.state != AuthState.ONLINE and (not ready or machine.state not in
                    (AuthState.WAIT_MD5_REQ, AuthState.WAIT_RESULT)):
                raise HealthFailure("auth_unavailable")
            try:
                snapshot = LinuxIPv4SnapshotProvider().read(interface)
            except Exception:
                raise HealthFailure("address_unavailable") from None
            if not snapshot.ready:
                raise HealthFailure("address_unavailable")
            if online_ip is not None and snapshot.ip != online_ip:
                raise HealthFailure("address_changed")
            if machine.state == AuthState.ONLINE:
                reauth_started = None
                return snapshot, waited
            if reauth_started is None:
                reauth_started = now
                print("health pending: reason=reauthentication; watchdog not updated", flush=True)
            if now - reauth_started >= REAUTH_GRACE:
                raise HealthFailure("reauth_timeout")
            waited = True
            if stopped.wait(0.2):
                return None
        return None

    try:
        while machine.state != AuthState.ONLINE:
            if stopped.wait(0.2):
                return
        while not stopped.is_set():
            deadline = time.monotonic() + HEALTH_CYCLE_TIMEOUT
            for attempt in (1, 2):
                current = online_snapshot(deadline)
                if current is None:
                    return
                snapshot, _ = current
                source_ip = snapshot.ip
                try:
                    code = probe(interface, source_ip, url)
                except HealthFailure as exc:
                    if stopped.is_set():
                        return
                    current = online_snapshot(deadline)
                    if current is None:
                        return
                    if current[0].ip != source_ip:
                        raise HealthFailure("address_changed")
                    if not exc.retryable or attempt == 2:
                        raise
                    print(f"health retry: {exc.diagnostic()} attempt={attempt}; one retry pending", flush=True)
                    if stopped.wait(PROBE_RETRY_DELAY):
                        return
                    continue
                current = online_snapshot(deadline)
                if current is None:
                    return
                fresh, waited = current
                if fresh.ip != source_ip:
                    raise HealthFailure("address_changed")
                if waited:
                    if attempt == 2:
                        raise HealthFailure("reauth_probe_stale")
                    continue
                try:
                    notify(("" if ready else "READY=1\n") + "WATCHDOG=1\nSTATUS=Online; bound HTTPS check passed")
                except OSError:
                    raise HealthFailure("notify_failed") from None
                print(f"health OK: HTTPS {code}; phase 2 complete", flush=True)
                ready, online_ip = True, source_ip
                break
            if stopped.wait(PROBE_INTERVAL):
                return
    except Exception as exc:
        # Only fixed categories and validated numeric fields may reach the journal.
        if not stopped.is_set():
            failure = exc if isinstance(exc, HealthFailure) else HealthFailure("internal_error")
            print(f"health failed: {failure.diagnostic()} attempt={attempt}; exiting for systemd restart", flush=True)
            failed.set()
            machine.stop()


def session_log(message):
    allowed = {
        "network script started": "DHCP started",
        "network script exited with code 0": "DHCP completed",
        "EAP authentication succeeded; IP connectivity not verified": "correlated EAP-Success",
        "Address ready; starting DHCP authentication phase 2 (no lease operation)": "starting EAP phase 2",
        "Logoff sent locally; server confirmation unavailable": "Logoff sent locally (unconfirmed)",
    }
    if message in allowed:
        print(allowed[message], flush=True)
    elif message.startswith("Authentication failed:"):
        print("authentication rejected; exiting for systemd restart", flush=True)


def run(interface):
    from minirj.core.session_guard import SessionGuard, detect_competitors
    from minirj.core.state_machine import StateMachine
    from minirj.network.raw_socket import RawSocketEngine

    class ProgressSocket(RawSocketEngine):
        progress = time.monotonic()

        def recv_frame(self, timeout=1.0):
            packet = super().recv_frame(timeout=timeout)
            self.progress = time.monotonic()  # Observe progress; do not alter frames/timers.
            return packet

    stopped, failed = threading.Event(), threading.Event()
    engine = ProgressSocket(interface)
    external_dns_raw = os.environ.get("MINIRJ_EXTERNAL_DNS", "").strip()
    external_dns = ()
    if external_dns_raw:
        try:
            parts = external_dns_raw.split(",")
            if any(not part.strip() for part in parts):
                raise ValueError("empty DNS entry")
            addresses = [ip_address(value) for part in parts for value in part.split()]
            if not 1 <= len(addresses) <= 3 or len(set(addresses)) != len(addresses):
                raise ValueError("must specify 1 to 3 unique IPv4 addresses")
            zero_net = ipaddress.IPv4Network("0.0.0.0/8")
            if any(a.version != 4 or a in zero_net or a.is_unspecified or a.is_loopback
                   or a.is_link_local or a.is_multicast or a.is_reserved or str(a) == "255.255.255.255"
                   for a in addresses):
                raise ValueError("must be unicast IPv4 addresses")
            external_dns = tuple(str(a) for a in addresses)
        except ValueError as exc:
            raise ValueError(f"invalid MINIRJ_EXTERNAL_DNS: {external_dns_raw}") from exc
    extra_kwargs = {"external_dns": external_dns} if external_dns else {}
    machine = StateMachine(
        interface, credential("username"), credential("password"), service_name="校外",
        client_ver="RG_SU_For_Windows 6.84", client_version=(6, 84, 0, 0),
        protocol_profile="ruijie", start_destination=bytes.fromhex("01d0f8000003"),
        dhcp_mode=1, network_backend="script", dhcp_script=str(Path(sys.argv[0]).resolve()),
        script_timeout=20, address_timeout=35, request_timeout=12, max_retries=1,
        logoff_on_exit=True, net_engine=engine, **extra_kwargs,
    )

    def stop(*_):
        stopped.set()
        machine.stop()

    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, stop)
    worker = threading.Thread(target=health_loop, args=(machine, engine, interface,
        os.environ.get("MINIRJ_PROBE_URL", "https://www.baidu.com/"), stopped, failed), daemon=True)
    with SessionGuard(interface):
        conflicts, incomplete = detect_competitors(interface)
        if conflicts or incomplete:
            raise RuntimeError("exclusive interface ownership not established")
        worker.start()
        try:
            authenticated = machine.authenticate(session_log)
            return 0 if authenticated and not failed.is_set() else 1
        finally:
            stop()
            worker.join(12)


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    try:
        interface, connection = settings()
        if argv == ["--down"]:
            network(interface, connection)
            return 0
        if argv == [interface]:  # NetworkConfig passes only the interface to its script.
            network(interface, connection, up=True)
            return 0
        if argv:
            raise ValueError("unexpected arguments")
        return run(interface)
    except Exception as exc:
        print(f"service error ({type(exc).__name__}); exiting for systemd restart", flush=True)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
