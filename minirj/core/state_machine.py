"""Event-driven 802.1X/EAP-MD5 session runner."""

from __future__ import annotations

import errno
import hashlib
import ipaddress
import math
import secrets
import threading
import time
from enum import Enum, auto
from typing import Callable, Optional

from .network_config import NetworkConfig
from ..network.raw_socket import RawSocketEngine
from ..network.snapshot import LinuxIPv4SnapshotProvider
from ..network.events import NetworkEvent, LinuxNetworkEventSource, snapshot_key
from ..protocol.eapol import (
    EAPOLPacket,
    EAP_CODE_FAILURE,
    EAP_CODE_REQUEST,
    EAP_CODE_SUCCESS,
    EAP_TYPE_IDENTITY,
    EAP_TYPE_NOTIFICATION,
    EAP_TYPE_NAK,
    EAP_TYPE_MD5,
)
from ..protocol.hello import HelloCodec
from ..protocol.private_property import parse_private_properties
from ..protocol.tlv import ClientTLVEncoder


class _NetworkIORecovery(Exception):
    """Unwind a failed I/O operation before its caller can advance session state."""


class AuthState(Enum):
    DISCONNECTED = auto()
    SEND_START = auto()
    WAIT_ID_REQ = auto()
    WAIT_MD5_REQ = auto()
    WAIT_RESULT = auto()
    WAIT_ADDRESS = auto()
    ONLINE = auto()
    FAILED = auto()


class StateMachine:
    """Maintain one authenticated session until failure, logoff, or shutdown."""

    START_DESTINATION = b"\x01\x80\xc2\x00\x00\x03"
    RUIJIE_OUIS = (bytes.fromhex("00d0f8"), bytes.fromhex("001aa9"),
                   bytes.fromhex("14144b"), bytes.fromhex("58696c"))

    def __init__(
        self,
        ifname: str,
        username: str,
        password: str,
        service_name: str = "internet",
        client_ver: str = "RG_SU_For_Windows 6.84",
        dhcp_mode: int = 1,
        dhcp_script: Optional[str] = None,
        max_retries: int = 3,
        *,
        net_engine=None,
        snapshot_provider=None,
        address_timeout: float = 44.0,
        network_backend: str = "external",
        script_timeout: float = 30.0,
        logoff_on_exit: bool = False,
        request_timeout: float = 10.0,
        retransmit_interval: float = 1.5,
        monotonic: Callable[[], float] = time.monotonic,
        hello_rand: Callable[[], int] = lambda: secrets.randbits(31),
        event_source=None,
        recovery_debounce: float = 0.5,
        recovery_max_backoff: float = 8.0,
        vlan_tci: int | None = None,
        vlan_ethertype: int = 0x8100,
        client_version: tuple[int, int, int, int] | None = (6, 84, 0, 0),
        start_destination: bytes = START_DESTINATION,
        protocol_profile: str = "auto",
        external_dns: tuple[str, ...] | list[str] | None = None,
    ):
        if vlan_tci is not None and (type(vlan_tci) is not int
                                    or not 0 <= vlan_tci <= 65535
                                    or vlan_tci & 0xfff == 0xfff):
            raise ValueError("invalid VLAN TCI (VID 4095 reserved)")
        if vlan_ethertype not in EAPOLPacket.VLAN_ETHERTYPES:
            raise ValueError("unsupported VLAN EtherType")
        if not isinstance(start_destination, bytes) or len(start_destination) != 6:
            raise ValueError("start_destination must contain six MAC bytes")
        if protocol_profile not in ("auto", "ruijie"):
            raise ValueError("protocol_profile must be auto or ruijie")
        self.protocol_profile = protocol_profile
        self.start_destination = start_destination
        self.external_dns = tuple(external_dns) if external_dns else ()
        self._vlan_tci = vlan_tci
        self._vlan_ethertype = vlan_ethertype
        if (not math.isfinite(recovery_debounce) or recovery_debounce <= 0
                or not math.isfinite(recovery_max_backoff)
                or recovery_max_backoff < recovery_debounce):
            raise ValueError("invalid recovery timing")
        if event_source is not None and network_backend != "external":
            raise ValueError("event recovery supports only external network ownership")
        self.event_source = event_source
        self._recovery_debounce = recovery_debounce
        self._recovery_max_backoff = recovery_max_backoff
        self._recovery_delay = recovery_debounce
        self._recovery_due = None
        self._recovering = False
        self._link_up = True
        self.network_observation_status = "unobserved"
        self._interface_index = None
        self._rebind_pending = False
        self._observed_snapshot = None
        self._event_snapshot = None
        self._stable_since = None
        if not math.isfinite(address_timeout) or address_timeout <= 0:
            raise ValueError("address timeout must be finite and positive")
        self.snapshot_provider = snapshot_provider if snapshot_provider is not None else LinuxIPv4SnapshotProvider()
        self.address_timeout = address_timeout
        self.address_status = "unobserved"
        self.post_auth_status = "not_started"
        self.dhcp_auth_phase = 0
        self._address_deadline = None
        self._next_address_poll = None
        self._snapshot_warnings = ()
        self.network_config = NetworkConfig(network_backend, dhcp_script, script_timeout, monotonic)
        self.logoff_on_exit = logoff_on_exit
        self.logoff_result = None
        self._log_callback = None
        self.ifname = ifname
        self.username = username
        self.password = password
        self.service_name = service_name
        self.client_ver = client_ver
        self.dhcp_mode = dhcp_mode
        self.dhcp_script = dhcp_script
        self.max_retries = max_retries
        self.request_timeout = request_timeout
        self.retransmit_interval = retransmit_interval
        self._monotonic = monotonic
        self._hello_rand = hello_rand

        self.net = net_engine if net_engine is not None else RawSocketEngine(ifname)
        self.tlv_encoder = ClientTLVEncoder(
            username=username,
            password=password,
            service_name=service_name,
            client_ver=client_ver,
            client_version=client_version,
            dhcp_mode=dhcp_mode,
        )
        self.state = AuthState.DISCONNECTED
        self.server_mac: Optional[bytes] = None
        self._phase_server_mac: Optional[bytes] = None
        self._stop_event = threading.Event()
        self._last_request_key = None
        self._last_response: Optional[bytes] = None
        self._last_md5_identifier: Optional[int] = None
        self._last_md5_challenge: Optional[bytes] = None
        self._dhcp_started = False
        self._session_authenticated = False
        self._hello_codec: Optional[HelloCodec] = None
        self._hello_interval: Optional[float] = None
        self._next_hello: Optional[float] = None
        self.last_private_properties = None
        self._reset_eap_control()

    @property
    def vlan_tci(self):
        return self._vlan_tci

    @property
    def vlan_ethertype(self):
        return self._vlan_ethertype

    def run_dhcp(self):
        if not self.dhcp_mode:
            return
        self.network_config.start(self.ifname, lambda msg: self._log(self._log_callback, msg))

    def _read_network_snapshot(self, *, before_dhcp=False):
        snapshot = self._event_snapshot or self.snapshot_provider.read(self.ifname)
        self._observed_snapshot = snapshot_key(snapshot)
        self.address_status = "ready" if snapshot.ready else "pending"
        warnings = tuple(snapshot.warnings)
        if warnings != self._snapshot_warnings:
            for warning in warnings:
                self._log(self._log_callback, f"Network snapshot: {warning}")
            self._snapshot_warnings = warnings
        self.tlv_encoder.fake_ip = "0.0.0.0" if before_dhcp else snapshot.ip
        self.tlv_encoder.fake_mask = "0.0.0.0" if before_dhcp else snapshot.netmask
        self.tlv_encoder.fake_gw = "0.0.0.0" if before_dhcp else snapshot.gateway
        self.tlv_encoder.ipv6_address = getattr(snapshot, "ipv6_address", "")
        self.tlv_encoder.ipv6_link_local = getattr(snapshot, "ipv6_link_local", "")
        self.tlv_encoder.ipv6_gateway = getattr(snapshot, "ipv6_gateway", "")
        self.tlv_encoder.ipv6_prefix_len = getattr(snapshot, "ipv6_prefix_len", 0)

        def _valid_dns(addr):
            if not addr or addr == "0.0.0.0":
                return False
            try:
                ip = ipaddress.IPv4Address(addr)
                return not (ip.is_loopback or ip.is_multicast or ip.is_unspecified)
            except ValueError:
                return False

        if self.external_dns:
            self.tlv_encoder.fake_dns = self.external_dns[0]
            alternates = list(self.external_dns[1:])
            snap_alts = list(getattr(snapshot, "alternate_dns", ()))
            if not snap_alts and _valid_dns(getattr(snapshot, "secondary_dns", "0.0.0.0")):
                snap_alts = [snapshot.secondary_dns]
            if _valid_dns(snapshot.dns) and snapshot.dns != self.tlv_encoder.fake_dns and snapshot.dns not in alternates:
                alternates.append(snapshot.dns)
            for item in snap_alts:
                if _valid_dns(item) and item not in alternates and item != self.tlv_encoder.fake_dns:
                    alternates.append(item)
        else:
            self.tlv_encoder.fake_dns = snapshot.dns if _valid_dns(snapshot.dns) else "0.0.0.0"
            alternates = [item for item in getattr(snapshot, "alternate_dns", ()) if _valid_dns(item)]
            if not alternates and _valid_dns(getattr(snapshot, "secondary_dns", "0.0.0.0")):
                alternates = [snapshot.secondary_dns]
        # The old getter runs for every frame (AppendPrivateProperty@4619e7),
        # but observed successful DHCP phase1 TX has empty VSA76, phase2 has
        # the acquired resolver list. With externally owned networking, residual
        # global DNS is not phase1 lease evidence: defer its publication here.
        # Do not alter the primary DNS field or the DHCP0/static profile.
        self.tlv_encoder.alternate_dns = (
            b"" if self.dhcp_mode and before_dhcp
            else ";".join(alternates).encode("ascii")
        )
        return snapshot

    def _poll_address(self, now):
        if self.state != AuthState.WAIT_ADDRESS:
            return None
        if self.network_config.failed:
            self.state = AuthState.FAILED
            self.post_auth_status = "network_script_failed"
            self._log(self._log_callback, "Network script failed; post-authentication not advanced")
            return "failure"
        if now >= self._address_deadline:
            self.state = AuthState.FAILED
            self.post_auth_status = "address_timeout"
            self._log(self._log_callback, "Address readiness timed out; no DHCP renewal or release requested")
            return "failure"
        if now < self._next_address_poll:
            return None
        self._next_address_poll = now + 2.0
        if self.network_config.process is not None:
            return None
        snapshot = self._read_network_snapshot()
        if not snapshot.ready:
            return None
        self._reset_eap_control()
        self.dhcp_auth_phase = 2
        self.tlv_encoder.dhcp_auth_phase = 2
        self.post_auth_status = "eap_phase2_pending"
        self._last_request_key = None
        self._last_response = None
        self._last_md5_identifier = None
        self._last_md5_challenge = None
        self._send_frame(self._build_start())
        self.state = AuthState.WAIT_ID_REQ
        self._log(self._log_callback, "Address ready; starting DHCP authentication phase 2 (no lease operation)")
        return "restart"

    def _invalidate_session(self, *, reason="network_changed"):
        """Forget all server-owned state, never release an external lease."""
        self.state = AuthState.DISCONNECTED
        self.server_mac = self._phase_server_mac = None
        self._last_request_key = self._last_response = None
        self._last_md5_identifier = self._last_md5_challenge = None
        self._session_authenticated = False
        self._hello_codec = self._hello_interval = self._next_hello = None
        self.last_private_properties = None
        self._reset_eap_control()
        self.dhcp_auth_phase = self.tlv_encoder.dhcp_auth_phase = 0
        self._address_deadline = self._next_address_poll = None
        self.address_status = "unobserved"
        self.post_auth_status = reason
        self._dhcp_started = False
        self.logoff_result = None
        self._stable_since = None
        self.network_config.reset(lambda msg: self._log(self._log_callback, msg))
        self.tlv_encoder.alternate_dns = b""
        for name in ("fake_ip", "fake_mask", "fake_gw", "fake_dns"):
            setattr(self.tlv_encoder, name, "0.0.0.0")
        self.tlv_encoder.ipv6_address = ""
        self.tlv_encoder.ipv6_link_local = ""
        self.tlv_encoder.ipv6_gateway = ""
        self.tlv_encoder.ipv6_prefix_len = 0

    def inject_network_event(self, event: NetworkEvent, now=None):
        """Consume on the runner thread; event_source.poll(now) may supply these.

        The CLI installs a read-only watcher for external ownership. Script ownership is
        excluded: reconnect must never implicitly rerun a configuration script.
        """
        if self.network_config.backend != "external":
            raise ValueError("event recovery requires external network ownership")
        if event.ifname != self.ifname:
            return False
        now = self._monotonic() if now is None else now
        key = snapshot_key(event.snapshot) if event.snapshot is not None else self._observed_snapshot
        replaced = (event.ifindex is not None and self._interface_index is not None
                    and event.ifindex != self._interface_index)
        if event.status == "missing" or replaced:
            self._rebind_pending = True
        if event.ifindex is not None:
            self._interface_index = event.ifindex
        self.network_observation_status = event.status if event.status != "observed" else ("up" if event.link_up else "down")
        changed = event.link_up != self._link_up or key != self._observed_snapshot or replaced
        was_up = self._link_up
        self._link_up = event.link_up
        if event.snapshot is not None:
            self._event_snapshot = event.snapshot
            self._observed_snapshot = key
        elif event.link_up != was_up:
            # A previous link's observation must not shadow the provider on
            # recovery. An explicit snapshot on this transition remains valid;
            # duplicate link-only events must not discard that newer snapshot.
            self._event_snapshot = None
        if not changed:
            return False
        # An address delivered during phase1 is the awaited input, not a new
        # authenticated session. Link transitions always invalidate it.
        if self.state == AuthState.WAIT_ADDRESS and was_up and event.link_up and not replaced:
            return False
        self._invalidate_session()
        self._recovering = True
        self._recovery_due = now + self._recovery_delay if event.link_up else None
        self._recovery_delay = min(self._recovery_max_backoff, self._recovery_delay * 2)
        return True

    def _poll_network_events(self, now):
        changed = False
        if self.event_source is not None:
            for event in self.event_source.poll(now):
                changed = self.inject_network_event(event, now) or changed
        if self._recovering and self._link_up and now >= self._recovery_due:
            if self._rebind_pending:
                self.net.close()
                self.net.open()
                self.tlv_encoder.mac_address = self.net.mac_addr
                self._rebind_pending = False
            self._read_network_snapshot(before_dhcp=bool(self.dhcp_mode))
            self._send_frame(self._build_start())
            self.state = AuthState.WAIT_ID_REQ
            self._recovering = False
            self._recovery_due = None
            return "restart"
        if (self.state == AuthState.ONLINE and self._stable_since is not None
                and now - self._stable_since >= self._recovery_max_backoff):
            self._recovery_delay = self._recovery_debounce
        return "invalidated" if changed else None

    def stop(self):
        self._stop_event.set()

    def _log(self, callback, message):
        for secret in sorted((self.username, self.password), key=len, reverse=True):
            if secret:
                message = message.replace(secret, "[redacted]")
        if callback:
            callback(message)
        else:
            print(f"[*] {message}")

    def _network_io(self, operation, *args, **kwargs):
        try:
            return operation(*args, **kwargs)
        except OSError as exc:
            # Only definite link/device errors with an installed read-only
            # monitor may recover. Provider/configuration errors never enter here.
            if (self.event_source is None or self._stop_event.is_set()
                    or exc.errno not in (errno.ENETDOWN, errno.ENODEV, errno.ENXIO)):
                raise
            status = "missing" if exc.errno in (errno.ENODEV, errno.ENXIO) else "unknown"
            self.inject_network_event(NetworkEvent(self.ifname, False, status=status))
            # Preserve normal poll cadence and debounce. Even a socket that fails
            # immediately on every call cannot spin; stop interrupts this wait.
            self._stop_event.wait(0.1)
            raise _NetworkIORecovery from None

    def _send_frame(self, frame):
        """One explicit immutable VLAN profile covers every outbound frame.

        Cache stores canonical untagged frames; tagging exactly once here also
        covers retransmitted Start/MD5, DHCP phase2, recovery, Hello and Logoff.
        Return canonical length to preserve the local send-completion contract.
        """
        if self.vlan_tci is None:
            return self._network_io(self.net.send_frame, frame)
        import struct
        tagged = frame[:12] + struct.pack("!HH", self.vlan_ethertype, self.vlan_tci) + frame[12:]
        sent = self._network_io(self.net.send_frame, tagged)
        return len(frame) if sent == len(tagged) else -1

    def _is_ruijie_server(self):
        # IsRuijieNas@409040 checks a wired-MD5 session manufacturer flag,
        # not the source OUI. An explicit profile models that choice without
        # bypassing frame validation, server locking or request correlation.
        return self.server_mac is not None and (
            self.protocol_profile == "ruijie" or self.server_mac[:3] in self.RUIJIE_OUIS
        )

    def _build_start(self):
        # ChangeToUChar@462a30 skips private data for standard 0180c2 Start.
        legacy_start = self.start_destination[:3] == b"\x01\xd0\xf8"
        if legacy_start and self.dhcp_mode and self.dhcp_auth_phase == 0:
            # Advertise phase 1 in the first Start, before a NAS is selected.
            # Retransmitted phase2 Start must retain phase 2 and its snapshot.
            self.dhcp_auth_phase = self.tlv_encoder.dhcp_auth_phase = 1
        vendor = self.tlv_encoder.encode_legacy() if legacy_start else b""
        return EAPOLPacket.build_eap_start(
            self.net.mac_addr, self.start_destination, vendor_data=vendor
        )

    def _valid_destination(self, parsed, source_mac):
        return parsed["dst_mac"] in (source_mac, self.START_DESTINATION, self.start_destination)

    def _accept_server(self, candidate):
        if self.server_mac is None:
            self.server_mac = candidate
            if self._phase_server_mac is not None and candidate != self._phase_server_mac:
                self.dhcp_auth_phase = 0
                self.post_auth_status = "not_started"
                self._session_authenticated = False
                self._hello_codec = None
                self._hello_interval = None
                self._next_hello = None
                self._read_network_snapshot(before_dhcp=bool(self.dhcp_mode))
            self._phase_server_mac = candidate
            if self.dhcp_mode and self._is_ruijie_server():
                self.dhcp_auth_phase = self.dhcp_auth_phase or 1
            else:
                self.dhcp_auth_phase = 0
            self.tlv_encoder.dhcp_auth_phase = self.dhcp_auth_phase
            return True
        return candidate == self.server_mac

    def _reset_eap_control(self):
        self._control_server = None
        self._control_key = self._control_response = None
        self._nak_identifier = None
        self._method_started = False

    def _handle_eap_control(self, eap, source_mac, sender, log_callback):
        """RFC 3748 §§2.1, 4.1, 5.2, 5.3.1, 5.7; no TLS/Expanded backend.

        Control response caching is separate from the pending MD5 exchange.
        Keys include peer, local MAC, immutable VLAN profile, ID, type and data.
        """
        kind, identifier, data = eap["type"], eap["req_id"], eap["type_data"]
        if kind == EAP_TYPE_NOTIFICATION:
            if self.state not in (AuthState.WAIT_ID_REQ, AuthState.WAIT_MD5_REQ, AuthState.WAIT_RESULT):
                return None  # §5.2: only before method completion.
            if not 0 < len(data) <= 1015 or data.endswith(b"\0"):
                return None
            try:
                message = data.decode("utf-8")
            except UnicodeError:
                return None
            builder = EAPOLPacket.build_eap_response_notification
            event = "notification"
        else:
            if kind is None or kind < 4 or kind == EAP_TYPE_MD5:
                return None  # Type 0 reserved; Identity/Notification are not methods; Nak is Response-only.
            if self._method_started or self.state not in (AuthState.WAIT_ID_REQ, AuthState.WAIT_MD5_REQ):
                return None  # §§2.1/4.1: no Nak once an authentication method was accepted.
            if kind == 254:
                if len(data) < 7:
                    return None  # §5.7: incomplete vendor header is not a valid Request.
                if data[:3] == b"\0\0\0" and int.from_bytes(data[3:7], "big") < 4:
                    return None  # No Request/Expanded Nak or reserved/special method negotiation.
            builder = EAPOLPacket.build_eap_response_nak
            event = "nak"
        key = (source_mac, sender, self.vlan_tci, self.vlan_ethertype, identifier, kind, bytes(data))
        if self._control_key is not None and self._control_key[4] == identifier:
            if key == self._control_key:
                self._send_frame(self._control_response)
                return "duplicate"
            return None  # Changed content under the same outstanding ID is not a retransmission.
        # A retained Identity response is a replay cache, not an ID reservation.
        # With a control key present, that accepted control Request is the latest;
        # otherwise the Identity/MD5 request is latest (including a cache replay).
        # Rejected inputs never advance either cache. A pending MD5 exchange has
        # its own challenge/result correlation guard even across Notifications.
        if (self._control_key is None and self._last_request_key is not None
                and self._last_request_key[1] == identifier
                or self._last_md5_identifier == identifier):
            return None
        response = builder(source_mac, sender, identifier)
        self._send_frame(response)
        self._control_server = sender
        self._control_key, self._control_response = key, response
        if event == "nak":
            self._nak_identifier = identifier
            self._log(log_callback, f"Unsupported EAP method type={kind}; sent Legacy Nak offering MD5 only")
        else:
            # Redact before repr so credentials containing controls are not
            # exposed in escaped form; repr prevents terminal/log injection.
            for secret in sorted((self.username, self.password), key=len, reverse=True):
                if secret:
                    message = message.replace(secret, "[redacted]")
            self._log(log_callback, f"EAP Notification: {message!r}")
        return event

    def _send_cached_or_new(self, request_key, builder):
        if request_key == self._last_request_key and self._last_response is not None:
            self._send_frame(self._last_response)
            return
        response = builder()
        self._send_frame(response)
        self._last_request_key = request_key
        self._last_response = response

    def _handle_identity(self, eap, source_mac):
        identifier = eap["req_id"]
        key = (source_mac, identifier, EAP_TYPE_IDENTITY)
        waiting_for_result = self.state == AuthState.WAIT_RESULT
        self._send_cached_or_new(
            key,
            lambda: EAPOLPacket.build_eap_response_identity(
                source_mac, self.server_mac, identifier, self.username,
                vendor_data=self.tlv_encoder.encode_legacy() if self._is_ruijie_server() else b"",
            ),
        )
        if not waiting_for_result:
            self.state = AuthState.WAIT_MD5_REQ

    def _handle_md5(self, eap, source_mac, sender):
        type_data = eap["type_data"]
        if not type_data:
            return False
        value_size = type_data[0]
        if value_size != 16 or len(type_data) < 17:
            return False
        challenge = bytes(type_data[1:17])
        identifier = eap["req_id"]

        if (
            self._last_md5_identifier == identifier
            and self._last_md5_challenge is not None
            and self._last_md5_challenge != challenge
        ):
            return False

        # Bind only after all MD5 validation. Rejected requests must not
        # mutate server/phase ownership, even when no server is bound yet.
        if not self._accept_server(sender):
            return False

        key = (source_mac, identifier, EAP_TYPE_MD5, challenge)

        def build_response():
            digest = hashlib.md5(
                bytes((identifier,))
                + self.password.encode("gb18030")
                + challenge
            ).digest()
            return EAPOLPacket.build_eap_response_md5(
                source_mac,
                self.server_mac,
                identifier,
                digest,
                (self.tlv_encoder.encode_legacy(challenge) if self._is_ruijie_server()
                 else self.tlv_encoder.encode(challenge)),
                username=self.username,
                vendor_in_eap=not self._is_ruijie_server(),
            )

        self._send_cached_or_new(key, build_response)
        self._last_md5_identifier = identifier
        self._last_md5_challenge = challenge
        self.state = AuthState.WAIT_RESULT
        return True

    def _configure_hello(self, source_mac):
        if not self._is_ruijie_server():
            return
        hello = (self.last_private_properties or {}).get("hello")
        if hello is None:
            return
        if not hello["enabled"]:
            self._hello_codec = None
            self._hello_interval = None
            self._next_hello = None
            return

        interval_ms = hello["interval_ms"]
        offset = hello["id"]
        if not isinstance(interval_ms, int) or not isinstance(offset, int):
            return
        if interval_ms == 0 and self._hello_codec is not None and self._hello_interval is not None:
            interval_ms = int(self._hello_interval * 1000)
        if self._hello_codec is None:
            seed = HelloCodec.sequence_seed_from_rand(self._hello_rand())
            self._hello_codec = HelloCodec(
                source_mac,
                dst_mac=self.server_mac or HelloCodec.INITIAL_DST_MAC,
                sequence=seed,
                offset=offset,
            )
        else:
            self._hello_codec.dst_mac = self.server_mac or HelloCodec.INITIAL_DST_MAC
            if offset != 0:
                self._hello_codec.offset = offset & 0xFFFFFFFF
            self._hello_codec.reset_hello_ids()
        self._send_frame(self._hello_codec.build())
        if 0 < interval_ms <= 0x7fffffff:
            self._hello_interval = interval_ms / 1000.0
            self._next_hello = self._monotonic() + self._hello_interval
        else:
            self._hello_interval = None
            self._next_hello = None
            self._log(self._log_callback, "Hello sent once; interval cannot create a positive signed-32-bit timer")

    def _send_due_hello(self, now):
        if (
            self._session_authenticated
            and self._hello_codec is not None
            and self._hello_interval is not None
            and self._next_hello is not None
            and now >= self._next_hello
        ):
            self._send_frame(self._hello_codec.build())
            self._next_hello = now + self._hello_interval

    def _handle_packet(self, raw_packet, source_mac, log_callback):
        if self._recovering or not self._link_up:
            return None
        parsed = EAPOLPacket.parse_frame(raw_packet)
        if not parsed or not parsed.get("state_valid"):
            return None
        # Never learn a VLAN from unauthenticated traffic. Strict TCI/TPID
        # equality deliberately also rejects PCP/DEI changes within a VID.
        if parsed["vlan_tci"] != self.vlan_tci:
            return None
        if self.vlan_tci is not None and parsed["outer_ethertype"] != self.vlan_ethertype:
            return None
        if not self._valid_destination(parsed, source_mac):
            return None

        eap = parsed["eap"]
        code = eap["code"]
        eap_type = eap["type"]
        sender = parsed["src_mac"]

        if code == EAP_CODE_REQUEST:
            if self.state not in (AuthState.WAIT_ID_REQ, AuthState.WAIT_MD5_REQ, AuthState.WAIT_RESULT, AuthState.ONLINE):
                return None
            if (self.server_mac is not None and sender != self.server_mac
                    or self._control_server is not None and sender != self._control_server):
                return None
            if eap_type not in (EAP_TYPE_IDENTITY, EAP_TYPE_MD5):
                return self._handle_eap_control(eap, source_mac, sender, log_callback)
            if self._control_key is not None and self._control_key[4] == eap["req_id"]:
                return None
            if eap_type == EAP_TYPE_IDENTITY:
                if not self._accept_server(sender):
                    return None
                self._log(log_callback, f"EAP-Request/Identity id={eap['req_id']}")
                if self.state == AuthState.ONLINE:
                    self._reset_eap_control()  # Existing explicit reauthentication entry point.
                self._handle_identity(eap, source_mac)
                self._control_key = self._control_response = None
                self._nak_identifier = None
                return "request"
            if self.state not in (AuthState.WAIT_MD5_REQ, AuthState.WAIT_RESULT, AuthState.ONLINE):
                # Preserve the existing no-unsolicited-MD5 admission policy.
                # An initial Nak has already pinned this negotiation's peer.
                if self.state != AuthState.WAIT_ID_REQ or self._nak_identifier is None:
                    return None
            if self._handle_md5(eap, source_mac, sender):
                self._method_started = True
                self._control_key = self._control_response = None
                self._nak_identifier = None
                self._log(log_callback, f"EAP-Request/MD5 id={eap['req_id']}")
                return "request"
            return None

        if (code == EAP_CODE_FAILURE and not self._method_started
                and self.state in (AuthState.WAIT_ID_REQ, AuthState.WAIT_MD5_REQ)
                and self._control_key is not None and self._control_key[5] != EAP_TYPE_NOTIFICATION
                and sender == self._control_server and eap["req_id"] == self._nak_identifier):
            self.state = AuthState.FAILED
            self.post_auth_status = "unsupported_method"
            self._session_authenticated = False
            self._hello_codec = self._hello_interval = self._next_hello = None
            self._log(log_callback, "EAP method negotiation rejected; only MD5 is implemented")
            return "failure"

        if self.server_mac is None or sender != self.server_mac:
            return None
        if code == EAP_CODE_SUCCESS:
            if self._last_md5_identifier is None or eap["req_id"] != self._last_md5_identifier:
                return None
        elif code == EAP_CODE_FAILURE:
            online_termination = self._session_authenticated and self.state == AuthState.ONLINE
            matching_exchange = (
                self._last_md5_identifier is not None
                and eap["req_id"] == self._last_md5_identifier
            )
            if not online_termination and not matching_exchange:
                return None

        if code in (EAP_CODE_SUCCESS, EAP_CODE_FAILURE):
            private_data = eap.get("private_data", b"")
            self.last_private_properties = eap.get("private_properties") or parse_private_properties(private_data)
            for warning in self.last_private_properties.get("warnings", ()):
                self._log(log_callback, f"Private property: {warning}")

        if code == EAP_CODE_SUCCESS and self.state == AuthState.WAIT_RESULT:
            self._session_authenticated = True
            self._log(log_callback, "EAP authentication succeeded; IP connectivity not verified")
            if self.dhcp_mode and self.dhcp_auth_phase == 0:
                self.state = AuthState.FAILED
                self.post_auth_status = "unsupported_management"
                self._log(log_callback, "This NAS requires a management post-authentication path that is not implemented")
                return "failure"
            if self.dhcp_auth_phase == 1:
                self.state = AuthState.WAIT_ADDRESS
                self.post_auth_status = "address_pending"
                self.address_status = "pending"
                self._address_deadline = self._monotonic() + self.address_timeout
                self._next_address_poll = self._monotonic()
                self._last_md5_identifier = None
                self._last_md5_challenge = None
                if not self._dhcp_started:
                    self._dhcp_started = True
                    self.run_dhcp()
                self._log(log_callback, "Phase 1 accepted; waiting for externally supplied address and gateway")
                return "address_pending"
            self.state = AuthState.ONLINE
            self._stable_since = self._monotonic()
            self.post_auth_status = "complete" if self.dhcp_auth_phase == 2 else "not_required"
            if not self._dhcp_started:
                self._dhcp_started = True
                self.run_dhcp()
            self._configure_hello(source_mac)
            self._last_md5_identifier = None
            self._last_md5_challenge = None
            return "success"

        if code == EAP_CODE_FAILURE:
            message = None
            if self.last_private_properties:
                message = self.last_private_properties.get("message")
            self.state = AuthState.FAILED
            self._session_authenticated = False
            self._hello_codec = None
            self._hello_interval = None
            self._next_hello = None
            self._log(log_callback, f"Authentication failed: {message or 'unknown reason'}")
            return "failure"
        return None

    def authenticate(self, log_callback: Optional[Callable[[str], None]] = None) -> bool:
        """Run until stopped or the authenticated session fails.

        A successful EAP exchange enters ``ONLINE`` but does not return; receive
        processing continues so reauthentication and an online Failure are not
        lost.  The method returns ``True`` only after a clean local stop of a
        session that reached ``ONLINE``.
        """
        self._log_callback = log_callback
        if self._stop_event.is_set():
            return False
        self._dhcp_started = False
        self._session_authenticated = False
        self._hello_codec = None
        self._hello_interval = None
        self._next_hello = None
        ever_online = False
        try:
            # Prime production observations before opening a possibly absent NIC.
            # Test/injected sources retain their existing runner timing contract.
            if isinstance(self.event_source, LinuxNetworkEventSource):
                while not self._stop_event.is_set():
                    for event in self.event_source.poll(self._monotonic()):
                        self.inject_network_event(event)
                    if self._link_up:
                        break
                    self._stop_event.wait(0.1)
                if self._stop_event.is_set():
                    return False
            self.net.open()
            self._rebind_pending = False
            source_mac = self.net.mac_addr
            self.tlv_encoder.mac_address = source_mac
            self._read_network_snapshot(before_dhcp=bool(self.dhcp_mode))
            self._log(log_callback, f"Bound to {self.ifname} ({source_mac.hex(':')})")
            for attempt in range(1, self.max_retries + 1):
                if self._stop_event.is_set():
                    break
                if attempt > 1:
                    # A timed-out phase2 is not a completed session. Restart
                    # the full exchange even if the same NAS answers again;
                    # never advertise its previous phase2/IP or resume Hello.
                    self._invalidate_session(reason="not_started")
                    self._read_network_snapshot(before_dhcp=bool(self.dhcp_mode))
                self._reset_eap_control()
                self.server_mac = None
                self._last_request_key = None
                self._last_response = None
                self._last_md5_identifier = None
                self._last_md5_challenge = None
                self.state = AuthState.SEND_START
                try:
                    initial_event = self._poll_network_events(self._monotonic())
                    if not self._recovering and initial_event != "restart":
                        self._send_frame(self._build_start())
                        self.state = AuthState.WAIT_ID_REQ
                except _NetworkIORecovery:
                    ever_online = False
                deadline = self._monotonic() + self.request_timeout
                next_start = self._monotonic() + self.retransmit_interval
                self._log(log_callback, f"Authentication attempt {attempt}/{self.max_retries}")

                while not self._stop_event.is_set():
                    try:
                        now = self._monotonic()
                        network_event = self._poll_network_events(now)
                        if network_event in ("invalidated", "restart"):
                            ever_online = False
                        if network_event == "restart":
                            deadline = now + self.request_timeout
                            next_start = now + self.retransmit_interval
                        if self._recovering:
                            ever_online = False
                            # Drain/discard stale frames while the link is down or
                            # debounce/backoff is pending; never revive old ONLINE.
                            self._network_io(self.net.recv_frame, timeout=0.1)
                            remaining = now + 0.1 - self._monotonic()
                            if remaining > 0:
                                self._stop_event.wait(remaining)
                            continue
                        self._send_due_hello(now)
                        self.network_config.poll(lambda msg: self._log(log_callback, msg))
                        address_event = self._poll_address(now)
                        if address_event == "failure":
                            return False
                        if address_event == "restart":
                            deadline = self._monotonic() + self.request_timeout
                            next_start = self._monotonic() + self.retransmit_interval
                        if ever_online and self.state != AuthState.ONLINE and now >= deadline:
                            self.state = AuthState.ONLINE
                            self._last_md5_identifier = None
                            self._last_md5_challenge = None
                            self._log(log_callback, "Reauthentication request timed out; retaining online session")
                        elif not ever_online and self.state != AuthState.WAIT_ADDRESS and now >= deadline:
                            break
                        timeout = min(self.retransmit_interval, 0.1)
                        if self.state != AuthState.WAIT_ADDRESS and (not ever_online or self.state != AuthState.ONLINE):
                            timeout = max(0.0, min(timeout, deadline - now))
                        if self._next_hello is not None:
                            timeout = max(0.0, min(timeout, self._next_hello - now))
                        try:
                            packet = self._network_io(self.net.recv_frame, timeout=timeout)
                        except OSError:
                            if self._stop_event.is_set():
                                break
                            raise

                        if self._stop_event.is_set():
                            break
                        if packet:
                            event = self._handle_packet(packet, self.net.mac_addr, log_callback)
                            if event in ("request", "success", "nak"):
                                deadline = self._monotonic() + self.request_timeout
                            if event == "success":
                                ever_online = True
                            elif event == "failure":
                                return False
                            continue

                        now = self._monotonic()
                        if not ever_online and self.state == AuthState.WAIT_ID_REQ and self._nak_identifier is None and now >= next_start:
                            self._send_frame(self._build_start())
                            next_start = now + self.retransmit_interval
                    except _NetworkIORecovery:
                        ever_online = False
                        continue

                if ever_online or self._stop_event.is_set():
                    break

            if self._stop_event.is_set() and ever_online:
                return True
            if not ever_online:
                self.state = AuthState.FAILED
            return False
        finally:
            try:
                if self.logoff_on_exit:
                    self.logoff(log_callback)
            finally:
                self.net.close()
                self.network_config.close(lambda msg: self._log(log_callback, msg))
                self._session_authenticated = False
                if self.state != AuthState.FAILED:
                    self.state = AuthState.DISCONNECTED

    def logoff(self, log_callback=None):
        """Attempt one local send, not a server-confirmed logout."""
        self.stop()
        if self.logoff_result is not None:
            return self.logoff_result
        if not self._session_authenticated or self.server_mac is None:
            self.logoff_result = "Logoff not sent: no authenticated session"
        else:
            frame = EAPOLPacket.build_eap_logoff(
                self.net.mac_addr, self.server_mac,
                vendor_data=(self.tlv_encoder.encode_legacy(logoff_reason=1)
                             if self._is_ruijie_server() else b""),
            )
            try:
                sent = self._send_frame(frame)
                self.logoff_result = (
                    "Logoff sent locally; server confirmation unavailable"
                    if sent == len(frame) else "Logoff send failed: incomplete local send"
                )
            except (OSError, RuntimeError):
                self.logoff_result = "Logoff send failed locally"
        self._log(log_callback, self.logoff_result)
        return self.logoff_result
