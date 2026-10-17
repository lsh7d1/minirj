"""
Linux AF_PACKET Raw Socket Layer 2 Engine for 802.1X Frames.
Pure standard library socket implementation (No external libpcap/cffi needed).
"""

import socket
import struct
import fcntl
import os
from typing import Optional, Tuple


def restore_vlan(data: bytes, ancillary, flags=0) -> Optional[bytes]:
    """Restore Linux stripped VLAN tags, fail closed on ambiguous metadata.

    A second in-band tag plus stripped tag would be stacked VLAN, unsupported.
    TP_STATUS_VLAN_VALID makes TCI=0 meaningful (priority tagged VID0).
    """
    if flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC) or len(data) < 14:
        return None
    aux = [value for level, kind, value in ancillary if (level, kind) == (263, 8)]
    if len(aux) > 1:
        return None
    if aux:
        if len(aux[0]) != 20:
            return None
        status, length, snaplen, mac, network, tci, tpid = struct.unpack("=IIIHHHH", aux[0])
        if status & (1 << 4):
            if data[12:14] in (b"\x81\x00", b"\x88\xa8"):
                return None
            tpid = tpid if status & (1 << 6) else 0x8100
            if tpid not in (0x8100, 0x88a8):
                return None
            data = data[:12] + struct.pack("!HH", tpid, tci) + data[12:]
    ethertype = data[12:14]
    if ethertype in (b"\x81\x00", b"\x88\xa8"):
        if len(data) < 18:
            return None
        ethertype = data[16:18]
    return data if ethertype == b"\x88\x8e" else None


class RawSocketEngine:
    """Linux AF_PACKET raw socket wrapper for sending and receiving Ethernet frames."""

    ETH_P_ALL = 0x0003
    ETH_P_PAE = 0x888E  # 802.1X Port Access Entity

    def __init__(self, ifname: str):
        self.ifname = ifname
        self.sock: Optional[socket.socket] = None
        self.mac_addr: bytes = b"\x00" * 6

    def open(self):
        """Open raw packet socket bound to the specified network interface."""
        # ETH_P_PAE alone misses in-band VLAN traffic. AUXDATA is mandatory:
        # silently losing an offloaded tag could bind an untagged session.
        self.sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(self.ETH_P_ALL))
        try:
            self.sock.setsockopt(263, 8, 1)  # SOL_PACKET, PACKET_AUXDATA
            self.sock.bind((self.ifname, 0))
            self.mac_addr = self.get_interface_mac()
        except Exception:
            self.close()
            raise

    def get_interface_mac(self) -> bytes:
        """Fetch hardware MAC address of the interface using SIOCGIFHWADDR ioctl."""
        SIOCGIFHWADDR = 0x8927
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        ifreq = struct.pack("256s", self.ifname.encode("ascii")[:15])
        res = fcntl.ioctl(s.fileno(), SIOCGIFHWADDR, ifreq)
        s.close()
        mac = res[18:24]
        return mac

    def send_frame(self, frame: bytes) -> int:
        """Send raw Ethernet frame."""
        if not self.sock:
            raise RuntimeError("Raw socket is not opened.")
        return self.sock.send(frame)

    def recv_frame(self, timeout: float = 3.0) -> Optional[bytes]:
        """Receive Ethernet frame with timeout."""
        if not self.sock:
            raise RuntimeError("Raw socket is not opened.")
        self.sock.settimeout(timeout)
        try:
            data, ancillary, flags, _ = self.sock.recvmsg(65536, socket.CMSG_SPACE(20))
            return restore_vlan(data, ancillary, flags)
        except socket.timeout:
            return None

    def close(self):
        """Close socket descriptor."""
        if self.sock:
            try:
                self.sock.close()
            except Exception:
                pass
            self.sock = None
