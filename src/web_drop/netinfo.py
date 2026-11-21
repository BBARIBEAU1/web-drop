"""Choose the address to print in one-liners.

tun0 is preferred because that is the interface HTB and most lab VPNs use.
If it has no IPv4 address, the address of the primary outbound interface is used.
"""

from __future__ import annotations

import ipaddress
import os
import socket
import struct


def host_for_url(ip: str) -> str:
    parsed = ipaddress.ip_address(ip)
    if isinstance(parsed, ipaddress.IPv6Address):
        return f"[{parsed.compressed}]"
    return str(parsed)


def choose_ip(requested: str, *, tun0: str | None, primary: str | None) -> tuple[str, str]:
    if requested != "auto":
        try:
            ipaddress.ip_address(requested)
        except ValueError as exc:
            raise ValueError(f"invalid ip: {requested}") from exc
        return requested, "explicit"
    if tun0:
        return tun0, "tun0"
    if primary:
        return primary, "primary"
    return "127.0.0.1", "loopback"


def tun0_ipv4() -> str | None:
    try:
        import fcntl
    except ImportError:
        return None
    if not os.path.exists("/sys/class/net/tun0"):
        return None
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        try:
            info = fcntl.ioctl(sock.fileno(), 0x8915, struct.pack("256s", b"tun0"))
        except OSError:
            return None
    finally:
        sock.close()
    return _valid_ip(socket.inet_ntoa(info[20:24]))


def primary_ipv4() -> str | None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        try:
            # UDP connect does not send a packet; it only selects the outbound address.
            sock.connect(("192.0.2.1", 9))
            address = sock.getsockname()[0]
        except OSError:
            return None
    finally:
        sock.close()
    if address.startswith("127."):
        return None
    return _valid_ip(address)


def detect_ip() -> tuple[str, str]:
    return choose_ip("auto", tun0=tun0_ipv4(), primary=primary_ipv4())


def _valid_ip(value: str | None) -> str | None:
    if not value:
        return None
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        return None
