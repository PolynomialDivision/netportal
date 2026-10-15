"""RADIUS Dynamic Authorization (RFC 5176): Disconnect-Request to the access point that holds
a device's session, so a revocation takes effect now and not at the next re-authentication.

Small on purpose (no RADIUS library): one request, one answer, Message-Authenticator included
(RFC 3579 / the 2024 BlastRADIUS hardening). Returns "ack", "nak", "timeout" or "error" (no usable address).
"""

import hashlib
import hmac
import os
import socket
import struct
import time

DISCONNECT_REQUEST, DISCONNECT_ACK, DISCONNECT_NAK = 40, 41, 42
USER_NAME, NAS_IP_ADDRESS, CALLING_STATION_ID, EVENT_TIMESTAMP, MESSAGE_AUTHENTICATOR, ERROR_CAUSE = 1, 4, 31, 55, 80, 101


def _attr(kind, value):
    return struct.pack("!BB", kind, len(value) + 2) + value


def build(identifier, secret, user_name, calling_station, nas_ip, now=None):
    """The Disconnect-Request packet (bytes). Event-Timestamp is included because access points
    running hostapd may require it (radius_das_require_event_timestamp, 5-minute window)."""
    stamp = int(time.time() if now is None else now)
    attrs = (_attr(USER_NAME, user_name.encode()) + _attr(CALLING_STATION_ID, calling_station.encode())
             + _attr(NAS_IP_ADDRESS, socket.inet_aton(nas_ip)) + _attr(EVENT_TIMESTAMP, struct.pack("!I", stamp)))
    # Message-Authenticator: HMAC-MD5 over the packet with a zero authenticator and zero MA.
    ma_placeholder = _attr(MESSAGE_AUTHENTICATOR, b"\x00" * 16)
    length = 20 + len(attrs) + len(ma_placeholder)
    header = struct.pack("!BBH", DISCONNECT_REQUEST, identifier, length)
    ma = hmac.new(secret, header + b"\x00" * 16 + attrs + ma_placeholder, hashlib.md5).digest()
    attrs = attrs + _attr(MESSAGE_AUTHENTICATOR, ma)
    # Request Authenticator (RFC 5176 2.3): MD5(Code+Identifier+Length+16 zero octets+Attributes+Secret).
    authenticator = hashlib.md5(header + b"\x00" * 16 + attrs + secret).digest()
    return header + authenticator + attrs


def verify_reply(packet, request, secret):
    """True if a reply packet answers request (same identifier, valid Response Authenticator)."""
    if len(packet) < 20:
        return False
    code, ident, length = struct.unpack("!BBH", packet[:4])
    if ident != request[1] or length != len(packet) or code not in (DISCONNECT_ACK, DISCONNECT_NAK):
        return False
    expected = hashlib.md5(packet[:4] + request[4:20] + packet[20:] + secret).digest()
    return hmac.compare_digest(expected, packet[4:20])


def disconnect(session, secret, port=3799, timeout=2.0, retries=2):
    """Send a Disconnect-Request for a stored session ({nas_ip, calling_station, user_name})."""
    if not secret or not session:
        return "skipped"
    secret = secret.encode() if isinstance(secret, str) else secret
    ident = os.urandom(1)[0]
    try:
        packet = build(ident, secret, session["user_name"], session["calling_station"], session["nas_ip"])
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(timeout)
            for _ in range(retries + 1):
                sock.sendto(packet, (session["nas_ip"], port))
                try:
                    while True:
                        reply, _addr = sock.recvfrom(4096)
                        if verify_reply(reply, packet, secret):
                            return "ack" if reply[0] == DISCONNECT_ACK else "nak"
                except socket.timeout:
                    continue
    except (OSError, ValueError, struct.error):   # no IPv4 NAS address, unreachable network
        return "error"
    return "timeout"
