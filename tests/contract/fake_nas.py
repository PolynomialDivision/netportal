"""A fake access point's Dynamic Authorization server (RFC 5176) for the contract tests: it
receives the portal's Disconnect-Requests on UDP, checks them independently of netportal's own
code (Request Authenticator per RFC 5176 2.3, Message-Authenticator per RFC 3579 3.2 with the
authenticator field zeroed), records them and answers ACK, NAK or nothing (timeout).
"""

import hashlib
import hmac
import socket
import struct
import threading
import time

DISCONNECT_REQUEST, DISCONNECT_ACK, DISCONNECT_NAK = 40, 41, 42
MESSAGE_AUTHENTICATOR = 80


def parse_attributes(data):
    """[(type, value bytes)] in packet order; raises ValueError on a malformed list."""
    attrs, i = [], 0
    while i < len(data):
        if i + 2 > len(data):
            raise ValueError("truncated attribute")
        t, length = data[i], data[i + 1]
        if length < 2 or i + length > len(data):
            raise ValueError("bad attribute length")
        attrs.append((t, data[i + 2:i + length]))
        i += length
    return attrs


class FakeNas:
    def __init__(self, port, secret, host="127.0.0.1"):
        self.secret = secret.encode()
        self.mode = "ack"                  # ack | nak | silent
        self.packets = []                  # every datagram received, decoded
        self.lock = threading.Lock()
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind((host, port))
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def reset(self, mode="ack"):
        with self.lock:
            self.mode = mode
            self.packets = []

    def received(self):
        with self.lock:
            return list(self.packets)

    def wait(self, count=1, timeout=10.0):
        """The packets once at least `count` arrived (or whatever arrived until the timeout)."""
        end = time.time() + timeout
        while time.time() < end:
            got = self.received()
            if len(got) >= count:
                return got
            time.sleep(0.05)
        return self.received()

    def _serve(self):
        while True:
            try:
                data, peer = self.sock.recvfrom(4096)
            except OSError:
                return
            packet = self.decode(data)
            packet["peer"] = peer
            with self.lock:
                self.packets.append(packet)
                mode = self.mode
            if mode == "silent" or not packet["valid"]:
                continue
            self.sock.sendto(self.reply(data, DISCONNECT_ACK if mode == "ack" else DISCONNECT_NAK), peer)

    def decode(self, data):
        out = {"raw": data, "valid": False, "at": time.time()}
        if len(data) < 20:
            out["error"] = "short"
            return out
        code, ident, length = struct.unpack("!BBH", data[:4])
        out.update(code=code, identifier=ident, length=length, length_ok=(length == len(data)))
        try:
            attrs = parse_attributes(data[20:length])
        except ValueError as e:
            out["error"] = str(e)
            return out
        out["attrs"] = attrs
        out["types"] = [t for t, _ in attrs]
        # Request Authenticator: MD5(Code + Identifier + Length + 16 zero octets + Attributes + Secret)
        expect = hashlib.md5(data[:4] + b"\0" * 16 + data[20:length] + self.secret).digest()
        out["request_authenticator_ok"] = hmac.compare_digest(expect, data[4:20])
        # Message-Authenticator: HMAC-MD5 over the packet with the authenticator field and the
        # attribute's own value zeroed
        out["message_authenticator_ok"] = False
        offset = 20
        for t, value in attrs:
            if t == MESSAGE_AUTHENTICATOR and len(value) == 16:
                zeroed = bytearray(data[:length])
                zeroed[4:20] = b"\0" * 16
                zeroed[offset + 2:offset + 18] = b"\0" * 16
                mac = hmac.new(self.secret, bytes(zeroed), hashlib.md5).digest()
                out["message_authenticator_ok"] = hmac.compare_digest(mac, value)
            offset += 2 + len(value)
        out["valid"] = (code == DISCONNECT_REQUEST and out["length_ok"] and out["request_authenticator_ok"]
                        and out["message_authenticator_ok"])
        return out

    def reply(self, request, code):
        """ACK/NAK with a Message-Authenticator (RFC 5176 3.3, RFC 3579 3.2) and the Response
        Authenticator MD5(Code + Identifier + Length + Request Authenticator + Attributes + Secret)."""
        ident, req_auth = request[1], request[4:20]
        attrs = bytes([MESSAGE_AUTHENTICATOR, 18]) + b"\0" * 16
        if code == DISCONNECT_NAK:
            attrs = bytes([101, 6]) + struct.pack("!I", 503) + attrs      # Error-Cause: Session Context Not Found
        header = struct.pack("!BBH", code, ident, 20 + len(attrs))
        mac = hmac.new(self.secret, header + req_auth + attrs, hashlib.md5).digest()
        attrs = attrs[:-16] + mac
        resp_auth = hashlib.md5(header + req_auth + attrs + self.secret).digest()
        return header + resp_auth + attrs
