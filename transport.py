"""
transport.py
------------
TCP is a byte stream, not a message stream - so we need length-prefixed
framing to know where one message ends and the next begins. This module
has nothing to do with cryptography; it's plumbing so handshake.py and
secure_channel.py can stay transport-agnostic and easily unit-testable
without a real socket.
"""

import json
import struct

HEADER_FMT = "!I"  # 4-byte unsigned big-endian length prefix
HEADER_SIZE = struct.calcsize(HEADER_FMT)


def send_bytes(sock, data: bytes):
    sock.sendall(struct.pack(HEADER_FMT, len(data)) + data)


def recv_exact(sock, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("Connection closed while reading.")
        buf += chunk
    return buf


def recv_bytes(sock) -> bytes:
    header = recv_exact(sock, HEADER_SIZE)
    (length,) = struct.unpack(HEADER_FMT, header)
    return recv_exact(sock, length)


def send_json(sock, obj: dict):
    send_bytes(sock, json.dumps(obj).encode("utf-8"))


def recv_json(sock) -> dict:
    return json.loads(recv_bytes(sock).decode("utf-8"))
