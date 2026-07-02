"""
transport.py
------------
TCP is a byte stream, not a message stream - so we need length-prefixed
framing to know where one message ends and the next begins. This module
has nothing to do with cryptography; it's plumbing so handshake.py and
secure_channel.py can stay transport-agnostic and easily unit-testable
without a real socket.

Because the length prefix and payload both come straight off the wire
from a peer that hasn't been authenticated yet (this runs *before* the
handshake completes), this module treats both as hostile input:
  - the length prefix is bounded by MAX_FRAME_SIZE, so a peer can't claim
    a multi-gigabyte frame and force us to allocate a huge buffer before
    we've verified anything about them (a cheap CPU/memory-exhaustion DoS
    otherwise);
  - JSON decoding failures are caught and turned into a specific
    FrameError rather than letting a raw json.JSONDecodeError propagate
    out of this module.
"""

import json
import struct

from audit_log import EventCode, security_logger

HEADER_FMT = "!I"  # 4-byte unsigned big-endian length prefix
HEADER_SIZE = struct.calcsize(HEADER_FMT)

# Generous enough for any real handshake/channel message (which are all
# small, fixed-shape JSON objects), but small enough that even an attacker
# who can claim any 32-bit length can't force multi-gigabyte allocations.
MAX_FRAME_SIZE = 1 * 1024 * 1024  # 1 MiB


class FrameError(Exception):
    """Raised for malformed or oversized frames from an untrusted peer."""


def send_bytes(sock, data: bytes):
    if len(data) > MAX_FRAME_SIZE:
        # This would be a local bug (we're constructing an oversized
        # message ourselves), not a hostile peer - fail loudly rather
        # than silently truncating or sending a frame the receiver will
        # reject anyway.
        raise FrameError(
            f"Refusing to send frame of {len(data)} bytes "
            f"(exceeds MAX_FRAME_SIZE={MAX_FRAME_SIZE})."
        )
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
    if length > MAX_FRAME_SIZE:
        security_logger.security(
            EventCode.FRAME_OVERSIZE_REJECTED,
            "peer claimed an oversized frame length",
            claimed_length=length,
            max_frame_size=MAX_FRAME_SIZE,
        )
        raise FrameError(
            f"Peer claimed a frame of {length} bytes, exceeding "
            f"MAX_FRAME_SIZE={MAX_FRAME_SIZE}; refusing to read it "
            f"(possible memory-exhaustion attempt)."
        )
    return recv_exact(sock, length)


def send_json(sock, obj: dict):
    send_bytes(sock, json.dumps(obj).encode("utf-8"))


def recv_json(sock) -> dict:
    raw = recv_bytes(sock)
    try:
        return json.loads(raw.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as e:
        security_logger.security(
            EventCode.FRAME_MALFORMED,
            "received frame that is not valid UTF-8 JSON",
            detail=str(e),
            frame_length=len(raw),
        )
        raise FrameError(f"Received malformed (non-JSON) frame: {e}")
