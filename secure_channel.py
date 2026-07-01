"""
secure_channel.py
------------------
Post-handshake encrypted channel. Wraps two independent AES-256-GCM keys
(one per direction) with monotonically-assigned message counters and a
sliding-window anti-replay filter.

Anti-replay / anti-reorder design:
  - Each direction has its own counter starting at 0, assigned in send
    order. The counter is used both as the GCM nonce AND as additional
    authenticated data (AAD), so an attacker cannot splice a ciphertext
    from position N into position M - the AAD mismatch would fail
    authentication.
  - The receiver uses a SLIDING WINDOW (bitmap of the last WINDOW_SIZE
    counters seen), the same approach used by IPsec/DTLS: any counter
    within the window that hasn't been seen before is accepted, even if
    it arrives out of order relative to other messages. Only a true
    duplicate (exact counter seen before) or a counter older than the
    window is rejected. This tolerates real-world packet reordering
    without weakening replay protection - a strict "must equal the next
    expected counter" scheme would treat ordinary reordering as an
    attack and drop legitimate messages.
"""

import crypto_utils as cu
from cryptography.exceptions import InvalidTag


class ReplayError(Exception):
    pass


class TamperError(Exception):
    pass


class SecureChannel:
    DEFAULT_WINDOW_SIZE = 1024

    def __init__(
        self, send_key: bytes, recv_key: bytes, window_size: int = DEFAULT_WINDOW_SIZE
    ):
        self._send_key = send_key
        self._recv_key = recv_key
        self._send_counter = 0
        self._window_size = window_size
        self._window_mask = (1 << window_size) - 1
        # bit i of _recv_bitmap == "counter (_highest_recv_counter - i) has
        # been seen". -1 means no messages received yet.
        self._highest_recv_counter = -1
        self._recv_bitmap = 0

    def encrypt(self, plaintext: bytes) -> bytes:
        nonce = cu.counter_to_nonce(self._send_counter)
        aad = self._send_counter.to_bytes(8, "big")
        ciphertext = cu.aes_gcm_encrypt(self._send_key, nonce, plaintext, aad)
        framed = aad + ciphertext
        self._send_counter += 1
        return framed

    def decrypt(self, framed: bytes) -> bytes:
        if len(framed) < 8:
            raise TamperError("Frame too short to contain a valid counter.")

        counter = int.from_bytes(framed[:8], "big")
        ciphertext = framed[8:]

        # Check freshness BEFORE spending CPU on authentication, and
        # before mutating any state - a forged packet with a stale or
        # duplicate counter should be rejected cheaply, and a forged
        # packet with a fresh-looking counter must not be allowed to
        # "burn" that counter in the window (which could let an attacker
        # pre-empt and block a legitimate future message).
        self._check_freshness(counter)

        nonce = cu.counter_to_nonce(counter)
        aad = framed[:8]
        try:
            plaintext = cu.aes_gcm_decrypt(self._recv_key, nonce, ciphertext, aad)
        except InvalidTag:
            raise TamperError(
                "GCM authentication tag mismatch - ciphertext was tampered "
                "with, corrupted, or encrypted under the wrong key."
            )

        self._mark_seen(counter)
        return plaintext

    def _check_freshness(self, counter: int):
        if counter > self._highest_recv_counter:
            return  # newer than anything seen so far - always fresh
        distance = self._highest_recv_counter - counter
        if distance >= self._window_size:
            raise ReplayError(
                f"Counter {counter} is older than the replay window "
                f"(oldest acceptable: {self._highest_recv_counter - self._window_size + 1})."
            )
        if self._recv_bitmap & (1 << distance):
            raise ReplayError(f"Counter {counter} has already been received (replay).")

    def _mark_seen(self, counter: int):
        if counter > self._highest_recv_counter:
            shift = counter - self._highest_recv_counter
            if shift >= self._window_size:
                self._recv_bitmap = 1
            else:
                self._recv_bitmap = (
                    (self._recv_bitmap << shift) | 1
                ) & self._window_mask
            self._highest_recv_counter = counter
        else:
            distance = self._highest_recv_counter - counter
            self._recv_bitmap |= 1 << distance
