"""
secure_channel.py
------------------
Post-handshake encrypted channel. Wraps two independent per-direction
key ratchets (see ratchet.py) with monotonically-assigned message
counters and a sliding-window anti-replay filter.

Key derivation - each message gets its OWN AES-256-GCM key, derived by
stepping an HMAC-based ratchet forward (ratchet.py), rather than reusing
one fixed session key for the whole conversation. This gives forward
secrecy within a session: compromising the current ratchet state does
not expose earlier messages, only the current and future ones.

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
  - The ratchet's own out-of-order handling (skipped-key cache, bounded
    by ReceivingChain.MAX_SKIP) is what makes deriving the right key for
    a reordered counter possible at all; the two mechanisms are
    complementary, not redundant - the bitmap answers "have I seen this
    counter before", the ratchet answers "what key does this counter
    decrypt with".
"""

import crypto_utils as cu
from cryptography.exceptions import InvalidTag
from ratchet import ChainDesync, ReceivingChain, SendingChain


class ReplayError(Exception):
    pass


class TamperError(Exception):
    pass


class SecureChannel:
    DEFAULT_WINDOW_SIZE = 1024

    def __init__(
        self, send_key: bytes, recv_key: bytes, window_size: int = DEFAULT_WINDOW_SIZE
    ):
        # send_key / recv_key are the INITIAL chain keys handed off by
        # the handshake - each is immediately consumed into a ratchet
        # and never used directly to encrypt/decrypt a message itself.
        self._sending_chain = SendingChain(send_key)
        self._receiving_chain = ReceivingChain(recv_key)
        self._window_size = window_size
        self._window_mask = (1 << window_size) - 1
        # bit i of _recv_bitmap == "counter (_highest_recv_counter - i) has
        # been seen". -1 means no messages received yet.
        self._highest_recv_counter = -1
        self._recv_bitmap = 0

    def encrypt(self, plaintext: bytes) -> bytes:
        counter, message_key = self._sending_chain.next()
        nonce = cu.counter_to_nonce(counter)
        aad = counter.to_bytes(8, "big")
        ciphertext = cu.aes_gcm_encrypt(message_key, nonce, plaintext, aad)
        return aad + ciphertext

    def decrypt(self, framed: bytes) -> bytes:
        if len(framed) < 8:
            raise TamperError("Frame too short to contain a valid counter.")

        counter = int.from_bytes(framed[:8], "big")
        ciphertext = framed[8:]

        # Check freshness BEFORE spending CPU on ratchet stepping or
        # authentication, and before mutating any state - a forged
        # packet with a stale or duplicate counter should be rejected
        # cheaply, and a forged packet with a fresh-looking counter must
        # not be allowed to "burn" that counter (which could let an
        # attacker pre-empt and block a legitimate future message).
        self._check_freshness(counter)

        try:
            message_key = self._receiving_chain.key_for(counter)
        except ChainDesync as e:
            raise TamperError(str(e))

        nonce = cu.counter_to_nonce(counter)
        aad = framed[:8]
        try:
            plaintext = cu.aes_gcm_decrypt(message_key, nonce, ciphertext, aad)
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
