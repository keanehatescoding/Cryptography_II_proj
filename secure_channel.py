"""
secure_channel.py
------------------
Post-handshake encrypted channel. Wraps two independent AES-256-GCM keys
(one per direction) with strictly-increasing message counters.

Anti-replay / anti-reorder design:
  - Each direction has its own monotonic counter starting at 0.
  - The counter is used both as the GCM nonce AND as additional
    authenticated data (AAD), so an attacker cannot splice a ciphertext
    from position N into position M - the AAD mismatch would fail
    authentication.
  - The receiver enforces that incoming counters are EXACTLY the next
    expected value (strict, not just "greater than"). This rejects both
    replays (same counter twice) and reordered/dropped packets, trading
    a little robustness on lossy transports for strong guarantees. (A
    production system over unreliable transport - e.g. UDP - would use a
    sliding-window replay filter instead; here we assume a reliable,
    ordered transport such as TCP, matching the socket demo.)
"""

import crypto_utils as cu
from cryptography.exceptions import InvalidTag


class ReplayError(Exception):
    pass


class TamperError(Exception):
    pass


class SecureChannel:
    def __init__(self, send_key: bytes, recv_key: bytes):
        self._send_key = send_key
        self._recv_key = recv_key
        self._send_counter = 0
        self._recv_counter = 0

    def encrypt(self, plaintext: bytes) -> bytes:
        nonce = cu.counter_to_nonce(self._send_counter)
        aad = self._send_counter.to_bytes(8, "big")
        ciphertext = cu.aes_gcm_encrypt(self._send_key, nonce, plaintext, aad)
        # Frame: 8-byte counter || ciphertext(+tag). The counter travels in
        # the clear (it's not secret) but is authenticated via AAD, so it
        # cannot be tampered with without detection.
        framed = self._send_counter.to_bytes(8, "big") + ciphertext
        self._send_counter += 1
        return framed

    def decrypt(self, framed: bytes) -> bytes:
        if len(framed) < 8:
            raise TamperError("Frame too short to contain a valid counter.")

        counter = int.from_bytes(framed[:8], "big")
        ciphertext = framed[8:]

        if counter != self._recv_counter:
            raise ReplayError(
                f"Expected message counter {self._recv_counter}, got "
                f"{counter} - message replayed, reordered, or dropped."
            )

        nonce = cu.counter_to_nonce(counter)
        aad = counter.to_bytes(8, "big")
        try:
            plaintext = cu.aes_gcm_decrypt(self._recv_key, nonce, ciphertext, aad)
        except InvalidTag:
            raise TamperError(
                "GCM authentication tag mismatch - ciphertext was tampered "
                "with, corrupted, or encrypted under the wrong key."
            )

        self._recv_counter += 1
        return plaintext
