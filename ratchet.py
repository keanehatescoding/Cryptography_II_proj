"""
ratchet.py
----------
Symmetric-key ratchet - the "chain key" half of Signal's Double Ratchet,
without the Diffie-Hellman ratchet half. Each message gets its own
AES-256-GCM key, derived by repeatedly stepping an HMAC-based KDF chain
forward. Because each step is a one-way function (you cannot invert an
HMAC to recover its input from its output), learning the CURRENT chain
key does NOT let an attacker recover any EARLIER message key.

Before this module existed, SecureChannel used one fixed AES key for
the entire session (derived once, during the handshake). That meant a
single key compromise - a memory dump, a debugger attached mid-session,
whatever - exposed every past and future message in that session. This
ratchet fixes the "every past message" half of that: compromising the
chain state at message N only exposes messages N and later, not
messages 1..N-1.

What this does NOT provide: post-compromise security / "healing". A
full Double Ratchet also re-runs Diffie-Hellman periodically, so that
even after a compromise, future messages become secret again once a new
DH step happens. This module has no DH step, so a compromised chain key
DOES still expose all future messages in that session (until the next
full handshake, which - being a fresh ephemeral X25519 exchange - starts
an entirely new, uncompromised chain). That asymmetry is a deliberate
scope reduction; see the README for what a full DH ratchet would add.

Out-of-order delivery: SecureChannel's sliding-window replay filter
already tolerates reordered messages, so the receiving side of this
ratchet must be able to produce a message key for a counter that
arrives before some earlier counter has been processed. It does this
the same way Signal's implementation does: when asked for counter N
while only having processed up to some earlier counter, it steps the
chain forward through all the intermediate counters, caching (not
losing) their message keys for later, and only forgetting a skipped key
once it's actually been used to decrypt a message. A MAX_SKIP bound
limits how large a single jump can force the receiver to compute, so an
attacker can't force unbounded HMAC work by sending a message with an
absurdly large counter.
"""

import hashlib
import hmac

CHAIN_KEY_LABEL = b"chain-key"
MESSAGE_KEY_LABEL = b"message-key"


def kdf_chain_step(chain_key: bytes):
    """One step of the ratchet: returns (message_key, next_chain_key).
    HMAC-SHA256 is used as the PRF, with fixed, distinct labels so the
    two outputs are cryptographically independent of each other and of
    the input - neither output reveals anything about the other."""
    message_key = hmac.new(chain_key, MESSAGE_KEY_LABEL, hashlib.sha256).digest()
    next_chain_key = hmac.new(chain_key, CHAIN_KEY_LABEL, hashlib.sha256).digest()
    return message_key, next_chain_key


class ChainDesync(Exception):
    """Raised when a receiving chain is asked for a message key it
    cannot or should not produce: either a counter far enough ahead that
    deriving it would mean an unbounded amount of HMAC work (a possible
    DoS), or a counter already consumed with no cached key remaining."""


class SendingChain:
    """One direction's ratchet state on the sending side. Strictly
    sequential - each call to next() advances the chain by exactly one
    step and returns that message's counter and key."""

    def __init__(self, chain_key: bytes):
        self._chain_key = chain_key
        self._counter = 0

    def next(self):
        counter = self._counter
        message_key, self._chain_key = kdf_chain_step(self._chain_key)
        self._counter += 1
        return counter, message_key


class ReceivingChain:
    """One direction's ratchet state on the receiving side. Supports
    out-of-order delivery by caching message keys for counters that get
    skipped over when the chain is stepped forward to reach a later
    counter, and evicting a cached key as soon as it's used."""

    MAX_SKIP = 1024  # bounds how far a single jump can force us to compute

    def __init__(self, chain_key: bytes):
        self._chain_key = chain_key
        self._next_counter = 0  # lowest counter this chain hasn't derived yet
        self._skipped: dict = {}

    def key_for(self, counter: int) -> bytes:
        if counter in self._skipped:
            return self._skipped.pop(counter)

        if counter < self._next_counter:
            raise ChainDesync(
                f"Counter {counter} was already passed by this chain with "
                f"no cached key remaining - cannot derive a decryption key "
                f"for it (already consumed, or evicted)."
            )

        if counter - self._next_counter > self.MAX_SKIP:
            raise ChainDesync(
                f"Counter {counter} is {counter - self._next_counter} steps "
                f"ahead of the current chain position ({self._next_counter}) "
                f"- refusing to derive that many intermediate keys at once "
                f"(possible DoS attempt)."
            )

        message_key = None
        while self._next_counter <= counter:
            derived_key, self._chain_key = kdf_chain_step(self._chain_key)
            if self._next_counter == counter:
                message_key = derived_key
            else:
                self._skipped[self._next_counter] = derived_key
            self._next_counter += 1

        self._evict_excess_skipped()
        return message_key

    def _evict_excess_skipped(self):
        # Bound memory: never hold more skipped keys than MAX_SKIP, even
        # if a peer never follows up on some very old skipped counters.
        excess = len(self._skipped) - self.MAX_SKIP
        if excess > 0:
            for key in sorted(self._skipped)[:excess]:
                del self._skipped[key]
