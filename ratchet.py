"""
ratchet.py
----------
Two complementary ratchets, together forming a (simplified) Double
Ratchet:

  1. SYMMETRIC RATCHET (SendingChain / ReceivingChain, kdf_chain_step):
     each message gets its own AES-256-GCM key, derived by repeatedly
     stepping an HMAC-based KDF chain forward. Because each step is a
     one-way function, learning the CURRENT chain key does not let an
     attacker recover any EARLIER message key - this gives forward
     secrecy within an "epoch" (the messages sent between two DH
     ratchet steps).

  2. DH RATCHET (dh_ratchet_step): periodically, a party generates a
     fresh X25519 keypair, performs a new Diffie-Hellman exchange with
     the peer's most recent ratchet public key, and mixes the result
     into the root key to derive a brand new chain key. Because the new
     private key was generated AFTER any hypothetical compromise and
     nobody else ever saw it, this "heals" the session: even an
     attacker who fully captured the chain state at some point cannot
     derive keys for messages sent after the next DH ratchet step. This
     is what the symmetric ratchet alone cannot provide (it only
     protects the past, not the future).

Design note on WHEN the DH ratchet fires: Signal's Double Ratchet
triggers a DH step reactively, on the first message of every new
"sending turn" - which works because X3DH (their handshake) only gives
the initiator a receiving chain up front, not a sending chain, so
there's a natural "I have nothing to send with yet" trigger the first
time they reply. Our handshake (handshake.py) is symmetric - both
sides derive BOTH directions' chains during the handshake itself - so
that trigger doesn't naturally exist here. Instead, SecureChannel uses
PERIODIC re-keying: every REKEY_INTERVAL messages sent, a party
proactively ratchets. This is a legitimate, simpler alternative used by
other real protocols for the same purpose (e.g. WireGuard rekeys on a
message-count/time basis) - it delivers the same post-compromise
healing property, just on a schedule rather than reactively.

Out-of-order delivery: SecureChannel's sliding-window replay filter
already tolerates reordered messages, so the receiving side of the
symmetric ratchet must be able to produce a message key for a counter
that arrives before some earlier counter has been processed. It does
this the same way Signal's implementation does: when asked for counter
N while only having processed up to some earlier counter, it steps the
chain forward through all the intermediate counters, caching (not
losing) their message keys for later, and only forgetting a skipped key
once it's actually been used to decrypt a message. A MAX_SKIP bound
limits how large a single jump can force the receiver to compute, so an
attacker can't force unbounded HMAC work by sending a message with an
absurdly large counter.
"""

import hashlib
import hmac

import crypto_utils as cu

CHAIN_KEY_LABEL = b"chain-key"
MESSAGE_KEY_LABEL = b"message-key"
ROOT_STEP_INFO = b"dh-ratchet-step"


def kdf_chain_step(chain_key: bytes):
    """One step of the symmetric ratchet: returns (message_key,
    next_chain_key). HMAC-SHA256 is used as the PRF, with fixed,
    distinct labels so the two outputs are cryptographically independent
    of each other and of the input - neither output reveals anything
    about the other."""
    message_key = hmac.new(chain_key, MESSAGE_KEY_LABEL, hashlib.sha256).digest()
    next_chain_key = hmac.new(chain_key, CHAIN_KEY_LABEL, hashlib.sha256).digest()
    return message_key, next_chain_key


def dh_ratchet_step(root_key: bytes, dh_output: bytes):
    """KDF_RK in Signal's terminology: mixes a fresh Diffie-Hellman
    output into the current root key, producing a NEW root key and a
    new chain key in a single HKDF expansion (64 bytes out, split in
    half). The root key acts as the HKDF salt so that even if the SAME
    dh_output were ever produced twice (it won't be, in practice - each
    step uses a freshly generated private key), the outputs would still
    differ because the root key has moved on.

    `dh_output` must come from a FRESHLY GENERATED private key, never
    reused across ratchet steps - that's what makes this "heal" a prior
    compromise: the new key material depends on secrets that did not
    exist yet at the time of the compromise."""
    okm = cu.hkdf(dh_output, salt=root_key, info=ROOT_STEP_INFO, length=64)
    new_root_key = okm[:32]
    new_chain_key = okm[32:]
    return new_root_key, new_chain_key


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
