"""
identity.py
-----------
Long-term identity keys and a minimal trust store.

This system does NOT implement a full PKI (no CA, no certificate chains -
that's a separate project). Instead it uses Trust-On-First-Use (TOFU) /
pre-shared public keys, similar to how SSH host keys or Signal "safety
numbers" work: each party's Ed25519 public key is the identity, and peers
must already know (pin) each other's public key before a handshake can
be authenticated.
"""

import json
import os
from pathlib import Path

from cryptography.hazmat.primitives import serialization

from audit_log import EventCode, security_logger
from crypto_utils import (
    generate_ed25519_keypair,
    ed25519_public_bytes,
    ed25519_public_from_bytes,
)


def fingerprint_for_bytes(raw_public_bytes: bytes) -> str:
    """Short human-verifiable fingerprint (like an SSH key fingerprint) for
    a raw public key. Shared by Identity.fingerprint, TrustStore's audit
    logging, and every caller that needs to show a peer's claimed
    fingerprint for out-of-band verification before pinning it - so all
    of them produce the same format for the same key instead of each
    re-deriving their own copy of this logic."""
    import hashlib

    digest = hashlib.sha256(raw_public_bytes).hexdigest()
    return ":".join(digest[i : i + 4] for i in range(0, 16, 4))


# Backwards-compatible alias for the old private name.
_fingerprint = fingerprint_for_bytes


class IdentityMismatchError(Exception):
    """Raised by TrustStore.pin() when a name that's already pinned is
    presented with a DIFFERENT public key. This is the TOFU equivalent
    of SSH's "REMOTE HOST IDENTIFICATION HAS CHANGED" warning: it can be
    a legitimate device change / re-install, but it's also exactly what
    an active attacker impersonating an already-trusted name would
    produce, so pin() refuses to silently accept it. A caller that has
    verified out-of-band that the change is legitimate should call
    TrustStore.repin() instead, which makes that override explicit."""

    def __init__(self, name: str, old_fingerprint: str, new_fingerprint: str):
        self.name = name
        self.old_fingerprint = old_fingerprint
        self.new_fingerprint = new_fingerprint
        super().__init__(
            f"'{name}' is already pinned to a different key "
            f"(pinned: {old_fingerprint}, presented: {new_fingerprint}). "
            f"Call TrustStore.repin() if this change has been verified "
            f"out-of-band."
        )


class Identity:
    """A party's long-term signing identity."""

    def __init__(self, name: str, private_key=None):
        self.name = name
        if private_key is None:
            private_key, _ = generate_ed25519_keypair()
        self.private_key = private_key
        self.public_key = private_key.public_key()

    @property
    def public_bytes(self) -> bytes:
        return ed25519_public_bytes(self.public_key)

    @property
    def fingerprint(self) -> str:
        """Short human-verifiable fingerprint (like an SSH key fingerprint),
        useful for out-of-band verification to defeat MITM at first contact."""
        return _fingerprint(self.public_bytes)

    def save(self, directory: str, passphrase: str = None):
        """Persist the private key to disk (PEM). If `passphrase` is
        given, the key is encrypted at rest (PKCS8 password-based
        encryption); otherwise it's written in the clear. Long-term
        identity keys are high-value (they're what authentication rests
        on), so encrypting them is strongly recommended over the demo
        default of no encryption."""
        os.makedirs(directory, exist_ok=True)
        key_path = Path(directory) / f"{self.name}_identity.pem"
        if passphrase:
            encryption = serialization.BestAvailableEncryption(
                passphrase.encode("utf-8")
            )
        else:
            encryption = serialization.NoEncryption()
        pem = self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=encryption,
        )
        key_path.write_bytes(pem)
        return str(key_path)

    @classmethod
    def load(cls, name: str, directory: str, passphrase: str = None) -> "Identity":
        """Raises TypeError if the key on disk is encrypted but no
        passphrase was given (or vice versa), and ValueError if a
        passphrase was given but is wrong - callers should catch these
        and re-prompt rather than treating them as fatal."""
        key_path = Path(directory) / f"{name}_identity.pem"
        pem = key_path.read_bytes()
        password = passphrase.encode("utf-8") if passphrase else None
        private_key = serialization.load_pem_private_key(pem, password=password)
        return cls(name, private_key)

    @staticmethod
    def is_encrypted(name: str, directory: str) -> bool:
        """Peek at a key file to see if it needs a passphrase, without
        actually attempting to decrypt it - lets callers decide whether
        to prompt for a passphrase before the first load attempt."""
        key_path = Path(directory) / f"{name}_identity.pem"
        pem = key_path.read_bytes()
        try:
            serialization.load_pem_private_key(pem, password=None)
            return False
        except TypeError:
            return True


class TrustStore:
    """Maps peer names -> pinned Ed25519 public keys.

    In a real deployment these pins would be exchanged out-of-band
    (QR code, verbal fingerprint comparison, etc.) exactly once, then
    reused for every future handshake - this is what prevents an
    active MITM from ever intercepting the *first* handshake and
    impersonating a party forever after.
    """

    def __init__(self):
        self._trusted = {}  # name -> raw public key bytes

    def pin(self, name: str, public_bytes: bytes):
        """Pin `name` to `public_bytes`. Safe to call repeatedly with the
        same key (a no-op past the first time). Raises
        IdentityMismatchError if `name` is already pinned to a
        DIFFERENT key - callers must not treat that as routine and
        silently move on; use repin() if the change has actually been
        verified out-of-band."""
        existing = self._trusted.get(name)
        if existing is None:
            self._trusted[name] = public_bytes
            security_logger.security(
                EventCode.IDENTITY_PINNED,
                "new identity pinned",
                peer_name=name,
                fingerprint=_fingerprint(public_bytes),
            )
        elif existing != public_bytes:
            old_fp = _fingerprint(existing)
            new_fp = _fingerprint(public_bytes)
            security_logger.security(
                EventCode.IDENTITY_MISMATCH,
                "pinned identity changed for an existing name",
                peer_name=name,
                old_fingerprint=old_fp,
                new_fingerprint=new_fp,
            )
            raise IdentityMismatchError(name, old_fp, new_fp)
        # else: re-pinning the same key that's already pinned - a no-op,
        # not worth logging.

    def repin(self, name: str, public_bytes: bytes):
        """Explicitly overwrite an existing pin with a new key, bypassing
        the mismatch check in pin(). Only call this after the change has
        actually been verified out-of-band (e.g. the human confirmed the
        new fingerprint over a call) - it exists so that override is a
        deliberate, separately-named action a caller has to opt into,
        rather than something that can happen as a side effect of an
        ordinary pin() call."""
        existing = self._trusted.get(name)
        self._trusted[name] = public_bytes
        security_logger.security(
            EventCode.IDENTITY_PINNED,
            "identity re-pinned after verified key change",
            peer_name=name,
            old_fingerprint=_fingerprint(existing) if existing else None,
            fingerprint=_fingerprint(public_bytes),
        )

    def get(self, name: str):
        raw = self._trusted.get(name)
        if raw is None:
            return None
        return ed25519_public_from_bytes(raw)

    def is_trusted(self, name: str, public_bytes: bytes) -> bool:
        pinned = self._trusted.get(name)
        return pinned is not None and pinned == public_bytes

    def verify_and_pin_interactive(
        self,
        peer_name: str,
        peer_pubkey: bytes,
        label: str,
        save_path: str = None,
        input_fn=input,
        print_fn=print,
    ) -> tuple:
        """Terminal-friendly TOFU flow shared by client.py and server.py
        (and any other interactive caller): on first contact with
        `peer_name`, shows the peer's claimed fingerprint and requires
        explicit confirmation before pinning it; on a name that's
        already pinned, verifies the presented key still matches.

        Returns (trusted, mismatch):
          - trusted=True: peer is trusted (just pinned, or already matched).
          - trusted=False, mismatch=False: human declined confirmation.
          - trusted=False, mismatch=True: presented key differs from the
            existing pin - possible impersonation, distinct from a plain
            decline so callers can treat it more seriously (e.g. feed it
            to a rate limiter) without penalizing someone who just said no.

        `input_fn`/`print_fn` default to the real builtins but are
        injectable so this can be unit-tested without a real terminal -
        see test_secure_comms.py's TOFU tests.
        """
        if self.get(peer_name) is None:
            fp = fingerprint_for_bytes(peer_pubkey)
            print_fn(f"[{label}] '{peer_name}' is not yet trusted.")
            print_fn(f"[{label}] their identity fingerprint is: {fp}")
            print_fn(
                f"[{label}] compare this, out-of-band (in person, on a call, "
                f"etc.), against the fingerprint '{peer_name}' sees printed "
                f"as THEIR OWN identity before trusting it. Anyone who "
                f"skips this step is trusting whoever is on the other end "
                f"of the TCP connection, not necessarily '{peer_name}'."
            )
            answer = (
                input_fn(
                    f"[{label}] trust and pin this identity as '{peer_name}'? [y/N]: "
                )
                .strip()
                .lower()
            )
            if answer != "y":
                print_fn(f"[{label}] declined to trust '{peer_name}'. Aborting.")
                return False, False
            self.pin(peer_name, peer_pubkey)
            if save_path:
                self.save(save_path)
            print_fn(f"[{label}] TOFU: pinned new identity '{peer_name}' ({fp})")
            return True, False

        if not self.is_trusted(peer_name, peer_pubkey):
            print_fn(
                f"[{label}] !!! WARNING: '{peer_name}' presented a DIFFERENT "
                f"public key than the one we have pinned. Possible "
                f"impersonation. Aborting."
            )
            return False, True

        return True, False

    def save(self, path: str):
        data = {name: raw.hex() for name, raw in self._trusted.items()}
        Path(path).write_text(json.dumps(data, indent=2))

    @classmethod
    def load(cls, path: str) -> "TrustStore":
        store = cls()
        if Path(path).exists():
            data = json.loads(Path(path).read_text())
            for name, hexval in data.items():
                store.pin(name, bytes.fromhex(hexval))
        return store
