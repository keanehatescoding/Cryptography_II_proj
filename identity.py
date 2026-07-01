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

from crypto_utils import (
    generate_ed25519_keypair,
    ed25519_public_bytes,
    ed25519_public_from_bytes,
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
        import hashlib

        digest = hashlib.sha256(self.public_bytes).hexdigest()
        return ":".join(digest[i : i + 4] for i in range(0, 16, 4))

    def save(self, directory: str):
        """Persist the private key to disk (PEM, unencrypted for demo
        purposes - production code should encrypt this at rest)."""
        os.makedirs(directory, exist_ok=True)
        key_path = Path(directory) / f"{self.name}_identity.pem"
        pem = self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        key_path.write_bytes(pem)
        return str(key_path)

    @classmethod
    def load(cls, name: str, directory: str) -> "Identity":
        key_path = Path(directory) / f"{name}_identity.pem"
        pem = key_path.read_bytes()
        private_key = serialization.load_pem_private_key(pem, password=None)
        return cls(name, private_key)


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
        self._trusted[name] = public_bytes

    def get(self, name: str):
        raw = self._trusted.get(name)
        if raw is None:
            return None
        return ed25519_public_from_bytes(raw)

    def is_trusted(self, name: str, public_bytes: bytes) -> bool:
        pinned = self._trusted.get(name)
        return pinned is not None and pinned == public_bytes

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
