"""
crypto_utils.py
----------------
Low-level cryptographic primitives used by the rest of the system.

Design choices (and why):
  - X25519 for key exchange: fast, constant-time, no parameter negotiation
    pitfalls (unlike classic Diffie-Hellman with custom groups).
  - Ed25519 for authentication/signatures: deterministic, fast to verify,
    small keys/signatures, resistant to nonce-reuse issues that plague
    ECDSA.
  - HKDF-SHA256 for key derivation: turns a raw ECDH shared secret (which
    is NOT uniformly random and must never be used directly as a cipher
    key) into properly whitened, purpose-bound symmetric keys.
  - AES-256-GCM for encryption: authenticated encryption (AEAD) - gives
    us confidentiality AND integrity/tamper-detection in one primitive,
    avoiding classic "encrypt-then-forget-to-MAC" bugs.
"""

import os
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidSignature


# ---------------------------------------------------------------------------
# Key exchange (X25519)
# ---------------------------------------------------------------------------


def generate_x25519_keypair():
    """Generate an ephemeral X25519 keypair for one handshake only."""
    priv = X25519PrivateKey.generate()
    pub = priv.public_key()
    return priv, pub


def x25519_public_bytes(pub: X25519PublicKey) -> bytes:
    return pub.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def x25519_public_from_bytes(data: bytes) -> X25519PublicKey:
    return X25519PublicKey.from_public_bytes(data)


def derive_shared_secret(priv: X25519PrivateKey, peer_pub: X25519PublicKey) -> bytes:
    """Raw ECDH shared secret. NEVER use this directly as a key - always
    pass it through HKDF first."""
    return priv.exchange(peer_pub)


# ---------------------------------------------------------------------------
# Authentication (Ed25519 signatures)
# ---------------------------------------------------------------------------


def generate_ed25519_keypair():
    """Generate a long-term identity keypair (persisted across sessions)."""
    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key()
    return priv, pub


def ed25519_public_bytes(pub: Ed25519PublicKey) -> bytes:
    return pub.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def ed25519_public_from_bytes(data: bytes) -> Ed25519PublicKey:
    return Ed25519PublicKey.from_public_bytes(data)


def sign(priv: Ed25519PrivateKey, message: bytes) -> bytes:
    return priv.sign(message)


def verify(pub: Ed25519PublicKey, signature: bytes, message: bytes) -> bool:
    """Returns True/False instead of raising, so callers can't accidentally
    forget to catch the exception and treat a failed verification as success."""
    try:
        pub.verify(signature, message)
        return True
    except InvalidSignature:
        return False


# ---------------------------------------------------------------------------
# Key derivation
# ---------------------------------------------------------------------------


def hkdf(shared_secret: bytes, salt: bytes, info: bytes, length: int = 32) -> bytes:
    """HKDF-SHA256. `info` MUST differ between distinct derived keys
    (e.g. b"initiator-to-responder" vs b"responder-to-initiator") so that
    two keys derived from the same secret are cryptographically independent."""
    return HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        info=info,
    ).derive(shared_secret)


# ---------------------------------------------------------------------------
# Symmetric encryption (AES-256-GCM)
# ---------------------------------------------------------------------------

NONCE_SIZE = 12  # 96 bits, standard for GCM


def aes_gcm_encrypt(
    key: bytes, nonce: bytes, plaintext: bytes, aad: bytes = b""
) -> bytes:
    return AESGCM(key).encrypt(nonce, plaintext, aad)


def aes_gcm_decrypt(
    key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes = b""
) -> bytes:
    """Raises cryptography.exceptions.InvalidTag on tampering, wrong key,
    or wrong AAD - this is the integrity guarantee."""
    return AESGCM(key).decrypt(nonce, ciphertext, aad)


def counter_to_nonce(counter: int) -> bytes:
    """Deterministic nonce derived from a strictly-increasing message
    counter. Safe for GCM as long as (key, nonce) pairs never repeat -
    which holds here because each direction has its own key AND the
    counter never repeats within a session."""
    return counter.to_bytes(NONCE_SIZE, "big")


def random_bytes(n: int) -> bytes:
    return os.urandom(n)
