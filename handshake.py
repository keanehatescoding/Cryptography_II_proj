"""
handshake.py
------------
The authenticated key exchange (AKE) protocol. This is the heart of the
system - it combines:

  1. KEY EXCHANGE   - fresh ephemeral X25519 keypairs per session, giving
                       forward secrecy (compromising a long-term identity
                       key later does NOT expose past session keys).
  2. AUTHENTICATION - each party signs the handshake transcript with their
                       long-term Ed25519 identity key, so an active
                       man-in-the-middle cannot substitute their own
                       ephemeral key without detection.
  3. KEY DERIVATION - the raw ECDH secret is expanded via HKDF into two
                       independent, directional AES-256-GCM keys.

Wire protocol (3 messages, mutual auth):

    Initiator                                   Responder
    ----------                                   ---------
    name_I, epk_I        ----------------->
                          <-----------------      name_R, epk_R, sig_R
    sig_I                ----------------->

  where sig_R = Sign_R(epk_I || epk_R)
        sig_I = Sign_I(epk_I || epk_R)

  Both signatures cover BOTH ephemeral public keys concatenated in a
  fixed order. This "binds" the signature to this exact exchange -
  an attacker cannot replay a signature from a different handshake or
  swap in a different ephemeral key, because that would change the
  signed transcript and the signature would fail to verify.

Why not sign only your own ephemeral key? Because that would let an
active MITM run two separate handshakes (one with each real party) and
splice the (valid, but wrongly-paired) signatures together. Binding the
transcript to *both* keys prevents this.
"""

from dataclasses import dataclass


import crypto_utils as cu
from identity import Identity, TrustStore
from secure_channel import SecureChannel


class HandshakeError(Exception):
    pass


@dataclass
class HandshakeMessage1:
    """Initiator -> Responder"""

    name: str
    ephemeral_pub: bytes

    def to_wire(self) -> dict:
        return {"name": self.name, "epk": self.ephemeral_pub.hex()}

    @classmethod
    def from_wire(cls, d: dict) -> "HandshakeMessage1":
        return cls(d["name"], bytes.fromhex(d["epk"]))


@dataclass
class HandshakeMessage2:
    """Responder -> Initiator"""

    name: str
    ephemeral_pub: bytes
    signature: bytes

    def to_wire(self) -> dict:
        return {
            "name": self.name,
            "epk": self.ephemeral_pub.hex(),
            "sig": self.signature.hex(),
        }

    @classmethod
    def from_wire(cls, d: dict) -> "HandshakeMessage2":
        return cls(d["name"], bytes.fromhex(d["epk"]), bytes.fromhex(d["sig"]))


@dataclass
class HandshakeMessage3:
    """Initiator -> Responder (final)"""

    signature: bytes

    def to_wire(self) -> dict:
        return {"sig": self.signature.hex()}

    @classmethod
    def from_wire(cls, d: dict) -> "HandshakeMessage3":
        return cls(bytes.fromhex(d["sig"]))


def _transcript(epk_initiator: bytes, epk_responder: bytes) -> bytes:
    return b"secure-comms-handshake-v1|" + epk_initiator + b"|" + epk_responder


def _derive_channel(
    shared_secret: bytes, epk_initiator: bytes, epk_responder: bytes, is_initiator: bool
) -> SecureChannel:
    """Derive two independent directional keys from the shared secret.
    Salt binds the derivation to this specific handshake's ephemeral keys
    so that even if (hypothetically) the same shared secret ever recurred,
    the derived keys would still differ."""
    salt = epk_initiator + epk_responder

    key_i2r = cu.hkdf(shared_secret, salt, b"initiator-to-responder", 32)
    key_r2i = cu.hkdf(shared_secret, salt, b"responder-to-initiator", 32)

    if is_initiator:
        return SecureChannel(send_key=key_i2r, recv_key=key_r2i)
    else:
        return SecureChannel(send_key=key_r2i, recv_key=key_i2r)


# ---------------------------------------------------------------------------
# Initiator side
# ---------------------------------------------------------------------------


def initiator_start(my_identity: Identity):
    """Step 1: generate ephemeral keypair, produce message 1 to send."""
    eph_priv, eph_pub = cu.generate_x25519_keypair()
    epk_bytes = cu.x25519_public_bytes(eph_pub)
    msg1 = HandshakeMessage1(name=my_identity.name, ephemeral_pub=epk_bytes)
    state = {"eph_priv": eph_priv, "epk_bytes": epk_bytes}
    return msg1, state


def initiator_finish(
    my_identity: Identity, trust_store: TrustStore, state: dict, msg2: HandshakeMessage2
):
    """Step 3: verify responder's signature, derive keys, produce message 3."""
    peer_pub = trust_store.get(msg2.name)
    if peer_pub is None:
        raise HandshakeError(
            f"No pinned public key for '{msg2.name}' - refusing to trust "
            f"an unknown identity (possible impersonation attempt)."
        )

    transcript = _transcript(state["epk_bytes"], msg2.ephemeral_pub)
    if not cu.verify(peer_pub, msg2.signature, transcript):
        raise HandshakeError(
            f"Signature verification FAILED for '{msg2.name}' - "
            f"handshake aborted (possible MITM attack or key mismatch)."
        )

    my_sig = cu.sign(my_identity.private_key, transcript)
    msg3 = HandshakeMessage3(signature=my_sig)

    shared_secret = cu.derive_shared_secret(
        state["eph_priv"], cu.x25519_public_from_bytes(msg2.ephemeral_pub)
    )
    channel = _derive_channel(
        shared_secret, state["epk_bytes"], msg2.ephemeral_pub, is_initiator=True
    )
    return msg3, channel


# ---------------------------------------------------------------------------
# Responder side
# ---------------------------------------------------------------------------


def responder_respond(my_identity: Identity, msg1: HandshakeMessage1):
    """Step 2: generate ephemeral keypair, sign transcript, produce message 2."""
    eph_priv, eph_pub = cu.generate_x25519_keypair()
    epk_bytes = cu.x25519_public_bytes(eph_pub)

    transcript = _transcript(msg1.ephemeral_pub, epk_bytes)
    signature = cu.sign(my_identity.private_key, transcript)

    msg2 = HandshakeMessage2(
        name=my_identity.name, ephemeral_pub=epk_bytes, signature=signature
    )
    state = {
        "eph_priv": eph_priv,
        "epk_bytes": epk_bytes,
        "peer_epk_bytes": msg1.ephemeral_pub,
        "peer_name": msg1.name,
    }
    return msg2, state


def responder_finish(
    trust_store: TrustStore, state: dict, msg3: HandshakeMessage3
) -> SecureChannel:
    """Step 4: verify initiator's signature, derive keys."""
    peer_pub = trust_store.get(state["peer_name"])
    if peer_pub is None:
        raise HandshakeError(
            f"No pinned public key for '{state['peer_name']}' - refusing "
            f"to trust an unknown identity."
        )

    transcript = _transcript(state["peer_epk_bytes"], state["epk_bytes"])
    if not cu.verify(peer_pub, msg3.signature, transcript):
        raise HandshakeError(
            f"Signature verification FAILED for '{state['peer_name']}' - "
            f"handshake aborted (possible MITM attack or key mismatch)."
        )

    shared_secret = cu.derive_shared_secret(
        state["eph_priv"], cu.x25519_public_from_bytes(state["peer_epk_bytes"])
    )
    channel = _derive_channel(
        shared_secret, state["peer_epk_bytes"], state["epk_bytes"], is_initiator=False
    )
    return channel
