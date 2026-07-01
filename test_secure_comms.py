"""
test_secure_comms.py
---------------------
Automated, in-process tests (no sockets needed) proving:
  1. A normal handshake + chat succeeds and both directions decrypt correctly.
  2. Tampering with a ciphertext is detected (AES-GCM auth tag fails).
  3. Replaying an old message is detected (counter check).
  4. An attacker without the real identity key CANNOT complete a handshake
     while impersonating a trusted name (signature verification fails).
  5. An unpinned/unknown identity is rejected outright.

Run with:  python3 -m pytest test_secure_comms.py -v
       or: python3 test_secure_comms.py
"""

import pytest

from identity import Identity, TrustStore
from handshake import (
    initiator_start,
    initiator_finish,
    responder_respond,
    responder_finish,
    HandshakeError,
    HandshakeMessage2,
)
from secure_channel import ReplayError, TamperError


def do_handshake(
    alice: Identity, bob: Identity, alice_trust: TrustStore, bob_trust: TrustStore
):
    """Runs a full 3-message handshake in-process and returns both channels."""
    msg1, i_state = initiator_start(alice)
    msg2, r_state = responder_respond(bob, msg1)
    msg3, alice_channel = initiator_finish(alice, alice_trust, i_state, msg2)
    bob_channel = responder_finish(bob_trust, r_state, msg3)
    return alice_channel, bob_channel


def make_pinned_pair():
    """Two identities that have already pinned each other's keys (simulates
    a completed TOFU exchange or out-of-band verification)."""
    alice = Identity("alice")
    bob = Identity("bob")

    alice_trust = TrustStore()
    alice_trust.pin("bob", bob.public_bytes)

    bob_trust = TrustStore()
    bob_trust.pin("alice", alice.public_bytes)

    return alice, bob, alice_trust, bob_trust


# ---------------------------------------------------------------------------


def test_handshake_succeeds_and_channels_are_symmetric():
    alice, bob, alice_trust, bob_trust = make_pinned_pair()
    alice_channel, bob_channel = do_handshake(alice, bob, alice_trust, bob_trust)

    # alice -> bob
    ct = alice_channel.encrypt(b"hello bob")
    assert bob_channel.decrypt(ct) == b"hello bob"

    # bob -> alice
    ct = bob_channel.encrypt(b"hello alice")
    assert alice_channel.decrypt(ct) == b"hello alice"


def test_multiple_messages_each_direction_independent_counters():
    alice, bob, alice_trust, bob_trust = make_pinned_pair()
    alice_channel, bob_channel = do_handshake(alice, bob, alice_trust, bob_trust)

    for i in range(5):
        msg = f"message {i}".encode()
        assert bob_channel.decrypt(alice_channel.encrypt(msg)) == msg
    for i in range(3):
        msg = f"reply {i}".encode()
        assert alice_channel.decrypt(bob_channel.encrypt(msg)) == msg


def test_tampered_ciphertext_is_rejected():
    alice, bob, alice_trust, bob_trust = make_pinned_pair()
    alice_channel, bob_channel = do_handshake(alice, bob, alice_trust, bob_trust)

    ct = bytearray(alice_channel.encrypt(b"transfer $10"))
    ct[-1] ^= 0xFF  # flip a bit in the auth tag / ciphertext
    with pytest.raises(TamperError):
        bob_channel.decrypt(bytes(ct))


def test_replayed_message_is_rejected():
    alice, bob, alice_trust, bob_trust = make_pinned_pair()
    alice_channel, bob_channel = do_handshake(alice, bob, alice_trust, bob_trust)

    ct = alice_channel.encrypt(b"one time payment")
    assert bob_channel.decrypt(ct) == b"one time payment"

    # Attacker captures and replays the exact same ciphertext later
    with pytest.raises(ReplayError):
        bob_channel.decrypt(ct)


def test_reordered_message_is_rejected():
    alice, bob, alice_trust, bob_trust = make_pinned_pair()
    alice_channel, bob_channel = do_handshake(alice, bob, alice_trust, bob_trust)

    ct1 = alice_channel.encrypt(b"first")
    ct2 = alice_channel.encrypt(b"second")

    # deliver out of order
    with pytest.raises(ReplayError):
        bob_channel.decrypt(ct2)
    # ct1 would still be accepted since counters are checked strictly
    assert bob_channel.decrypt(ct1) == b"first"


def test_impersonation_without_private_key_fails():
    """An attacker who knows Bob's *name* but not his private signing key
    cannot forge message 2 - even though they can freely pick any
    ephemeral X25519 key they like."""
    alice, bob, alice_trust, bob_trust = make_pinned_pair()

    attacker = Identity("mallory")  # different keypair entirely

    msg1, i_state = initiator_start(alice)

    # Attacker crafts a message2 claiming to be "bob" but signs with their
    # OWN key instead of bob's real private key.
    forged_msg2, _ = responder_respond(attacker, msg1)
    forged_msg2 = HandshakeMessage2(
        name="bob",  # lies about identity
        ephemeral_pub=forged_msg2.ephemeral_pub,
        signature=forged_msg2.signature,  # signed by mallory, not bob
    )

    with pytest.raises(HandshakeError):
        initiator_finish(alice, alice_trust, i_state, forged_msg2)


def test_unpinned_identity_is_rejected():
    """If we've never pinned a public key for a name, the handshake must
    refuse to proceed rather than trust-on-the-fly."""
    alice = Identity("alice")
    stranger = Identity("charlie")
    empty_trust = TrustStore()  # alice has pinned nobody

    msg1, i_state = initiator_start(alice)
    msg2, _ = responder_respond(stranger, msg1)

    with pytest.raises(HandshakeError):
        initiator_finish(alice, empty_trust, i_state, msg2)


def test_forward_secrecy_ephemeral_keys_are_fresh_each_time():
    """Two handshakes between the same identities must produce completely
    different session keys (fresh ephemeral keys each time)."""
    alice, bob, alice_trust, bob_trust = make_pinned_pair()

    channel_a1, channel_b1 = do_handshake(alice, bob, alice_trust, bob_trust)
    channel_a2, channel_b2 = do_handshake(alice, bob, alice_trust, bob_trust)

    assert channel_a1._send_key != channel_a2._send_key
    assert channel_b1._send_key != channel_b2._send_key


if __name__ == "__main__":
    import sys

    sys.exit(pytest.main([__file__, "-v"]))
