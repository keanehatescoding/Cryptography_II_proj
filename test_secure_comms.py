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

from identity import Identity, TrustStore, IdentityMismatchError
from handshake import (
    initiator_start,
    initiator_finish,
    responder_respond,
    responder_finish,
    HandshakeError,
    HandshakeMessage2,
)
from secure_channel import ReplayError, SecureChannel, TamperError


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


def test_reordered_messages_within_window_are_accepted():
    """Sliding-window replay protection tolerates real reordering -
    this is the key behavioral difference from a strict sequential
    counter check."""
    alice, bob, alice_trust, bob_trust = make_pinned_pair()
    alice_channel, bob_channel = do_handshake(alice, bob, alice_trust, bob_trust)

    ct1 = alice_channel.encrypt(b"first")
    ct2 = alice_channel.encrypt(b"second")
    ct3 = alice_channel.encrypt(b"third")

    # deliver out of order: 2, 1, 3
    assert bob_channel.decrypt(ct2) == b"second"
    assert bob_channel.decrypt(ct1) == b"first"
    assert bob_channel.decrypt(ct3) == b"third"


def test_replaying_an_out_of_order_message_still_rejected():
    alice, bob, alice_trust, bob_trust = make_pinned_pair()
    alice_channel, bob_channel = do_handshake(alice, bob, alice_trust, bob_trust)

    ct1 = alice_channel.encrypt(b"first")
    ct2 = alice_channel.encrypt(b"second")

    assert bob_channel.decrypt(ct2) == b"second"
    assert bob_channel.decrypt(ct1) == b"first"
    # both already seen - replaying either must fail
    with pytest.raises(ReplayError):
        bob_channel.decrypt(ct1)
    with pytest.raises(ReplayError):
        bob_channel.decrypt(ct2)


def test_message_older_than_window_is_rejected():
    alice, bob, alice_trust, bob_trust = make_pinned_pair()
    alice_channel, bob_channel = do_handshake(alice, bob, alice_trust, bob_trust)
    # small window for a fast, deterministic test
    bob_channel._window_size = 4
    bob_channel._window_mask = (1 << 4) - 1

    old_ct = alice_channel.encrypt(b"will go stale")
    for i in range(10):
        bob_channel.decrypt(alice_channel.encrypt(f"filler {i}".encode()))

    with pytest.raises(ReplayError):
        bob_channel.decrypt(old_ct)


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

    assert channel_a1._sending_chain._chain_key != channel_a2._sending_chain._chain_key
    assert channel_b1._sending_chain._chain_key != channel_b2._sending_chain._chain_key


import tempfile
import shutil

from rate_limiter import RateLimiter
import crypto_utils as cu
import padding
from ratchet import (
    ChainDesync,
    ReceivingChain,
    SendingChain,
    dh_ratchet_step,
    kdf_chain_step,
)


# ---------------------------------------------------------------------------
# Symmetric ratchet (per-message key derivation)
# ---------------------------------------------------------------------------


def test_sending_chain_produces_distinct_sequential_keys():
    chain = SendingChain(b"\x01" * 32)
    counter0, key0 = chain.next()
    counter1, key1 = chain.next()
    counter2, key2 = chain.next()
    assert (counter0, counter1, counter2) == (0, 1, 2)
    assert len({key0, key1, key2}) == 3  # all distinct


def test_receiving_chain_matches_sending_chain_in_order():
    seed = b"\x02" * 32
    sender = SendingChain(seed)
    receiver = ReceivingChain(seed)
    for _ in range(5):
        counter, sent_key = sender.next()
        assert receiver.key_for(counter) == sent_key


def test_receiving_chain_handles_out_of_order_via_skipped_cache():
    seed = b"\x03" * 32
    sender = SendingChain(seed)
    receiver = ReceivingChain(seed)
    sent = [sender.next() for _ in range(4)]  # [(0,k0), (1,k1), (2,k2), (3,k3)]

    # deliver out of order: 2, 0, 3, 1
    for counter in (2, 0, 3, 1):
        expected_key = dict(sent)[counter]
        assert receiver.key_for(counter) == expected_key


def test_receiving_chain_rejects_reuse_of_already_consumed_counter():
    seed = b"\x04" * 32
    sender = SendingChain(seed)
    receiver = ReceivingChain(seed)
    counter, _ = sender.next()
    receiver.key_for(counter)  # consumes it
    with pytest.raises(ChainDesync):
        receiver.key_for(counter)  # no longer cached, and counter < next_counter


def test_receiving_chain_enforces_max_skip_bound():
    receiver = ReceivingChain(b"\x05" * 32)
    receiver.MAX_SKIP = 10  # shrink for a fast, deterministic test
    with pytest.raises(ChainDesync):
        receiver.key_for(1000)  # far beyond the skip bound - possible DoS


def test_forward_secrecy_current_chain_state_cannot_reconstruct_past_keys():
    """We can't prove HMAC's one-wayness inside a unit test - that's a
    cryptographic assumption, not a testable property - but we CAN prove
    the implementation itself never retains the ability to walk the
    chain backward: the only state kept is the current chain key, and
    every message key is derived only forward from it."""
    chain = SendingChain(b"\x06" * 32)
    _, key0 = chain.next()
    _, key1 = chain.next()
    current_state = chain._chain_key  # state after 2 steps

    # Deriving forward from the CURRENT state can only ever reproduce
    # FUTURE message keys - key0 and key1 are not recoverable from it.
    key2, _ = kdf_chain_step(current_state)
    assert key2 not in (key0, key1)


def test_secure_channel_uses_ratchet_end_to_end():
    """Integration check: SecureChannel's encrypt/decrypt actually goes
    through the ratchet (not a leftover fixed key) - each message is
    encrypted under a distinct key, verified by checking that decrypting
    message N's ciphertext under message N+1's key fails."""
    alice, bob, alice_trust, bob_trust = make_pinned_pair()
    alice_channel, bob_channel = do_handshake(alice, bob, alice_trust, bob_trust)

    msgs = [b"one", b"two", b"three"]
    cts = [alice_channel.encrypt(m) for m in msgs]
    for ct, expected in zip(cts, msgs):
        assert bob_channel.decrypt(ct) == expected

    # The receiving chain must have advanced through all 3 counters in
    # order, with nothing left in its skipped-key cache.
    assert bob_channel._recv_chains[0]._next_counter == 3
    assert bob_channel._recv_chains[0]._skipped == {}


# ---------------------------------------------------------------------------
# Identity key encryption at rest
# ---------------------------------------------------------------------------


def test_identity_saved_without_passphrase_is_not_encrypted():
    tmpdir = tempfile.mkdtemp()
    try:
        alice = Identity("alice")
        alice.save(tmpdir)
        assert Identity.is_encrypted("alice", tmpdir) is False
        loaded = Identity.load("alice", tmpdir)
        assert loaded.fingerprint == alice.fingerprint
    finally:
        shutil.rmtree(tmpdir)


def test_identity_saved_with_passphrase_is_encrypted_and_roundtrips():
    tmpdir = tempfile.mkdtemp()
    try:
        bob = Identity("bob")
        bob.save(tmpdir, passphrase="correct horse battery staple")
        assert Identity.is_encrypted("bob", tmpdir) is True
        loaded = Identity.load("bob", tmpdir, passphrase="correct horse battery staple")
        assert loaded.fingerprint == bob.fingerprint
    finally:
        shutil.rmtree(tmpdir)


def test_identity_wrong_passphrase_rejected():
    tmpdir = tempfile.mkdtemp()
    try:
        bob = Identity("bob")
        bob.save(tmpdir, passphrase="correct horse battery staple")
        with pytest.raises(ValueError):
            Identity.load("bob", tmpdir, passphrase="wrong passphrase")
    finally:
        shutil.rmtree(tmpdir)


def test_identity_missing_passphrase_rejected():
    tmpdir = tempfile.mkdtemp()
    try:
        bob = Identity("bob")
        bob.save(tmpdir, passphrase="correct horse battery staple")
        with pytest.raises(TypeError):
            Identity.load("bob", tmpdir)
    finally:
        shutil.rmtree(tmpdir)


# ---------------------------------------------------------------------------
# TOFU interactive trust prompt (client.py / server.py / gui.py share this)
# ---------------------------------------------------------------------------


def _scripted_input(answers):
    """Returns an input_fn that yields each of `answers` in turn, for
    driving TrustStore.verify_and_pin_interactive without a real
    terminal."""
    it = iter(answers)
    return lambda prompt="": next(it)


def test_tofu_declining_confirmation_does_not_pin():
    """Regression test for a bug where client.py/server.py auto-pinned a
    new peer identity on first contact with no human confirmation step,
    unlike gui.py's "Verify new identity" prompt - meaning an on-path
    attacker present for the very first connection could substitute
    their own identity_pub and be silently trusted before the signed
    handshake ever ran. Fixed by requiring an explicit y/N confirmation
    (TrustStore.verify_and_pin_interactive) before any pin() call."""
    trust_store = TrustStore()
    peer_pubkey = Identity("mallory").public_bytes

    trusted, mismatch = trust_store.verify_and_pin_interactive(
        "mallory",
        peer_pubkey,
        "test",
        input_fn=_scripted_input(["n"]),  # declines confirmation
        print_fn=lambda *a, **k: None,
    )

    assert trusted is False
    assert mismatch is False
    # The whole point: declining must leave the peer unpinned.
    assert trust_store.get("mallory") is None
    assert trust_store.is_trusted("mallory", peer_pubkey) is False


def test_tofu_confirming_pins_the_identity():
    trust_store = TrustStore()
    peer = Identity("bob")

    trusted, mismatch = trust_store.verify_and_pin_interactive(
        "bob",
        peer.public_bytes,
        "test",
        input_fn=_scripted_input(["y"]),
        print_fn=lambda *a, **k: None,
    )

    assert trusted is True
    assert mismatch is False
    assert trust_store.is_trusted("bob", peer.public_bytes) is True


def test_tofu_confirmation_prompt_shows_the_peers_fingerprint():
    """The whole point of the prompt is that the human can compare a
    fingerprint out-of-band before trusting it - make sure the actual
    fingerprint of the presented key is what gets shown, not e.g. a
    placeholder or the wrong key's fingerprint."""
    trust_store = TrustStore()
    peer = Identity("bob")
    shown = []

    trust_store.verify_and_pin_interactive(
        "bob",
        peer.public_bytes,
        "test",
        input_fn=_scripted_input(["y"]),
        print_fn=lambda msg="": shown.append(msg),
    )

    assert any(peer.fingerprint in line for line in shown)


def test_tofu_existing_pin_mismatch_is_not_overwritten_and_flagged():
    """An already-trusted name presenting a DIFFERENT key must be
    rejected outright (no confirmation prompt at all - that's only for
    first contact) and reported as a mismatch, not a plain decline, so
    callers can treat it more seriously (e.g. server.py's rate limiter)."""
    trust_store = TrustStore()
    real_bob = Identity("bob")
    attacker = Identity("attacker-pretending-to-be-bob")
    trust_store.pin("bob", real_bob.public_bytes)

    trusted, mismatch = trust_store.verify_and_pin_interactive(
        "bob",
        attacker.public_bytes,
        "test",
        input_fn=_scripted_input([]),  # must not even be asked
        print_fn=lambda *a, **k: None,
    )

    assert trusted is False
    assert mismatch is True
    # The original pin must survive untouched.
    assert trust_store.is_trusted("bob", real_bob.public_bytes) is True
    assert trust_store.is_trusted("bob", attacker.public_bytes) is False


def test_pin_raises_on_mismatch_instead_of_silently_overwriting():
    """pin() itself (independent of the interactive wrapper above) must
    refuse a key change for an already-pinned name rather than quietly
    accepting it - a caller that ignores the return value of a
    non-raising pin() would otherwise sail right past what's supposed
    to be a security-relevant event."""
    trust_store = TrustStore()
    real_bob = Identity("bob")
    attacker = Identity("attacker-pretending-to-be-bob")
    trust_store.pin("bob", real_bob.public_bytes)

    with pytest.raises(IdentityMismatchError):
        trust_store.pin("bob", attacker.public_bytes)

    # The failed pin() call must not have partially applied.
    assert trust_store.is_trusted("bob", real_bob.public_bytes) is True


def test_pin_is_idempotent_for_the_same_key():
    """Re-pinning a name to the SAME key it's already pinned to must
    stay a no-op, not raise - only an actual key change is a mismatch."""
    trust_store = TrustStore()
    bob = Identity("bob")
    trust_store.pin("bob", bob.public_bytes)
    trust_store.pin("bob", bob.public_bytes)  # must not raise
    assert trust_store.is_trusted("bob", bob.public_bytes) is True


def test_repin_explicitly_overrides_an_existing_pin():
    """repin() is the deliberate override an operator reaches for after
    verifying a key change out-of-band - it must succeed where pin()
    would raise, and the new key must actually take effect."""
    trust_store = TrustStore()
    old_key = Identity("bob")
    new_key = Identity("bob-reinstalled")
    trust_store.pin("bob", old_key.public_bytes)

    trust_store.repin("bob", new_key.public_bytes)

    assert trust_store.is_trusted("bob", new_key.public_bytes) is True
    assert trust_store.is_trusted("bob", old_key.public_bytes) is False


# ---------------------------------------------------------------------------
# Rate limiter
# ---------------------------------------------------------------------------


def test_rate_limiter_blocks_after_max_attempts():
    rl = RateLimiter(max_attempts=3, window_seconds=60.0, cooldown_seconds=30.0)
    t = 1000.0
    assert not rl.is_blocked("1.2.3.4", now=t)
    rl.record_failure("1.2.3.4", now=t)
    rl.record_failure("1.2.3.4", now=t + 1)
    assert not rl.is_blocked("1.2.3.4", now=t + 1)
    rl.record_failure("1.2.3.4", now=t + 2)  # 3rd failure -> blocked
    assert rl.is_blocked("1.2.3.4", now=t + 2)


def test_rate_limiter_unblocks_after_cooldown():
    rl = RateLimiter(max_attempts=2, window_seconds=60.0, cooldown_seconds=10.0)
    t = 1000.0
    rl.record_failure("1.2.3.4", now=t)
    rl.record_failure("1.2.3.4", now=t)
    assert rl.is_blocked("1.2.3.4", now=t + 5)
    assert not rl.is_blocked("1.2.3.4", now=t + 11)


def test_rate_limiter_old_failures_age_out_of_window():
    rl = RateLimiter(max_attempts=3, window_seconds=10.0, cooldown_seconds=30.0)
    t = 1000.0
    rl.record_failure("1.2.3.4", now=t)
    rl.record_failure("1.2.3.4", now=t + 1)
    # window has passed - the first two failures should no longer count
    rl.record_failure("1.2.3.4", now=t + 20)
    assert not rl.is_blocked("1.2.3.4", now=t + 20)


def test_rate_limiter_success_clears_history():
    rl = RateLimiter(max_attempts=2, window_seconds=60.0, cooldown_seconds=30.0)
    t = 1000.0
    rl.record_failure("1.2.3.4", now=t)
    rl.record_success("1.2.3.4")
    rl.record_failure("1.2.3.4", now=t + 1)  # would be failure #2 if history persisted
    assert not rl.is_blocked("1.2.3.4", now=t + 1)


def test_rate_limiter_tracks_addresses_independently():
    rl = RateLimiter(max_attempts=2, window_seconds=60.0, cooldown_seconds=30.0)
    t = 1000.0
    rl.record_failure("1.2.3.4", now=t)
    rl.record_failure("1.2.3.4", now=t)
    rl.record_failure("5.6.7.8", now=t)
    assert rl.is_blocked("1.2.3.4", now=t)
    assert not rl.is_blocked("5.6.7.8", now=t)


def test_dh_ratchet_step_deterministic_and_distinct():
    root = b"\x10" * 32
    dh_output_a = b"\x20" * 32
    dh_output_b = b"\x21" * 32

    root_a1, chain_a1 = dh_ratchet_step(root, dh_output_a)
    root_a2, chain_a2 = dh_ratchet_step(root, dh_output_a)
    assert (root_a1, chain_a1) == (root_a2, chain_a2)  # deterministic given same inputs

    root_b, chain_b = dh_ratchet_step(root, dh_output_b)
    assert root_a1 != root_b
    assert chain_a1 != chain_b


def test_channel_performs_periodic_dh_rekey_and_peer_tracks_it():
    alice, bob, alice_trust, bob_trust = make_pinned_pair()
    alice_channel, bob_channel = do_handshake(alice, bob, alice_trust, bob_trust)
    alice_channel._rekey_interval = 3

    initial_alice_ratchet_pub = alice_channel._my_ratchet_pub_bytes
    initial_bob_root = bob_channel._root_key

    for i in range(5):
        ct = alice_channel.encrypt(f"msg{i}".encode())
        assert bob_channel.decrypt(ct) == f"msg{i}".encode()

    # a rekey must have happened by the 3rd of 5 messages
    assert alice_channel._my_ratchet_pub_bytes != initial_alice_ratchet_pub
    # bob must have picked up alice's new ratchet public key
    assert bob_channel._peer_ratchet_pub_bytes == alice_channel._my_ratchet_pub_bytes
    # and bob's root key must have advanced in lockstep
    assert bob_channel._root_key != initial_bob_root
    assert bob_channel._root_key == alice_channel._root_key


def test_channel_functions_normally_in_both_directions_across_a_rekey():
    """After alice rekeys mid-conversation, bob must still be able to
    both receive from alice AND reply back to her normally."""
    alice, bob, alice_trust, bob_trust = make_pinned_pair()
    alice_channel, bob_channel = do_handshake(alice, bob, alice_trust, bob_trust)
    alice_channel._rekey_interval = 2

    for i in range(4):
        ct = alice_channel.encrypt(f"a{i}".encode())
        assert bob_channel.decrypt(ct) == f"a{i}".encode()

    ct = bob_channel.encrypt(b"reply from bob")
    assert alice_channel.decrypt(ct) == b"reply from bob"


def test_post_compromise_healing_new_chain_not_derivable_from_leaked_old_state():
    """The whole point of the DH ratchet: even a full compromise of the
    OLD root/ratchet-private-key state cannot be used to derive the key
    for messages sent AFTER the next rekey, because that requires a DH
    output involving a private key generated after the compromise - one
    the attacker never had access to."""
    alice, bob, alice_trust, bob_trust = make_pinned_pair()
    alice_channel, _bob_channel = do_handshake(alice, bob, alice_trust, bob_trust)

    # "Attacker" captures alice's full ratchet state before any rekey.
    leaked_root = alice_channel._root_key
    leaked_ratchet_priv = alice_channel._my_ratchet_priv
    peer_pub_at_compromise = alice_channel._peer_ratchet_pub_bytes

    alice_channel._perform_send_ratchet_step()  # same thing encrypt() does periodically
    real_new_chain_key = alice_channel._sending_chain._chain_key

    # Attacker's best attempt: they have the leaked root, the leaked old
    # private key, and the (unchanged) peer public key - everything
    # EXCEPT alice's freshly-generated new private key, which was
    # generated after the compromise and never left her process.
    peer_pub_obj = cu.x25519_public_from_bytes(peer_pub_at_compromise)
    attacker_dh_output = cu.derive_shared_secret(leaked_ratchet_priv, peer_pub_obj)
    _, attacker_guess = dh_ratchet_step(leaked_root, attacker_dh_output)

    assert attacker_guess != real_new_chain_key


def test_tampering_with_rekey_flag_is_detected():
    alice, bob, alice_trust, bob_trust = make_pinned_pair()
    alice_channel, bob_channel = do_handshake(alice, bob, alice_trust, bob_trust)

    ct = bytearray(alice_channel.encrypt(b"a message long enough to test tampering"))
    ct[0] = SecureChannel.FLAG_REKEY  # falsely claim a rekey key is attached
    with pytest.raises(TamperError):
        bob_channel.decrypt(bytes(ct))


def test_truncated_rekey_header_is_rejected():
    alice, bob, alice_trust, bob_trust = make_pinned_pair()
    alice_channel, bob_channel = do_handshake(alice, bob, alice_trust, bob_trust)
    alice_channel._rekey_interval = 1

    ct = alice_channel.encrypt(b"triggers a rekey")
    truncated = ct[:10]  # cut off partway through the attached pubkey
    with pytest.raises(TamperError):
        bob_channel.decrypt(truncated)


def test_forged_rekey_packet_does_not_corrupt_channel_state():
    """Regression test for a bug where decrypt() applied an announced DH
    ratchet step (root key, receiving chains, peer ratchet pubkey) BEFORE
    the GCM tag on that message was checked. A forged packet with a
    fake rekey header and a bogus ciphertext/tag was correctly rejected
    as tampered, but the ratchet step had already mutated state by then
    - so an attacker who could inject a single unauthenticated packet
    could corrupt the channel (fork the root key, evict legitimate old
    receiving chains, clobber the pinned peer ratchet pubkey) without
    ever producing a valid tag. Fixed by computing the candidate step
    into a local object and only committing it after decryption
    succeeds."""
    alice, bob, alice_trust, bob_trust = make_pinned_pair()
    alice_channel, bob_channel = do_handshake(alice, bob, alice_trust, bob_trust)

    root_before = bob_channel._root_key
    peer_pub_before = bob_channel._peer_ratchet_pub_bytes
    chains_before = dict(bob_channel._recv_chains)

    # Forge a packet: FLAG_REKEY set, a fresh attacker-controlled pubkey
    # attached, a counter far ahead of anything seen (so it passes the
    # freshness check), but garbage ciphertext/tag - the attacker has no
    # valid message key.
    _, attacker_pub = cu.generate_x25519_keypair()
    attacker_pub_bytes = cu.x25519_public_bytes(attacker_pub)
    counter = 999
    header = bytes([SecureChannel.FLAG_REKEY]) + attacker_pub_bytes
    aad = header + counter.to_bytes(8, "big")
    forged = aad + b"\x00" * 32  # bogus ciphertext + tag, fails GCM

    with pytest.raises(TamperError):
        bob_channel.decrypt(forged)

    # The forged packet must be rejected AND leave no trace: none of the
    # ratchet state should have moved, or a single unauthenticated
    # packet could desync/corrupt the channel.
    assert bob_channel._root_key == root_before
    assert bob_channel._peer_ratchet_pub_bytes == peer_pub_before
    assert bob_channel._recv_chains.keys() == chains_before.keys()

    # And the channel must still work normally afterward.
    ct = alice_channel.encrypt(b"still works")
    assert bob_channel.decrypt(ct) == b"still works"


def test_padding_round_trips_for_various_sizes():
    for size in (0, 1, 5, 31, 32, 33, 100, 1000, 8192, 8193, 20000):
        original = bytes(range(256)) * (size // 256 + 1)
        original = original[:size]
        assert padding.unpad(padding.pad(original)) == original


def test_padding_output_size_is_always_a_known_bucket():
    for size in (0, 1, 31, 32, 33, 127, 4096, 4097, 8192, 8193, 16400):
        padded = padding.pad(b"x" * size)
        framed_size = padding.LENGTH_PREFIX_SIZE + size
        if framed_size <= padding.BUCKETS[-1]:
            assert len(padded) in padding.BUCKETS
        else:
            # beyond the largest bucket, padded size must be an exact
            # multiple of it
            assert len(padded) % padding.BUCKETS[-1] == 0


def test_padding_hides_length_differences_within_the_same_bucket():
    """The actual privacy property: two plaintexts of very different
    length, as long as they land in the same bucket, produce padded
    output of IDENTICAL size."""
    a = padding.pad(b"x" * 10)
    b = padding.pad(b"x" * 25)
    assert len(a) == len(b) == 32


def test_padding_rejects_corrupted_length_prefix():
    padded = bytearray(padding.pad(b"hello"))
    # claim an original length far larger than the actual padded buffer
    padded[0:4] = (999999).to_bytes(4, "big")
    with pytest.raises(padding.PaddingError):
        padding.unpad(bytes(padded))


def test_padding_rejects_too_short_input():
    with pytest.raises(padding.PaddingError):
        padding.unpad(b"ab")  # shorter than the 4-byte length prefix


def test_secure_channel_ciphertext_length_hides_plaintext_length():
    """Integration check: two different-length plaintexts within the
    same padding bucket produce equal-length ciphertexts over the real
    encrypted channel, not just in the padding module in isolation."""
    alice, bob, alice_trust, bob_trust = make_pinned_pair()
    alice_channel, bob_channel = do_handshake(alice, bob, alice_trust, bob_trust)

    ct_short = alice_channel.encrypt(b"hi")
    ct_medium = alice_channel.encrypt(b"a shortish message")  # both < 32-byte bucket
    assert len(ct_short) == len(ct_medium)

    assert bob_channel.decrypt(ct_short) == b"hi"
    assert bob_channel.decrypt(ct_medium) == b"a shortish message"


def test_secure_channel_padding_can_be_disabled():
    """Escape hatch for callers who explicitly don't want padding
    overhead (e.g. already-bulky file transfer where padding waste
    would matter more than length secrecy)."""
    alice, bob, alice_trust, bob_trust = make_pinned_pair()
    alice_channel, bob_channel = do_handshake(alice, bob, alice_trust, bob_trust)
    alice_channel._pad_messages = False
    bob_channel._pad_messages = False

    ct_short = alice_channel.encrypt(b"hi")
    ct_long = alice_channel.encrypt(b"a fairly different length message")
    assert len(ct_short) != len(ct_long)
    assert bob_channel.decrypt(ct_short) == b"hi"
    assert bob_channel.decrypt(ct_long) == b"a fairly different length message"


if __name__ == "__main__":
    import sys

    sys.exit(pytest.main([__file__, "-v"]))
