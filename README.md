# Secure Communication System

A from-scratch demonstration of an authenticated key exchange + encrypted
channel protocol, combining the three pillars of secure communication:

| Pillar                      | Primitive                                                   | Purpose                                                                   |
| --------------------------- | ----------------------------------------------------------- | ------------------------------------------------------------------------- |
| Key exchange                | X25519 (ECDH), fresh per session                            | Establish a shared secret; forward secrecy                                |
| Authentication              | Ed25519 signatures over the handshake transcript            | Prevent man-in-the-middle impersonation                                   |
| Encryption                  | AES-256-GCM with HKDF-derived directional keys              | Confidentiality + tamper detection (AEAD)                                 |
| Forward secrecy (in-epoch)  | HMAC-based symmetric ratchet, one key per message           | A compromised key only exposes current/future messages, not past ones     |
| Post-compromise healing     | Periodic DH ratchet (fresh X25519 keypair every N messages) | A compromised state stops mattering once the next rekey happens           |
| Traffic analysis resistance | Fixed-size padding buckets before encryption                | Ciphertext length reveals only a size range, not the exact message length |
| Key protection              | Passphrase-encrypted identity keys at rest                  | Long-term keys aren't plaintext on disk                                   |
| Replay defense              | Sliding-window counter bitmap                               | Tolerates reordering, rejects true replays                                |
| Availability                | Per-address rate limiting on handshake attempts             | Throttles brute-force / CPU-exhaustion DoS                                |

It is modeled loosely on the handshake patterns used by real protocols
like Signal and Noise, simplified for clarity.

## Why this design

A secure channel needs all three properties working together — key
exchange alone is vulnerable to MITM, authentication alone doesn't give
you confidentiality, and encryption alone (without integrity) can be
silently tampered with. This project wires them together correctly and
demonstrates _why_ each piece matters with concrete attack tests.

**Forward secrecy (between sessions)**: identity keys (Ed25519) are
long-term and only ever used to _sign_, never to encrypt. The actual
encryption keys are derived from fresh, ephemeral X25519 keypairs
generated new for every handshake. If a long-term identity key leaks
later, past sessions still cannot be decrypted.

**Forward secrecy (within an epoch)**: each direction's chain key is fed
into a symmetric ratchet (`ratchet.py`) that derives a fresh AES-256-GCM
key per message via HMAC-SHA256 chain-stepping, the same technique used
in the "chain key" half of Signal's Double Ratchet. Because each step is
one-way, capturing the ratchet's current state - a memory dump, a
debugger attached mid-session - exposes only the current and future
messages, not earlier ones in the same epoch.

**Post-compromise healing (across epochs)**: every `REKEY_INTERVAL`
messages (20 by default), a party generates a brand-new X25519 keypair,
performs a fresh Diffie-Hellman exchange with the peer's most recent
ratchet public key, and mixes the result into the root key to start a
new epoch with a new chain key (`ratchet.py: dh_ratchet_step`). Because
that new private key didn't exist yet at the time of any earlier
compromise, an attacker who captured the _old_ state cannot derive keys
for the _new_ epoch - even full knowledge of the old root key and old
ratchet private key isn't enough (proven in
`test_post_compromise_healing_new_chain_not_derivable_from_leaked_old_state`).
This closes the gap the symmetric ratchet alone leaves open: forward
secrecy protects the past, the DH ratchet protects the future.

Signal's Double Ratchet triggers this DH step _reactively_, on the first
message of a new "sending turn" - that works because their X3DH
handshake leaves the initiator with no sending chain at first, giving a
natural trigger. Our handshake derives both directions' chains
symmetrically, so that trigger doesn't exist here; the DH ratchet fires
_periodically_ by message count instead (similar in spirit to how
WireGuard rekeys on a message-count/time basis). Both approaches deliver
the same healing property, just on a different schedule - see
`ratchet.py` for the full reasoning.

**Traffic analysis resistance**: `padding.py` pads every plaintext up to
the smallest of a fixed set of size buckets (32, 64, 128, ... 8192
bytes, then multiples of 8192 beyond that) before encryption. AES-GCM,
like any AEAD, does not hide plaintext length on its own - ciphertext
length is always plaintext length plus a fixed tag - so without this,
an eavesdropper who can't read message contents could still often infer
a lot from lengths alone (e.g. telling a short "yes" apart from a longer
reply). Padding is on by default and can be disabled per-channel for
callers who'd rather avoid the overhead (e.g. bulk file transfer, where
padding waste matters more than length secrecy). This hides individual
message _length_ only - not how many messages are sent or their timing;
a complete traffic-analysis defense would need cover traffic too.

**MITM resistance**: both parties sign a transcript that includes _both_
ephemeral public keys, not just their own. This binds the signature to
one specific exchange — an attacker can't splice signatures from separate
handshakes together to impersonate either side.

**Trust model**: this is TOFU (Trust-On-First-Use) / key-pinning, like SSH
host keys — not a certificate authority. Identities are pinned by name on
first contact and verified on every subsequent handshake. A full CA/PKI
chain-of-trust is a different, larger project; the `Identity.fingerprint`
property exists here so pins could be verified out-of-band (e.g., read
aloud on a call) exactly like Signal safety numbers.

**Anti-replay / anti-tamper**: each direction has an independent counter
used as both nonce and authenticated associated data (AAD) for that
message's ratchet-derived key - along with the epoch's rekey flag/pubkey
when one is attached, so tampering with whether a rekey announcement is
present is caught by GCM authentication too. The receiver uses a
sliding-window bitmap (the same approach IPsec/DTLS use): any counter
within the last 1024 slots that hasn't been seen before is accepted, even
out of order, but a true duplicate or a counter older than the window is
rejected. The ratchet's own skipped-key cache (bounded, to prevent a
large-counter-jump DoS) is what makes deriving the correct key for a
reordered message possible in the first place.

**Key protection at rest**: long-term Ed25519 identity keys can be saved
with a passphrase (PKCS8 password-based encryption). Losing an unencrypted
identity key file means an attacker can impersonate you in every future
handshake with anyone who's pinned your fingerprint - encrypting it at
rest means a stolen laptop/disk isn't automatically a stolen identity.

**Handshake rate limiting**: a per-IP rate limiter (`rate_limiter.py`)
throttles repeated failed handshake attempts (5 failures/minute -> 30s
cooldown, by default). This defends against a different failure mode
than the cryptography does: even a correctly-implemented protocol still
costs CPU (ECDH + signature verification) per attempt, so unlimited
retries are a DoS vector regardless of whether the crypto itself holds up.
`server.py` and the GUI's "Host" mode both loop on the listening socket
so a legitimate peer isn't blocked out just because someone else's failed
attempts came first.

## Files

```
crypto_utils.py       Low-level primitives: X25519, Ed25519, HKDF, AES-GCM
identity.py            Long-term identity keys + TrustStore (TOFU pinning)
                        Supports passphrase-encrypted keys at rest
handshake.py           The 3-message authenticated key exchange protocol
ratchet.py              Symmetric per-message ratchet + periodic DH ratchet (healing)
padding.py              Fixed-bucket plaintext padding (hides message length)
secure_channel.py      Encrypted channel: ratchets + padding + sliding-window replay
rate_limiter.py        Per-address handshake attempt throttling
transport.py           TCP length-prefixed message framing (plumbing only)
server.py / client.py  Runnable two-party encrypted chat demo (terminal)
gui.py                 Tkinter GUI - either side (Host or Connect) in one app
test_secure_comms.py   Automated tests incl. tampering/replay/impersonation/ratchet
```

`gui.py` is a presentation layer only - it imports the exact same crypto
and networking modules as the terminal demo, so the security properties
are identical either way.

## Running the tests

```bash
pip install cryptography pytest
python3 -m pytest test_secure_comms.py -v
```

19 tests cover: successful handshake, bidirectional messaging, tampered
ciphertext rejection, replay rejection, sliding-window reordering
tolerance, replay-of-a-reordered-message rejection, out-of-window
rejection, forged signature rejection (impersonation), unpinned-identity
rejection, forward secrecy (fresh keys per session), encrypted-identity
save/load round-tripping, wrong/missing passphrase rejection, and rate
limiter blocking/cooldown/window-expiry/per-address isolation.

7 further tests cover the symmetric ratchet: sequential key derivation,
out-of-order delivery via the skipped-key cache, rejection of a counter
reused after its key was already consumed, the MAX_SKIP DoS bound, and
an end-to-end SecureChannel integration check.

6 more cover the DH ratchet: deterministic root-key mixing, a real
periodic rekey with the peer correctly tracking the new epoch, normal
bidirectional messaging across a rekey boundary, header tampering
detection, a truncated-header rejection, and - the key property -
`test_post_compromise_healing_new_chain_not_derivable_from_leaked_old_state`,
which mathematically demonstrates that even a full leak of the old root
key and old ratchet private key cannot reproduce the new epoch's chain
key.

32 tests in total.

6 more cover padding: round-tripping across a wide range of sizes,
output always landing on a known bucket boundary (or exact multiple of
the largest bucket beyond it), the actual privacy property (very
different plaintext lengths within the same bucket producing identical
padded/ciphertext size - checked both in the padding module directly
and through a real SecureChannel), corrupted-length-prefix rejection,
too-short-input rejection, and the opt-out path for callers who disable
padding. 39 tests in total.

## Running the live demo

Two terminals, same directory:

```bash
# terminal 1
python3 server.py

# terminal 2
python3 client.py
```

Type messages back and forth; each is authenticated, encrypted, and
integrity-checked in transit. Type `/quit` to end the session. Identity
keys and pinned trust stores persist under `./demo_keys/` between runs.
On first run each side is asked whether to encrypt its identity key with
a passphrase (recommended); on later runs you'll be prompted for it. The
server keeps listening and accepts new peers after a session ends, and
throttles an address that fails the handshake repeatedly.

## Running the GUI

Requires `tkinter` (usually bundled with Python; on Debian/Ubuntu:
`sudo apt-get install python3-tk`). Same directory, two windows:

```bash
python3 gui.py   # window 1: enter name "bob",   click "Host (wait for peer)"
python3 gui.py   # window 2: enter name "alice",  click "Connect to peer"
```

Each window shows your identity fingerprint at the top - the same one
you'd read aloud to a peer over the phone to verify you're really talking
to them before trusting a new identity (SSH-style TOFU). When two
identities connect for the first time, you'll get a "Verify new identity"
prompt showing the peer's fingerprint; accepting pins it for future
sessions. After the handshake completes, the window switches to an
encrypted chat view. All the cryptography is identical to the terminal
demo - `gui.py` only adds a UI on top of the same modules.

The optional **Passphrase** field encrypts a newly-created identity key,
or unlocks an existing encrypted one - leave it blank for a brand-new
unencrypted identity. A wrong passphrase surfaces as a plain error
dialog rather than crashing the app.

## What this is _not_

- Not a full PKI (see: mini-CA + certificate validation as a separate
  project idea) — no certificate chains, no revocation.
- Not hardened for production: rekeying is on a fixed message-count
  schedule rather than Signal's per-turn reactive trigger (see
  `ratchet.py` for why), which means an attacker who compromises state
  right after a rekey still has a window of up to `REKEY_INTERVAL`
  messages before the next one heals it - shortening the interval trades
  performance for a smaller window. Padding hides individual message
  length but not the number of messages sent or their timing - a
  determined observer can still build a traffic profile from _when_ and
  _how often_ messages flow, even with every message the same size. The
  rate limiter is also in-memory/per-process, so it resets on restart
  and doesn't help if an attacker can rotate source addresses.
- Only the last few epochs' receiving chains are retained
  (`MAX_RETAINED_CHAINS`), so a message delayed across more than a
  couple of rekey boundaries will fail to decrypt with a clear error
  rather than silently succeeding - a deliberate bounded-memory
  trade-off, not a bug.
- No reconnect/resumption - a dropped TCP connection ends the session
  and requires a fresh handshake (which does start an entirely new,
  uncompromised ratchet chain, since it derives from a new ephemeral
  X25519 exchange).
- Encrypting the identity key at rest protects against a stolen disk,
  not against malware running as the same user while the app is open.
