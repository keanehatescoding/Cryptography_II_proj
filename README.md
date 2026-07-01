# Secure Communication System

A from-scratch demonstration of an authenticated key exchange + encrypted
channel protocol, combining the three pillars of secure communication:

| Pillar         | Primitive                                        | Purpose                                    |
| -------------- | ------------------------------------------------ | ------------------------------------------ |
| Key exchange   | X25519 (ECDH), fresh per session                 | Establish a shared secret; forward secrecy |
| Authentication | Ed25519 signatures over the handshake transcript | Prevent man-in-the-middle impersonation    |
| Encryption     | AES-256-GCM with HKDF-derived directional keys   | Confidentiality + tamper detection (AEAD)  |
| Key protection | Passphrase-encrypted identity keys at rest       | Long-term keys aren't plaintext on disk    |
| Replay defense | Sliding-window counter bitmap                    | Tolerates reordering, rejects true replays |
| Availability   | Per-address rate limiting on handshake attempts  | Throttles brute-force / CPU-exhaustion DoS |

It is modeled loosely on the handshake patterns used by real protocols
like Signal and Noise, simplified for clarity.

## Why this design

A secure channel needs all three properties working together — key
exchange alone is vulnerable to MITM, authentication alone doesn't give
you confidentiality, and encryption alone (without integrity) can be
silently tampered with. This project wires them together correctly and
demonstrates _why_ each piece matters with concrete attack tests.

**Forward secrecy**: identity keys (Ed25519) are long-term and only ever
used to _sign_, never to encrypt. The actual encryption keys are derived
from fresh, ephemeral X25519 keypairs generated new for every handshake.
If a long-term identity key leaks later, past session traffic still
cannot be decrypted.

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

**Anti-replay / anti-tamper**: each direction has an independent AES-GCM
key and a strictly-increasing message counter used as both nonce and
authenticated associated data (AAD). Replayed, reordered, or bit-flipped
messages are all rejected — proven by automated tests.

**Anti-replay / anti-tamper**: each direction has an independent AES-GCM
key and a message counter used as both nonce and authenticated
associated data (AAD). The receiver uses a sliding-window bitmap (the
same approach IPsec/DTLS use): any counter within the last 1024 slots
that hasn't been seen before is accepted, even out of order, but a true
duplicate or a counter older than the window is rejected. This tolerates
ordinary network reordering without weakening replay protection.

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
secure_channel.py      Encrypted channel w/ sliding-window replay protection
rate_limiter.py        Per-address handshake attempt throttling
transport.py           TCP length-prefixed message framing (plumbing only)
server.py / client.py  Runnable two-party encrypted chat demo (terminal)
gui.py                 Tkinter GUI - either side (Host or Connect) in one app
test_secure_comms.py   Automated tests incl. tampering/replay/impersonation attacks
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
- Not hardened for production: no session re-keying / ratcheting (the
  session key is fixed for the whole conversation, unlike Signal's
  Double Ratchet), no protection against traffic analysis, and the rate
  limiter is in-memory/per-process so it resets on restart and doesn't
  help if an attacker can rotate source addresses.
- No reconnect/resumption - a dropped TCP connection ends the session
  and requires a fresh handshake.
- Encrypting the identity key at rest protects against a stolen disk,
  not against malware running as the same user while the app is open.
