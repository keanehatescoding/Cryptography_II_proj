# Secure Communication System

A from-scratch demonstration of an authenticated key exchange + encrypted
channel protocol, combining the three pillars of secure communication:

| Pillar         | Primitive                                        | Purpose                                    |
| -------------- | ------------------------------------------------ | ------------------------------------------ |
| Key exchange   | X25519 (ECDH), fresh per session                 | Establish a shared secret; forward secrecy |
| Authentication | Ed25519 signatures over the handshake transcript | Prevent man-in-the-middle impersonation    |
| Encryption     | AES-256-GCM with HKDF-derived directional keys   | Confidentiality + tamper detection (AEAD)  |

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

## Files

```
crypto_utils.py       Low-level primitives: X25519, Ed25519, HKDF, AES-GCM
identity.py            Long-term identity keys + TrustStore (TOFU pinning)
handshake.py           The 3-message authenticated key exchange protocol
secure_channel.py      Post-handshake encrypted channel w/ replay protection
transport.py           TCP length-prefixed message framing (plumbing only)
server.py / client.py  Runnable two-party encrypted chat demo
test_secure_comms.py   Automated tests incl. tampering/replay/impersonation attacks
```

## Running the tests

```bash
pip install cryptography pytest
python3 -m pytest test_secure_comms.py -v
```

8 tests cover: successful handshake, bidirectional messaging, tampered
ciphertext rejection, replay rejection, reordering rejection, forged
signature rejection (impersonation), unpinned-identity rejection, and
forward secrecy (fresh keys per session).

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

## What this is _not_

- Not a full PKI (see: mini-CA + certificate validation as a separate
  project idea) — no certificate chains, no revocation.
- Not hardened for production: private keys are stored unencrypted on
  disk for demo simplicity, and there's no rate limiting, session
  timeout/rekeying, or resistance to traffic analysis.
- The replay filter is strict-ordering, which assumes a reliable
  in-order transport (TCP). A UDP-based version would need a sliding
  replay window instead.
