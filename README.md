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

**Post-compromise healing (across epochs)**: a party generates a
brand-new X25519 keypair, performs a fresh Diffie-Hellman exchange with
the peer's most recent ratchet public key, and mixes the result into the
root key to start a new epoch with a new chain key (`ratchet.py:
dh_ratchet_step`). Because that new private key didn't exist yet at the
time of any earlier compromise, an attacker who captured the _old_ state
cannot derive keys for the _new_ epoch - even full knowledge of the old
root key and old ratchet private key isn't enough (proven in
`test_post_compromise_healing_new_chain_not_derivable_from_leaked_old_state`).
This closes the gap the symmetric ratchet alone leaves open: forward
secrecy protects the past, the DH ratchet protects the future.

This DH step fires _reactively_ - the same trigger Signal's Double
Ratchet uses in steady state: the moment a party accepts a message
announcing a new peer ratchet pubkey, its own next send ratchets in
reply, using that same pubkey. In an active back-and-forth conversation
this heals on _every round trip_, tighter than any fixed schedule. The
one real difference from Signal is the bootstrap: their X3DH handshake
leaves the initiator with no sending chain at all, forcing a reactive
ratchet on message 1 by necessity, whereas this system's handshake hands
both sides a full, symmetric send+receive chain pair up front (see
"Forward secrecy (within an epoch)" above) - so epoch 0 needs no ratchet
from either side, and a `REKEY_INTERVAL`-messages/`REKEY_INTERVAL_SECONDS`
fallback (in the spirit of how WireGuard rekeys) is what both kicks the
reactive chain off in the first place _and_ covers a one-sided
conversation that never gets a reply to react to - vanilla Double
Ratchet has no such fallback and shares that same one-sided gap. See
`secure_channel.py`'s module docstring for the full reasoning.

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
history.py              Opt-in, passphrase-encrypted local chat history (GUI only)
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
python3 -m pytest -v
```

`test_secure_comms.py` covers the crypto/protocol modules, including
`history.py` (encryption roundtrip, wrong-passphrase/corrupted-file
rejection, per-peer filtering, and that the file on disk never contains
plaintext). `test_gui_file_transfer.py` and
`test_gui_peerworker_integration.py` cover `gui.py`'s file-transfer
framing and its reconnect-with-backoff loop - the latter drives two real
`PeerWorker`s over real loopback TCP sockets (no Tk widgets involved)
through a handshake, a multi-chunk file transfer, a simulated dropped
connection to confirm both sides reconnect and resume chatting, and a
simulated app restart to confirm chat history survives and replays for
the right peer.

None of this needs an actual Tk display: `PeerWorker` has no Tk
dependency (it only ever talks to its consumer through a queue.Queue of
event dicts), so these tests exercise the real networking/threading/
crypto logic - including the `session_id` tagging multi-peer tabs rely
on - directly, which is also why CI (no virtual display available) can
run them. The `SecureCommsApp` Tk widget layer itself (tabs, per-session
widgets, unread badges, ...) is verified with manual smoke tests driving
real `SecureCommsApp` instances under Xvfb, not part of the automated
suite.

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

8 more cover the DH ratchet: deterministic root-key mixing, a real
periodic (count-triggered) rekey with the peer correctly tracking the
new epoch, normal bidirectional messaging across a rekey boundary,
header tampering detection, a truncated-header rejection, the reactive
trigger firing on the very next send after accepting a peer's rekey
announcement (well before the count/time fallback would have),
a full back-and-forth conversation healing on every round trip once
seeded, and - the key property -
`test_post_compromise_healing_new_chain_not_derivable_from_leaked_old_state`,
which mathematically demonstrates that even a full leak of the old root
key and old ratchet private key cannot reproduce the new epoch's chain
key.

34 tests in total.

6 more cover padding: round-tripping across a wide range of sizes,
output always landing on a known bucket boundary (or exact multiple of
the largest bucket beyond it), the actual privacy property (very
different plaintext lengths within the same bucket producing identical
padded/ciphertext size - checked both in the padding module directly
and through a real SecureChannel), corrupted-length-prefix rejection,
too-short-input rejection, and the opt-out path for callers who disable
padding. 40 tests in total.

5 more cover the TOFU trust-prompt flow shared by client.py and
server.py (`TrustStore.verify_and_pin_interactive`): declining
confirmation on first contact leaves the peer unpinned, confirming pins
it and shows the peer's actual fingerprint (not a placeholder), and an
already-pinned name presenting a different key is rejected outright
without ever prompting - distinguished from a plain decline so callers
can rate-limit it separately. Plus a regression test for a fixed bug
where a forged rekey packet with an invalid GCM tag could still
corrupt receiving-side ratchet state (root key, receiving chains,
pinned peer pubkey) before the forgery was caught - decrypt() now
computes a candidate ratchet step and only commits it after
authentication succeeds. 45 tests in total.

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

On first contact with a new peer, you'll see their identity fingerprint
printed and be asked to confirm - out-of-band, e.g. read aloud on a call
- that it matches before it's pinned (same SSH-style TOFU flow the GUI
uses; see below). Declining aborts the connection without pinning
anything.

## Running the GUI

Requires Python 3.10+ (the codebase uses `X | None` union type hints
throughout, evaluated at function-definition time) and `tkinter`
(usually bundled with Python; on Debian/Ubuntu:
`sudo apt-get install python3-tk`). CI runs on 3.11 and 3.12. Same
directory, two windows:

```bash
python3 gui.py   # window 1: enter name "bob",   click "Host (wait for peer)"
python3 gui.py   # window 2: enter name "alice",  click "Connect to peer"
```

A window's "New Connection" tab shows your identity fingerprint at the
top - the same one you'd read aloud to a peer over the phone to verify
you're really talking to them before trusting a new identity (SSH-style
TOFU). Alongside the hex form, the GUI also renders it as a phrase of
adjective-noun pairs (e.g. `brave-falcon calm-opal ...`, one pair per
byte) - reading words aloud over a call is far less error-prone than
reading hex nibbles one at a time, the same problem Signal's word-based
safety numbers and the classic PGP word list solve. It's a pure display
encoding of the same fingerprint (see `gui.py`'s `_fingerprint_to_words`);
the hex form remains the identity's real form everywhere else (TrustStore,
CLI, audit log). When two identities connect for the first time, you'll
get a "Verify new identity" prompt showing the peer's fingerprint in both
forms; accepting pins it for future sessions. All the cryptography is
identical to the terminal demo - `gui.py` only adds a UI on top of the
same modules.

**Multiple concurrent sessions**: each new session's first successful
handshake opens its own tab and frees the "New Connection" tab for the
next attempt, so one window can Host for one peer and Connect out to
several others at once, each chatting, transferring files, and replaying
its own history completely independently. A *reconnect's* handshake
reuses that same tab rather than opening a duplicate one - see
`_ensure_session_tab`, which is a no-op once a session already has a tab.
A dropped connection or a security alert only affects its own tab. A tab that isn't the one currently
selected gets an unread-count badge on its label when a message arrives
(even if the window itself is focused - you might just be looking at a
different tab); the OS-level popup and window-title badge are reserved
for when the whole window has lost focus, so switching tabs within a
focused window doesn't also spam a desktop notification. Every
`PeerWorker` tags its events with a `session_id` so the shared events
queue can be routed to the right tab (or, before a connection's first
handshake completes, to the "New Connection" tab's own status/fingerprint
display - only one connection attempt can be *pending* at a time, though
any number of already-established ones can run concurrently).

The optional **Passphrase** field encrypts a newly-created identity key,
or unlocks an existing encrypted one - leave it blank for a brand-new
unencrypted identity. A wrong passphrase surfaces as a plain error
dialog rather than crashing the app.

**File transfer**: the "Send File…" button sends any local file through
the same encrypted channel as chat messages. Large files are split into
256 KiB plaintext chunks (each independently ratchet-encrypted, so the
usual forward-secrecy/authentication properties apply per chunk); a
SHA-256 of the whole file is sent up front and checked against the
reassembled file on completion, and a mismatch discards the partial file
with a security alert instead of silently saving corrupted data.
Received files are saved under `./received_files/`, deduplicated by
appending `(1)`, `(2)`, ... on a name collision. There's a 200 MiB cap
per file for this demo app, and a progress bar tracks the active
transfer in either direction.

**Automatic reconnect**: a dropped TCP connection no longer ends the
session outright. The initiating ("Connect") side keeps redialing the
peer with exponential backoff (1s, 2s, 4s, ... capped at 30s); the
listening ("Host") side goes back to accepting new connections on the
same socket. Either way, reconnecting performs a brand-new 3-message
handshake - there is no session resumption, so a reconnect starts a
fresh ratchet chain exactly like manually restarting would. A "Send" /
"Send File" input is disabled while disconnected and re-enabled once the
new handshake completes; a "Disconnect" button in the chat view stops
the retry loop and returns to the connect screen.

**Chat history** (`history.py`) is opt-in and off by default - check
"Save chat history to disk" before connecting. It's only available for a
passphrase-protected identity: forward secrecy protects past *on-the-wire*
traffic from a leaked session key, but says nothing about a copy of the
decrypted plaintext the app writes to disk afterward, and there's no
honest way to encrypt that copy without a secret to derive a key from -
an unencrypted log, or a key sitting next to its own ciphertext, isn't
real protection. With history on, each local identity's log
(`./gui_keys/{name}_history.enc`) is AES-256-GCM-encrypted with a key
derived from the passphrase via scrypt (deliberately slow/memory-hard,
unlike the HKDF used for the handshake's high-entropy session keys - a
human passphrase needs a KDF that resists brute-forcing, not just
whitening), and every append is written via a temp-file-then-rename so a
crash mid-save can't corrupt history that was already durable. On
reconnecting to a peer you've talked to before, the prior conversation is
replayed into the chat window before the new session's messages. File
transfers aren't recorded, only text messages.

## What this is _not_

- Not a full PKI (see: mini-CA + certificate validation as a separate
  project idea) — no certificate chains, no revocation.
- Not hardened for production: rekeying is reactive (see
  `secure_channel.py` for how and why) with a message-count/time
  fallback for one-sided traffic, so a compromise mid-conversation heals
  on the next reply rather than waiting for a fixed schedule - but a
  compromise during a one-sided monologue, or right before the fallback
  fires, still has a window of up to `REKEY_INTERVAL` messages or
  `REKEY_INTERVAL_SECONDS` before that heals it; shortening either trades
  performance for a smaller worst-case window. Padding hides individual message
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
- No session resumption - the GUI's automatic reconnect (see "Running
  the GUI" above) retries the underlying TCP connection, but each
  successful reconnect still performs a brand-new 3-message handshake
  and starts an entirely new, uncompromised ratchet chain rather than
  resuming the old one. Any file transfer in flight when the connection
  drops is abandoned, not resumed. `server.py`/`client.py` (the terminal
  demo) don't reconnect at all - a dropped connection there still ends
  the session outright.
- Encrypting the identity key at rest protects against a stolen disk,
  not against malware running as the same user while the app is open.
