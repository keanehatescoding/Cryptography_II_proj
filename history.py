"""
history.py
-----------
Optional, opt-in, passphrase-encrypted local chat history for the GUI.

Forward secrecy (ratchet.py, secure_channel.py) guarantees that a leaked
session key can't decrypt past on-the-wire traffic. It says nothing about
a copy of the decrypted PLAINTEXT the application deliberately writes to
disk afterward - that copy is a second, independent target that no amount
of ratchet design protects. So this is opt-in, off by default, and only
available when the local identity has a passphrase: that's the one secret
the user already holds, and there is no honest way to "encrypt" the log
without one - a key stored unencrypted next to its ciphertext isn't real
protection, just a checkbox. With no passphrase, the GUI disables the
feature outright rather than pretending otherwise.

File format (one per local identity, ./gui_keys/{name}_history.enc):
    [16-byte scrypt salt][12-byte AES-GCM nonce][ciphertext+tag]
The ciphertext is a JSON array of {ts, peer, direction, text} entries
covering every peer this identity has ever chatted with (one file, not
split per peer, since it's one person's history). AAD binds the
ciphertext to the identity name, so a history file can't be silently
swapped between two local identities' key directories without the swap
being detected on load.

The scrypt derivation runs once, when the file is opened - not on every
append - so a chat session doesn't pay scrypt's deliberately-slow cost
per message. Every append rewrites the whole file (fresh nonce, cached
key) via a temp-file-then-atomic-rename, rather than an in-place partial
write, so a crash mid-save can't corrupt history that was already durable
before that append. File transfers are not recorded here, only text
messages - see gui.py.
"""

import json
import os
import threading
import time
from pathlib import Path

import crypto_utils as cu

SALT_SIZE = 16
NONCE_SIZE = 12


class HistoryUnavailable(Exception):
    """Raised when history persistence is requested for an identity with
    no passphrase - there is no secret to derive an encryption key from."""


class EncryptedHistory:
    def __init__(self, path: Path, identity_name: str, key: bytes, salt: bytes, entries=None):
        self._path = path
        self._identity_name = identity_name
        self._key = key
        self._salt = salt
        self._entries = entries if entries is not None else []
        self._lock = threading.Lock()

    @classmethod
    def load(cls, name: str, directory: str, passphrase: str) -> "EncryptedHistory":
        """Loads and decrypts existing history for `name`, or starts a
        fresh (empty) history if no file exists yet. Raises ValueError on
        a wrong passphrase or a corrupt/tampered file (mirrors
        Identity.load's contract) rather than silently starting an empty
        history, which would look like data loss instead of an
        authentication failure."""
        if not passphrase:
            raise HistoryUnavailable(
                "Chat history requires a passphrase-protected identity."
            )

        path = Path(directory) / f"{name}_history.enc"
        if not path.exists():
            salt = cu.random_bytes(SALT_SIZE)
            key = cu.derive_key_from_passphrase(passphrase, salt)
            return cls(path, name, key, salt, entries=[])

        raw = path.read_bytes()
        if len(raw) < SALT_SIZE + NONCE_SIZE:
            raise ValueError("History file is corrupt (too short).")
        salt = raw[:SALT_SIZE]
        nonce = raw[SALT_SIZE : SALT_SIZE + NONCE_SIZE]
        ciphertext = raw[SALT_SIZE + NONCE_SIZE :]
        key = cu.derive_key_from_passphrase(passphrase, salt)
        try:
            plaintext = cu.aes_gcm_decrypt(key, nonce, ciphertext, aad=name.encode("utf-8"))
        except Exception as e:
            raise ValueError(f"Wrong passphrase or corrupt history file: {e}") from e
        entries = json.loads(plaintext.decode("utf-8"))
        return cls(path, name, key, salt, entries=entries)

    def for_peer(self, peer_name: str) -> list:
        """Entries exchanged with `peer_name`, oldest first."""
        with self._lock:
            return [e for e in self._entries if e["peer"] == peer_name]

    def append(self, peer_name: str, direction: str, text: str):
        """`direction` is "sent" or "received". Persists immediately -
        history that's only written on a clean exit would lose everything
        from a crash or a killed process. Callable from either the GUI
        thread (outbound sends) or the worker thread (inbound messages);
        the lock keeps a send racing a receive from corrupting the
        in-memory list or interleaving two file writes."""
        with self._lock:
            self._entries.append(
                {"ts": time.time(), "peer": peer_name, "direction": direction, "text": text}
            )
            self._save()

    def _save(self):
        nonce = cu.random_bytes(NONCE_SIZE)
        plaintext = json.dumps(self._entries).encode("utf-8")
        ciphertext = cu.aes_gcm_encrypt(
            self._key, nonce, plaintext, aad=self._identity_name.encode("utf-8")
        )
        self._path.parent.mkdir(parents=True, exist_ok=True)
        tmp_path = self._path.with_name(self._path.name + ".tmp")
        tmp_path.write_bytes(self._salt + nonce + ciphertext)
        os.replace(tmp_path, self._path)
