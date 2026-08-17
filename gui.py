"""
gui.py
------
Tkinter GUI for the secure communication system. This is purely a
presentation layer - it uses the exact same identity.py / handshake.py /
secure_channel.py / transport.py modules and crypto as the CLI demo
(server.py / client.py). No cryptographic logic lives in this file.

One window can act as EITHER side of the connection: pick "Host" to
listen for a peer, or "Connect" to dial one. Handshake progress, the
identity fingerprint (for out-of-band verification), and new-identity
trust prompts are all surfaced in the UI instead of the terminal.

Run with:
    python3 gui.py
"""

import hashlib
import json
import platform
import queue
import shutil
import socket
import subprocess
import threading
import time
import tkinter as tk
import uuid
from datetime import datetime
from pathlib import Path
from tkinter import filedialog, messagebox, scrolledtext, ttk

import history
import transport
from handshake import (
    HandshakeError,
    HandshakeMessage1,
    HandshakeMessage2,
    HandshakeMessage3,
    initiator_finish,
    initiator_start,
    responder_finish,
    responder_respond,
)
from identity import Identity, TrustStore, fingerprint_for_bytes
from rate_limiter import SQLiteRateLimiter
from secure_channel import ReplayError, TamperError
from audit_log import configure_logging

KEY_DIR = "./gui_keys"
FILE_RECV_DIR = Path("./received_files")

# Every application-level plaintext handed to SecureChannel.encrypt() is
# prefixed with one of these type bytes so text and file traffic can share
# the same encrypted stream. TCP already guarantees in-order delivery on a
# single connection, so a file's chunks never need their own sequence
# numbers - just a 16-byte transfer id to tell concurrent chunk streams
# apart (interleaved with normal chat messages) and to disambiguate a stray
# chunk left over after a reconnect drops an in-progress transfer.
MSG_TEXT = 0x01
MSG_FILE_OFFER = 0x02
MSG_FILE_CHUNK = 0x03

FILE_CHUNK_SIZE = 256 * 1024
MAX_FILE_SIZE = 200 * 1024 * 1024  # sanity cap for this demo app
MAX_CONCURRENT_INBOUND_TRANSFERS = 4


def _human_size(num_bytes: int) -> str:
    size = float(num_bytes)
    for unit in ("B", "KB", "MB", "GB"):
        if size < 1024 or unit == "GB":
            return f"{size:.0f} {unit}" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} GB"


def _encode_file_offer(file_id: bytes, name: str, size: int, sha256_hex: str) -> bytes:
    payload = json.dumps(
        {"id": file_id.hex(), "name": name, "size": size, "sha256": sha256_hex}
    ).encode("utf-8")
    return bytes([MSG_FILE_OFFER]) + payload


def _encode_file_chunk(file_id: bytes, chunk: bytes) -> bytes:
    return bytes([MSG_FILE_CHUNK]) + file_id + chunk


# Turns the 8-byte hex fingerprint (identity.py's fingerprint_for_bytes)
# into a spoken phrase for out-of-band verification - reading "brave-falcon
# calm-opal ..." aloud over a call is far less error-prone than reading
# hex nibbles one at a time, the same problem Signal's word-based safety
# numbers and the classic PGP word list solve. This is presentation only:
# each byte maps deterministically to one adjective-noun pair (high nibble
# picks the adjective, low nibble the noun), so the 16 adjectives and 16
# nouns below are guaranteed to produce 256 distinct pairs by construction
# - no risk of an accidental duplicate the way a hand-authored 256-word
# list would have. The underlying hex fingerprint stays the identity's
# real form everywhere else (TrustStore, CLI, audit log); this is purely
# an alternate rendering of it for the GUI.
_FINGERPRINT_ADJECTIVES = [
    "amber", "brave", "calm", "dusty", "eager", "fuzzy", "giant", "hollow",
    "icy", "jolly", "keen", "lucky", "misty", "noble", "olive", "proud",
]
_FINGERPRINT_NOUNS = [
    "anchor", "badger", "cactus", "delta", "ember", "falcon", "granite", "harbor",
    "ivory", "jasper", "kestrel", "lagoon", "meadow", "nectar", "opal", "pepper",
]


def _fingerprint_to_words(hex_fingerprint: str) -> str:
    raw = bytes.fromhex(hex_fingerprint.replace(":", ""))
    words = (
        f"{_FINGERPRINT_ADJECTIVES[b >> 4]}-{_FINGERPRINT_NOUNS[b & 0x0F]}" for b in raw
    )
    return " ".join(words)


def _unique_dest_path(directory: Path, name: str) -> Path:
    """Picks a non-colliding path under `directory` for an incoming file.

    `Path(name).name` strips any directory components a malicious or buggy
    peer might embed (e.g. "../../etc/passwd") so a received file can never
    be written outside `directory`.
    """
    safe_name = Path(name).name or "received_file"
    candidate = directory / safe_name
    if not candidate.exists():
        return candidate
    stem, suffix = Path(safe_name).stem, Path(safe_name).suffix
    i = 1
    while True:
        candidate = directory / f"{stem} ({i}){suffix}"
        if not candidate.exists():
            return candidate
        i += 1


def _notify_desktop(title: str, message: str) -> None:
    """Best-effort native OS notification for an incoming message.

    Deliberately dependency-free (uses whatever notifier ships with the
    OS) and deliberately swallows every error: a missing `notify-send`
    binary or a sandboxed/headless environment should never crash the
    chat session over a nice-to-have.
    """
    try:
        system = platform.system()
        if system == "Darwin":
            # osascript ships with every macOS install.
            safe_title = title.replace('"', '\\"')
            safe_msg = message.replace('"', '\\"')
            subprocess.run(
                [
                    "osascript",
                    "-e",
                    f'display notification "{safe_msg}" with title "{safe_title}"',
                ],
                check=False,
                timeout=2,
            )
        elif system == "Linux":
            if shutil.which("notify-send"):
                subprocess.run(
                    ["notify-send", "--", title, message],
                    check=False,
                    timeout=2,
                )
            # No notify-send available (e.g. minimal WM/headless): the
            # audible bell + title badge still cover it.
        elif system == "Windows":
            _notify_windows(title, message)
    except Exception:
        pass


def _notify_windows(title: str, message: str) -> None:
    """Native Windows balloon notification via pywin32's Shell_NotifyIcon.

    pywin32 is an optional dependency (not in requirements.txt), so the
    import happens lazily here and any failure is swallowed exactly like
    the other OS branches in _notify_desktop - a missing pywin32 install
    should never crash the chat session over a nice-to-have.

    The whole register-window / add-icon / pop-balloon / tear-down
    sequence runs on its own daemon thread because it needs a short
    sleep to give the balloon time to actually appear before the icon
    is removed, and that must never block the Tk main loop.
    """

    def _show():
        try:
            import win32api  # ty:ignore[unresolved-import]
            import win32con  # ty:ignore[unresolved-import]
            import win32gui  # ty:ignore[unresolved-import]
        except ImportError:
            return

        try:
            wc = win32gui.WNDCLASS()
            wc.hInstance = win32api.GetModuleHandle(None)
            wc.lpszClassName = "SecureCommsNotifyIcon"
            wc.lpfnWndProc = {win32con.WM_DESTROY: lambda hwnd, msg, wparam, lparam: 0}

            try:
                class_atom = win32gui.RegisterClass(wc)
            except win32gui.error:
                # Already registered by an earlier notification in this
                # process - reuse the class name instead of failing.
                class_atom = wc.lpszClassName

            hwnd = win32gui.CreateWindow(
                class_atom,
                "SecureCommsNotifyWindow",
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                wc.hInstance,
                None,
            )
            win32gui.UpdateWindow(hwnd)
        except Exception:
            return

        try:
            hicon = win32gui.LoadIcon(0, win32con.IDI_APPLICATION)
            flags = win32gui.NIF_ICON | win32gui.NIF_MESSAGE | win32gui.NIF_TIP
            win32gui.Shell_NotifyIcon(
                win32gui.NIM_ADD,
                (hwnd, 0, flags, win32con.WM_USER + 20, hicon, "Secure Comms"),
            )
            win32gui.Shell_NotifyIcon(
                win32gui.NIM_MODIFY,
                (
                    hwnd,
                    0,
                    win32gui.NIF_INFO,
                    win32con.WM_USER + 20,
                    hicon,
                    "Secure Comms",
                    message,
                    200,
                    title,
                    win32gui.NIIF_INFO,
                ),
            )
            # The balloon pop is asynchronous; hold the tray icon around
            # long enough for Windows to actually display it before we
            # clean up, or it can get dropped silently.
            time.sleep(4)
        except Exception:
            pass
        finally:
            try:
                win32gui.Shell_NotifyIcon(win32gui.NIM_DELETE, (hwnd, 0))
            except Exception:
                pass
            try:
                win32gui.DestroyWindow(hwnd)
            except Exception:
                pass

    threading.Thread(target=_show, daemon=True).start()


class PassphraseNeeded(Exception):
    """Raised by load_or_create_identity when a passphrase must be
    collected from the GUI before an identity can be loaded/created."""


def load_or_create_identity(name: str, passphrase: str = None) -> Identity:
    key_path_exists = (Path(KEY_DIR) / f"{name}_identity.pem").exists()

    if not key_path_exists:
        identity = Identity(name)
        identity.save(KEY_DIR, passphrase=passphrase or None)
        return identity

    if Identity.is_encrypted(name, KEY_DIR):
        if not passphrase:
            raise PassphraseNeeded("This identity is passphrase-protected.")
        return Identity.load(name, KEY_DIR, passphrase=passphrase)

    return Identity.load(name, KEY_DIR)


class PeerWorker(threading.Thread):
    """All networking + crypto runs here, off the GUI thread. Talks back
    to the GUI only through a thread-safe queue of event dicts, and any
    time it needs a decision from the human (e.g. "trust this new
    identity?") it blocks on a threading.Event until the GUI thread
    supplies an answer - this keeps Tk's single-threaded UI rule intact
    while still letting the crypto/network code run synchronously.

    A dropped connection does not end the thread: run() loops, retrying
    the connect (role="connect") or going back to listening for a new
    peer (role="host") with exponential backoff, until stop() is called.
    Each reconnect performs a brand-new handshake - there is no session
    resumption, so a reconnect starts a fresh ratchet chain exactly like
    a manual restart would (see README: "No reconnect/resumption").
    """

    RECONNECT_BASE_DELAY = 1.0
    RECONNECT_MAX_DELAY = 30.0
    # A stalled peer (connects, then sends nothing) must not hang the
    # worker thread forever - especially on the host side, where the
    # listening socket is now persistent across reconnects, so a single
    # stuck peer would otherwise block every later peer indefinitely.
    HANDSHAKE_TIMEOUT = 15.0

    def __init__(
        self,
        name: str,
        role: str,
        host: str,
        port: int,
        events: queue.Queue,
        passphrase: str = None,
        save_history: bool = False,
        session_id: str = None,
    ):
        super().__init__(daemon=True)
        self.name = name
        self.role = role  # "host" or "connect"
        self.host = host
        self.port = port
        self.events = events
        self.passphrase = passphrase or None
        self.save_history = save_history
        self.history = None
        # Tags every event this worker emits, so a GUI juggling several
        # concurrent PeerWorkers (multi-peer tabs) sharing one events
        # queue can tell which tab/session an event belongs to. Defaults
        # to a fresh id so existing single-session callers (and tests)
        # don't need to know this exists.
        self.session_id = session_id or uuid.uuid4().hex[:8]
        self.sock = None
        self.channel = None
        self.peer_name = None
        self._stop_event = threading.Event()
        self._send_lock = threading.Lock()
        self._srv = None
        self._limiter = None
        self._reconnect_attempt = 0
        self._inbound_transfers = {}
        self._history_shown_for = set()

    def emit(self, kind, **kwargs):
        self.events.put({"kind": kind, "session_id": self.session_id, **kwargs})

    def run(self):
        try:
            self.identity = load_or_create_identity(self.name, self.passphrase)
            self.trust_store = TrustStore.load(f"{KEY_DIR}/{self.name}_trust.json")
            self.emit("identity", fingerprint=self.identity.fingerprint)
        except PassphraseNeeded:
            self.emit(
                "error",
                text="This identity is passphrase-protected. "
                "Enter the passphrase and try again.",
            )
            return
        except ValueError:
            self.emit("error", text="Incorrect passphrase.")
            return
        except Exception as e:  # noqa: BLE001 - surface anything unexpected to the UI
            self.emit("error", text=f"Unexpected error: {e}")
            return

        if self.save_history:
            try:
                self.history = history.EncryptedHistory.load(
                    self.name, KEY_DIR, self.passphrase
                )
            except (ValueError, history.HistoryUnavailable) as e:
                self.emit("error", text=str(e))
                return

        while not self._stop_event.is_set():
            try:
                if self.role == "host":
                    connected = self._run_host()
                else:
                    connected = self._run_connect()
            except HandshakeError as e:
                # A failed handshake with the transport already up (bad
                # signature, unpinned/mismatched identity) is a crypto or
                # trust failure, not a network blip - don't mask it behind
                # an automatic retry loop.
                self.emit("error", text=f"Handshake failed: {e}")
                return
            except (ConnectionError, OSError) as e:
                if self._stop_event.is_set():
                    return
                if not self._reconnect_wait(str(e)):
                    return
                continue
            except Exception as e:  # noqa: BLE001
                self.emit("error", text=f"Unexpected error: {e}")
                return

            if not connected:
                return  # stop() was set before a handshake ever completed

            self._reconnect_attempt = 0
            # Only replay a given peer's history once, not on every
            # reconnect to them - the chat log already has it on screen
            # from the first time, and re-dumping it would just duplicate
            # it. Tracked per peer, not as one worker-wide latch: on the
            # host side, a single worker can serve a different peer on
            # each reconnect (whoever dials in next), and that peer's own
            # history must still get replayed the first time.
            if self.history is not None and self.peer_name not in self._history_shown_for:
                self._history_shown_for.add(self.peer_name)
                self.emit("history_loaded", entries=self.history.for_peer(self.peer_name))
            self.emit("handshake_done")
            self._recv_loop()
            self._abort_inbound_transfers()
            if self.sock is not None:
                try:
                    self.sock.close()
                except OSError:
                    pass
            self.channel = None
            self.sock = None
            if self._stop_event.is_set():
                return
            self.emit("connection_lost")
            if not self._reconnect_wait("Connection lost."):
                return

    def _reconnect_wait(self, reason: str) -> bool:
        """Sleeps out an exponential backoff, checking _stop_event every 200ms
        so a Disconnect click or window close interrupts it promptly.
        Returns False if stop() fired during (or before) the wait."""
        self._reconnect_attempt += 1
        delay = self._compute_backoff_delay(self._reconnect_attempt)
        self.emit(
            "status",
            text=f"{reason} Reconnecting in {delay:.0f}s "
            f"(attempt {self._reconnect_attempt})...",
        )
        waited = 0.0
        step = 0.2
        while waited < delay:
            if self._stop_event.is_set():
                return False
            time.sleep(step)
            waited += step
        return not self._stop_event.is_set()

    @classmethod
    def _compute_backoff_delay(cls, attempt: int) -> float:
        return min(cls.RECONNECT_BASE_DELAY * (2 ** (attempt - 1)), cls.RECONNECT_MAX_DELAY)

    def _run_host(self) -> bool:
        if self._srv is None:
            self.emit(
                "status",
                text=f"Waiting for a connection on {self.host}:{self.port}...",
            )
            srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv.bind((self.host, self.port))
            srv.listen(5)
            srv.settimeout(0.5)  # lets the accept loop notice self._stop_event
            self._srv = srv
            # SQLite-backed (per identity, under KEY_DIR) rather than
            # in-memory: persists across repeated connection attempts on
            # this listen socket AND across reconnects, same as before,
            # but now also across the app being closed and reopened - an
            # attacker who trips the cooldown no longer gets a free reset
            # just by waiting for (or forcing) a restart.
            self._limiter = SQLiteRateLimiter(
                f"{KEY_DIR}/{self.name}_ratelimit.db",
                max_attempts=5,
                window_seconds=60.0,
                cooldown_seconds=30.0,
            )
        else:
            self.emit("status", text=f"Waiting for a peer on {self.host}:{self.port}...")

        while not self._stop_event.is_set():
            try:
                conn, addr = self._srv.accept()
            except socket.timeout:
                continue
            ip = addr[0]
            if self._limiter.is_blocked(ip):
                wait = self._limiter.seconds_until_unblocked(ip)
                self.emit(
                    "status",
                    text=f"Rejected connection from {ip} - "
                    f"rate-limited for {wait:.0f}s more "
                    f"after repeated failed attempts.",
                )
                conn.close()
                continue

            self.sock = conn
            conn.settimeout(self.HANDSHAKE_TIMEOUT)
            self.emit("status", text=f"Connection from {addr[0]}:{addr[1]}")

            try:
                self._exchange_identity_and_pin()
                msg1 = HandshakeMessage1.from_wire(transport.recv_json(self.sock))
                msg2, state = responder_respond(self.identity, msg1)
                transport.send_json(self.sock, msg2.to_wire())
                msg3 = HandshakeMessage3.from_wire(transport.recv_json(self.sock))
                self.channel = responder_finish(self.trust_store, state, msg3)
            except (HandshakeError, TimeoutError) as e:
                self._limiter.record_failure(ip)
                self.emit(
                    "status",
                    text=f"Handshake with {ip} failed ({e}). Waiting for next peer...",
                )
                try:
                    self.sock.close()
                except OSError:
                    pass
                self.sock = None
                continue

            conn.settimeout(None)
            self._limiter.record_success(ip)
            return True

        return False

    def _run_connect(self) -> bool:
        self.emit("status", text=f"Connecting to {self.host}:{self.port}...")
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # Kept through the handshake reads below, not just connect() - a
        # peer that accepts the TCP connection and then sends nothing
        # must not hang this thread forever either.
        sock.settimeout(self.HANDSHAKE_TIMEOUT)
        sock.connect((self.host, self.port))
        self.sock = sock
        self.emit("status", text="Connected. Starting handshake...")

        self._exchange_identity_and_pin()

        msg1, state = initiator_start(self.identity)
        transport.send_json(self.sock, msg1.to_wire())
        msg2 = HandshakeMessage2.from_wire(transport.recv_json(self.sock))
        msg3, self.channel = initiator_finish(
            self.identity, self.trust_store, state, msg2
        )
        transport.send_json(self.sock, msg3.to_wire())
        sock.settimeout(None)
        return True

    def _exchange_identity_and_pin(self):
        transport.send_json(
            self.sock,
            {
                "name": self.identity.name,
                "identity_pub": self.identity.public_bytes.hex(),
            },
        )
        peer_intro = transport.recv_json(self.sock)
        peer_name = peer_intro["name"]
        peer_pub = bytes.fromhex(peer_intro["identity_pub"])

        if self.trust_store.get(peer_name) is None:
            fp = fingerprint_for_bytes(peer_pub)
            if not self._ask_trust(peer_name, fp):
                self.sock.close()
                raise HandshakeError(f"Declined to trust '{peer_name}'.")
            self.trust_store.pin(peer_name, peer_pub)
            self.trust_store.save(f"{KEY_DIR}/{self.name}_trust.json")
            self.emit("status", text=f"Pinned new identity '{peer_name}' ({fp})")
        elif not self.trust_store.is_trusted(peer_name, peer_pub):
            self.emit(
                "security_alert",
                text=f"'{peer_name}' presented a DIFFERENT public key than "
                f"the one on file. Possible impersonation. Aborting.",
            )
            self.sock.close()
            raise HandshakeError("Trust store mismatch - possible impersonation.")

        self.peer_name = peer_name

    def _ask_trust(self, name: str, fingerprint: str) -> bool:
        """Blocks this (background) thread until the GUI thread shows a
        dialog and the human answers it."""
        response = {}
        event = threading.Event()
        self.emit(
            "trust_prompt",
            name=name,
            fingerprint=fingerprint,
            response=response,
            event=event,
        )
        event.wait()
        return response.get("trusted", False)

    def _recv_loop(self):
        while not self._stop_event.is_set():
            try:
                framed = transport.recv_bytes(self.sock)
            except (ConnectionError, OSError):
                return
            try:
                plaintext = self.channel.decrypt(framed)
            except (ReplayError, TamperError) as e:
                self.emit("security_alert", text=str(e))
                continue
            self._handle_plaintext(plaintext)

    def _append_history(self, direction: str, text: str):
        """A local disk error (full disk, permissions, ...) writing
        history must not take the whole chat session down with it -
        history is a nice-to-have on top of the conversation, not the
        other way around. Disables history for the rest of this session
        rather than retrying every message, and tells the user once."""
        if self.history is None:
            return
        try:
            self.history.append(self.peer_name, direction, text)
        except OSError as e:
            self.history = None
            self.emit("status", text=f"Chat history disabled: {e}")

    def _handle_plaintext(self, plaintext: bytes):
        if not plaintext:
            return
        msg_type, body = plaintext[0], plaintext[1:]
        if msg_type == MSG_TEXT:
            text = body.decode("utf-8", "replace")
            self._append_history("received", text)
            self.emit("message", sender=self.peer_name, text=text)
        elif msg_type == MSG_FILE_OFFER:
            self._handle_file_offer(body)
        elif msg_type == MSG_FILE_CHUNK:
            self._handle_file_chunk(body)
        # Unknown type bytes are ignored rather than treated as tampering:
        # the GCM tag already authenticated this payload, so an unexpected
        # type only means a future/older protocol version, not an attack.

    def _handle_file_offer(self, body: bytes):
        try:
            meta = json.loads(body.decode("utf-8"))
            file_id = bytes.fromhex(meta["id"])
            name = str(meta["name"])
            size = int(meta["size"])
            sha256_hex = str(meta["sha256"])
        except (json.JSONDecodeError, KeyError, ValueError, UnicodeDecodeError):
            self.emit("security_alert", text="Received a malformed file offer.")
            return
        if size > MAX_FILE_SIZE:
            self.emit(
                "security_alert",
                text=f"Peer offered an oversized file ({_human_size(size)}); refusing.",
            )
            return
        if size <= 0:
            self.emit("security_alert", text="Peer offered a file with an invalid size.")
            return
        if len(self._inbound_transfers) >= MAX_CONCURRENT_INBOUND_TRANSFERS:
            self.emit(
                "security_alert",
                text="Too many simultaneous incoming file transfers; refusing.",
            )
            return

        FILE_RECV_DIR.mkdir(parents=True, exist_ok=True)
        dest = _unique_dest_path(FILE_RECV_DIR, name)
        try:
            handle = open(dest, "wb")
        except OSError as e:
            self.emit("error", text=f"Can't save incoming file: {e}")
            return

        self._inbound_transfers[file_id] = {
            "name": name,
            "size": size,
            "sha256": sha256_hex,
            "received": 0,
            "handle": handle,
            "path": dest,
            "digest": hashlib.sha256(),
        }
        self.emit("file_offer", name=name, size=size)

    def _handle_file_chunk(self, body: bytes):
        if len(body) < 16:
            self.emit("security_alert", text="Received a malformed file chunk.")
            return
        file_id, data = body[:16], body[16:]
        transfer = self._inbound_transfers.get(file_id)
        if transfer is None:
            # No matching offer - most likely a leftover chunk from a
            # transfer that was in flight when the connection dropped and
            # got abandoned on reconnect. Drop it rather than crash.
            return

        try:
            transfer["handle"].write(data)
        except OSError as e:
            # A full disk or similar must be reported and cleaned up here,
            # not left to propagate up into run()'s network-error handler
            # (where it would be misreported as a dropped connection and
            # leave this handle/partial file behind).
            del self._inbound_transfers[file_id]
            try:
                transfer["handle"].close()
            except OSError:
                pass
            try:
                transfer["path"].unlink()
            except OSError:
                pass
            self.emit("error", text=f"Can't write incoming file: {e}")
            return
        transfer["digest"].update(data)
        transfer["received"] += len(data)
        self.emit(
            "file_recv_progress",
            name=transfer["name"],
            received=transfer["received"],
            total=transfer["size"],
        )

        if transfer["received"] >= transfer["size"]:
            transfer["handle"].close()
            del self._inbound_transfers[file_id]
            if transfer["digest"].hexdigest() != transfer["sha256"]:
                self.emit(
                    "security_alert",
                    text=f"Integrity check failed for received file "
                    f"'{transfer['name']}' - discarding.",
                )
                try:
                    transfer["path"].unlink()
                except OSError:
                    pass
                return
            self.emit(
                "file_received",
                name=transfer["name"],
                size=transfer["size"],
                path=str(transfer["path"]),
            )

    def _abort_inbound_transfers(self):
        for transfer in self._inbound_transfers.values():
            try:
                transfer["handle"].close()
            except OSError:
                pass
            try:
                transfer["path"].unlink()
            except OSError:
                pass
        self._inbound_transfers.clear()

    def _send_raw(self, plaintext: bytes):
        if self.channel is None or self.sock is None:
            raise ConnectionError("Not connected.")
        # encrypt() mutates shared ratchet state (send counter, sending
        # chain, and possibly a rekey step) - two threads calling it
        # concurrently (e.g. a text send from the GUI thread racing a
        # background file-send) could read the same counter or tear a
        # rekey step in half, which breaks AES-GCM's nonce-uniqueness
        # guarantee. So encrypt() has to be inside the lock too, not just
        # the socket write; this also keeps wire order matching counter
        # order for free.
        with self._send_lock:
            framed = self.channel.encrypt(plaintext)
            transport.send_bytes(self.sock, framed)

    def send(self, text: str):
        if self.channel is None or self.sock is None:
            return
        self._send_raw(bytes([MSG_TEXT]) + text.encode("utf-8"))
        self._append_history("sent", text)

    def send_file(self, path_str: str):
        threading.Thread(target=self._send_file, args=(path_str,), daemon=True).start()

    def _send_file(self, path_str: str):
        path = Path(path_str)
        try:
            size = path.stat().st_size
        except OSError as e:
            self.emit("file_send_failed", name=path.name, text=str(e))
            return
        if size > MAX_FILE_SIZE:
            self.emit(
                "file_send_failed",
                name=path.name,
                text=f"file is {_human_size(size)}, limit is "
                f"{_human_size(MAX_FILE_SIZE)}",
            )
            return
        if size <= 0:
            self.emit(
                "file_send_failed", name=path.name, text="file is empty; nothing to send"
            )
            return

        digest = hashlib.sha256()
        try:
            with open(path, "rb") as f:
                for chunk in iter(lambda: f.read(FILE_CHUNK_SIZE), b""):
                    digest.update(chunk)
        except OSError as e:
            self.emit("file_send_failed", name=path.name, text=str(e))
            return

        file_id = uuid.uuid4().bytes
        # A reconnect mid-transfer swaps in a brand-new SecureChannel with
        # no memory of this offer, so blindly continuing to send chunks
        # under the old file_id would just have the receiver silently
        # drop every one of them (no matching offer) while this thread
        # still reports success. Pin to the channel that was live when the
        # transfer started and bail out the moment it changes.
        session = self.channel
        try:
            if self.channel is not session:
                raise ConnectionError("connection was lost before the transfer started")
            self._send_raw(_encode_file_offer(file_id, path.name, size, digest.hexdigest()))
            sent = 0
            with open(path, "rb") as f:
                for chunk in iter(lambda: f.read(FILE_CHUNK_SIZE), b""):
                    if self.channel is not session:
                        raise ConnectionError("connection was lost mid-transfer")
                    self._send_raw(_encode_file_chunk(file_id, chunk))
                    sent += len(chunk)
                    self.emit(
                        "file_send_progress", name=path.name, sent=sent, total=size
                    )
        except (ConnectionError, OSError) as e:
            self.emit("file_send_failed", name=path.name, text=str(e))
            return

        self.emit("file_sent", name=path.name, size=size)

    def stop(self):
        self._stop_event.set()
        # Snapshot the references once: the worker thread clears self.sock
        # (and, less often, self._srv) on every connection loss, so
        # re-reading the attribute between an "if" check and the call
        # below would race into "NoneType has no attribute shutdown".
        sock = self.sock
        srv = self._srv
        # Plain close() from this (GUI) thread does not reliably unblock a
        # recv() the worker thread is blocked in on the same socket - the
        # kernel won't tear the connection down (and send the peer a FIN)
        # until every thread's reference to it is released, and the
        # blocked recv() itself holds one of those references. shutdown()
        # forces it immediately regardless of what other threads are
        # doing with the socket.
        try:
            if sock:
                sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        try:
            if sock:
                sock.close()
        except OSError:
            pass
        try:
            if srv:
                srv.close()
        except OSError:
            pass


class SecureCommsApp(tk.Tk):
    """One window, many concurrent encrypted sessions: a permanent "New
    Connection" tab for starting the next Host/Connect attempt, plus one
    tab per PeerWorker that's completed a handshake. All workers share a
    single events queue; PeerWorker.emit() tags every event with its
    session_id so _handle_event can route it to the right tab (or, for a
    still-pending worker that hasn't reached its first handshake yet, to
    the New Connection tab's own status/fingerprint display).

    Only one connection attempt can be "pending" (pre-handshake) at a
    time - Host/Connect are disabled while self.pending_worker is set -
    but any number of already-established sessions can be open as tabs
    simultaneously, each reconnecting independently in the background.
    """

    def __init__(self):
        super().__init__()
        self.title("Secure Comms")
        self.geometry("560x640")
        self.minsize(420, 480)

        self.pending_worker: PeerWorker | None = None
        self.sessions: dict[str, ttk.Frame] = {}
        self.events: queue.Queue = queue.Queue()

        # -- new-message notifications ---------------------------------
        self._base_title = "Secure Comms"
        self._window_focused = True
        self._unread_count = 0
        self.bind("<FocusIn>", self._on_focus_in)
        self.bind("<FocusOut>", self._on_focus_out)

        self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill="both", expand=True)
        self.notebook.bind("<<NotebookTabChanged>>", self._on_tab_changed)

        self._build_connect_frame()

        self.protocol("WM_DELETE_WINDOW", self._on_close)
        self.after(100, self._poll_events)

    # -- layout: the permanent "New Connection" tab -----------------------

    def _build_connect_frame(self):
        frame = ttk.Frame(self.notebook, padding=20)
        self.connect_frame = frame
        self.notebook.add(frame, text="New Connection")

        ttk.Label(
            frame, text="Secure Communication System", font=("", 16, "bold")
        ).pack(pady=(0, 4))
        ttk.Label(
            frame,
            text="X25519 key exchange \u2022 Ed25519 authentication \u2022 AES-256-GCM",
            foreground="#666",
        ).pack(pady=(0, 16))

        form = ttk.Frame(frame)
        form.pack(fill="x")
        form.columnconfigure(1, weight=1)

        ttk.Label(form, text="Your name:").grid(row=0, column=0, sticky="w", pady=4)
        self.name_var = tk.StringVar(value="alice")
        ttk.Entry(form, textvariable=self.name_var).grid(
            row=0, column=1, sticky="ew", pady=4
        )

        ttk.Label(form, text="Host:").grid(row=1, column=0, sticky="w", pady=4)
        self.host_var = tk.StringVar(value="127.0.0.1")
        ttk.Entry(form, textvariable=self.host_var).grid(
            row=1, column=1, sticky="ew", pady=4
        )

        ttk.Label(form, text="Port:").grid(row=2, column=0, sticky="w", pady=4)
        self.port_var = tk.StringVar(value="8000")
        ttk.Entry(form, textvariable=self.port_var).grid(
            row=2, column=1, sticky="ew", pady=4
        )

        ttk.Label(form, text="Passphrase:").grid(row=3, column=0, sticky="w", pady=4)
        self.passphrase_var = tk.StringVar(value="")
        ttk.Entry(form, textvariable=self.passphrase_var, show="*").grid(
            row=3, column=1, sticky="ew", pady=4
        )
        ttk.Label(
            frame,
            text="Leave blank for a new/unencrypted identity. Required "
            "if this name's identity key is passphrase-protected.",
            foreground="#888",
            font=("", 8),
        ).pack(anchor="w", pady=(0, 4))

        self.save_history_var = tk.BooleanVar(value=False)
        self.history_check = ttk.Checkbutton(
            frame,
            text="Save chat history to disk (encrypted, requires a passphrase)",
            variable=self.save_history_var,
        )
        self.history_check.pack(anchor="w", pady=(0, 4))
        self.history_check.state(["disabled"])
        self.passphrase_var.trace_add("write", self._on_passphrase_changed)

        btns = ttk.Frame(frame)
        btns.pack(fill="x", pady=16)
        self.host_btn = ttk.Button(
            btns, text="Host (wait for peer)", command=self._start_host
        )
        self.host_btn.pack(side="left", expand=True, fill="x", padx=(0, 4))
        self.connect_btn = ttk.Button(
            btns, text="Connect to peer", command=self._start_connect
        )
        self.connect_btn.pack(side="left", expand=True, fill="x", padx=(4, 0))

        self.status_var = tk.StringVar(
            value="Enter your name and choose a role to begin."
        )
        ttk.Label(
            frame,
            textvariable=self.status_var,
            foreground="#555",
            wraplength=480,
            justify="left",
        ).pack(pady=8, fill="x")

        self.fingerprint_var = tk.StringVar(value="")
        fingerprint_label = ttk.Label(
            frame,
            textvariable=self.fingerprint_var,
            font=("Courier", 10),
            wraplength=480,
            justify="center",
        )
        fingerprint_label.pack(fill="x")
        # A fixed wraplength only fits the window's initial 560px width -
        # shrink the window down toward its 420px minsize (the word-phrase
        # line is long enough to hit this in practice) and a constant
        # wraplength would overflow instead of wrapping further. Recompute
        # it from the frame's actual width on every resize instead.
        frame.bind(
            "<Configure>",
            lambda e: fingerprint_label.configure(wraplength=max(e.width - 40, 100)),
        )

    def _build_session_tab(self, worker: "PeerWorker") -> ttk.Frame:
        """Builds one chat tab's widgets for `worker` and returns the
        Frame with them attached as plain attributes (log, msg_var, ...) -
        there's no separate session-state class; the Frame itself is the
        per-session container, mirroring how self.log/self.msg_var etc.
        used to be single instance attributes back when there was only
        ever one session."""
        session_id = worker.session_id
        frame = ttk.Frame(self.notebook, padding=12)
        frame.worker = worker
        frame.chat_shown = False
        frame.unread = 0

        header_row = ttk.Frame(frame)
        header_row.pack(fill="x")
        frame.header_var = tk.StringVar(value="")
        ttk.Label(
            header_row, textvariable=frame.header_var, font=("", 11, "bold"), wraplength=440
        ).pack(side="left", anchor="w")
        ttk.Button(
            header_row, text="Disconnect", command=lambda: self._disconnect_session(session_id)
        ).pack(side="right")

        frame.log = scrolledtext.ScrolledText(frame, state="disabled", wrap="word")
        frame.log.pack(fill="both", expand=True, pady=8)
        frame.log.tag_config("me", foreground="#0b5fff")
        frame.log.tag_config("peer", foreground="#1a7a1a")
        frame.log.tag_config("system", foreground="#888888")
        frame.log.tag_config("alert", foreground="#cc0000", font=("", 10, "bold"))

        frame.transfer_var = tk.StringVar(value="")
        frame.transfer_frame = ttk.Frame(frame)
        ttk.Label(
            frame.transfer_frame, textvariable=frame.transfer_var, foreground="#555"
        ).pack(side="left")
        frame.transfer_bar = ttk.Progressbar(
            frame.transfer_frame, mode="determinate", length=200
        )
        frame.transfer_bar.pack(side="left", padx=(6, 0), fill="x", expand=True)

        entry_row = ttk.Frame(frame)
        entry_row.pack(fill="x")
        frame.entry_row = entry_row
        frame.msg_var = tk.StringVar()
        entry = ttk.Entry(entry_row, textvariable=frame.msg_var)
        entry.pack(side="left", fill="x", expand=True)
        entry.bind("<Return>", lambda _e: self._send(session_id))
        frame.msg_entry = entry
        frame.send_btn = ttk.Button(
            entry_row, text="Send", command=lambda: self._send(session_id)
        )
        frame.send_btn.pack(side="left", padx=(6, 0))
        frame.sendfile_btn = ttk.Button(
            entry_row, text="Send File…", command=lambda: self._send_file(session_id)
        )
        frame.sendfile_btn.pack(side="left", padx=(6, 0))

        return frame

    # -- actions ---------------------------------------------------------

    def _start_host(self):
        self._start_worker("host")

    def _start_connect(self):
        self._start_worker("connect")

    def _on_passphrase_changed(self, *_args):
        if self.passphrase_var.get():
            self.history_check.state(["!disabled"])
        else:
            # No passphrase means no secret to derive a history-encryption
            # key from - uncheck it too, not just disable, so it can't
            # stay silently checked-but-inert.
            self.save_history_var.set(False)
            self.history_check.state(["disabled"])

    def _start_worker(self, role: str):
        if self.pending_worker is not None:
            return  # Host/Connect are disabled while one is already starting
        name = self.name_var.get().strip()
        host = self.host_var.get().strip()
        try:
            port = int(self.port_var.get().strip())
        except ValueError:
            messagebox.showerror("Invalid port", "Port must be a number.")
            return
        if not name:
            messagebox.showerror("Missing name", "Please enter your name.")
            return
        passphrase = self.passphrase_var.get() or None
        save_history = self.save_history_var.get()
        if save_history and not passphrase:
            messagebox.showerror(
                "Passphrase required",
                "Saving chat history requires a passphrase - it's the "
                "key the history file is encrypted with.",
            )
            return

        self.host_btn.state(["disabled"])
        self.connect_btn.state(["disabled"])
        self.status_var.set("Starting...")
        self.pending_worker = PeerWorker(
            name,
            role,
            host,
            port,
            self.events,
            passphrase=passphrase,
            save_history=save_history,
        )
        self.pending_worker.start()

    def _send(self, session_id: str):
        tab = self.sessions.get(session_id)
        if tab is None:
            return
        text = tab.msg_var.get()
        if not text or tab.worker.channel is None:
            return
        tab.worker.send(text)
        self._log(tab, text, "me", label=tab.worker.name)
        tab.msg_var.set("")

    def _send_file(self, session_id: str):
        tab = self.sessions.get(session_id)
        if tab is None or tab.worker.channel is None:
            return
        path = filedialog.askopenfilename(title="Select a file to send")
        if not path:
            return
        tab.worker.send_file(path)

    def _disconnect_session(self, session_id: str):
        tab = self.sessions.pop(session_id, None)
        if tab is None:
            return
        tab.worker.stop()
        # destroy(), not notebook.forget(): forget() only unmaps the tab
        # from the notebook's layout, it doesn't free the underlying Tk
        # widgets (the log, entry, buttons, ...) - repeated disconnect/
        # reconnect cycles would otherwise leak them for the rest of the
        # process's life. destroy() frees them and removes the tab from
        # the notebook as a side effect, so forget() isn't needed too.
        tab.destroy()

    def _worker_for(self, session_id: str) -> "PeerWorker | None":
        tab = self.sessions.get(session_id)
        if tab is not None:
            return tab.worker
        if self.pending_worker is not None and self.pending_worker.session_id == session_id:
            return self.pending_worker
        return None

    def _ensure_session_tab(self, session_id: str) -> "ttk.Frame | None":
        """Creates the tab for `session_id` the first time it's needed
        (called from whichever of history_loaded/handshake_done arrives
        first for a newly-graduating session) and is a no-op after that.
        Returns None for a stale session_id that matches neither an
        existing tab nor the current pending worker - e.g. a very late
        event from a worker that's since been disconnected."""
        if session_id in self.sessions:
            return self.sessions[session_id]
        worker = self._worker_for(session_id)
        if worker is None:
            return None

        tab = self._build_session_tab(worker)
        self.sessions[session_id] = tab
        self.notebook.add(tab, text=worker.peer_name or worker.name)
        self.notebook.select(tab)

        if self.pending_worker is worker:
            # This connection has graduated from "pending" to a real tab -
            # free the New Connection form for the next attempt. Not
            # nulling pending_worker would be wrong here (unlike the
            # single-session app's old _disconnect, which deliberately
            # left a stale reference around): a NEW pending_worker must
            # be able to start right away, and leaving the old one in
            # place would make _worker_for keep resolving new pending-
            # phase events to the wrong (already-graduated) worker.
            self.pending_worker = None
            self.host_btn.state(["!disabled"])
            self.connect_btn.state(["!disabled"])
            self.status_var.set("Ready to start another connection.")
            self.fingerprint_var.set("")
        return tab

    def _set_chat_input_enabled(self, tab, enabled: bool):
        state = ["!disabled"] if enabled else ["disabled"]
        tab.msg_entry.state(state)
        tab.send_btn.state(state)
        tab.sendfile_btn.state(state)

    def _update_transfer_bar(self, tab, label: str, done: int, total: int):
        if not tab.transfer_frame.winfo_ismapped():
            tab.transfer_frame.pack(fill="x", pady=(0, 8), before=tab.entry_row)
        percent = int(done / total * 100) if total else 100
        tab.transfer_bar["value"] = percent
        tab.transfer_var.set(
            f"{label}: {percent}% ({_human_size(done)}/{_human_size(total)})"
        )

    def _hide_transfer_bar(self, tab):
        tab.transfer_frame.pack_forget()

    def _log(self, tab, text: str, tag: str, label: str | None = None, when: float | None = None):
        tab.log.configure(state="normal")
        # History replay passes the entry's original timestamp (a past
        # date, possibly not today) instead of "now"; live messages don't.
        if when is None:
            ts = datetime.now().strftime("%H:%M:%S")
        else:
            ts = datetime.fromtimestamp(when).strftime("%Y-%m-%d %H:%M")
        prefix = f"[{ts}] {label}: " if label else f"[{ts}] "
        tab.log.insert("end", prefix + text + "\n", tag)
        tab.log.see("end")
        tab.log.configure(state="disabled")

    # -- tabs / new-message notifications ---------------------------------

    def _on_tab_changed(self, _event=None):
        selected = self.notebook.select()
        for session_id, tab in self.sessions.items():
            if str(tab) == selected and tab.unread:
                tab.unread = 0
                self._update_tab_title(session_id)

    def _update_tab_title(self, session_id: str):
        tab = self.sessions.get(session_id)
        if tab is None:
            return
        label = tab.worker.peer_name or tab.worker.name
        if tab.unread:
            label = f"{label} ({tab.unread})"
        self.notebook.tab(tab, text=label)

    def _on_focus_in(self, _event=None):
        self._window_focused = True
        self._unread_count = 0
        self.title(self._base_title)

    def _on_focus_out(self, _event=None):
        self._window_focused = False

    def _notify_incoming(self, session_id: str, tab, sender: str, text: str):
        """Alert the user to a newly-received (already-decrypted) message.

        Called from _handle_event, which runs on the GUI thread via the
        Tk .after() poll loop, so it's safe to touch widgets directly.
        The audible bell always fires. A tab that isn't the one currently
        showing gets an unread badge on its label regardless of window
        focus (you might be looking at a different tab); the OS popup and
        window-title badge are reserved for when the whole window isn't
        focused, so switching between tabs within a focused window
        doesn't also spam a desktop notification.
        """
        self.bell()
        if str(tab) != self.notebook.select():
            tab.unread += 1
            self._update_tab_title(session_id)
        if self._window_focused:
            return
        self._unread_count += 1
        self.title(f"({self._unread_count}) {self._base_title} - new message")
        preview = text if len(text) <= 80 else text[:77] + "..."
        _notify_desktop(f"New message from {sender}", preview)

    # -- event loop --------------------------------------------------------

    def _poll_events(self):
        try:
            while True:
                self._handle_event(self.events.get_nowait())
        except queue.Empty:
            pass
        self.after(100, self._poll_events)

    def _handle_event(self, ev: dict):
        kind = ev["kind"]
        session_id = ev["session_id"]
        if kind == "identity":
            # Identity/trust-store loading happens once, at the very
            # start of a worker's run() - always before that worker's
            # first handshake, so this is always about the pending
            # connection, never an already-graduated tab.
            self.fingerprint_var.set(
                f"Your identity fingerprint: {ev['fingerprint']}\n"
                f"({_fingerprint_to_words(ev['fingerprint'])})"
            )
        elif kind == "status":
            tab = self.sessions.get(session_id)
            if tab is not None:
                self._log(tab, ev["text"], "system")
            elif self.pending_worker is not None and self.pending_worker.session_id == session_id:
                self.status_var.set(ev["text"])
        elif kind == "connection_lost":
            tab = self.sessions.get(session_id)
            if tab is not None:
                self._set_chat_input_enabled(tab, False)
                self._hide_transfer_bar(tab)
        elif kind == "error":
            tab = self.sessions.get(session_id)
            if tab is not None:
                self._log(tab, f"Error: {ev['text']}", "alert")
            elif self.pending_worker is not None and self.pending_worker.session_id == session_id:
                # run() has already returned for this worker (every path
                # that emits "error" is a fatal one it returns after) -
                # release the slot, or Host/Connect would look re-enabled
                # but silently no-op forever on the dead pending_worker.
                self.pending_worker = None
                self.status_var.set(ev["text"])
                self.host_btn.state(["!disabled"])
                self.connect_btn.state(["!disabled"])
                messagebox.showerror("Error", ev["text"])
        elif kind == "trust_prompt":
            trusted = messagebox.askyesno(
                "Verify new identity",
                f"'{ev['name']}' is presenting identity fingerprint:\n\n"
                f"    {ev['fingerprint']}\n"
                f"    ({_fingerprint_to_words(ev['fingerprint'])})\n\n"
                f"This is a Trust-On-First-Use pin, like an SSH host key. "
                f"Ideally you'd confirm this fingerprint with '{ev['name']}' "
                f"over a separate channel (phone call, in person) before "
                f"trusting it - anyone claiming to be '{ev['name']}' can "
                f"connect otherwise.\n\nTrust '{ev['name']}' and pin this key?",
            )
            ev["response"]["trusted"] = trusted
            ev["event"].set()
        elif kind == "history_loaded":
            tab = self._ensure_session_tab(session_id)
            if tab is None:
                return
            if ev["entries"]:
                self._log(tab, "----- Previous conversation -----", "system")
                for entry in ev["entries"]:
                    sent = entry["direction"] == "sent"
                    tag = "me" if sent else "peer"
                    label = tab.worker.name if sent else tab.worker.peer_name
                    self._log(tab, entry["text"], tag, label=label, when=entry["ts"])
                self._log(tab, "----- New session -----", "system")
        elif kind == "handshake_done":
            tab = self._ensure_session_tab(session_id)
            if tab is None:
                return
            tab.chat_shown = True
            self._update_tab_title(session_id)
            tab.header_var.set(
                f"\U0001f512 Encrypted chat with {tab.worker.peer_name}  "
                f"(AES-256-GCM, mutually authenticated, forward-secret)"
            )
            self._log(
                tab,
                "Handshake complete - mutual authentication succeeded. "
                "Session is now end-to-end encrypted.",
                "system",
            )
            self._set_chat_input_enabled(tab, True)
            # Only steal keyboard focus if this tab is the one on screen -
            # a background tab reconnecting shouldn't yank focus away from
            # whatever the user is actually doing.
            if str(tab) == self.notebook.select():
                tab.msg_entry.focus_set()
        elif kind == "message":
            tab = self.sessions.get(session_id)
            if tab is None:
                return
            self._log(tab, ev["text"], "peer", label=ev["sender"])
            self._notify_incoming(session_id, tab, ev["sender"], ev["text"])
        elif kind == "security_alert":
            tab = self.sessions.get(session_id)
            if tab is not None:
                self._log(tab, f"SECURITY ALERT: {ev['text']}", "alert")
            elif self.pending_worker is not None and self.pending_worker.session_id == session_id:
                self.status_var.set(f"SECURITY ALERT: {ev['text']}")
        elif kind == "file_offer":
            tab = self.sessions.get(session_id)
            if tab is None:
                return
            self._log(
                tab,
                f"{tab.worker.peer_name} is sending a file: "
                f"{ev['name']} ({_human_size(ev['size'])})",
                "system",
            )
        elif kind == "file_recv_progress":
            tab = self.sessions.get(session_id)
            if tab is None:
                return
            self._update_transfer_bar(tab, f"Receiving {ev['name']}", ev["received"], ev["total"])
        elif kind == "file_received":
            tab = self.sessions.get(session_id)
            if tab is None:
                return
            self._hide_transfer_bar(tab)
            self._log(
                tab,
                f"Received file '{ev['name']}' ({_human_size(ev['size'])}) "
                f"- saved to {ev['path']}",
                "system",
            )
        elif kind == "file_send_progress":
            tab = self.sessions.get(session_id)
            if tab is None:
                return
            self._update_transfer_bar(tab, f"Sending {ev['name']}", ev["sent"], ev["total"])
        elif kind == "file_sent":
            tab = self.sessions.get(session_id)
            if tab is None:
                return
            self._hide_transfer_bar(tab)
            self._log(tab, f"Sent file '{ev['name']}' ({_human_size(ev['size'])})", "system")
        elif kind == "file_send_failed":
            tab = self.sessions.get(session_id)
            if tab is None:
                return
            self._hide_transfer_bar(tab)
            self._log(tab, f"Failed to send '{ev['name']}': {ev['text']}", "alert")

    def _on_close(self):
        if self.pending_worker:
            self.pending_worker.stop()
        for tab in self.sessions.values():
            tab.worker.stop()
        self.destroy()


if __name__ == "__main__":
    # One shared logfile: this window may act as either "alice" or "bob"
    # depending on the name entered in the form, so events aren't split
    # per-identity the way the CLI demo's are.
    configure_logging(logfile="secure_comms_audit.log", also_stderr=False)
    app = SecureCommsApp()
    app.mainloop()
