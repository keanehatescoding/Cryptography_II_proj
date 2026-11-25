"""
server.py
---------
Demo server ("bob"). Loops accepting connections, running the responder
side of the handshake for each, then exchanges encrypted chat messages
over the resulting SecureChannel. A per-address rate limiter throttles
repeated failed handshake attempts.

Usage:
    python3 server.py
"""

import getpass
import queue
import secrets
import socket
import sys
import threading
from pathlib import Path

import transport
from identity import Identity, TrustStore
from handshake import (
    HandshakeMessage1,
    HandshakeMessage3,
    responder_respond,
    responder_finish,
    HandshakeError,
)
from secure_channel import ReplayError, TamperError
from rate_limiter import SQLiteRateLimiter
from audit_log import configure_logging

HOST, PORT = "127.0.0.1", 8000
KEY_DIR = "./demo_keys"

# How long a handler may block the console thread waiting for a TOFU
# confirmation. The console thread cannot be interrupted by a peer
# disconnecting, so without a bound a flood of unknown peers would pin
# every handler slot forever waiting on input that will never come.
HANDSHAKE_INPUT_TIMEOUT = 30.0

# Backpressure on reply prompts: while the console thread is busy typing
# one reply, the handler keeps reading and queueing more. Cap that so one
# peer cannot grow the retained message backlog without limit.
MAX_PENDING_REPLIES = 64


def load_or_create_identity(name: str) -> Identity:
    key_path = Path(KEY_DIR) / f"{name}_identity.pem"

    if not key_path.exists():
        use_pass = (
            input(f"Create identity '{name}'. Encrypt it with a passphrase? [Y/n]: ")
            .strip()
            .lower()
        )
        passphrase = None
        if use_pass != "n":
            passphrase = getpass.getpass("New passphrase: ")
            confirm = getpass.getpass("Confirm passphrase: ")
            if not passphrase:
                # An empty passphrase would be coerced to None by
                # `passphrase or None` below and silently write an
                # UNENCRYPTED key while the user believes they opted into
                # encryption. Refuse instead.
                print(
                    "Passphrase cannot be empty - refusing to create an "
                    "unencrypted identity. Aborting."
                )
                sys.exit(1)
            if passphrase != confirm:
                print("Passphrases did not match. Aborting.")
                sys.exit(1)
        identity = Identity(name)
        identity.save(KEY_DIR, passphrase=passphrase or None)
        return identity

    if Identity.is_encrypted(name, KEY_DIR):
        for _ in range(3):
            passphrase = getpass.getpass(f"Passphrase for '{name}': ")
            try:
                return Identity.load(name, KEY_DIR, passphrase=passphrase)
            except (ValueError, TypeError):
                # ValueError: wrong passphrase. TypeError: empty/absent
                # passphrase for an encrypted key - both should re-prompt,
                # not crash with a traceback (see Identity.load's docstring).
                print("Incorrect passphrase.")
        print("Too many incorrect attempts. Aborting.")
        sys.exit(1)

    return Identity.load(name, KEY_DIR)


class ConsoleDispatcher:
    """Single owner for all terminal input. Handler threads submit input
    requests (TOFU confirmations, chat replies) and wait for the response,
    so concurrent connections cannot race on input() or misroute replies."""

    def __init__(self):
        self._requests = queue.Queue()
        self._lock = threading.Lock()
        self._pending_replies = 0
        # token -> (display name, send function). Two connections may
        # authenticate as the same identity, so the name cannot be the key.
        self._peers = {}

    def register_peer(self, token, peer_name, send_fn):
        with self._lock:
            self._peers[token] = (peer_name, send_fn)

    def unregister_peer(self, token):
        with self._lock:
            self._peers.pop(token, None)

    def request_input(self, prompt: str, timeout: float | None = None) -> str:
        state = {"value": "", "expired": False}
        event = threading.Event()
        self._requests.put(("input", prompt, state, event))
        if not event.wait(timeout):
            # The console may still be busy with an earlier prompt. Mark the
            # request expired so a late answer cannot complete this request.
            with self._lock:
                state["expired"] = True
            raise TimeoutError("timed out waiting for operator input")
        if state["expired"]:
            raise TimeoutError("input request expired")
        return state["value"]

    def request_reply(self, token, peer_name: str, message: str) -> bool:
        # While the console is typing one reply the handler keeps reading.
        # Cap the backlog so one peer cannot grow it without limit.
        with self._lock:
            if self._pending_replies >= MAX_PENDING_REPLIES:
                return False
            self._pending_replies += 1
        self._requests.put(("reply", token, peer_name, message))
        return True

    def print(self, text: str):
        with self._lock:
            print(text)

    def run(self):
        while True:
            kind, *args = self._requests.get()
            if kind == "stop":
                return
            if kind == "input":
                prompt, state, event = args
                if state["expired"]:
                    continue  # requester gave up; do not consume terminal input
                try:
                    value = input(prompt)
                except EOFError:
                    value = ""
                with self._lock:
                    if not state["expired"]:
                        state["value"] = value
                event.set()
            elif kind == "reply":
                with self._lock:
                    self._pending_replies -= 1
                token, peer_name, message = args
                self.print(f"[{peer_name}] {message}")
                with self._lock:
                    entry = self._peers.get(token)
                if entry is None:
                    self.print(f"[bob] peer '{peer_name}' disconnected; dropping reply prompt.")
                    continue
                _, send_fn = entry
                try:
                    reply = input(f"[bob -> {peer_name}] > ")
                except EOFError:
                    reply = "/quit"
                try:
                    send_fn(reply)
                except Exception as e:
                    self.print(f"[bob] failed to send reply to '{peer_name}': {e}")

    def stop(self):
        self._requests.put(("stop",))


HANDSHAKE_TIMEOUT = 30.0
MAX_CONCURRENT_HANDLERS = 16


def handle_connection(
    conn,
    addr,
    me: Identity,
    trust_store: TrustStore,
    limiter: SQLiteRateLimiter,
    console: ConsoleDispatcher,
    handler_slots: threading.Semaphore,
):
    ip = addr[0]
    peer_name = None
    token = secrets.token_hex(16)
    try:
        conn.settimeout(HANDSHAKE_TIMEOUT)
        # --- TOFU: on first contact, learn and pin the peer's public key ---
        peer_intro = transport.recv_json(conn)
        peer_name = peer_intro["name"]
        peer_pubkey = bytes.fromhex(peer_intro["identity_pub"])
        trusted, mismatch = trust_store.verify_and_pin_interactive(
            peer_name,
            peer_pubkey,
            "bob",
            f"{KEY_DIR}/bob_trust.json",
            input_fn=lambda prompt: console.request_input(
                prompt, HANDSHAKE_INPUT_TIMEOUT
            ),
            print_fn=console.print,
        )
        if not trusted:
            # Only a key mismatch (possible impersonation) counts against
            # the rate limiter - a plain decline is the human choosing
            # not to trust, not a failed/malicious attempt.
            if mismatch:
                limiter.record_failure(ip)
            return

        transport.send_json(
            conn, {"name": me.name, "identity_pub": me.public_bytes.hex()}
        )

        # --- Handshake ---
        msg1 = HandshakeMessage1.from_wire(transport.recv_json(conn))
        msg2, state = responder_respond(me, msg1)
        transport.send_json(conn, msg2.to_wire())
        msg3 = HandshakeMessage3.from_wire(transport.recv_json(conn))
        channel = responder_finish(trust_store, state, msg3)
        limiter.record_success(ip)
        conn.settimeout(None)

        console.print("[bob] handshake complete - mutual authentication succeeded.")
        console.print(f"[bob] session secured with {peer_name}. Type replies when prompted.\n")

        send_lock = threading.Lock()   # orders socket writes
        channel_lock = threading.Lock()  # serializes SecureChannel state

        def send_reply(reply: str):
            with send_lock:
                with channel_lock:
                    frame = channel.encrypt(reply.encode("utf-8"))
                transport.send_bytes(conn, frame)

        console.register_peer(token, peer_name, send_reply)
        try:
            # --- Encrypted chat loop ---
            while True:
                framed = transport.recv_bytes(conn)
                try:
                    with channel_lock:
                        plaintext = channel.decrypt(framed)
                except (ReplayError, TamperError) as e:
                    console.print(f"[bob] SECURITY ALERT: {e}")
                    continue
                text = plaintext.decode("utf-8")
                if text.strip().lower() == "/quit":
                    console.print(f"[{peer_name}] {text}")
                    break
                if not console.request_reply(token, peer_name, text):
                    console.print(
                        f"[bob] reply backlog full for '{peer_name}' "
                        f"({MAX_PENDING_REPLIES}); closing this session."
                    )
                    break
        finally:
            console.unregister_peer(token)

    except TimeoutError as e:
        console.print(f"[bob] handshake input timed out: {e}")
    except HandshakeError as e:
        console.print(f"[bob] HANDSHAKE FAILED: {e}")
        limiter.record_failure(ip)
    except (ConnectionError, OSError, socket.timeout) as e:
        console.print(f"[bob] connection error: {e}")
    finally:
        conn.close()
        handler_slots.release()


def main():
    configure_logging(logfile="bob_audit.log", also_stderr=False)

    me = load_or_create_identity("bob")
    trust_store = TrustStore.load(f"{KEY_DIR}/bob_trust.json")
    limiter = SQLiteRateLimiter(
        f"{KEY_DIR}/bob_ratelimit.db",
        max_attempts=5,
        window_seconds=60.0,
        cooldown_seconds=30.0,
    )

    print(f"[bob] identity fingerprint: {me.fingerprint}")

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((HOST, PORT))
    srv.listen(5)
    print(f"[bob] listening on {HOST}:{PORT} - Ctrl+C to stop.")

    console = ConsoleDispatcher()
    handler_slots = threading.Semaphore(MAX_CONCURRENT_HANDLERS)

    def accept_loop():
        try:
            while True:
                try:
                    conn, addr = srv.accept()
                except OSError:
                    break
                ip = addr[0]
                if limiter.is_blocked(ip):
                    wait = limiter.seconds_until_unblocked(ip)
                    console.print(
                        f"[bob] rejecting {ip} - rate-limited for another "
                        f"{wait:.0f}s after repeated failed attempts."
                    )
                    conn.close()
                    continue
                if not handler_slots.acquire(timeout=0.1):
                    console.print(
                        f"[bob] rejecting {ip} - too many concurrent connections."
                    )
                    conn.close()
                    continue
                console.print(f"[bob] connection from {addr}")
                threading.Thread(
                    target=handle_connection,
                    args=(conn, addr, me, trust_store, limiter, console, handler_slots),
                    daemon=True,
                ).start()
        finally:
            console.stop()

    threading.Thread(target=accept_loop, daemon=True).start()
    try:
        console.run()
    except KeyboardInterrupt:
        print("\n[bob] shutting down.")
    finally:
        srv.close()


if __name__ == "__main__":
    main()
