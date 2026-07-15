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
import socket
import sys
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
from rate_limiter import RateLimiter
from audit_log import configure_logging

HOST, PORT = "127.0.0.1", 8000
KEY_DIR = "./demo_keys"


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
            except ValueError:
                print("Incorrect passphrase.")
        print("Too many incorrect attempts. Aborting.")
        sys.exit(1)

    return Identity.load(name, KEY_DIR)


def handle_connection(
    conn, addr, me: Identity, trust_store: TrustStore, limiter: RateLimiter
):
    ip = addr[0]
    try:
        # --- TOFU: on first contact, learn and pin the peer's public key ---
        peer_intro = transport.recv_json(conn)
        peer_name = peer_intro["name"]
        peer_pubkey = bytes.fromhex(peer_intro["identity_pub"])
        trusted, mismatch = trust_store.verify_and_pin_interactive(
            peer_name, peer_pubkey, "bob", f"{KEY_DIR}/bob_trust.json"
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

        print("[bob] handshake complete - mutual authentication succeeded.")
        print("[bob] session secured with AES-256-GCM. Type messages below.\n")

        # --- Encrypted chat loop ---
        while True:
            framed = transport.recv_bytes(conn)
            try:
                plaintext = channel.decrypt(framed)
            except (ReplayError, TamperError) as e:
                print(f"[bob] SECURITY ALERT: {e}")
                continue
            text = plaintext.decode("utf-8")
            print(f"[{peer_name}] {text}")
            if text.strip().lower() == "/quit":
                break
            reply = input("[bob] > ")
            transport.send_bytes(conn, channel.encrypt(reply.encode("utf-8")))
            if reply.strip().lower() == "/quit":
                break

    except HandshakeError as e:
        print(f"[bob] HANDSHAKE FAILED: {e}")
        limiter.record_failure(ip)
    except (ConnectionError, OSError) as e:
        print(f"[bob] connection error: {e}")
    finally:
        conn.close()


def main():
    configure_logging(logfile="bob_audit.log", also_stderr=False)

    me = load_or_create_identity("bob")
    trust_store = TrustStore.load(f"{KEY_DIR}/bob_trust.json")
    limiter = RateLimiter(max_attempts=5, window_seconds=60.0, cooldown_seconds=30.0)

    print(f"[bob] identity fingerprint: {me.fingerprint}")

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((HOST, PORT))
    srv.listen(5)
    print(f"[bob] listening on {HOST}:{PORT} - Ctrl+C to stop.")

    try:
        while True:
            conn, addr = srv.accept()
            ip = addr[0]
            if limiter.is_blocked(ip):
                wait = limiter.seconds_until_unblocked(ip)
                print(
                    f"[bob] rejecting {ip} - rate-limited for another "
                    f"{wait:.0f}s after repeated failed attempts."
                )
                conn.close()
                continue
            print(f"[bob] connection from {addr}")
            handle_connection(conn, addr, me, trust_store, limiter)
            print("[bob] connection ended. Waiting for next peer...\n")
    except KeyboardInterrupt:
        print("\n[bob] shutting down.")
    finally:
        srv.close()


if __name__ == "__main__":
    main()
