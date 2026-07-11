"""
client.py
---------
Demo client ("alice"). Runs the initiator side of the handshake, then
exchanges encrypted chat messages over the resulting SecureChannel.

Usage:
    python3 client.py
"""

import getpass
import socket
import sys
from pathlib import Path

import transport
from identity import Identity, TrustStore
from handshake import (
    HandshakeMessage2,
    initiator_start,
    initiator_finish,
    HandshakeError,
)
from secure_channel import ReplayError, TamperError

HOST, PORT = "127.0.0.1", 6543
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


def main():
    me = load_or_create_identity("alice")
    trust_store = TrustStore.load(f"{KEY_DIR}/alice_trust.json")

    print(f"[alice] identity fingerprint: {me.fingerprint}")

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((HOST, PORT))
    print("[alice] connected to bob")

    try:
        transport.send_json(
            sock, {"name": me.name, "identity_pub": me.public_bytes.hex()}
        )
        peer_intro = transport.recv_json(sock)
        peer_name = peer_intro["name"]
        peer_pubkey = bytes.fromhex(peer_intro["identity_pub"])
        trusted, _mismatch = trust_store.verify_and_pin_interactive(
            peer_name, peer_pubkey, "alice", f"{KEY_DIR}/alice_trust.json"
        )
        if not trusted:
            sock.close()
            return

        # --- Handshake ---
        msg1, state = initiator_start(me)
        transport.send_json(sock, msg1.to_wire())
        msg2 = HandshakeMessage2.from_wire(transport.recv_json(sock))
        msg3, channel = initiator_finish(me, trust_store, state, msg2)
        transport.send_json(sock, msg3.to_wire())

        print("[alice] handshake complete - mutual authentication succeeded.")
        print("[alice] session secured with AES-256-GCM. Type messages below.\n")

        # --- Encrypted chat loop ---
        while True:
            text = input("[alice] > ")
            transport.send_bytes(sock, channel.encrypt(text.encode("utf-8")))
            if text.strip().lower() == "/quit":
                break
            framed = transport.recv_bytes(sock)
            try:
                plaintext = channel.decrypt(framed)
            except (ReplayError, TamperError) as e:
                print(f"[alice] SECURITY ALERT: {e}")
                continue
            reply = plaintext.decode("utf-8")
            print(f"[bob] {reply}")
            if reply.strip().lower() == "/quit":
                break

    except HandshakeError as e:
        print(f"[alice] HANDSHAKE FAILED: {e}")
    except (ConnectionError, OSError) as e:
        print(f"[alice] connection error: {e}")
    finally:
        sock.close()


if __name__ == "__main__":
    main()
