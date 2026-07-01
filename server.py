"""
server.py
---------
Demo server ("bob"). Runs the responder side of the handshake, then
exchanges encrypted chat messages over the resulting SecureChannel.

Usage:
    python3 server.py
"""

import socket

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

HOST, PORT = "127.0.0.1", 6543
KEY_DIR = "./demo_keys"


def load_or_create_identity(name: str) -> Identity:
    try:
        return Identity.load(name, KEY_DIR)
    except FileNotFoundError:
        identity = Identity(name)
        identity.save(KEY_DIR)
        return identity


def main():
    me = load_or_create_identity("bob")
    trust_store = TrustStore.load(f"{KEY_DIR}/bob_trust.json")

    print(f"[bob] identity fingerprint: {me.fingerprint}")
    print("[bob] waiting for 'alice' to connect and share her identity...")

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((HOST, PORT))
    srv.listen(1)
    conn, addr = srv.accept()
    print(f"[bob] connection from {addr}")

    try:
        # --- TOFU: on first contact, learn and pin the peer's public key ---
        # (In a real system this pinning step would require independent
        # out-of-band verification of the fingerprint - e.g. reading it
        # aloud over a phone call - to actually prevent MITM on first use.)
        peer_intro = transport.recv_json(conn)
        peer_name = peer_intro["name"]
        peer_pubkey = bytes.fromhex(peer_intro["identity_pub"])
        if trust_store.get(peer_name) is None:
            trust_store.pin(peer_name, peer_pubkey)
            trust_store.save(f"{KEY_DIR}/bob_trust.json")
            print(f"[bob] TOFU: pinned new identity '{peer_name}'")
        elif not trust_store.is_trusted(peer_name, peer_pubkey):
            print(
                f"[bob] !!! WARNING: '{peer_name}' presented a DIFFERENT "
                f"public key than the one we have pinned. Possible "
                f"impersonation. Aborting."
            )
            conn.close()
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
            print(f"[alice] {text}")
            if text.strip().lower() == "/quit":
                break
            reply = input("[bob] > ")
            transport.send_bytes(conn, channel.encrypt(reply.encode("utf-8")))
            if reply.strip().lower() == "/quit":
                break

    except HandshakeError as e:
        print(f"[bob] HANDSHAKE FAILED: {e}")
    except (ConnectionError, OSError) as e:
        print(f"[bob] connection error: {e}")
    finally:
        conn.close()
        srv.close()


if __name__ == "__main__":
    main()
