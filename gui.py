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
import queue
import socket
import threading
import tkinter as tk
from datetime import datetime
from tkinter import messagebox, scrolledtext, ttk

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
from identity import Identity, TrustStore
from secure_channel import ReplayError, TamperError

KEY_DIR = "./gui_keys"


def load_or_create_identity(name: str) -> Identity:
    try:
        return Identity.load(name, KEY_DIR)
    except FileNotFoundError:
        identity = Identity(name)
        identity.save(KEY_DIR)
        return identity


def fingerprint_from_bytes(raw: bytes) -> str:
    digest = hashlib.sha256(raw).hexdigest()
    return ":".join(digest[i : i + 4] for i in range(0, 16, 4))


class PeerWorker(threading.Thread):
    """All networking + crypto runs here, off the GUI thread. Talks back
    to the GUI only through a thread-safe queue of event dicts, and any
    time it needs a decision from the human (e.g. "trust this new
    identity?") it blocks on a threading.Event until the GUI thread
    supplies an answer - this keeps Tk's single-threaded UI rule intact
    while still letting the crypto/network code run synchronously."""

    def __init__(self, name: str, role: str, host: str, port: int, events: queue.Queue):
        super().__init__(daemon=True)
        self.name = name
        self.role = role  # "host" or "connect"
        self.host = host
        self.port = port
        self.events = events
        self.sock = None
        self.channel = None
        self.peer_name = None
        self._stop = threading.Event()

    def emit(self, kind, **kwargs):
        self.events.put({"kind": kind, **kwargs})

    def run(self):
        try:
            self.identity = load_or_create_identity(self.name)
            self.trust_store = TrustStore.load(f"{KEY_DIR}/{self.name}_trust.json")
            self.emit("identity", fingerprint=self.identity.fingerprint)

            if self.role == "host":
                self._run_host()
            else:
                self._run_connect()
        except HandshakeError as e:
            self.emit("error", text=f"Handshake failed: {e}")
            return
        except (ConnectionError, OSError) as e:
            self.emit("error", text=f"Connection error: {e}")
            return
        except Exception as e:  # noqa: BLE001 - surface anything unexpected to the UI
            self.emit("error", text=f"Unexpected error: {e}")
            return

        self._recv_loop()

    def _run_host(self):
        self.emit(
            "status", text=f"Waiting for a connection on {self.host}:{self.port}..."
        )
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((self.host, self.port))
        srv.listen(1)
        conn, addr = srv.accept()
        srv.close()
        self.sock = conn
        self.emit("status", text=f"Connection from {addr[0]}:{addr[1]}")

        self._exchange_identity_and_pin()

        msg1 = HandshakeMessage1.from_wire(transport.recv_json(self.sock))
        msg2, state = responder_respond(self.identity, msg1)
        transport.send_json(self.sock, msg2.to_wire())
        msg3 = HandshakeMessage3.from_wire(transport.recv_json(self.sock))
        self.channel = responder_finish(self.trust_store, state, msg3)
        self.emit("handshake_done")

    def _run_connect(self):
        self.emit("status", text=f"Connecting to {self.host}:{self.port}...")
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
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
        self.emit("handshake_done")

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
            fp = fingerprint_from_bytes(peer_pub)
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
        while not self._stop.is_set():
            try:
                framed = transport.recv_bytes(self.sock)
            except (ConnectionError, OSError):
                self.emit("status", text="Connection closed.")
                return
            try:
                plaintext = self.channel.decrypt(framed)
            except (ReplayError, TamperError) as e:
                self.emit("security_alert", text=str(e))
                continue
            self.emit(
                "message",
                sender=self.peer_name,
                text=plaintext.decode("utf-8", "replace"),
            )

    def send(self, text: str):
        if self.channel is None or self.sock is None:
            return
        framed = self.channel.encrypt(text.encode("utf-8"))
        transport.send_bytes(self.sock, framed)

    def stop(self):
        self._stop.set()
        try:
            if self.sock:
                self.sock.close()
        except OSError:
            pass


class SecureCommsApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Secure Comms")
        self.geometry("560x640")
        self.minsize(420, 480)

        self.worker: PeerWorker | None = None
        self.events: queue.Queue = queue.Queue()

        self._build_connect_frame()
        self._build_chat_frame()
        self.chat_frame.pack_forget()

        self.protocol("WM_DELETE_WINDOW", self._on_close)
        self.after(100, self._poll_events)

    # -- layout --------------------------------------------------------

    def _build_connect_frame(self):
        frame = ttk.Frame(self, padding=20)
        frame.pack(fill="both", expand=True)
        self.connect_frame = frame

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
        self.port_var = tk.StringVar(value="6543")
        ttk.Entry(form, textvariable=self.port_var).grid(
            row=2, column=1, sticky="ew", pady=4
        )

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
        ttk.Label(frame, textvariable=self.fingerprint_var, font=("Courier", 10)).pack()

    def _build_chat_frame(self):
        frame = ttk.Frame(self, padding=12)
        self.chat_frame = frame

        self.header_var = tk.StringVar(value="")
        ttk.Label(
            frame, textvariable=self.header_var, font=("", 11, "bold"), wraplength=520
        ).pack(anchor="w")

        self.log = scrolledtext.ScrolledText(frame, state="disabled", wrap="word")
        self.log.pack(fill="both", expand=True, pady=8)
        self.log.tag_config("me", foreground="#0b5fff")
        self.log.tag_config("peer", foreground="#1a7a1a")
        self.log.tag_config("system", foreground="#888888")
        self.log.tag_config("alert", foreground="#cc0000", font=("", 10, "bold"))

        entry_row = ttk.Frame(frame)
        entry_row.pack(fill="x")
        self.msg_var = tk.StringVar()
        entry = ttk.Entry(entry_row, textvariable=self.msg_var)
        entry.pack(side="left", fill="x", expand=True)
        entry.bind("<Return>", lambda _e: self._send())
        ttk.Button(entry_row, text="Send", command=self._send).pack(
            side="left", padx=(6, 0)
        )
        self.msg_entry = entry

    # -- actions ---------------------------------------------------------

    def _start_host(self):
        self._start_worker("host")

    def _start_connect(self):
        self._start_worker("connect")

    def _start_worker(self, role: str):
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

        self.host_btn.state(["disabled"])
        self.connect_btn.state(["disabled"])
        self.status_var.set("Starting...")
        self.worker = PeerWorker(name, role, host, port, self.events)
        self.worker.start()

    def _send(self):
        text = self.msg_var.get()
        if not text or self.worker is None or self.worker.channel is None:
            return
        self.worker.send(text)
        self._log(text, "me", label=self.worker.name)
        self.msg_var.set("")

    def _log(self, text: str, tag: str, label: str | None = None):
        self.log.configure(state="normal")
        ts = datetime.now().strftime("%H:%M:%S")
        prefix = f"[{ts}] {label}: " if label else f"[{ts}] "
        self.log.insert("end", prefix + text + "\n", tag)
        self.log.see("end")
        self.log.configure(state="disabled")

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
        if kind == "identity":
            self.fingerprint_var.set(f"Your identity fingerprint: {ev['fingerprint']}")
        elif kind == "status":
            self.status_var.set(ev["text"])
        elif kind == "error":
            self.status_var.set(ev["text"])
            self.host_btn.state(["!disabled"])
            self.connect_btn.state(["!disabled"])
            messagebox.showerror("Error", ev["text"])
        elif kind == "trust_prompt":
            trusted = messagebox.askyesno(
                "Verify new identity",
                f"'{ev['name']}' is presenting identity fingerprint:\n\n"
                f"    {ev['fingerprint']}\n\n"
                f"This is a Trust-On-First-Use pin, like an SSH host key. "
                f"Ideally you'd confirm this fingerprint with '{ev['name']}' "
                f"over a separate channel (phone call, in person) before "
                f"trusting it - anyone claiming to be '{ev['name']}' can "
                f"connect otherwise.\n\nTrust '{ev['name']}' and pin this key?",
            )
            ev["response"]["trusted"] = trusted
            ev["event"].set()
        elif kind == "handshake_done":
            self.status_var.set("Secure channel established.")
            self.header_var.set(
                f"\U0001f512 Encrypted chat with {self.worker.peer_name}  "
                f"(AES-256-GCM, mutually authenticated, forward-secret)"
            )
            self.connect_frame.pack_forget()
            self.chat_frame.pack(fill="both", expand=True)
            self._log(
                "Handshake complete - mutual authentication succeeded. "
                "Session is now end-to-end encrypted.",
                "system",
            )
            self.msg_entry.focus_set()
        elif kind == "message":
            self._log(ev["text"], "peer", label=ev["sender"])
        elif kind == "security_alert":
            self._log(f"SECURITY ALERT: {ev['text']}", "alert")

    def _on_close(self):
        if self.worker:
            self.worker.stop()
        self.destroy()


if __name__ == "__main__":
    app = SecureCommsApp()
    app.mainloop()
