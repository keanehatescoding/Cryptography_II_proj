"""
test_gui_peerworker_integration.py
------------------------------------
End-to-end tests of gui.py's PeerWorker over real loopback TCP sockets and
real threads - no Tk widgets involved (PeerWorker has no Tk dependency; it
only ever talks to its consumer through a queue.Queue of event dicts, which
these tests stand in for directly). Covers the two behaviors added on top
of the original single-shot worker: multi-chunk file transfer, and
automatic reconnect-with-backoff after a dropped connection.

Run with:  python3 -m pytest test_gui_peerworker_integration.py -v
"""

import queue
import socket
import threading
import time

import gui


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _start_event_pump(worker: gui.PeerWorker, collected: list):
    """Stands in for the GUI thread: drains worker.events forever, auto-
    accepting any trust prompt (equivalent to the user clicking "Yes" on
    the TOFU verification dialog) and recording everything else."""

    def _run():
        while True:
            ev = worker.events.get()
            collected.append(ev)
            if ev["kind"] == "trust_prompt":
                ev["response"]["trusted"] = True
                ev["event"].set()

    t = threading.Thread(target=_run, daemon=True)
    t.start()
    return t


def _wait_for(predicate, timeout: float = 10.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if predicate():
            return True
        time.sleep(0.02)
    return False


def test_end_to_end_handshake_chat_file_transfer_and_reconnect(tmp_path, monkeypatch):
    monkeypatch.setattr(gui, "FILE_RECV_DIR", tmp_path / "received")
    monkeypatch.setattr(gui, "KEY_DIR", str(tmp_path / "keys"))

    port = _free_port()
    host_worker = gui.PeerWorker("bob", "host", "127.0.0.1", port, queue.Queue())
    connect_worker = gui.PeerWorker("alice", "connect", "127.0.0.1", port, queue.Queue())

    host_seen, connect_seen = [], []
    _start_event_pump(host_worker, host_seen)
    _start_event_pump(connect_worker, connect_seen)

    try:
        host_worker.start()
        assert _wait_for(lambda: host_worker._srv is not None, timeout=5), (
            "host never started listening"
        )
        connect_worker.start()

        assert _wait_for(
            lambda: host_worker.channel is not None and connect_worker.channel is not None,
            timeout=10,
        ), "initial handshake never completed on both sides"

        # -- bidirectional text --------------------------------------------
        connect_worker.send("hello from alice")
        assert _wait_for(
            lambda: any(
                e["kind"] == "message" and e.get("text") == "hello from alice"
                for e in host_seen
            ),
            timeout=5,
        )

        host_worker.send("hi alice, this is bob")
        assert _wait_for(
            lambda: any(
                e["kind"] == "message" and e.get("text") == "hi alice, this is bob"
                for e in connect_seen
            ),
            timeout=5,
        )

        # -- file transfer, large enough to span several chunks -------------
        payload = tmp_path / "payload.bin"
        payload.write_bytes(b"secure-comms-integration-test-payload-" * 20000)  # ~760 KB
        connect_worker.send_file(str(payload))

        assert _wait_for(
            lambda: any(e["kind"] == "file_received" for e in host_seen), timeout=15
        ), "file was never received"
        received = tmp_path / "received" / "payload.bin"
        assert received.read_bytes() == payload.read_bytes()
        assert not any(e["kind"] == "security_alert" for e in host_seen), (
            "integrity check should not have failed"
        )

        # -- dropped connection triggers automatic reconnect on both sides --
        # shutdown() before close() is required to simulate a real drop
        # here: plain close() from this (test) thread would not unblock
        # connect_worker's own thread, which is blocked in recv() on this
        # exact socket - see PeerWorker.stop()'s docstring-comment for why.
        old_connect_channel = connect_worker.channel
        connect_worker.sock.shutdown(socket.SHUT_RDWR)
        connect_worker.sock.close()

        assert _wait_for(
            lambda: any(e["kind"] == "connection_lost" for e in host_seen), timeout=5
        )
        assert _wait_for(
            lambda: any(e["kind"] == "connection_lost" for e in connect_seen), timeout=5
        )
        assert _wait_for(
            lambda: host_worker.channel is not None and connect_worker.channel is not None,
            timeout=15,
        ), "reconnect never completed on both sides"
        assert connect_worker.channel is not old_connect_channel, (
            "reconnect should perform a brand-new handshake, not resume the old one"
        )

        # channel still works post-reconnect
        connect_worker.send("still alive after reconnect")
        assert _wait_for(
            lambda: any(
                e["kind"] == "message" and e.get("text") == "still alive after reconnect"
                for e in host_seen
            ),
            timeout=5,
        )
    finally:
        connect_worker.stop()
        host_worker.stop()
        connect_worker.join(timeout=5)
        host_worker.join(timeout=5)
