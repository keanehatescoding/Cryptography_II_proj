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
import sys
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


def test_concurrent_sends_do_not_corrupt_the_channel(tmp_path, monkeypatch):
    """Regression test: SecureChannel.encrypt() mutates shared ratchet state
    (send counter, sending chain, and possibly a rekey step), so concurrent
    callers on different threads (e.g. a text send racing a background
    file-send) MUST be serialized around encrypt() itself, not just the
    socket write - otherwise two threads can grab the same counter, which
    reuses an AES-GCM nonce, or tear a rekey step in half and desync the
    peer. Drives many concurrent send() calls from separate threads and
    checks every message arrives exactly once, undamaged."""
    monkeypatch.setattr(gui, "FILE_RECV_DIR", tmp_path / "received")
    monkeypatch.setattr(gui, "KEY_DIR", str(tmp_path / "keys"))
    # A shorter GIL switch interval makes CPython swap threads far more
    # often, which is what actually makes this race land reliably instead
    # of only once in a while.
    old_interval = sys.getswitchinterval()
    host_worker = connect_worker = None

    try:
        sys.setswitchinterval(1e-6)

        port = _free_port()
        host_worker = gui.PeerWorker("bob2", "host", "127.0.0.1", port, queue.Queue())
        connect_worker = gui.PeerWorker("alice2", "connect", "127.0.0.1", port, queue.Queue())

        host_seen, connect_seen = [], []
        _start_event_pump(host_worker, host_seen)
        _start_event_pump(connect_worker, connect_seen)

        host_worker.start()
        assert _wait_for(lambda: host_worker._srv is not None, timeout=5)
        connect_worker.start()
        assert _wait_for(
            lambda: host_worker.channel is not None and connect_worker.channel is not None,
            timeout=10,
        )

        n = 60
        # A barrier makes every thread call send() as close to
        # simultaneously as possible, which is what actually exercises the
        # race instead of threads trickling in one at a time.
        barrier = threading.Barrier(n)

        def _send(i):
            barrier.wait()
            connect_worker.send(f"msg-{i}")

        threads = [threading.Thread(target=_send, args=(i,)) for i in range(n)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=5)
        assert not any(t.is_alive() for t in threads), (
            "a sender thread didn't finish within the join timeout"
        )

        assert _wait_for(
            lambda: sum(1 for e in host_seen if e["kind"] == "message") >= n, timeout=10
        ), f"only received {sum(1 for e in host_seen if e['kind'] == 'message')}/{n} messages"

        received_texts = [e["text"] for e in host_seen if e["kind"] == "message"]
        assert len(received_texts) == n, (
            f"expected exactly {n} messages, got {len(received_texts)} "
            "(a race would show up as duplicates or drops)"
        )
        assert set(received_texts) == {f"msg-{i}" for i in range(n)}
        assert not any(e["kind"] in ("security_alert",) for e in host_seen), (
            "a torn/duplicated counter would surface as a tamper/replay alert"
        )
    finally:
        if connect_worker is not None:
            connect_worker.stop()
        if host_worker is not None:
            host_worker.stop()
        if connect_worker is not None:
            connect_worker.join(timeout=5)
        if host_worker is not None:
            host_worker.join(timeout=5)
        sys.setswitchinterval(old_interval)


def test_stalled_peer_does_not_block_later_peers(tmp_path, monkeypatch):
    """Regression test: the host's listening socket is now persistent
    across reconnects (see PeerWorker docstring), so a peer that opens
    the TCP connection and then sends nothing must time out instead of
    hanging the worker thread forever - otherwise every later peer would
    be blocked out indefinitely by one stalled connection."""
    monkeypatch.setattr(gui, "FILE_RECV_DIR", tmp_path / "received")
    monkeypatch.setattr(gui, "KEY_DIR", str(tmp_path / "keys"))
    monkeypatch.setattr(gui.PeerWorker, "HANDSHAKE_TIMEOUT", 0.5)

    port = _free_port()
    host_worker = gui.PeerWorker("bob3", "host", "127.0.0.1", port, queue.Queue())
    host_seen = []
    _start_event_pump(host_worker, host_seen)

    try:
        host_worker.start()
        assert _wait_for(lambda: host_worker._srv is not None, timeout=5)

        # Connects but never speaks - the old behavior hung the worker
        # thread here forever.
        stalled = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        stalled.connect(("127.0.0.1", port))
        assert _wait_for(
            lambda: any(
                e["kind"] == "status" and "Waiting for next peer" in e.get("text", "")
                for e in host_seen
            ),
            timeout=5,
        ), "stalled peer's handshake never timed out"
        stalled.close()

        # A real peer must still be able to connect afterward - proves
        # the accept loop wasn't left permanently stuck on the first one.
        connect_worker = gui.PeerWorker("alice3", "connect", "127.0.0.1", port, queue.Queue())
        _start_event_pump(connect_worker, [])
        connect_worker.start()
        try:
            assert _wait_for(
                lambda: host_worker.channel is not None and connect_worker.channel is not None,
                timeout=10,
            ), "a real peer couldn't connect after the stalled one timed out"
        finally:
            connect_worker.stop()
            connect_worker.join(timeout=5)
    finally:
        host_worker.stop()
        host_worker.join(timeout=5)
