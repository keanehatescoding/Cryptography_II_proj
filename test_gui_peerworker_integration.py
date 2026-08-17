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
import history


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


def test_history_persists_across_a_restart_and_replays_for_the_same_peer(tmp_path, monkeypatch):
    """End-to-end: two real PeerWorkers, real handshake, real chat, with
    save_history=True on both sides. Stop them, start a brand-new pair of
    workers under the same names/passphrases (simulating the app being
    closed and reopened), and confirm the prior conversation comes back
    via a history_loaded event - scoped to the right peer."""
    monkeypatch.setattr(gui, "FILE_RECV_DIR", tmp_path / "received")
    monkeypatch.setattr(gui, "KEY_DIR", str(tmp_path / "keys"))

    def run_session(port, host_events=None, connect_events=None):
        host_events = host_events if host_events is not None else []
        connect_events = connect_events if connect_events is not None else []
        host_worker = gui.PeerWorker(
            "bob4", "host", "127.0.0.1", port, queue.Queue(),
            passphrase="hunter2", save_history=True,
        )
        connect_worker = gui.PeerWorker(
            "alice4", "connect", "127.0.0.1", port, queue.Queue(),
            passphrase="hunter2", save_history=True,
        )
        _start_event_pump(host_worker, host_events)
        _start_event_pump(connect_worker, connect_events)
        host_worker.start()
        assert _wait_for(lambda: host_worker._srv is not None, timeout=5)
        connect_worker.start()
        # Wait for handshake_done specifically (not just channel being
        # set): history_loaded is emitted strictly before handshake_done,
        # so once handshake_done has actually landed in the collected
        # events list, history_loaded is guaranteed to already be there
        # too - checking channel directly races the event-pump thread.
        assert _wait_for(
            lambda: any(e["kind"] == "handshake_done" for e in host_events)
            and any(e["kind"] == "handshake_done" for e in connect_events),
            timeout=10,
        )
        return host_worker, connect_worker, host_events, connect_events

    port = _free_port()
    host1, connect1, host1_events, connect1_events = run_session(port)
    try:
        connect1.send("hello from session one")
        assert _wait_for(
            lambda: any(
                e["kind"] == "message" and e.get("text") == "hello from session one"
                for e in host1_events
            ),
            timeout=5,
        )
        host1.send("got it, bob here")
        assert _wait_for(
            lambda: any(
                e["kind"] == "message" and e.get("text") == "got it, bob here"
                for e in connect1_events
            ),
            timeout=5,
        )
    finally:
        connect1.stop()
        host1.stop()
        connect1.join(timeout=5)
        host1.join(timeout=5)

    # A fresh pair of workers, same identities/passphrases, different port
    # (simulates closing and reopening the app) - history must survive.
    port2 = _free_port()
    host2, connect2, host2_events, connect2_events = run_session(port2)
    try:
        host2_history = [e for e in host2_events if e["kind"] == "history_loaded"]
        connect2_history = [e for e in connect2_events if e["kind"] == "history_loaded"]
        assert len(host2_history) == 1
        assert len(connect2_history) == 1

        host_texts = [(e["direction"], e["text"]) for e in host2_history[0]["entries"]]
        connect_texts = [(e["direction"], e["text"]) for e in connect2_history[0]["entries"]]
        assert host_texts == [
            ("received", "hello from session one"),
            ("sent", "got it, bob here"),
        ]
        assert connect_texts == [
            ("sent", "hello from session one"),
            ("received", "got it, bob here"),
        ]
    finally:
        connect2.stop()
        host2.stop()
        connect2.join(timeout=5)
        host2.join(timeout=5)


def test_history_replay_latch_is_per_peer_not_worker_wide(tmp_path, monkeypatch):
    """Regression test: one host worker's listening socket persists
    across reconnects, so it can go on to serve a completely different
    peer after the first one disconnects (see PeerWorker docstring). The
    history-replay-once guard must therefore track "have I shown peer X
    their history yet", not "have I shown history at all" - otherwise the
    second, different peer never gets their own (real, pre-existing)
    history replayed just because some earlier peer already consumed a
    worker-wide latch."""
    monkeypatch.setattr(gui, "FILE_RECV_DIR", tmp_path / "received")
    keydir = tmp_path / "keys"
    monkeypatch.setattr(gui, "KEY_DIR", str(keydir))

    # Pre-seed hostX's history with a prior conversation with peerB -
    # simulates a session that happened before this test even starts.
    seeded = history.EncryptedHistory.load("hostX", str(keydir), passphrase="hostpass")
    seeded.append("peerB", "received", "message from a previous session")

    port = _free_port()
    host_worker = gui.PeerWorker(
        "hostX", "host", "127.0.0.1", port, queue.Queue(),
        passphrase="hostpass", save_history=True,
    )
    host_seen = []
    _start_event_pump(host_worker, host_seen)

    try:
        host_worker.start()
        assert _wait_for(lambda: host_worker._srv is not None, timeout=5)

        # peerA connects first - brand new peer, no prior history - then
        # disconnects (without stopping the host).
        peer_a = gui.PeerWorker("peerA", "connect", "127.0.0.1", port, queue.Queue())
        _start_event_pump(peer_a, [])
        peer_a.start()
        assert _wait_for(
            lambda: any(e["kind"] == "handshake_done" for e in host_seen), timeout=10
        )
        peer_a.stop()
        peer_a.join(timeout=5)
        assert _wait_for(
            lambda: any(e["kind"] == "connection_lost" for e in host_seen), timeout=5
        ), "host never noticed peerA disconnect"

        # host goes back to listening; peerB (who HAS prior history with
        # hostX) connects next.
        peer_b = gui.PeerWorker(
            "peerB", "connect", "127.0.0.1", port, queue.Queue(), passphrase="anything"
        )
        peer_b_seen = []
        _start_event_pump(peer_b, peer_b_seen)
        peer_b.start()
        try:
            assert _wait_for(
                lambda: sum(1 for e in host_seen if e["kind"] == "handshake_done") >= 2,
                timeout=10,
            ), "host never completed a second handshake, with peerB"

            # One history_loaded event per peer (peerA's is empty - a
            # brand new peer with no prior history - peerB's has the
            # pre-seeded entry). Both must be present: peerA's empty one
            # proves the latch fired for peerA at all, and peerB's
            # non-empty one is the actual regression this test guards.
            host_history_events = [e for e in host_seen if e["kind"] == "history_loaded"]
            assert len(host_history_events) == 2
            all_texts = [e["text"] for ev in host_history_events for e in ev["entries"]]
            assert all_texts == ["message from a previous session"], (
                "peerB's real prior history must still be replayed even though "
                "peerA (a different, history-less peer) already connected once"
            )
        finally:
            peer_b.stop()
            peer_b.join(timeout=5)
    finally:
        host_worker.stop()
        host_worker.join(timeout=5)


def test_history_write_failure_disables_history_without_killing_the_session(monkeypatch):
    """Regression test: a local disk error persisting history (full disk,
    permissions, ...) must not take the whole chat session down with it -
    history is a nice-to-have layered on top of the conversation. Drives
    PeerWorker._append_history directly (no real socket needed) with a
    fake history object that always fails to append."""
    worker = gui.PeerWorker("alice5", "connect", "127.0.0.1", 8000, queue.Queue())
    worker.peer_name = "bob5"

    class BrokenHistory:
        def append(self, peer_name, direction, text):
            raise OSError("No space left on device")

    worker.history = BrokenHistory()
    worker._append_history("sent", "this should not crash anything")

    assert worker.history is None, "history must be disabled after a persistence failure"
    events = []
    while True:
        try:
            events.append(worker.events.get_nowait())
        except queue.Empty:
            break
    assert len(events) == 1
    assert events[0]["kind"] == "status"
    assert events[0]["text"] == "Chat history disabled: No space left on device"
    assert events[0]["session_id"] == worker.session_id
