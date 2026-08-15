"""
test_gui_file_transfer.py
--------------------------
Covers the gui.py additions that don't require an actual Tk display or
socket: the file-transfer wire framing/state-machine on PeerWorker, and
the reconnect backoff math. These exercise PeerWorker's methods directly
(never .start()'d as a thread, never given a real socket) with a plain
queue.Queue standing in for the GUI's event loop.

Run with:  python3 -m pytest test_gui_file_transfer.py -v
"""

import hashlib
import queue

import gui


def make_worker(tmp_path, monkeypatch):
    monkeypatch.setattr(gui, "FILE_RECV_DIR", tmp_path)
    worker = gui.PeerWorker("alice", "connect", "127.0.0.1", 8000, queue.Queue())
    worker.peer_name = "bob"
    return worker


def drain(worker):
    events = []
    while True:
        try:
            events.append(worker.events.get_nowait())
        except queue.Empty:
            return events


# -- _human_size -------------------------------------------------------


def test_human_size_formats_each_unit():
    assert gui._human_size(0) == "0 B"
    assert gui._human_size(999) == "999 B"
    assert gui._human_size(2048) == "2.0 KB"
    assert gui._human_size(5 * 1024 * 1024) == "5.0 MB"
    assert gui._human_size(3 * 1024 ** 3) == "3.0 GB"


# -- _unique_dest_path ---------------------------------------------------


def test_unique_dest_path_avoids_collision(tmp_path):
    (tmp_path / "photo.png").write_bytes(b"existing")
    dest = gui._unique_dest_path(tmp_path, "photo.png")
    assert dest == tmp_path / "photo (1).png"


def test_unique_dest_path_strips_directory_traversal(tmp_path):
    dest = gui._unique_dest_path(tmp_path, "../../etc/passwd")
    assert dest.parent == tmp_path
    assert dest.name == "passwd"


def test_unique_dest_path_handles_empty_name(tmp_path):
    dest = gui._unique_dest_path(tmp_path, "")
    assert dest == tmp_path / "received_file"


# -- inbound file offer/chunk state machine -----------------------------


def test_full_file_transfer_roundtrip(tmp_path, monkeypatch):
    worker = make_worker(tmp_path, monkeypatch)
    content = b"the quick brown fox jumps over the lazy dog" * 100
    sha256_hex = hashlib.sha256(content).hexdigest()
    file_id = b"0123456789abcdef"

    worker._handle_plaintext(
        gui._encode_file_offer(file_id, "note.txt", len(content), sha256_hex)
    )
    mid = len(content) // 2
    worker._handle_plaintext(gui._encode_file_chunk(file_id, content[:mid]))
    worker._handle_plaintext(gui._encode_file_chunk(file_id, content[mid:]))

    events = drain(worker)
    kinds = [e["kind"] for e in events]
    assert kinds == ["file_offer", "file_recv_progress", "file_recv_progress", "file_received"]

    received_path = tmp_path / "note.txt"
    assert received_path.read_bytes() == content
    assert file_id not in worker._inbound_transfers


def test_corrupted_file_is_discarded_on_hash_mismatch(tmp_path, monkeypatch):
    worker = make_worker(tmp_path, monkeypatch)
    content = b"hello world"
    wrong_sha256 = hashlib.sha256(b"not the same content").hexdigest()
    file_id = b"0123456789abcdef"

    worker._handle_plaintext(gui._encode_file_offer(file_id, "msg.txt", len(content), wrong_sha256))
    worker._handle_plaintext(gui._encode_file_chunk(file_id, content))

    events = drain(worker)
    assert events[-1]["kind"] == "security_alert"
    assert "Integrity check failed" in events[-1]["text"]
    assert not (tmp_path / "msg.txt").exists()


def test_malformed_file_offer_is_rejected_without_crashing(tmp_path, monkeypatch):
    worker = make_worker(tmp_path, monkeypatch)
    worker._handle_plaintext(bytes([gui.MSG_FILE_OFFER]) + b"not json")

    events = drain(worker)
    assert events == [{"kind": "security_alert", "text": "Received a malformed file offer."}]
    assert worker._inbound_transfers == {}


def test_oversized_file_offer_is_refused(tmp_path, monkeypatch):
    worker = make_worker(tmp_path, monkeypatch)
    file_id = b"0123456789abcdef"
    oversized = gui.MAX_FILE_SIZE + 1
    worker._handle_plaintext(
        gui._encode_file_offer(file_id, "huge.bin", oversized, "deadbeef")
    )

    events = drain(worker)
    assert events[0]["kind"] == "security_alert"
    assert "oversized" in events[0]["text"]
    assert worker._inbound_transfers == {}


def test_chunk_with_no_matching_offer_is_dropped_silently(tmp_path, monkeypatch):
    worker = make_worker(tmp_path, monkeypatch)
    worker._handle_plaintext(gui._encode_file_chunk(b"0123456789abcdef", b"stray data"))

    assert drain(worker) == []


def test_abort_inbound_transfers_deletes_partial_file(tmp_path, monkeypatch):
    worker = make_worker(tmp_path, monkeypatch)
    file_id = b"0123456789abcdef"
    worker._handle_plaintext(
        gui._encode_file_offer(file_id, "partial.bin", 1_000_000, "deadbeef")
    )
    worker._handle_plaintext(gui._encode_file_chunk(file_id, b"only some bytes"))
    assert (tmp_path / "partial.bin").exists()

    worker._abort_inbound_transfers()

    assert not (tmp_path / "partial.bin").exists()
    assert worker._inbound_transfers == {}


# -- text messages still work alongside the new framing ------------------


def test_text_message_still_dispatches_as_before(tmp_path, monkeypatch):
    worker = make_worker(tmp_path, monkeypatch)
    worker._handle_plaintext(bytes([gui.MSG_TEXT]) + "hi there".encode("utf-8"))

    events = drain(worker)
    assert events == [{"kind": "message", "sender": "bob", "text": "hi there"}]


# -- reconnect backoff ----------------------------------------------------


def test_backoff_delay_grows_and_caps():
    assert gui.PeerWorker._compute_backoff_delay(1) == 1.0
    assert gui.PeerWorker._compute_backoff_delay(2) == 2.0
    assert gui.PeerWorker._compute_backoff_delay(3) == 4.0
    assert gui.PeerWorker._compute_backoff_delay(4) == 8.0
    assert gui.PeerWorker._compute_backoff_delay(5) == 16.0
    assert gui.PeerWorker._compute_backoff_delay(6) == 30.0  # capped
    assert gui.PeerWorker._compute_backoff_delay(20) == 30.0
