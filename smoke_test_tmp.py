import os, tempfile, queue, hashlib, shutil, sys
sys.path.insert(0, '.')
from rate_limiter import SQLiteRateLimiter

d = tempfile.mkdtemp()
try:
    db = os.path.join(d, 'rl.db')
    rl = SQLiteRateLimiter(db, max_attempts=3, window_seconds=60.0, cooldown_seconds=30.0)
    t = 1000.0
    assert not rl.is_blocked('1.2.3.4', now=t)
    rl.record_failure('1.2.3.4', now=t)
    rl.record_failure('1.2.3.4', now=t+1)
    assert not rl.is_blocked('1.2.3.4', now=t+1)
    rl.record_failure('1.2.3.4', now=t+2)
    assert rl.is_blocked('1.2.3.4', now=t+2)
    rl.close()
    rl2 = SQLiteRateLimiter(db, max_attempts=3, window_seconds=60.0, cooldown_seconds=30.0)
    assert rl2.is_blocked('1.2.3.4', now=t+2)
    assert not rl2.is_blocked('1.2.3.4', now=t+33)
    rl2.close()
    print('rate_limiter ok')
finally:
    shutil.rmtree(d)

import gui
d = tempfile.mkdtemp()
try:
    class MP:
        def setattr(self, obj, name, val):
            setattr(obj, name, val)
    mp = MP()
    mp.setattr(gui, 'FILE_RECV_DIR', os.path.join(d, 'recv'))
    # empty file
    empty = os.path.join(d, 'empty.bin')
    with open(empty, 'wb') as f: pass
    worker = gui.PeerWorker('alice', 'connect', '127.0.0.1', 8000, queue.Queue())
    worker.peer_name = 'bob'
    worker._send_file(empty)
    evs = []
    while True:
        try: evs.append(worker.events.get_nowait())
        except queue.Empty: break
    assert any(e['kind']=='file_send_failed' and 'empty' in e['text'] for e in evs), evs
    # normal send
    payload_path = os.path.join(d, 'payload.bin')
    content = b'hello world' * 100
    with open(payload_path, 'wb') as f: f.write(content)
    worker3 = gui.PeerWorker('alice', 'connect', '127.0.0.1', 8000, queue.Queue())
    worker3.peer_name = 'bob'
    worker3.sock = object()
    worker3.channel = object()
    sent_chunks = []
    def fake_send_raw(plaintext):
        sent_chunks.append(plaintext)
    worker3._send_raw = fake_send_raw
    worker3._send_file(payload_path)
    evs = []
    while True:
        try: evs.append(worker3.events.get_nowait())
        except queue.Empty: break
    kinds = [e['kind'] for e in evs]
    assert 'file_sent' in kinds, kinds
    import json
    meta = json.loads(sent_chunks[0][1:].decode('utf-8'))
    assert meta['sha256'] == hashlib.sha256(content).hexdigest()
    got = b''
    for c in sent_chunks[1:]:
        assert c[0] == gui.MSG_FILE_CHUNK
        got += c[17:]
    assert got == content
    # channel replaced mid-transfer
    mp.setattr(gui, 'FILE_CHUNK_SIZE', 10)
    worker4 = gui.PeerWorker('alice', 'connect', '127.0.0.1', 8000, queue.Queue())
    worker4.sock = object()
    worker4.channel = object()
    calls = []
    def fake_send_raw2(plaintext):
        calls.append(plaintext)
        if len(calls) == 2:
            worker4.channel = object()
    worker4._send_raw = fake_send_raw2
    p = os.path.join(d, 'p.bin')
    with open(p, 'wb') as f: f.write(b'x'*55)
    worker4._send_file(p)
    evs = []
    while True:
        try: evs.append(worker4.events.get_nowait())
        except queue.Empty: break
    assert evs[-1]['kind'] == 'file_send_failed'
    assert len(calls) == 2
    print('gui ok')
finally:
    shutil.rmtree(d)
