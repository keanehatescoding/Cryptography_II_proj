"""
test_gui_empty_passphrase.py
---------------------------
Regression test for gui.load_or_create_identity() with an empty
passphrase: an empty string must be rejected (not silently coerced to
None, which would write an UNENCRYPTED key) for a newly-created
identity. Mirrors test_cli_identity_prompts.py for the GUI path.
"""

import pytest

import gui
from identity import Identity


def test_empty_passphrase_rejected_for_new_identity(tmp_path, monkeypatch):
    monkeypatch.setattr(gui, "KEY_DIR", str(tmp_path))

    with pytest.raises((gui.EmptyPassphraseError, ValueError, SystemExit)):
        gui.load_or_create_identity("alice", "")

    assert not (tmp_path / "alice_identity.pem").exists()


def test_none_passphrase_creates_unencrypted_identity(tmp_path, monkeypatch):
    monkeypatch.setattr(gui, "KEY_DIR", str(tmp_path))

    identity = gui.load_or_create_identity("alice", None)

    assert identity.name == "alice"
    assert Identity.is_encrypted("alice", str(tmp_path)) is False


def test_nonempty_passphrase_creates_encrypted_identity(tmp_path, monkeypatch):
    monkeypatch.setattr(gui, "KEY_DIR", str(tmp_path))

    identity = gui.load_or_create_identity("alice", "hunter2")

    assert identity.name == "alice"
    assert Identity.is_encrypted("alice", str(tmp_path)) is True