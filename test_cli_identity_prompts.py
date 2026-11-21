"""
test_cli_identity_prompts.py
----------------------------
Regression tests for the CLI identity-creation/load prompts shared by
client.py and server.py.

The bug under test: a user who answers "Y" to "Encrypt it with a
passphrase?" and then presses Enter at both passphrase prompts got an
empty string, which `passphrase or None` silently turned into
"no encryption requested" - writing a plaintext private key to disk
while the user believed they had opted into encryption. These tests pin
the corrected behavior: empty means abort, never silently unencrypted.
"""

import builtins
import getpass

import pytest

import client
import server
from identity import Identity


def _use_module(module, monkeypatch, tmp_path):
    """Point a CLI module's KEY_DIR at a fresh temp dir."""
    monkeypatch.setattr(module, "KEY_DIR", str(tmp_path))


@pytest.mark.parametrize("module", [client, server])
def test_opt_in_with_empty_passphrase_aborts_without_writing_a_key(
    module, monkeypatch, tmp_path
):
    """Answering 'Y' but entering an empty passphrase must NOT create an
    unencrypted identity key behind the user's back."""
    _use_module(module, monkeypatch, tmp_path)
    monkeypatch.setattr(builtins, "input", lambda prompt="": "y")
    monkeypatch.setattr(getpass, "getpass", lambda prompt="": "")

    with pytest.raises(SystemExit):
        module.load_or_create_identity("alice")

    assert not (tmp_path / "alice_identity.pem").exists()


@pytest.mark.parametrize("module", [client, server])
def test_opt_in_with_matching_passphrase_creates_encrypted_key(
    module, monkeypatch, tmp_path
):
    _use_module(module, monkeypatch, tmp_path)
    monkeypatch.setattr(builtins, "input", lambda prompt="": "y")
    monkeypatch.setattr(getpass, "getpass", lambda prompt="": "hunter2")

    identity = module.load_or_create_identity("alice")

    assert identity.name == "alice"
    assert Identity.is_encrypted("alice", str(tmp_path)) is True


@pytest.mark.parametrize("module", [client, server])
def test_opt_in_with_mismatched_confirmation_aborts(module, monkeypatch, tmp_path):
    _use_module(module, monkeypatch, tmp_path)
    monkeypatch.setattr(builtins, "input", lambda prompt="": "y")
    answers = iter(["one passphrase", "a different one"])
    monkeypatch.setattr(getpass, "getpass", lambda prompt="": next(answers))

    with pytest.raises(SystemExit):
        module.load_or_create_identity("alice")

    assert not (tmp_path / "alice_identity.pem").exists()


@pytest.mark.parametrize("module", [client, server])
def test_declining_encryption_still_creates_unencrypted_key(
    module, monkeypatch, tmp_path
):
    """Answering 'n' is an explicit choice for no encryption and must keep
    working - only the *opted-in but empty* case is ambiguous/dangerous."""
    _use_module(module, monkeypatch, tmp_path)
    monkeypatch.setattr(builtins, "input", lambda prompt="": "n")
    monkeypatch.setattr(
        getpass, "getpass", lambda prompt="": pytest.fail("must not prompt")
    )

    identity = module.load_or_create_identity("alice")

    assert Identity.is_encrypted("alice", str(tmp_path)) is False


@pytest.mark.parametrize("module", [client, server])
def test_empty_passphrase_for_existing_encrypted_key_reprompts_not_crashes(
    module, monkeypatch, tmp_path
):
    """Pressing Enter at the load prompt passes password=None to
    cryptography, which raises TypeError (not ValueError). The loop must
    treat that like a wrong passphrase instead of letting a traceback
    escape."""
    _use_module(module, monkeypatch, tmp_path)
    Identity("alice").save(str(tmp_path), passphrase="real passphrase")
    monkeypatch.setattr(getpass, "getpass", lambda prompt="": "")

    with pytest.raises(SystemExit):
        module.load_or_create_identity("alice")


@pytest.mark.parametrize("module", [client, server])
def test_correct_passphrase_loads_existing_encrypted_key(
    module, monkeypatch, tmp_path
):
    _use_module(module, monkeypatch, tmp_path)
    original = Identity("alice")
    original.save(str(tmp_path), passphrase="real passphrase")
    monkeypatch.setattr(getpass, "getpass", lambda prompt="": "real passphrase")

    loaded = module.load_or_create_identity("alice")

    assert loaded.fingerprint == original.fingerprint
