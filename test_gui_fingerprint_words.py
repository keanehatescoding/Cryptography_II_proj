"""
test_gui_fingerprint_words.py
-------------------------------
Covers gui.py's word-list rendering of the hex identity fingerprint
(identity.fingerprint_for_bytes) used for out-of-band verification in the
GUI - purely a display-formatting concern, not cryptographic logic, so
these only touch gui.py's helper functions directly.

Run with:  python3 -m pytest test_gui_fingerprint_words.py -v
"""

import gui
from identity import fingerprint_for_bytes


def test_adjective_and_noun_lists_have_no_duplicates():
    assert len(gui._FINGERPRINT_ADJECTIVES) == 16
    assert len(set(gui._FINGERPRINT_ADJECTIVES)) == 16
    assert len(gui._FINGERPRINT_NOUNS) == 16
    assert len(set(gui._FINGERPRINT_NOUNS)) == 16


def test_every_byte_value_maps_to_a_distinct_word_pair():
    pairs = {bytes([b]).hex(): gui._fingerprint_to_words(bytes([b]).hex()) for b in range(256)}
    assert len(set(pairs.values())) == 256, "every byte 0-255 must produce a unique word pair"


def test_word_pair_matches_adjective_high_nibble_noun_low_nibble():
    for b in range(256):
        expected = f"{gui._FINGERPRINT_ADJECTIVES[b >> 4]}-{gui._FINGERPRINT_NOUNS[b & 0x0F]}"
        assert gui._fingerprint_to_words(bytes([b]).hex()) == expected


def test_accepts_the_colon_grouped_fingerprint_format():
    raw = bytes(range(8))
    plain = gui._fingerprint_to_words(raw.hex())
    grouped = gui._fingerprint_to_words(":".join(raw.hex()[i : i + 4] for i in range(0, 16, 4)))
    assert plain == grouped


def test_matches_the_real_identity_fingerprint_format(monkeypatch):
    fp = fingerprint_for_bytes(b"some fake public key bytes for this test")
    words = gui._fingerprint_to_words(fp)
    assert len(words.split(" ")) == 8, "the 16-hex-char fingerprint is 8 bytes -> 8 word pairs"
    for pair in words.split(" "):
        adjective, noun = pair.split("-")
        assert adjective in gui._FINGERPRINT_ADJECTIVES
        assert noun in gui._FINGERPRINT_NOUNS


def test_is_deterministic():
    fp = fingerprint_for_bytes(b"another fake key")
    assert gui._fingerprint_to_words(fp) == gui._fingerprint_to_words(fp)


def test_different_fingerprints_produce_different_phrases():
    fp_a = fingerprint_for_bytes(b"key A")
    fp_b = fingerprint_for_bytes(b"key B")
    assert gui._fingerprint_to_words(fp_a) != gui._fingerprint_to_words(fp_b)
