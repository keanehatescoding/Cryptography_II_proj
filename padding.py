"""
padding.py
----------
Pads plaintext to a fixed-size bucket before encryption, so ciphertext
length reveals only which size bucket a message falls into, not its
exact length.

AES-GCM - like any stream/CTR-mode AEAD - does NOT hide plaintext
length on its own: ciphertext length is always plaintext length plus a
fixed 16-byte tag. Without padding, an eavesdropper who can't read the
contents can often still learn a lot from lengths alone: distinguishing
a "yes" from a longer reply, fingerprinting which of a known set of
canned responses was sent, or inferring message structure over time.
This is exactly the kind of side channel AEAD's confidentiality
guarantee does NOT cover - it's a separate problem that needs a
separate mitigation.

Padding scheme: [4-byte original length, big-endian][original bytes]
[zero bytes out to the chosen bucket size]. The bucket is the smallest
entry in BUCKETS that fits the framed (4 + len(plaintext)) size; a
message larger than the biggest bucket is padded up to the next
multiple of the biggest bucket instead, so arbitrarily large messages
are still supported, just with coarser bucketing beyond that point.

This hides individual message LENGTH. It does NOT hide the number of
messages sent, their timing, or which direction they flow - a complete
traffic-analysis defense would need cover traffic and timing
obfuscation too, which is out of scope here.
"""

BUCKETS = (32, 64, 128, 256, 512, 1024, 2048, 4096, 8192)
LENGTH_PREFIX_SIZE = 4
MAX_PLAINTEXT_SIZE = 0xFFFFFFFF  # fits in the 4-byte length prefix


class PaddingError(Exception):
    pass


def pad(plaintext: bytes) -> bytes:
    if len(plaintext) > MAX_PLAINTEXT_SIZE:
        raise PaddingError(
            f"Message of {len(plaintext)} bytes exceeds the maximum "
            f"{MAX_PLAINTEXT_SIZE} bytes representable in the length prefix."
        )

    framed = len(plaintext).to_bytes(LENGTH_PREFIX_SIZE, "big") + plaintext
    target = _bucket_for(len(framed))
    return framed + b"\x00" * (target - len(framed))


def unpad(padded: bytes) -> bytes:
    if len(padded) < LENGTH_PREFIX_SIZE:
        raise PaddingError("Padded message too short to contain a length prefix.")

    original_length = int.from_bytes(padded[:LENGTH_PREFIX_SIZE], "big")
    end = LENGTH_PREFIX_SIZE + original_length
    if end > len(padded):
        raise PaddingError(
            "Encoded length exceeds the padded message size - corrupt or "
            "tampered padding."
        )
    return padded[LENGTH_PREFIX_SIZE:end]


def _bucket_for(framed_size: int) -> int:
    for bucket in BUCKETS:
        if framed_size <= bucket:
            return bucket
    largest = BUCKETS[-1]
    return ((framed_size + largest - 1) // largest) * largest
