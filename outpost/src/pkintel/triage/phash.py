"""Perceptual hashing of logo/favicon images (pHash).

A perceptual hash is robust to re-encoding, resizing and minor edits, so it
catches brand logos that a kit author lightly modified to dodge exact-hash
matching. Compare an observed image's pHash against a curated brand-logo set
with :func:`hamming`; a small distance (empirically <= 10 on a 64-bit hash)
means "same logo".

PIL/imagehash are imported lazily inside the function so importing this module
stays cheap and never fails if the optional image stack is unavailable.
"""

from __future__ import annotations

import io

# Brand -> pHash (hex) of that brand's canonical logo.
#
# HOW TO GROW THIS: run each brand's official logo image through ``logo_phash``
# and store the resulting hex string here. At match time, compute the observed
# image's pHash and take ``hamming(observed, known)`` against every entry,
# flagging brands within a small threshold. Seeded empty on purpose.
KNOWN_LOGO_PHASHES: dict[str, str] = {}


def logo_phash(image_bytes: bytes | None) -> str | None:
    """Return the 64-bit perceptual hash (hex string) of ``image_bytes``.

    Returns ``None`` if the bytes are empty or cannot be decoded as an image, or
    if the optional PIL/imagehash stack is not installed. Purely in-memory; no
    I/O beyond decoding the provided bytes.
    """
    if not image_bytes:
        return None
    try:
        import imagehash
        from PIL import Image
    except Exception:  # pragma: no cover - optional dependency guard
        return None
    try:
        with Image.open(io.BytesIO(image_bytes)) as img:
            # Flatten to RGB for deterministic hashing regardless of alpha/mode.
            return str(imagehash.phash(img.convert("RGB")))
    except Exception:
        return None


def hamming(a: str | None, b: str | None) -> int:
    """Hamming distance between two hex pHash strings (0..64).

    Returns the sentinel ``64`` (maximally different) when either operand is
    missing, non-hex, or of a different length, so a missing hash never reads as
    a match.
    """
    if not a or not b or len(a) != len(b):
        return 64
    try:
        xor = int(a, 16) ^ int(b, 16)
    except ValueError:
        return 64
    return bin(xor).count("1")
