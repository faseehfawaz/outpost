"""Favicon hashing and discovery.

Two jobs:

* :func:`favicon_mmh3` computes the *urlscan.io / Shodan* favicon hash. Phishing
  kits routinely reuse the impersonated brand's real favicon, so a favicon hash
  is a cheap, high-signal brand fingerprint that survives HTML edits.
* :func:`find_favicon_url` extracts the declared favicon location from a page.

Nothing here touches the DB or network, so importing the module is cheap and safe.
"""

from __future__ import annotations

import base64
from urllib.parse import urljoin

import mmh3
from bs4 import BeautifulSoup

# mmh3 favicon hash -> brand label.
#
# Populated from measured data captured by ``pkintel refs capture``, which
# fetches each brand's real favicon once and records its hash. The same recipe
# is used by urlscan.io's ``page.favicon.hash`` and Shodan's
# ``http.favicon.hash``, so values found there are directly reusable and can be
# added to the JSON file by hand.
#
# This dict was previously seeded with two hardcoded values whose own comment
# admitted they were "ILLUSTRATIVE placeholders (not measured)". That is worse
# than an empty dict: a fabricated hash that happens to collide with a real
# favicon awards a spurious +20 (``favicon_known``) and up to +25 with the
# corroboration bonus, attributing a page to a brand on the strength of a number
# nobody ever measured. We now start empty and only ever hold measured values.
KNOWN_FAVICON_HASHES: dict[int, str] = {}


def _load_measured_favicons() -> None:
    """Load measured favicon hashes written by ``pkintel refs capture``.

    Best-effort and silent: if the reference set has not been captured yet the
    favicon signal simply never fires, which is the correct degradation. We do
    not guess at what a brand's icon hashes to.
    """
    import json
    from pathlib import Path

    try:
        from pkintel.config import settings

        path = Path(settings.render_screenshot_dir) / "reference" / "favicons.json"
        if not path.is_file():
            return
        data = json.loads(path.read_text())
    except Exception:  # noqa: BLE001 - never break import of a pure module
        return

    for raw_hash, brand in data.items():
        try:
            KNOWN_FAVICON_HASHES[int(raw_hash)] = str(brand)
        except (TypeError, ValueError):
            continue


_load_measured_favicons()


def favicon_mmh3(data: bytes) -> int:
    """Return the urlscan/Shodan-style MurmurHash3 of a favicon.

    The community recipe (which we replicate exactly so our hashes are
    comparable to urlscan.io / Shodan): standard-base64 encode the raw favicon
    bytes with a newline every 76 characters *and* a trailing newline — i.e.
    exactly what :func:`base64.encodebytes` emits — then take ``mmh3.hash`` of
    that ASCII payload. The default signed 32-bit result matches Shodan's
    convention.
    """
    encoded = base64.encodebytes(data)  # 76-char lines + trailing newline
    return mmh3.hash(encoded)


def find_favicon_url(html: str | None, base_url: str) -> str | None:
    """Return the favicon URL declared in ``html`` (resolved against
    ``base_url``), or ``None`` if the page declares none.

    Looks for ``<link rel="icon">`` / ``rel="shortcut icon"`` and friends. The
    caller is expected to fall back to ``/favicon.ico`` when this returns None.
    """
    if not html:
        return None
    try:
        soup = BeautifulSoup(html, "html.parser")
    except Exception:  # pragma: no cover - defensive against malformed markup
        return None

    for link in soup.find_all("link"):
        rel = link.get("rel")
        if not rel:
            continue
        rels = " ".join(rel) if isinstance(rel, list) else str(rel)
        if "icon" in rels.lower():
            href = link.get("href")
            if href and href.strip():
                return urljoin(base_url, href.strip())
    return None
