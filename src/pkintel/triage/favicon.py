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
# HOW TO GROW THIS: fetch a known brand's real favicon (e.g. GET
# https://www.paypal.com/favicon.ico), run the raw bytes through
# ``favicon_mmh3``, and paste the returned int here mapped to the brand. The
# same recipe is used by urlscan.io's ``page.favicon.hash`` and Shodan's
# ``http.favicon.hash``, so values found there are directly reusable.
#
# The two entries below are ILLUSTRATIVE placeholders (not measured) to show the
# shape; replace them with real, measured hashes before relying on them.
KNOWN_FAVICON_HASHES: dict[int, str] = {
    116323821: "Microsoft",
    -235701012: "Emirates NBD",
}


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
