"""Open-directory detection and listing parsing — pure, side-effect free.

When a phishing server has autoindex turned on, the attacker's staging archive
and results logs are frequently sitting in plain sight. Detecting and reading an
*already public* index page is passive collection (the server offered the page
to any anonymous visitor). We still only ever pull links from the page; we never
guess beyond what is listed. All functions here are pure so the fetching layer
(:mod:`pkintel.kithunter.collect`) stays the single place that touches the wire.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from urllib.parse import urljoin, urlsplit

from bs4 import BeautifulSoup

# Archive extensions we recognise as a collectable kit staging file.
ARCHIVE_EXTS: tuple[str, ...] = (".zip", ".tar.gz", ".tgz", ".rar")

# Markers of the common autoindex generators: Apache mod_autoindex and nginx
# ("Index of /path"), and Python's http.server ("Directory listing for /").
_OPENDIR_MARKERS = re.compile(
    r"<title>\s*(?:index of |directory listing for )"
    r"|<h1>\s*index of ",
    re.IGNORECASE,
)


def is_open_directory(html: str) -> bool:
    """Return True if ``html`` looks like an autoindex directory listing."""
    if not html:
        return False
    return bool(_OPENDIR_MARKERS.search(html))


def parse_listing(html: str, base_url: str) -> list[str]:
    """Extract the linked entries of a directory listing as absolute URLs.

    Navigation/sort links (``?C=N;O=D``), parent-directory links (``../``) and
    anchors like ``mailto:``/``javascript:`` are skipped. Order and uniqueness
    are preserved.
    """
    soup = BeautifulSoup(html or "", "lxml")
    out: list[str] = []
    seen: set[str] = set()
    for anchor in soup.find_all("a", href=True):
        href = anchor["href"].strip()
        if not href or href[0] in "?#":
            continue
        if href in ("..", "../", "/"):
            continue
        if href.lower().startswith(("mailto:", "javascript:")):
            continue
        full = urljoin(base_url, href)
        if full in seen:
            continue
        seen.add(full)
        out.append(full)
    return out


def find_archives(links: Iterable[str]) -> list[str]:
    """Filter ``links`` down to those ending in a known archive extension."""
    out: list[str] = []
    for link in links:
        if urlsplit(link).path.lower().endswith(ARCHIVE_EXTS):
            out.append(link)
    return out
