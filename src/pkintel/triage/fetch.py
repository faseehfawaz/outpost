"""Politely fetch a candidate URL and gather the raw material triage needs.

One :func:`fetch_page` call performs a throttled GET of the page (and, when the
page is reachable, a second throttled GET for its favicon). Every request goes
through :func:`pkintel.http.polite_get`, so the honest User-Agent and per-host
rate limit are enforced for us. Response bodies are size-capped so a hostile
server cannot exhaust memory. Nothing is executed — we only read bytes.
"""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urljoin

import httpx

from pkintel.http import polite_get
from pkintel.logging import get_logger
from pkintel.triage.favicon import find_favicon_url

log = get_logger(__name__)

# Hard caps: read at most this much of a body. Triage needs the <head>/forms,
# not megabytes of payload.
_MAX_HTML_BYTES = 2 * 1024 * 1024      # 2 MiB
_MAX_FAVICON_BYTES = 256 * 1024        # 256 KiB
# Short per-request timeout: unreachable candidates should fail fast.
_FETCH_TIMEOUT_S = 10.0


@dataclass
class PageFetch:
    """Everything one polite fetch of a URL yielded."""

    status: int | None
    final_url: str
    html: str | None
    is_live: bool
    favicon_bytes: bytes | None = None
    error: str | None = None


def _decode_html(resp: httpx.Response) -> str | None:
    """Decode a response body to text iff it looks like HTML/text/XML."""
    ctype = resp.headers.get("content-type", "").lower()
    if ctype and not any(t in ctype for t in ("html", "text", "xml")):
        return None
    raw = resp.content[:_MAX_HTML_BYTES]
    encoding = resp.encoding or "utf-8"
    try:
        return raw.decode(encoding, "replace")
    except (LookupError, TypeError):
        return raw.decode("utf-8", "replace")


def _fetch_favicon(
    client: httpx.Client,
    html: str | None,
    final_url: str,
) -> bytes | None:
    """Fetch the page's favicon (declared, else ``/favicon.ico``). Best-effort."""
    try:
        fav_url = find_favicon_url(html, final_url) or urljoin(final_url, "/favicon.ico")
        resp = polite_get(client, fav_url, timeout=_FETCH_TIMEOUT_S)
        if resp.status_code == 200 and resp.content:
            return resp.content[:_MAX_FAVICON_BYTES]
    except Exception as exc:  # pragma: no cover - favicon is optional, never fatal
        log.debug("triage_favicon_error", url=final_url, error=str(exc))
    return None


def fetch_page(client: httpx.Client, url: str) -> PageFetch:
    """Politely fetch ``url`` and return a :class:`PageFetch`.

    Network errors are captured (not raised) as ``error`` with ``is_live=False``
    so the caller can record a terminal-but-not-crashed triage outcome.
    """
    try:
        resp = polite_get(client, url, timeout=_FETCH_TIMEOUT_S)
    except Exception as exc:
        log.info("triage_fetch_error", url=url, error=str(exc))
        return PageFetch(
            status=None, final_url=url, html=None, is_live=False,
            favicon_bytes=None, error=str(exc),
        )

    status = resp.status_code
    final_url = str(resp.url)
    is_live = 200 <= status < 400
    html = _decode_html(resp)
    favicon_bytes = _fetch_favicon(client, html, final_url) if is_live else None

    return PageFetch(
        status=status, final_url=final_url, html=html,
        is_live=is_live, favicon_bytes=favicon_bytes, error=None,
    )
