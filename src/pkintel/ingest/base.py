"""Feed-adapter contract and small shared HTTP/parse helpers.

A :class:`FeedAdapter` is anything with a ``name``, a ``kind`` (one of the
``sources.kind`` values), and a ``fetch(client)`` method yielding raw URL
strings. Adapters do no canonicalisation or DB work — that is the runner's job;
they just turn a feed into an iterable of candidate URL strings.

This module is kept deliberately import-light: it pulls in ``httpx`` only, and
imports the politeness layer / logger *lazily* inside the helpers. That keeps
``import pkintel.ingest.<adapter>`` cheap and free of the pydantic/DB stack, so
the pure parse helpers in each adapter can be unit tested in isolation.
"""

from __future__ import annotations

from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from typing import Any, Protocol, runtime_checkable

import httpx


@dataclass(frozen=True)
class Candidate:
    """One raw candidate URL and the human-readable name of its source feed."""

    url: str
    source_name: str


@runtime_checkable
class FeedAdapter(Protocol):
    """Structural type every feed adapter satisfies."""

    name: str
    kind: str

    def fetch(self, client: httpx.Client) -> Iterable[str]:
        """Yield raw (un-canonicalised) URL strings pulled from the feed."""
        ...


def parse_url_lines(text: str) -> Iterator[str]:
    """Yield one stripped URL per non-empty, non-comment line.

    Pure. Used by the OpenPhish and GitHub line-list adapters.
    """
    for line in text.splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        yield s


def polite_fetch(
    client: httpx.Client,
    url: str,
    **kwargs: Any,
) -> httpx.Response | None:
    """Politely GET ``url``, returning the response or ``None`` on any error.

    Network errors are swallowed and logged (never raised) so a single dead
    feed endpoint cannot abort an ingest run. The per-host throttle in
    :func:`pkintel.http.polite_get` is always applied.
    """
    from pkintel.http import polite_get
    from pkintel.logging import get_logger

    log = get_logger(__name__)
    try:
        return polite_get(client, url, **kwargs)
    except Exception as exc:  # noqa: BLE001 - one bad endpoint must not abort the run
        log.warning("feed_fetch_error", url=url, error=str(exc))
        return None


def fetch_first_text(
    client: httpx.Client,
    urls: Iterable[str],
    **kwargs: Any,
) -> str | None:
    """Try each URL in order; return the body of the first ``200`` response.

    Used by adapters that publish the same feed on a primary and a fallback
    host. Returns ``None`` if every candidate failed or returned non-200.
    """
    from pkintel.logging import get_logger

    log = get_logger(__name__)
    for u in urls:
        resp = polite_fetch(client, u, **kwargs)
        if resp is None:
            continue
        if resp.status_code == 200:
            return resp.text
        log.warning("feed_http_status", url=u, status=resp.status_code)
    return None
