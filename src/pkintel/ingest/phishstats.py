"""PhishStats adapter — free JSON API with scored phishing URLs.

PhishStats (phishstats.info) publishes a comprehensive database of phishing URLs
via their REST API at ``api.phishstats.info``. The old CSV feed is defunct (404).
The API returns rich JSON objects with URL, IP, ASN, score, brand, and more.

We paginate through recent results (sorted by date, newest first) and yield the
``url`` field. No API key required. Typically yields 500+ fresh URLs per cycle.
"""

from __future__ import annotations

from collections.abc import Iterable, Iterator
from typing import Any

import httpx

from pkintel.ingest.base import polite_fetch
from pkintel.logging import get_logger

log = get_logger(__name__)

# REST API endpoint. Supports query params: _sort, _limit, _offset, _where.
API_URL = "https://api.phishstats.info/api/phishing"

# How many results per page and max pages to fetch.
_PAGE_SIZE = 500
_MAX_PAGES = 3


def parse_phishstats_json(payload: Any) -> Iterator[str]:
    """Yield the ``url`` field from each PhishStats API result. Pure."""
    if not isinstance(payload, list):
        return
    for entry in payload:
        if not isinstance(entry, dict):
            continue
        url = entry.get("url")
        if isinstance(url, str) and url.startswith("http"):
            yield url


class PhishStatsAdapter:
    """Feed adapter for the PhishStats JSON API."""

    name = "phishstats"
    kind = "phishstats"

    def fetch(self, client: httpx.Client) -> Iterable[str]:
        for page in range(_MAX_PAGES):
            offset = page * _PAGE_SIZE
            resp = polite_fetch(
                client,
                API_URL,
                params={
                    "_sort": "-date",
                    "_limit": str(_PAGE_SIZE),
                    "_offset": str(offset),
                },
                timeout=30,
            )
            if resp is None or resp.status_code != 200:
                log.warning("phishstats_page_failed", page=page, status=getattr(resp, "status_code", None))
                break

            try:
                payload = resp.json()
            except Exception:  # noqa: BLE001
                log.warning("phishstats_json_error", page=page)
                break

            urls = list(parse_phishstats_json(payload))
            if not urls:
                break

            log.info("phishstats_page_ok", page=page, count=len(urls))
            yield from urls

            # Stop early if we got fewer than a full page.
            if len(urls) < _PAGE_SIZE:
                break
