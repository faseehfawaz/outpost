"""urlscan.io adapter — search API over recent suspicious pages.

urlscan.io exposes a search API (``/api/v1/search/``) that takes an
Elasticsearch-style query. We ask for recently scanned pages that carry a
phishing tag or a malicious verdict and yield the scanned page URLs.

The public search API works without a key at a low rate, but an ``API-Key``
header (``settings.urlscan_api_key``) raises the limit; the adapter is only
built by the runner when a key is configured. If constructed without a key it
still degrades cleanly — ``fetch`` yields nothing.
"""

from __future__ import annotations

from collections.abc import Iterable, Iterator
from typing import Any

import httpx

from pkintel.ingest.base import polite_fetch

SEARCH_URL = "https://urlscan.io/api/v1/search/"

# Conservative default: recently indexed pages flagged as phishing or malicious.
DEFAULT_QUERY = "task.tags:phishing OR verdicts.overall.malicious:true"


def parse_urlscan_json(payload: Any) -> Iterator[str]:
    """Yield ``result.page.url`` for each hit in a urlscan search response. Pure."""
    if not isinstance(payload, dict):
        return
    results = payload.get("results")
    if not isinstance(results, list):
        return
    for result in results:
        if not isinstance(result, dict):
            continue
        page = result.get("page")
        if not isinstance(page, dict):
            continue
        url = page.get("url")
        if isinstance(url, str) and url:
            yield url


class UrlscanAdapter:
    """Feed adapter for the urlscan.io search API."""

    name = "urlscan"
    kind = "urlscan"

    def __init__(
        self,
        api_key: str = "",
        query: str = DEFAULT_QUERY,
        size: int = 100,
    ) -> None:
        self.api_key = api_key
        self.query = query
        self.size = size

    def fetch(self, client: httpx.Client) -> Iterable[str]:
        if not self.api_key:
            from pkintel.logging import get_logger

            get_logger(__name__).info("urlscan_skipped_no_key")
            return

        params: dict[str, Any] = {"q": self.query, "size": self.size}
        headers = {"API-Key": self.api_key}
        resp = polite_fetch(client, SEARCH_URL, params=params, headers=headers)
        if resp is None or resp.status_code != 200:
            return
        try:
            payload = resp.json()
        except Exception:  # noqa: BLE001 - malformed body must not abort the run
            return
        yield from parse_urlscan_json(payload)
