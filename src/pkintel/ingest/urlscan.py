"""urlscan.io adapter — search API over recent suspicious pages.

urlscan.io exposes a search API (``/api/v1/search/``) that takes an
Elasticsearch-style query. We ask for recently scanned pages that carry a
phishing tag or a malicious verdict and yield the scanned page URLs.

The **public search API works without a key** at a reduced rate (2 req/min).
An ``API-Key`` header raises the limit. We paginate via ``search_after`` to
pull up to 600 results per cycle across multiple queries.
"""

from __future__ import annotations

from collections.abc import Iterable, Iterator
from typing import Any

import httpx

from pkintel.ingest.base import polite_fetch
from pkintel.logging import get_logger

log = get_logger(__name__)

SEARCH_URL = "https://urlscan.io/api/v1/search/"

# Multiple targeted queries to maximise coverage, especially GCC/UAE brands.
QUERIES = [
    "task.tags:phishing AND date:>now-7d",
    "verdicts.overall.malicious:true AND date:>now-3d",
    "(page.domain:*.ae OR page.domain:*.sa) AND task.tags:phishing AND date:>now-30d",
]

_PAGE_SIZE = 200
_MAX_PAGES = 2


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
    ) -> None:
        self.api_key = api_key

    def fetch(self, client: httpx.Client) -> Iterable[str]:
        headers: dict[str, str] = {}
        if self.api_key:
            headers["API-Key"] = self.api_key

        seen: set[str] = set()

        for query in QUERIES:
            search_after: str | None = None

            for page in range(_MAX_PAGES):
                params: dict[str, Any] = {"q": query, "size": _PAGE_SIZE}
                if search_after:
                    params["search_after"] = search_after

                try:
                    resp = polite_fetch(
                        client, SEARCH_URL, params=params, headers=headers, timeout=30
                    )
                except Exception as exc:  # noqa: BLE001
                    log.warning("urlscan_request_error", query=query, page=page, error=str(exc))
                    break

                if resp is None or resp.status_code == 429:
                    log.info("urlscan_rate_limited", query=query, page=page)
                    break
                if resp.status_code != 200:
                    log.warning("urlscan_http_error", query=query, status=resp.status_code)
                    break

                try:
                    payload = resp.json()
                except Exception:  # noqa: BLE001
                    break

                count = 0
                for url in parse_urlscan_json(payload):
                    if url not in seen:
                        seen.add(url)
                        yield url
                        count += 1

                if count == 0:
                    break

                # Get the search_after cursor for pagination.
                results = payload.get("results", [])
                if results and isinstance(results[-1], dict):
                    sort_val = results[-1].get("sort")
                    if isinstance(sort_val, list) and sort_val:
                        search_after = ",".join(str(s) for s in sort_val)
                    else:
                        break
                else:
                    break

                log.info("urlscan_page_ok", query=query[:40], page=page, count=count)
