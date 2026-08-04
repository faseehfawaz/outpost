"""StalkPhish-OSS adapter — free phishing URL feed from StalkPhish.io.

StalkPhish.io provides a free public feed endpoint for the last 24 hours of
phishing URLs without requiring an API key. If the primary API endpoint fails
or returns non-200, the adapter falls back to the GitHub-hosted PhishTrap
phishing URL list.
"""

from __future__ import annotations

from collections.abc import Iterable, Iterator
from typing import Any

import httpx

from pkintel.ingest.base import parse_url_lines, polite_fetch
from pkintel.logging import get_logger

log = get_logger(__name__)

API_FEED_URL = "https://api.stalkphish.io/api/v1/search/last/24h"
GITHUB_FEED_URL = "https://raw.githubusercontent.com/stalkphish/PhishTrap/master/feeds/phishing_urls.txt"


def parse_stalkphish_json(payload: Any) -> Iterator[str]:
    """Yield URLs from StalkPhish JSON response array. Pure."""
    if not isinstance(payload, list):
        return
    for item in payload:
        if isinstance(item, dict):
            url = item.get("url")
            if isinstance(url, str) and url.strip():
                yield url.strip()


class StalkPhishAdapter:
    """Feed adapter for the StalkPhish-OSS phishing intelligence feed."""

    name = "stalkphish"
    kind = "stalkphish"

    def fetch(self, client: httpx.Client) -> Iterable[str]:
        resp = polite_fetch(client, API_FEED_URL)
        if resp is not None and resp.status_code == 200:
            try:
                payload = resp.json()
                urls = list(parse_stalkphish_json(payload))
                if urls:
                    yield from urls
                    return
            except Exception as exc:  # noqa: BLE001 - fallback if API JSON parsing fails
                log.warning("stalkphish_api_json_error", error=str(exc))
        elif resp is not None:
            log.warning("stalkphish_api_http_status", status=resp.status_code)

        fallback_resp = polite_fetch(client, GITHUB_FEED_URL)
        if fallback_resp is None or fallback_resp.status_code != 200:
            if fallback_resp is not None:
                log.warning("stalkphish_fallback_http_status", status=fallback_resp.status_code)
            return
        yield from parse_url_lines(fallback_resp.text)
