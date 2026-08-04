"""Phishunt.io feed adapter — free phishing feed with TXT primary and JSON fallback.

Phishunt.io provides a free, no-auth-required phishing feed. We try the plain-text
endpoint (one URL per line) first. If that fails or is unavailable, we fall back
to the JSON endpoint (an array of objects containing a 'url' field).
"""

from __future__ import annotations

from collections.abc import Iterable, Iterator
from typing import Any

import httpx

from pkintel.ingest.base import parse_url_lines, polite_fetch

TXT_FEED_URL = "https://phishunt.io/feed.txt"
JSON_FEED_URL = "https://phishunt.io/feed.json"


def parse_phishunt_json(payload: Any) -> Iterator[str]:
    """Yield URLs from Phishunt JSON feed (array of objects with 'url' field). Pure."""
    if not isinstance(payload, list):
        return
    for item in payload:
        if isinstance(item, dict):
            url = item.get("url")
            if isinstance(url, str):
                s = url.strip()
                if s:
                    yield s


class PhishuntAdapter:
    """Feed adapter for the Phishunt.io phishing feed."""

    name = "phishunt"
    kind = "phishunt"

    def fetch(self, client: httpx.Client) -> Iterable[str]:
        resp = polite_fetch(client, TXT_FEED_URL)
        if resp is not None and resp.status_code == 200 and resp.text:
            yield from parse_url_lines(resp.text)
            return

        json_resp = polite_fetch(client, JSON_FEED_URL)
        if json_resp is not None and json_resp.status_code == 200:
            try:
                payload = json_resp.json()
            except Exception:
                return
            yield from parse_phishunt_json(payload)
