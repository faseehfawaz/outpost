"""OpenPhish community adapter — one URL per line.

The OpenPhish community feed is a plain-text list, one phishing URL per line,
mirrored on GitHub. We read the GitHub raw mirror first (stable, CDN-backed)
and fall back to the canonical openphish.com endpoint. No API key is required
for the community feed.
"""

from __future__ import annotations

from collections.abc import Iterable

import httpx

from pkintel.ingest.base import fetch_first_text, parse_url_lines

FEED_URLS = [
    "https://raw.githubusercontent.com/openphish/public_feed/main/feed.txt",
    "https://openphish.com/feed.txt",
]


class OpenPhishAdapter:
    """Feed adapter for the OpenPhish community line-list feed."""

    name = "openphish"
    kind = "openphish"

    def fetch(self, client: httpx.Client) -> Iterable[str]:
        text = fetch_first_text(client, FEED_URLS)
        if not text:
            return
        yield from parse_url_lines(text)
