"""Phishing.Database adapter — large community GitHub blocklist.

mitchellkrogza/Phishing.Database is one of the largest community-maintained
phishing URL lists on GitHub. The ``phishing-links-ACTIVE.txt`` file contains
10,000+ known-active phishing URLs, one per line. No API key required.
"""

from __future__ import annotations

from collections.abc import Iterable

import httpx

from pkintel.ingest.base import fetch_first_text, parse_url_lines

FEED_URLS = [
    "https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-links-ACTIVE.txt",
]


class PhishingDatabaseAdapter:
    """Feed adapter for the Phishing.Database GitHub community list."""

    name = "phishing_database"
    kind = "community"

    def fetch(self, client: httpx.Client) -> Iterable[str]:
        text = fetch_first_text(client, FEED_URLS)
        if not text:
            return
        yield from parse_url_lines(text)
