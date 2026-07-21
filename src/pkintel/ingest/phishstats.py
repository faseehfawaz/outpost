"""PhishStats adapter — free CSV feed with scored phishing URLs.

PhishStats (phishstats.info) publishes a rolling CSV of phishing URLs with
scores. The feed is free, requires no API key, and typically contains 5,000+
active URLs. The CSV schema is::

    Date,Score,URL,IP

We yield the ``URL`` column. Canonicalisation happens in the runner.
"""

from __future__ import annotations

import csv
from collections.abc import Iterable, Iterator

import httpx

from pkintel.ingest.base import fetch_first_text

FEED_URLS = [
    "https://phishstats.info/phish_score.csv",
]

_URL_COLUMN = 2


def parse_phishstats_csv(text: str) -> Iterator[str]:
    """Yield the ``URL`` column from each PhishStats CSV row. Pure.

    Comment lines (``#`` prefix) and the header row are skipped.
    """
    data_rows = (
        line
        for line in text.splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    )
    for row in csv.reader(data_rows):
        if len(row) > _URL_COLUMN:
            value = row[_URL_COLUMN].strip().strip('"')
            if value and value.startswith("http"):
                yield value


class PhishStatsAdapter:
    """Feed adapter for the PhishStats CSV feed."""

    name = "phishstats"
    kind = "phishstats"

    def fetch(self, client: httpx.Client) -> Iterable[str]:
        text = fetch_first_text(client, FEED_URLS)
        if not text:
            return
        yield from parse_phishstats_csv(text)
