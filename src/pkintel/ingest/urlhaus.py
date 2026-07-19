"""URLhaus adapter (abuse.ch) — free recent-URLs CSV feed.

URLhaus publishes a rolling CSV of recently submitted malware/phishing URLs.
Comment lines start with ``#`` (including the column header); data rows are
CSV with the URL in the third column::

    # id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter
    "123","2026-07-18 10:00:00","http://evil.example/login","online",...

We yield the ``url`` column verbatim; canonicalisation happens in the runner.
No API key is required for this feed.
"""

from __future__ import annotations

import csv
from collections.abc import Iterable, Iterator

import httpx

from pkintel.ingest.base import fetch_first_text

# Primary + fallback hosts for the same feed (abuse.ch mirrors it).
FEED_URLS = [
    "https://urlhaus.dgsi.abuse.ch/downloads/csv_recent/",
    "https://urlhaus.abuse.ch/downloads/csv_recent/",
]

# Column index of the URL in the URLhaus CSV schema.
_URL_COLUMN = 2


def parse_urlhaus_csv(text: str) -> Iterator[str]:
    """Yield the ``url`` column from each URLhaus CSV data row. Pure.

    Comment lines (``#`` prefix, after optional whitespace) are skipped, which
    covers the header row. Quoting is handled by :mod:`csv`.
    """
    data_rows = (line for line in text.splitlines() if not line.lstrip().startswith("#"))
    for row in csv.reader(data_rows):
        if len(row) > _URL_COLUMN:
            value = row[_URL_COLUMN].strip()
            if value:
                yield value


class URLhausAdapter:
    """Feed adapter for the URLhaus recent-CSV feed."""

    name = "urlhaus"
    kind = "urlhaus"

    def fetch(self, client: httpx.Client) -> Iterable[str]:
        text = fetch_first_text(client, FEED_URLS)
        if not text:
            return
        yield from parse_urlhaus_csv(text)
