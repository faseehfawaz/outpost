"""ThreatFox adapter (abuse.ch) — IOC feed for malware/phishing infrastructure.

ThreatFox publishes a rolling CSV of IOCs (indicators of compromise) reported
by the community. Each row includes a URL or IP associated with known
malware families and botnets. We extract only URL-type IOCs. Free, no key.

CSV schema (after comment lines)::

    "id","ioc_id","ioc_value","ioc_type","threat_type","threat_type_desc",...
"""

from __future__ import annotations

import csv
from collections.abc import Iterable, Iterator

import httpx

from pkintel.ingest.base import fetch_first_text

FEED_URLS = [
    "https://threatfox.abuse.ch/downloads/csv/",
]

_IOC_VALUE_COL = 2
_IOC_TYPE_COL = 3


def parse_threatfox_csv(text: str) -> Iterator[str]:
    """Yield URL-type IOC values from ThreatFox CSV rows. Pure."""
    data_rows = (
        line for line in text.splitlines() if line.strip() and not line.lstrip().startswith("#")
    )
    for row in csv.reader(data_rows):
        if len(row) > _IOC_TYPE_COL:
            ioc_type = row[_IOC_TYPE_COL].strip().strip('"').lower()
            if ioc_type in ("url", "payload_delivery"):
                value = row[_IOC_VALUE_COL].strip().strip('"')
            if value and value.startswith("http"):
                yield value


class ThreatFoxAdapter:
    """Feed adapter for the ThreatFox CSV feed."""

    name = "threatfox"
    kind = "threatfox"

    def fetch(self, client: httpx.Client) -> Iterable[str]:
        text = fetch_first_text(client, FEED_URLS)
        if not text:
            return
        yield from parse_threatfox_csv(text)
