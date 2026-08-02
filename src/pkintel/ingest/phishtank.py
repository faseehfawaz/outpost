"""PhishTank community adapter — bulk verified phishing URL database.

PhishTank maintains one of the largest community-verified phishing databases
(~65K+ active URLs). The CSV feed requires no API key and is updated frequently.
"""

from __future__ import annotations

from collections.abc import Iterable

import httpx

from pkintel.ingest.base import polite_fetch
from pkintel.logging import get_logger

log = get_logger(__name__)

# PhishTank provides a CSV download of verified phishing URLs.
# The JSON endpoint now requires a key, but the CSV is still open.
FEED_URL = "http://data.phishtank.com/data/online-valid.csv"


class PhishTankAdapter:
    """Feed adapter for the PhishTank verified phishing database (CSV)."""

    name = "phishtank"
    kind = "phishtank"

    def fetch(self, client: httpx.Client) -> Iterable[str]:
        resp = polite_fetch(client, FEED_URL, timeout=60)
        if resp is None or resp.status_code != 200:
            return

        # CSV format: phish_id,url,phish_detail_url,submission_time,verified,...
        # First line is the header.
        first = True
        for line in resp.text.splitlines():
            if first:
                first = False
                continue
            parts = line.split(",", 3)
            if len(parts) >= 2:
                url = parts[1].strip().strip('"')
                if url and url.startswith(("http://", "https://")):
                    yield url
