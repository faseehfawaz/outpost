"""ThreatFox adapter (abuse.ch) — IOC feed for malware/phishing infrastructure.

ThreatFox publishes IOCs (indicators of compromise) reported by the community.
Each entry includes a URL or IP associated with known malware families and
botnets. We extract only URL-type IOCs. Free, no key.

Two endpoints are tried:
  1. **JSON API** (POST ``/api/v1/``) — structured, reliable, returns recent IOCs.
  2. **CSV bulk download** — full dataset fallback.
"""

from __future__ import annotations

import csv
from collections.abc import Iterable, Iterator
from typing import Any

import httpx

from pkintel.ingest.base import fetch_first_text, polite_fetch
from pkintel.logging import get_logger

log = get_logger(__name__)

CSV_FEED_URLS = [
    "https://threatfox.abuse.ch/downloads/csv/",
]

JSON_API_URL = "https://threatfox-api.abuse.ch/api/v1/"

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


def parse_threatfox_json(payload: Any) -> Iterator[str]:
    """Yield URL IOCs from the ThreatFox JSON API response."""
    if not isinstance(payload, dict):
        return
    data = payload.get("data")
    if not isinstance(data, list):
        return
    for entry in data:
        if not isinstance(entry, dict):
            continue
        ioc_type = (entry.get("ioc_type") or "").lower()
        if ioc_type != "url":
            continue
        value = entry.get("ioc") or ""
        if value.startswith("http"):
            yield value


class ThreatFoxAdapter:
    """Feed adapter for the ThreatFox IOC feed (JSON API + CSV fallback)."""

    name = "threatfox"
    kind = "threatfox"

    def fetch(self, client: httpx.Client) -> Iterable[str]:
        # Try the structured JSON API first (more reliable, last 7 days).
        try:
            resp = client.post(
                JSON_API_URL,
                json={"query": "get_iocs", "days": 7},
                timeout=30,
            )
            if resp.status_code == 200:
                payload = resp.json()
                urls = list(parse_threatfox_json(payload))
                if urls:
                    log.info("threatfox_json_ok", count=len(urls))
                    yield from urls
                    return
        except Exception as exc:  # noqa: BLE001
            log.warning("threatfox_json_error", error=str(exc))

        # Fallback: CSV bulk download.
        text = fetch_first_text(client, CSV_FEED_URLS)
        if not text:
            return
        yield from parse_threatfox_csv(text)
