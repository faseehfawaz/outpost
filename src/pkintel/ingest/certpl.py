"""Cert.pl Malicious Domains adapter — the Polish CERT's malware/phish blocklist.

CERT Polska publishes a daily-updated JSON file of domains observed in phishing,
malware distribution, and other abuse. The file contains ~800K+ entries, making
it one of the largest freely available feeds.

Each entry has a domain name; we reconstruct a URL from it (http://<domain>/).
"""

from __future__ import annotations

from collections.abc import Iterable

import httpx

from pkintel.ingest.base import polite_fetch
from pkintel.logging import get_logger

log = get_logger(__name__)

FEED_URL = "https://hole.cert.pl/domains/domains.json"


class CertPlAdapter:
    """Feed adapter for the Cert.pl malicious domain list."""

    name = "certpl"
    kind = "certpl"

    def fetch(self, client: httpx.Client) -> Iterable[str]:
        resp = polite_fetch(client, FEED_URL, timeout=60)
        if resp is None or resp.status_code != 200:
            return

        try:
            entries = resp.json()
        except Exception:
            log.warning("certpl_json_parse_error")
            return

        for entry in entries:
            domain = None
            if isinstance(entry, dict):
                domain = entry.get("DomainAddress") or entry.get("domain")
            elif isinstance(entry, str):
                domain = entry

            if domain:
                domain = domain.strip().rstrip(".")
                if domain and "." in domain:
                    yield f"http://{domain}/"
