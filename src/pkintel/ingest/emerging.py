"""Maltrail and community domain blocklist feed adapter.

Fetches open community-maintained domain blocklists including Discord-targeted
phishing domains and Maltrail suspicious/malware domain trails. Converts bare
domains into HTTP URLs (http://{domain}/) for ingestion.
"""

from __future__ import annotations

from collections.abc import Iterable, Iterator

import httpx

from pkintel.ingest.base import parse_url_lines, polite_fetch
from pkintel.logging import get_logger

log = get_logger(__name__)

FEED_URLS = [
    "https://raw.githubusercontent.com/nikolaischunk/discord-phishing-links/main/txt/domain-list.txt",
    "https://raw.githubusercontent.com/stamparm/maltrail/master/trails/static/suspicious/domain.txt",
    "https://raw.githubusercontent.com/stamparm/maltrail/master/trails/static/malware/domain.txt",
]


def parse_domain_lines(text: str) -> Iterator[str]:
    """Yield ``http://{domain}/`` for each non-empty, non-comment domain line. Pure."""
    for line in parse_url_lines(text):
        if line.startswith(("http://", "https://")):
            yield line
        else:
            domain = line.rstrip("/")
            yield f"http://{domain}/"


class MaltrailAdapter:
    """Feed adapter for Maltrail and community domain blocklists."""

    name = "maltrail"
    kind = "community"

    def fetch(self, client: httpx.Client) -> Iterable[str]:
        for url in FEED_URLS:
            resp = polite_fetch(client, url)
            if resp is None:
                continue
            if resp.status_code != 200:
                log.warning("maltrail_http_status", url=url, status=resp.status_code)
                continue
            yield from parse_domain_lines(resp.text)
