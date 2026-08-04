"""Community phishing lists adapter — free GitHub and community-hosted feeds.

Pulls from multiple free, open GitHub and community-hosted phishing/malware lists:
1. Google Safe Browsing hostnames (domain_list format)
2. Malware Filter Project (hosts format)
3. ScamBlocklist (hosts format)
4. RPiList Phishing-Angriffe (domain_list format)
"""

from __future__ import annotations

from collections.abc import Iterable, Iterator

import httpx

from pkintel.ingest.base import polite_fetch
from pkintel.logging import get_logger

log = get_logger(__name__)

FEED_URLS: list[tuple[str, str]] = [
    (
        "https://raw.githubusercontent.com/elliotwutingfeng/Inversion-DNSBL-Blocklists/main/Google_hostnames_light.txt",
        "domain_list",
    ),
    (
        "https://malware-filter.gitlab.io/malware-filter/phishing-filter-hosts.txt",
        "hosts",
    ),
    (
        "https://raw.githubusercontent.com/durablenapkin/scamblocklist/master/hosts.txt",
        "hosts",
    ),
    (
        "https://raw.githubusercontent.com/RPiList/specials/master/Blocklisten/Phishing-Angriffe",
        "domain_list",
    ),
]


def parse_community_feed(text: str, fmt: str) -> Iterator[str]:
    """Parse feed text according to format ('hosts', 'domain_list', or 'url_list'). Pure."""
    for line in text.splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue

        if fmt == "hosts":
            parts = s.split()
            if len(parts) >= 2 and parts[0] in ("0.0.0.0", "127.0.0.1"):  # noqa: S104
                domain = parts[1].strip()
                if domain and not domain.startswith("#"):
                    if domain.startswith(("http://", "https://")):
                        yield domain
                    else:
                        yield f"http://{domain}/"
        elif fmt == "domain_list":
            if s.startswith(("http://", "https://")):
                yield s
            else:
                yield f"http://{s}/"
        elif fmt == "url_list":
            if s.startswith(("http://", "https://")):
                yield s
            else:
                yield f"http://{s}/"
        else:
            if s.startswith(("http://", "https://")):
                yield s
            else:
                yield f"http://{s}/"


class CommunityListsAdapter:
    """Feed adapter for additional free GitHub-hosted phishing lists."""

    name = "community_lists"
    kind = "community"

    def fetch(self, client: httpx.Client) -> Iterable[str]:
        for url, fmt in FEED_URLS:
            resp = polite_fetch(client, url)
            if resp is None:
                continue
            if resp.status_code != 200:
                log.warning("community_list_http_status", url=url, status=resp.status_code)
                continue
            yield from parse_community_feed(resp.text, fmt)


# Alias for backward compatibility / module name match
ApwgAdapter = CommunityListsAdapter
