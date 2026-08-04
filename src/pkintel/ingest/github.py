"""Community GitHub phishing-list adapter — raw text lists.

Several community projects publish continuously-updated phishing URL/domain
lists as raw text files on GitHub. We read multiple well-known lists (one URL
or bare domain per line) and yield them; bare domains are given an ``http://``
scheme. These lists are large and noisy — the runner caps how many we take per
poll and triage decides what is actually a phish.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence

import httpx

from pkintel.ingest.base import polite_fetch
from pkintel.logging import get_logger

log = get_logger(__name__)

# Well-known community lists. Each tuple: (url, format).
# format: "url" = lines are full URLs, "domain" = lines are bare domains.
# NOTE: Feeds already covered by CommunityListsAdapter (apwg.py) and
# MaltrailAdapter (emerging.py) are NOT duplicated here.
DEFAULT_LISTS: list[tuple[str, str]] = [
    # Recently updated phishing URLs from the community
    (
        "https://raw.githubusercontent.com/romainmarcoux/malicious-domains/main/full-domains-aa.txt",
        "domain",
    ),
    # Phishing filter project — domains only (not hosts format)
    (
        "https://malware-filter.gitlab.io/malware-filter/phishing-filter-domains.txt",
        "domain",
    ),
]


def _parse_hosts_line(line: str) -> str | None:
    """Extract domain from a hosts-format line (``0.0.0.0 evil.com``)."""
    s = line.strip()
    if not s or s.startswith("#"):
        return None
    parts = s.split()
    if len(parts) >= 2 and parts[0] in ("0.0.0.0", "127.0.0.1"):
        domain = parts[1].strip().rstrip(".")
        if domain and "." in domain and domain != "localhost":
            return domain
    return None


class GitHubListAdapter:
    """Feed adapter for community GitHub phishing line-lists."""

    name = "github"
    kind = "github"

    def __init__(self, lists: Sequence[tuple[str, str]] | None = None) -> None:
        self.lists = list(lists) if lists else list(DEFAULT_LISTS)

    def fetch(self, client: httpx.Client) -> Iterable[str]:
        for url, fmt in self.lists:
            resp = polite_fetch(client, url, timeout=30)
            if resp is None:
                continue
            if resp.status_code == 404:
                log.info("github_list_missing", url=url)
                continue
            if resp.status_code != 200:
                log.warning("github_http_status", url=url, status=resp.status_code)
                continue

            for line in resp.text.splitlines():
                s = line.strip()
                if not s or s.startswith("#"):
                    continue

                if fmt == "url":
                    if s.startswith(("http://", "https://")):
                        yield s
                elif fmt == "hosts":
                    domain = _parse_hosts_line(s)
                    if domain:
                        yield f"http://{domain}/"
                elif fmt == "domain":
                    # Bare domain — ensure it's valid-ish.
                    s = s.rstrip(".")
                    if "." in s and not s.startswith("http"):
                        yield f"http://{s}/"
                    elif s.startswith("http"):
                        yield s
