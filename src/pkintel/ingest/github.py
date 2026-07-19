"""Community GitHub phishing-list adapter — raw text lists.

Several community projects publish continuously-updated phishing URL/domain
lists as raw text files on GitHub. We read one or two well-known lists (one URL
or bare domain per line) and yield them; bare domains are given an ``http://``
scheme by the runner during canonicalisation.

These lists are large and noisy — the runner caps how many we take per poll and
triage decides what is actually a phish. A missing list (``404`` after a repo
reshuffle) is tolerated and simply skipped.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from typing import Optional

import httpx

from pkintel.ingest.base import parse_url_lines, polite_fetch

# Well-known community lists. Kept short and stable on purpose.
DEFAULT_LISTS = [
    "https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-links-ACTIVE.txt",
]


class GitHubListAdapter:
    """Feed adapter for community GitHub phishing line-lists."""

    name = "github"
    kind = "github"

    def __init__(self, lists: Optional[Sequence[str]] = None) -> None:
        self.lists = list(lists) if lists else list(DEFAULT_LISTS)

    def fetch(self, client: httpx.Client) -> Iterable[str]:
        for url in self.lists:
            resp = polite_fetch(client, url)
            if resp is None:
                continue
            if resp.status_code == 404:
                from pkintel.logging import get_logger

                get_logger(__name__).info("github_list_missing", url=url)
                continue
            if resp.status_code != 200:
                from pkintel.logging import get_logger

                get_logger(__name__).warning(
                    "github_http_status", url=url, status=resp.status_code
                )
                continue
            yield from parse_url_lines(resp.text)
