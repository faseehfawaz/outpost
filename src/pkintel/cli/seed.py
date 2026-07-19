"""Seed the ``sources`` table with the feeds we poll.

Idempotent: safe to run repeatedly. Which adapters actually run at poll time is
still gated by :data:`settings` (e.g. a urlscan source stays registered but is
skipped if no API key is configured).
"""

from __future__ import annotations

from pkintel.db import execute
from pkintel.logging import get_logger

log = get_logger(__name__)

DEFAULT_SOURCES: list[tuple[str, str]] = [
    ("certificate-transparency", "ct"),
    ("urlhaus", "urlhaus"),
    ("openphish", "openphish"),
    ("urlscan", "urlscan"),
    ("github-community", "github"),
    ("manual", "manual"),
]


def seed_sources() -> int:
    n = 0
    for name, kind in DEFAULT_SOURCES:
        n += execute(
            """
            INSERT INTO sources (name, kind)
            VALUES (%s, %s)
            ON CONFLICT (name) DO UPDATE SET kind = EXCLUDED.kind
            """,
            (name, kind),
        )
    log.info("sources_seeded", count=len(DEFAULT_SOURCES))
    return len(DEFAULT_SOURCES)
