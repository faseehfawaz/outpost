"""Ingest runner — the uniform ``run_once`` entrypoint for the CLI.

One cycle:

  1. Build the enabled adapter list from :data:`pkintel.config.settings`.
  2. Upsert each adapter's ``sources`` row (by name).
  3. For each adapter, fetch raw URLs (capped), canonicalise + dedupe, and
     ``INSERT ... ON CONFLICT (url_hash) DO UPDATE SET last_seen = now()`` into
     ``urls``. New rows are counted via the ``xmax = 0`` idiom.
  4. Stamp ``sources.last_polled_at`` and write an audit row per source.

A network failure inside one adapter is caught and logged; it never aborts the
whole run. Importing this module is side-effect free — nothing here touches the
DB or network until :func:`run_once` is called.
"""

from __future__ import annotations

from collections.abc import Iterable, Iterator, Sequence
from typing import Any, Optional

import httpx

from pkintel.config import Settings, settings
from pkintel.db import connection, record_audit
from pkintel.http import polite_client
from pkintel.logging import get_logger
from pkintel.ingest.base import FeedAdapter
from pkintel.ingest.ct import CTAdapter
from pkintel.ingest.github import GitHubListAdapter
from pkintel.ingest.normalize import canonical_url, host_of, url_hash
from pkintel.ingest.openphish import OpenPhishAdapter
from pkintel.ingest.urlhaus import URLhausAdapter
from pkintel.ingest.urlscan import UrlscanAdapter

log = get_logger(__name__)

_INSERT_SQL = """
    INSERT INTO urls (url, url_hash, host, source_id)
    VALUES (%s, %s, %s, %s)
    ON CONFLICT (url_hash) DO UPDATE SET last_seen = now()
    RETURNING (xmax = 0) AS inserted
"""

_UPSERT_SOURCE_SQL = """
    INSERT INTO sources (name, kind) VALUES (%s, %s)
    ON CONFLICT (name) DO UPDATE SET kind = EXCLUDED.kind
    RETURNING id
"""


def build_adapters(cfg: Optional[Settings] = None) -> list[FeedAdapter]:
    """Return the list of enabled feed adapters given the config. Pure.

    Enablement mirrors the ``settings`` flags: URLhaus/OpenPhish/CT are toggled
    by booleans, urlscan is enabled iff an API key is present, and the community
    GitHub list is always available (needs no key). No I/O happens here.
    """
    cfg = cfg if cfg is not None else settings
    adapters: list[FeedAdapter] = []
    if cfg.urlhaus_enabled:
        adapters.append(URLhausAdapter())
    if cfg.openphish_enabled:
        adapters.append(OpenPhishAdapter())
    if cfg.urlscan_api_key:
        adapters.append(UrlscanAdapter(api_key=cfg.urlscan_api_key))
    if cfg.ct_enabled:
        adapters.append(CTAdapter(cfg.priority_brands))
    adapters.append(GitHubListAdapter())
    return adapters


def _normalize_candidates(
    raw_urls: Iterable[str], cap: int
) -> list[tuple[str, str, str]]:
    """Canonicalise + dedupe raw URLs into ``(canonical, url_hash, host)`` rows.

    Pure. Stops after ``cap`` *valid, distinct* candidates. Malformed and
    host-less URLs are silently dropped; duplicates within the batch are
    collapsed by ``url_hash``.
    """
    out: list[tuple[str, str, str]] = []
    seen_hashes: set[str] = set()
    for raw in raw_urls:
        if len(out) >= cap:
            break
        try:
            canon = canonical_url(raw)
            host = host_of(canon)
        except Exception:  # noqa: BLE001 - skip anything we cannot canonicalise
            continue
        if not host:
            continue
        h = url_hash(canon)
        if h in seen_hashes:
            continue
        seen_hashes.add(h)
        out.append((canon, h, host))
    return out


def _upsert_source(cur: Any, name: str, kind: str) -> int:
    """Insert-or-update the ``sources`` row for a feed and return its id."""
    cur.execute(_UPSERT_SOURCE_SQL, (name, kind))
    return cur.fetchone()["id"]


def _insert_candidates(
    cur: Any, source_id: int, candidates: Sequence[tuple[str, str, str]]
) -> tuple[int, int]:
    """Upsert candidates into ``urls``; return ``(new_rows, seen_rows)``.

    ``xmax = 0`` is true only for a freshly inserted row, so it distinguishes a
    brand-new URL from a re-seen one whose ``last_seen`` we just bumped.
    """
    new = 0
    seen = 0
    for canon, h, host in candidates:
        cur.execute(_INSERT_SQL, (canon, h, host, source_id))
        row = cur.fetchone()
        if row and row.get("inserted"):
            new += 1
        else:
            seen += 1
    return new, seen


def _poll_adapter(
    client: httpx.Client, adapter: FeedAdapter, cap: int
) -> tuple[int, int]:
    """Poll one adapter end-to-end; return ``(new, seen)`` counts.

    The network fetch happens *outside* any DB transaction so we never hold a
    row lock while waiting on a feed.
    """
    with connection() as conn, conn.cursor() as cur:
        source_id = _upsert_source(cur, adapter.name, adapter.kind)

    raw_urls = adapter.fetch(client)  # generator; network happens on iteration
    candidates = _normalize_candidates(raw_urls, cap)

    with connection() as conn, conn.cursor() as cur:
        new, seen = _insert_candidates(cur, source_id, candidates)
        cur.execute(
            "UPDATE sources SET last_polled_at = now() WHERE id = %s", (source_id,)
        )

    record_audit("ingest", "poll", adapter.name, new=new, seen=seen)
    return new, seen


def run_once(worker_id: str = "ingest-1", limit: int = 500) -> int:
    """Run one ingest cycle across all enabled feeds; return total new URLs.

    ``limit`` caps how many candidate URLs are taken from *each* adapter per
    cycle. Per-adapter failures are logged and skipped, never fatal.
    """
    adapters = build_adapters()
    total_new = 0
    client = polite_client()
    try:
        for adapter in adapters:
            try:
                new, seen = _poll_adapter(client, adapter, cap=limit)
            except Exception as exc:  # noqa: BLE001 - isolate a bad adapter
                log.warning(
                    "ingest_adapter_failed",
                    adapter=getattr(adapter, "name", "?"),
                    error=str(exc),
                )
                continue
            total_new += new
            log.info("ingest_adapter_done", adapter=adapter.name, new=new, seen=seen)
    finally:
        client.close()

    log.info("ingest_run_done", worker_id=worker_id, new=total_new)
    return total_new
