"""Triage worker — the queue-draining entrypoint for this subsystem.

:func:`run_once` claims a batch of ``new`` URLs from the ``urls`` state machine,
fetches each politely, computes signals, scores it, and writes the terminal
triage result back (also arming or skipping the kit hunter). It is the sole
DB/network-touching surface here: every other module in ``pkintel.triage`` is
pure and import-safe, and so is *importing* this one (the pool and HTTP client
are created only when ``run_once`` actually runs).
"""

from __future__ import annotations

import json

import httpx

from pkintel.config import settings
from pkintel.db import claim_rows, execute, record_audit
from pkintel.http import polite_client
from pkintel.logging import get_logger
from pkintel.models import TriageResult
from pkintel.triage.brand import detect_brand, keyword_hits
from pkintel.triage.favicon import KNOWN_FAVICON_HASHES, favicon_mmh3
from pkintel.triage.fetch import fetch_page
from pkintel.triage.forms import analyze_forms
from pkintel.triage.phash import logo_phash
from pkintel.triage.score import score

log = get_logger(__name__)

_ACTOR = "triage"

_UPDATE_TRIAGED = """
    UPDATE urls SET
        triage_state   = 'triaged',
        is_phish       = %(is_phish)s,
        phish_score    = %(score)s,
        brand          = %(brand)s,
        triage_reasons = %(reasons)s::jsonb,
        favicon_mmh3   = %(favicon_mmh3)s,
        logo_phash     = %(logo_phash)s,
        is_live        = %(is_live)s,
        http_status    = %(http_status)s,
        triaged_at     = now(),
        kithunt_state  = %(kithunt_state)s,
        locked_by      = NULL,
        locked_at      = NULL
    WHERE id = %(id)s
"""

_UPDATE_ERROR = "UPDATE urls SET triage_state='error', locked_by=NULL, locked_at=NULL WHERE id=%s"


def _process_one(
    client: httpx.Client,
    url: str,
    priority_brands: list[str],
    priority_lower: set[str],
) -> TriageResult:
    """Fetch ``url`` and compute its :class:`TriageResult`. No DB writes."""
    fetched = fetch_page(client, url)

    # Unreachable/dead page: minimal, non-phish triage result.
    if fetched.error or not fetched.is_live:
        result = score(is_live=False)
        result.http_status = fetched.status
        return result

    html = fetched.html
    page_url = fetched.final_url

    form = analyze_forms(html, page_url)
    brand, brand_reasons = detect_brand(html, page_url, priority_brands)
    kw_count, _hits = keyword_hits(html, page_url)

    favicon_hash: int | None = None
    favicon_brand: str | None = None
    logo_hash: str | None = None
    if fetched.favicon_bytes:
        favicon_hash = favicon_mmh3(fetched.favicon_bytes)
        favicon_brand = KNOWN_FAVICON_HASHES.get(favicon_hash)
        logo_hash = logo_phash(fetched.favicon_bytes)

    brand_is_priority = bool(brand) and brand.strip().lower() in priority_lower

    result = score(
        is_live=True,
        brand=brand,
        brand_is_priority=brand_is_priority,
        favicon_brand=favicon_brand,
        form=form,
        keyword_hits=kw_count,
        reasons=brand_reasons,
    )
    result.http_status = fetched.status
    result.favicon_mmh3 = favicon_hash
    result.logo_phash = logo_hash
    return result


def run_once(worker_id: str = "triage-1", limit: int = 50) -> int:
    """Claim up to ``limit`` new URLs, triage them, and persist. Returns the
    number of URLs whose triage was written (0 if the queue was empty)."""
    rows = claim_rows(
        table="urls",
        ready_col="triage_state",
        ready_value="new",
        busy_value="triaging",
        worker_id=worker_id,
        limit=limit,
    )
    if not rows:
        return 0

    priority_brands = list(settings.priority_brands)
    priority_lower = {b.strip().lower() for b in priority_brands}

    processed = 0
    client = polite_client()
    try:
        for row in rows:
            url_id = row["id"]
            url = row["url"]
            try:
                result = _process_one(client, url, priority_brands, priority_lower)
            except Exception as exc:  # per-row isolation: one bad URL can't stop the batch
                log.warning("triage_row_error", url_id=url_id, error=str(exc))
                execute(_UPDATE_ERROR, (url_id,))
                record_audit(_ACTOR, "triage_error", target=str(url_id), error=str(exc))
                continue

            # Arm the kit hunter only for phish; otherwise take this URL out of scope.
            kithunt_state = "pending" if result.is_phish else "skipped"
            execute(
                _UPDATE_TRIAGED,
                {
                    "id": url_id,
                    "is_phish": result.is_phish,
                    "score": result.score,
                    "brand": result.brand,
                    "reasons": json.dumps(result.reasons),
                    "favicon_mmh3": result.favicon_mmh3,
                    "logo_phash": result.logo_phash,
                    "is_live": result.is_live,
                    "http_status": result.http_status,
                    "kithunt_state": kithunt_state,
                },
            )
            record_audit(
                _ACTOR,
                "triaged",
                target=str(url_id),
                url=url,
                is_phish=result.is_phish,
                score=result.score,
                brand=result.brand,
            )
            processed += 1
    finally:
        client.close()

    log.info(
        "triage_run_complete",
        worker=worker_id,
        claimed=len(rows),
        processed=processed,
    )
    return processed
