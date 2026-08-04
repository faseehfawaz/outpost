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
import time
from dataclasses import dataclass
from dataclasses import field as dc_field
from pathlib import Path

import httpx

from pkintel.config import settings
from pkintel.db import claim_rows, connection, execute_many
from pkintel.http import polite_client
from pkintel.logging import get_logger
from pkintel.models import TriageResult
from pkintel.pool import map_concurrent
from pkintel.triage.brand import detect_brand, keyword_hits
from pkintel.triage.cloak import detect_cloaking
from pkintel.triage.deep import BrandScreenshot, deep_score
from pkintel.triage.favicon import KNOWN_FAVICON_HASHES, favicon_mmh3
from pkintel.triage.fetch import fetch_page
from pkintel.triage.forms import analyze_forms
from pkintel.triage.llm import evaluate_borderline_url
from pkintel.triage.phash import logo_phash
from pkintel.triage.render import RenderResult, render_page
from pkintel.triage.score import score

log = get_logger(__name__)

_ACTOR = "triage"

_UPDATE_TRIAGED = """
    UPDATE urls SET
        triage_state    = 'triaged',
        is_phish        = %(is_phish)s,
        phish_score     = %(score)s,
        brand           = %(brand)s,
        triage_reasons  = %(reasons)s::jsonb,
        favicon_mmh3    = %(favicon_mmh3)s,
        logo_phash      = %(logo_phash)s,
        is_live         = %(is_live)s,
        http_status     = %(http_status)s,
        rendered        = %(rendered)s,
        screenshot_phash = %(screenshot_phash)s,
        cloaking_score  = %(cloaking_score)s,
        exfil_endpoints = %(exfil_endpoints)s::jsonb,
        triaged_at      = now(),
        kithunt_state   = %(kithunt_state)s,
        locked_by       = NULL,
        locked_at       = NULL
    WHERE id = %(id)s
"""

_UPDATE_ERROR = "UPDATE urls SET triage_state='error', locked_by=NULL, locked_at=NULL WHERE id=%s"


@dataclass
class TriageOutcome:
    """A triage verdict plus the deep artefacts that produced it.

    The static score is kept alongside the final one so we can measure what the
    browser pool actually bought us. Rendering costs real CPU; "deep triage
    found N phish that static triage scored below threshold" is the only honest
    justification for that cost, and it needs both numbers to compute.
    """

    result: TriageResult
    static_score: int = 0
    rendered: bool = False
    screenshot_phash: str | None = None
    cloaking_score: float | None = None
    exfil_endpoints: list[str] = dc_field(default_factory=list)


def _load_brand_references() -> list[BrandScreenshot]:
    """Reference pHashes of the real brands' login pages, for clone detection.

    Populated from ``settings.render_screenshot_dir/reference/<Brand>.phash``.
    Absent file => empty list => the screenshot signal simply never fires, which
    is the correct degradation: we must not guess at a brand's appearance.
    """
    refs: list[BrandScreenshot] = []
    ref_dir = Path(settings.render_screenshot_dir) / "reference"
    if not ref_dir.is_dir():
        return refs
    for path in sorted(ref_dir.glob("*.phash")):
        try:
            phash = path.read_text().strip()
        except OSError:
            continue
        if phash:
            refs.append(BrandScreenshot(brand=path.stem, phash=phash))
    return refs


def _process_deep(
    client: httpx.Client,
    url: str,
    base: TriageResult,
    static_had_password: bool,
    brand_refs: list[BrandScreenshot],
) -> TriageOutcome:
    """Run the browser/cloaking path and fold its signals into ``base``.

    Only called for candidates that already cleared ``render_min_score``.
    Rendering every URL would spend the whole browser pool on dead 404s — the
    overwhelming majority of what the bulk feeds deliver.

    Every step here is best-effort: a failure leaves the static verdict intact
    rather than downgrading it. Absence of evidence is not evidence.
    """
    outcome = TriageOutcome(result=base, static_score=base.score)

    cloak_score: float | None = None
    try:
        cloak = detect_cloaking(client, url)
        if cloak.fetches:
            cloak_score = cloak.score
            outcome.cloaking_score = cloak.score
    except Exception as exc:  # noqa: BLE001
        log.debug("cloak_detect_failed", url=url, error=str(exc))

    render = RenderResult(ok=False)
    try:
        render = render_page(url)
    except Exception as exc:  # noqa: BLE001 - a hostile page must not kill the row
        log.debug("render_failed_outer", url=url, error=str(exc))

    outcome.rendered = render.ok
    outcome.screenshot_phash = render.screenshot_phash
    outcome.exfil_endpoints = list(render.exfil_endpoints)

    outcome.result = deep_score(
        base,
        render,
        static_had_password_field=static_had_password,
        brand_references=brand_refs,
        cloaking_score=cloak_score,
        cloak_threshold=settings.cloak_diff_threshold,
    )
    return outcome


def _process_one(
    client: httpx.Client,
    url: str,
    priority_brands: list[str],
    priority_lower: set[str],
    brand_refs: list[BrandScreenshot] | None = None,
) -> TriageOutcome:
    """Fetch ``url``, score it, and deep-triage it if warranted. No DB writes."""
    fetched = fetch_page(client, url)

    # Unreachable/dead page: minimal, non-phish triage result.
    if fetched.error or not fetched.is_live:
        result = score(is_live=False)
        result.http_status = fetched.status
        return TriageOutcome(result=result, static_score=result.score)

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

    # --- deep triage gate --------------------------------------------------
    if settings.render_enabled and result.score >= settings.render_min_score:
        outcome = _process_deep(
            client,
            page_url,
            result,
            static_had_password=bool(form and form.has_password_field),
            brand_refs=brand_refs or [],
        )
        result = outcome.result
    else:
        outcome = TriageOutcome(result=result, static_score=result.score)

    # --- local LLM tie-breaker gate (Ollama) -------------------------------
    if settings.llm_enabled and settings.llm_band_low <= result.score <= settings.llm_band_high:
        llm_res = evaluate_borderline_url(page_url, html, result.score)
        if llm_res.get("is_phishing") and llm_res.get("confidence", 0.0) >= 0.7:
            new_score = max(result.score, settings.triage_phish_threshold + 5)
            result.is_phish = True
            result.score = new_score
            result.reasons.append(f"llm_rescue: {llm_res.get('reason', 'LLM verdict')}")
            log.info(
                "llm_rescued_phish",
                url=page_url,
                static_score=outcome.static_score,
                new_score=new_score,
                confidence=llm_res.get("confidence"),
            )

    return outcome


def run_once(worker_id: str = "triage-1", limit: int = 500, workers: int | None = None) -> int:
    """Claim up to ``limit`` new URLs, triage them concurrently, and persist.

    Returns the number of URLs whose triage was written (0 if the queue empty).

    Concurrency
    -----------
    Fetching is the entire cost here — a batch is ~99% socket wait — so the
    batch is fanned out across ``settings.triage_workers`` threads instead of
    being walked one URL at a time. That was the pipeline's dominant bottleneck:
    at one-at-a-time with a 3s per-host throttle plus a favicon round-trip, 50
    URLs took 5-10 minutes and eleven of twelve CPU threads sat idle.

    The per-host rate limit is **unchanged and still enforced** inside
    :func:`pkintel.http.polite_get`. Threads only overlap work against
    *different* hosts; any single host still sees requests spaced exactly
    ``per_host_min_interval_s`` apart. See :mod:`pkintel.pool`.

    Writes are batched into two statements (one for results, one for errors)
    rather than 2N round-trips, because at this fan-out the old per-row
    ``execute()`` — each opening its own pooled connection and transaction —
    became the next bottleneck.
    """
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
    n_workers = workers if workers is not None else settings.triage_workers

    # httpx.Client is thread-safe and pools connections, so one shared client
    # across the pool is both correct and what we want (connection reuse).
    client = polite_client()
    started = time.monotonic()

    ok_params: list[dict] = []
    err_ids: list[tuple] = []
    audits: list[tuple] = []

    brand_refs = _load_brand_references()
    # How many verdicts the deep path flipped. This is the number that justifies
    # the browser pool's CPU cost, so it is logged every batch rather than
    # assumed.
    deep_rescued = 0

    def _work(row: dict) -> TriageOutcome:
        return _process_one(client, row["url"], priority_brands, priority_lower, brand_refs)

    try:
        for row, outcome, exc in map_concurrent(_work, rows, workers=n_workers, stage="triage"):
            url_id = row["id"]
            if exc is not None:
                # Per-row isolation preserved: one hostile host cannot abort the batch.
                log.warning("triage_row_error", url_id=url_id, error=str(exc))
                err_ids.append((url_id,))
                audits.append(
                    (_ACTOR, "triage_error", str(url_id), json.dumps({"error": str(exc)}))
                )
                continue

            result = outcome.result

            # A verdict the static path would have missed entirely.
            if result.is_phish and outcome.static_score < settings.triage_phish_threshold:
                deep_rescued += 1
                log.info(
                    "deep_triage_rescued",
                    url_id=url_id,
                    url=row["url"],
                    static_score=outcome.static_score,
                    deep_score=result.score,
                    rendered=outcome.rendered,
                    cloaking_score=outcome.cloaking_score,
                )

            # Arm the kit hunter only for phish; otherwise take this URL out of scope.
            ok_params.append(
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
                    "rendered": outcome.rendered,
                    "screenshot_phash": outcome.screenshot_phash,
                    "cloaking_score": outcome.cloaking_score,
                    "exfil_endpoints": json.dumps(outcome.exfil_endpoints),
                    "kithunt_state": "pending" if result.is_phish else "skipped",
                }
            )
            audits.append(
                (
                    _ACTOR,
                    "triaged",
                    str(url_id),
                    json.dumps(
                        {
                            "url": row["url"],
                            "is_phish": result.is_phish,
                            "score": result.score,
                            "brand": result.brand,
                        }
                    ),
                )
            )
    finally:
        client.close()

    # --- batched persistence ------------------------------------------------
    if ok_params:
        with connection() as conn, conn.cursor() as cur:
            cur.executemany(_UPDATE_TRIAGED, ok_params)
    if err_ids:
        execute_many(_UPDATE_ERROR, err_ids)
    if audits:
        try:
            execute_many(
                "INSERT INTO audit_log (actor, action, target, detail) VALUES (%s, %s, %s, %s)",
                audits,
            )
        except Exception as exc:  # noqa: BLE001 - audit must never break the pipeline
            log.warning("triage_audit_batch_failed", error=str(exc))

    elapsed = time.monotonic() - started
    processed = len(ok_params)

    try:
        from pkintel.metrics import (
            deep_rescued as m_deep_rescued,
        )
        from pkintel.metrics import (
            stage_duration,
            stage_errors,
            urls_processed,
        )

        stage_duration.labels(stage="triage").observe(elapsed)
        stage_errors.labels(stage="triage").inc(len(err_ids))
        m_deep_rescued.inc(deep_rescued)
        phish = sum(1 for p in ok_params if p["is_phish"])
        urls_processed.labels(stage="triage", outcome="phish").inc(phish)
        urls_processed.labels(stage="triage", outcome="clean").inc(processed - phish)
    except Exception:  # noqa: BLE001, S110 - metrics must never break the pipeline
        pass
    log.info(
        "triage_run_complete",
        worker=worker_id,
        claimed=len(rows),
        processed=processed,
        errors=len(err_ids),
        workers=n_workers,
        elapsed_s=round(elapsed, 1),
        urls_per_min=round(len(rows) / elapsed * 60, 1) if elapsed > 0 else 0,
        rendered=sum(1 for p in ok_params if p["rendered"]),
        deep_rescued=deep_rescued,
    )
    return processed
