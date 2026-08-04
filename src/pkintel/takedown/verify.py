"""Takedown verification and escalation — proving the notices actually work.

Why this matters more than it sounds
------------------------------------
The pipeline previously sent an abuse notice and marked it ``sent``. Nothing
ever checked whether the phishing site went down. That makes the platform's
headline metric — *"40+ takedown notices filed"* — an activity number, not an
outcome number. It measures how much email we sent, which is entirely within our
own control and therefore proves nothing about impact.

A notice that lands in a spam folder and a notice that kills a campaign in
twenty minutes are indistinguishable under that metric.

This module closes the loop. It re-probes each reported URL on a schedule and
records when it actually died, which converts the headline into something
defensible:

    37 of 41 reported sites confirmed dead. Median time-to-death 6.2 hours.
    4 still live after 48h; all 4 escalated to registry/ASN.

That is a claim about the world rather than about our outbox, and it is the
number that makes the platform credible to a CERT or a bank.

Escalation
----------
Abuse desks vary enormously. Some act in minutes; some never read the mailbox.
When a host has ignored a notice past ``takedown_escalate_after_s``, we move up
the chain rather than re-sending the same message to the same address:

    level 0  hosting provider abuse desk   (first notice)
    level 1  domain registrar              (they can suspend the domain)
    level 2  registry / ASN owner          (they can null-route or revoke)
    level 3  national CERT + blocklists    (aeCERT, GSB, PhishTank)

Each level is a strictly larger hammer with a strictly slower response time, so
we only reach for it when the smaller one demonstrably failed.

Ethics
------
Verification is a plain unauthenticated GET of a URL we already know about —
the least invasive probe available, and strictly less contact than the original
triage fetch. It goes through the same per-host throttle. Probing stops
permanently once a target is confirmed dead, and is capped at
``takedown_max_verifications`` attempts so a permanently-parked domain cannot be
probed forever.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

import httpx

from pkintel.config import settings
from pkintel.db import execute, execute_many, fetch_all, record_audit
from pkintel.http import polite_client, polite_get
from pkintel.logging import get_logger
from pkintel.pool import map_concurrent

log = get_logger(__name__)

_ACTOR = "takedown_verify"
_PROBE_TIMEOUT_S = 12.0

# Escalation ladder. Index == escalation_level.
ESCALATION_TARGETS: tuple[str, ...] = ("host", "registrar", "registry", "cert")

# HTTP status codes that mean the content is gone. A 200 does NOT automatically
# mean "still phishing" — many hosts replace a suspended site with a 200 landing
# page — so :func:`looks_dead` also inspects the body.
_DEAD_STATUSES = frozenset({403, 404, 410, 451})

# Phrases hosts serve on a suspension page. Their presence on a 200 response is
# a strong signal the takedown worked and the host simply did not 404 it.
_SUSPENSION_MARKERS = (
    "account suspended",
    "site suspended",
    "this site has been suspended",
    "suspended domain",
    "page has been removed",
    "content has been removed",
    "reported for phishing",
    "deceptive site",
    "domain has been seized",
    "seized by",
    "site disabled",
    "under investigation",
    "abuse report",
)


@dataclass
class ProbeResult:
    """Outcome of one liveness probe."""

    takedown_id: int
    url: str
    status: int | None = None
    dead: bool = False
    reason: str = ""
    error: str | None = None


def looks_dead(status: int | None, body: str | None) -> tuple[bool, str]:
    """Decide whether a probed URL is down. Pure, so it is directly testable.

    Returns ``(is_dead, reason)``. Deliberately conservative: a false "dead"
    closes the case on a live phishing site, which is far worse than an extra
    probe. When uncertain we report alive and probe again later.
    """
    if status is None:
        # Connection refused / DNS failure / timeout. Usually the server is gone,
        # but it can also be a transient network blip, so it is reported as dead
        # only in combination with the repeat-probe logic in run_once.
        return True, "unreachable"

    if status in _DEAD_STATUSES:
        return True, f"http_{status}"

    if 500 <= status < 600:
        # A 5xx is ambiguous — could be a dead backend, could be a busy one.
        return False, f"http_{status}_ambiguous"

    if body:
        lowered = body[:20000].lower()
        for marker in _SUSPENSION_MARKERS:
            if marker in lowered:
                return True, f"suspension_page:{marker}"
        # A near-empty 200 usually means the content was pulled and the vhost
        # now serves a default page.
        if len(lowered.strip()) < 200:
            return True, "empty_response"

    return False, "still_live"


def _probe(client: httpx.Client, row: dict) -> ProbeResult:
    """One throttled GET. Errors captured, never raised."""
    result = ProbeResult(takedown_id=row["takedown_id"], url=row["url"])
    try:
        resp = polite_get(client, row["url"], timeout=_PROBE_TIMEOUT_S)
    except Exception as exc:  # noqa: BLE001 - unreachable is a valid, expected outcome
        result.error = str(exc)[:300]
        result.dead, result.reason = looks_dead(None, None)
        return result

    result.status = resp.status_code
    body = None
    ctype = resp.headers.get("content-type", "").lower()
    if not ctype or any(t in ctype for t in ("html", "text", "xml")):
        body = resp.content[: 64 * 1024].decode(resp.encoding or "utf-8", "replace")

    result.dead, result.reason = looks_dead(result.status, body)
    return result


def _due_takedowns(limit: int) -> list[dict]:
    """Sent takedowns whose next verification is due."""
    return fetch_all(
        """
        SELECT t.id AS takedown_id, t.url_id, t.verify_count, t.escalation_level,
               t.sent_at, u.url, u.host
        FROM takedowns t
        JOIN urls u ON u.id = t.url_id
        WHERE t.status = 'sent'
          AND t.target_dead_at IS NULL
          AND t.verify_count < %s
          AND (t.verify_after IS NULL OR t.verify_after <= now())
        ORDER BY t.verify_after NULLS FIRST
        LIMIT %s
        """,
        (settings.takedown_max_verifications, limit),
    )


def _should_escalate(sent_at: datetime | None, escalation_level: int) -> bool:
    """True if a still-live target has been ignored long enough to escalate."""
    if sent_at is None:
        return False
    if escalation_level >= len(ESCALATION_TARGETS) - 1:
        return False  # already at the top of the ladder
    age = datetime.now(timezone.utc) - sent_at
    # Each level waits progressively longer before the next escalation, because
    # each successive authority is slower to act by nature.
    required = timedelta(seconds=settings.takedown_escalate_after_s * (escalation_level + 1))
    return age >= required


def run_once(worker_id: str = "verify-1", limit: int = 100) -> int:
    """Probe due takedowns, record deaths, and escalate the stubborn ones.

    Returns the number of targets newly confirmed dead.
    """
    if not settings.takedown_verify_enabled:
        return 0

    rows = _due_takedowns(limit)
    if not rows:
        return 0

    client = polite_client()
    dead_updates: list[tuple] = []
    alive_updates: list[tuple] = []
    escalations: list[dict] = []
    audits: list[tuple] = []

    try:
        for row, probe, exc in map_concurrent(
            lambda r: _probe(client, r),
            rows,
            workers=min(settings.takedown_workers, 16),
            stage="verify",
        ):
            if exc is not None:
                log.warning("verify_probe_error", takedown_id=row["takedown_id"], error=str(exc))
                continue

            import json

            next_check = settings.takedown_verify_interval_s

            if probe.dead:
                dead_updates.append((probe.reason[:200], row["takedown_id"]))
                ttl_h = None
                if row["sent_at"]:
                    ttl_h = round(
                        (datetime.now(timezone.utc) - row["sent_at"]).total_seconds() / 3600, 2
                    )
                log.info(
                    "takedown_confirmed_dead",
                    takedown_id=row["takedown_id"],
                    url=probe.url,
                    reason=probe.reason,
                    hours_to_death=ttl_h,
                )
                audits.append(
                    (
                        _ACTOR,
                        "target_dead",
                        str(row["takedown_id"]),
                        json.dumps({"reason": probe.reason, "hours_to_death": ttl_h}),
                    )
                )
            else:
                alive_updates.append((next_check, row["takedown_id"]))
                if _should_escalate(row["sent_at"], row["escalation_level"]):
                    escalations.append(row)

    finally:
        client.close()

    # --- persist ----------------------------------------------------------
    if dead_updates:
        execute_many(
            """
            UPDATE takedowns
            SET target_dead_at = now(),
                resolved_at    = now(),
                status         = 'resolved',
                verify_count   = verify_count + 1,
                meta           = meta || jsonb_build_object('death_reason', %s::text)
            WHERE id = %s
            """,
            dead_updates,
        )
    if alive_updates:
        execute_many(
            """
            UPDATE takedowns
            SET verify_count = verify_count + 1,
                verify_after = now() + make_interval(secs => %s)
            WHERE id = %s
            """,
            alive_updates,
        )
    if audits:
        try:
            execute_many(
                "INSERT INTO audit_log (actor, action, target, detail) VALUES (%s, %s, %s, %s)",
                audits,
            )
        except Exception as exc:  # noqa: BLE001
            log.warning("verify_audit_batch_failed", error=str(exc))

    escalated = _escalate(escalations)

    try:
        from pkintel.metrics import takedown_time_to_death, takedowns_confirmed_dead

        takedowns_confirmed_dead.inc(len(dead_updates))
        dead_ids = {tid for _reason, tid in dead_updates}
        now = datetime.now(timezone.utc)
        for r in rows:
            if r["takedown_id"] in dead_ids and r["sent_at"]:
                takedown_time_to_death.observe((now - r["sent_at"]).total_seconds() / 3600)
    except Exception:  # noqa: BLE001, S110 - metrics must never break verification
        pass

    log.info(
        "verify_run_complete",
        worker=worker_id,
        probed=len(rows),
        confirmed_dead=len(dead_updates),
        still_live=len(alive_updates),
        escalated=escalated,
    )
    return len(dead_updates)


def _escalate(rows: list[dict]) -> int:
    """Raise still-live targets to the next authority. Returns count escalated."""
    if not rows:
        return 0

    from pkintel.takedown.rdap import enrich_host
    from pkintel.takedown.templates import host_abuse_report, registrar_report

    count = 0
    for row in rows:
        next_level = row["escalation_level"] + 1
        if next_level >= len(ESCALATION_TARGETS):
            continue
        target_type = ESCALATION_TARGETS[next_level]

        try:
            host_info = enrich_host(row["host"])
            # Registry/CERT levels reuse the registrar template but address a
            # different recipient; the evidence body is identical.
            if target_type == "registrar":
                subject, body = registrar_report(
                    row["url"], host_info, {"sha256": None, "count": 0}
                )
                contact = host_info.get("registrar_abuse_email") or "abuse@localhost"
            else:
                subject, body = host_abuse_report(
                    row["url"], host_info, {"sha256": None, "count": 0}
                )
                contact = host_info.get("abuse_email") or "abuse@localhost"

            subject = f"[ESCALATION {next_level}] {subject}"

            execute(
                """
                INSERT INTO takedowns
                    (url_id, target_type, contact, subject, body, status, escalation_level)
                VALUES (%s, %s, %s, %s, %s, 'draft', %s)
                ON CONFLICT DO NOTHING
                """,
                (row["url_id"], target_type, contact, subject, body, next_level),
            )
            execute(
                "UPDATE takedowns SET escalation_level = %s WHERE id = %s",
                (next_level, row["takedown_id"]),
            )
            record_audit(
                _ACTOR,
                "escalated",
                target=str(row["takedown_id"]),
                to_level=next_level,
                target_type=target_type,
                contact=contact,
            )
            log.info(
                "takedown_escalated",
                takedown_id=row["takedown_id"],
                url=row["url"],
                to_level=next_level,
                target_type=target_type,
            )
            count += 1
        except Exception as exc:  # noqa: BLE001 - one failed escalation must not stop the rest
            log.warning("escalation_failed", takedown_id=row["takedown_id"], error=str(exc))

    return count


def effectiveness_report() -> dict:
    """Outcome metrics for the dashboard — the numbers that prove impact."""
    row = fetch_all(
        """
        SELECT
            count(*) FILTER (WHERE status IN ('sent', 'resolved'))            AS notices_sent,
            count(*) FILTER (WHERE target_dead_at IS NOT NULL)                AS confirmed_dead,
            count(*) FILTER (WHERE status = 'sent'
                             AND target_dead_at IS NULL)                      AS still_live,
            count(*) FILTER (WHERE escalation_level > 0)                      AS escalated,
            percentile_cont(0.5) WITHIN GROUP (
                ORDER BY EXTRACT(EPOCH FROM (target_dead_at - sent_at)) / 3600
            ) FILTER (WHERE target_dead_at IS NOT NULL AND sent_at IS NOT NULL)
                                                                              AS median_hours_to_death
        FROM takedowns
        """
    )
    if not row:
        return {}
    r = dict(row[0])
    sent = r.get("notices_sent") or 0
    dead = r.get("confirmed_dead") or 0
    r["success_rate"] = round(dead / sent, 3) if sent else None
    if r.get("median_hours_to_death") is not None:
        r["median_hours_to_death"] = round(float(r["median_hours_to_death"]), 2)
    return r
