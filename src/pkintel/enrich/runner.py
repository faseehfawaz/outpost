"""Host enrichment worker — populates the facts the pivot graph pivots on.

Pipeline position: after ``triage`` (which decides what is phish) and before
``pivot`` (which clusters on infrastructure). Without this stage,
:mod:`pkintel.fingerprint.pivot` reads a ``hosts`` table populated only by the
late RDAP path in ``takedown/rdap.py`` — so its two strongest signals,
``shared_cert`` (weight 1.0) and ``shared_ip`` (0.7), were almost entirely
absent and the pivot could not do the job it exists for.

One cycle:

  1. **Seed.** Insert a ``hosts`` row for every confirmed-phish host that lacks
     one, and re-arm hosts whose enrichment has gone stale.
  2. **Claim.** Take a batch via the usual ``FOR UPDATE SKIP LOCKED`` contract.
  3. **Enrich.** Concurrently: resolve A records, map the origin ASN, and
     fingerprint the served TLS certificate.
  4. **Persist + discover.** Write the facts back, and feed any *new* hostnames
     found in the certificate's SAN list back into ``urls`` as fresh candidates.

Step 4's discovery loop is the highest-leverage part: one handshake against one
known-bad host routinely reveals the operator's entire domain portfolio,
including lookalikes that appear in no public feed.
"""

from __future__ import annotations

from pkintel.config import settings
from pkintel.db import claim_rows, connection, execute, execute_many, record_audit
from pkintel.enrich.dnsinfo import lookup_asn, resolve_host
from pkintel.enrich.tlscert import fetch_cert
from pkintel.http import throttle_host
from pkintel.ingest.normalize import canonical_url, host_of, url_hash
from pkintel.ingest.priority import compute_priority
from pkintel.logging import get_logger
from pkintel.pool import map_concurrent

log = get_logger(__name__)

_ACTOR = "enrich"

# Seed a hosts row for every confirmed-phish host we have not recorded yet.
_SEED_SQL = """
    INSERT INTO hosts (hostname)
    SELECT DISTINCT u.host
    FROM urls u
    WHERE u.is_phish = true AND u.host <> ''
    ON CONFLICT (hostname) DO NOTHING
"""

# Attacker infrastructure rotates fast. Enrichment older than the TTL links
# today's hosts to yesterday's IPs, which actively corrupts the pivot graph
# rather than merely being incomplete.
_REARM_STALE_SQL = """
    UPDATE hosts
    SET enrich_state = 'pending'
    WHERE enrich_state = 'enriched'
      AND enriched_at < now() - make_interval(days => %s)
"""

_UPDATE_ENRICHED = """
    UPDATE hosts SET
        ip              = %(ip)s,
        ips             = %(ips)s,
        asn             = %(asn)s,
        asn_name        = %(asn_name)s,
        country         = %(country)s,
        cert_sha256     = %(cert_sha256)s,
        cert_issuer     = %(cert_issuer)s,
        cert_names      = %(cert_names)s,
        cert_not_before = %(cert_not_before)s,
        cert_not_after  = %(cert_not_after)s,
        nameservers     = %(nameservers)s,
        favicon_mmh3    = %(favicon_mmh3)s,
        enrich_state    = 'enriched',
        enrich_error    = %(enrich_error)s,
        enriched_at     = now(),
        locked_by       = NULL,
        locked_at       = NULL
    WHERE id = %(id)s
"""

_UPDATE_ERROR = """
    UPDATE hosts
    SET enrich_state = 'error', enrich_error = %s, locked_by = NULL, locked_at = NULL
    WHERE id = %s
"""

# Discovered SAN siblings become new candidates.
_INSERT_DISCOVERED = """
    INSERT INTO urls (url, url_hash, host, source_id, priority)
    VALUES (%s, %s, %s, %s, %s)
    ON CONFLICT (url_hash) DO UPDATE SET last_seen = now()
"""


class _Enriched:
    """Per-host enrichment result. Plain object; only crosses thread boundaries."""

    __slots__ = ("row", "dns", "asn", "cert")

    def __init__(self, row, dns, asn, cert) -> None:
        self.row = row
        self.dns = dns
        self.asn = asn
        self.cert = cert


def _enrich_one(row: dict) -> _Enriched:
    """Resolve, map and fingerprint one host. Runs in a worker thread."""
    hostname = row["hostname"]

    # DNS never touches the target, so it needs no throttle. The TLS handshake
    # does contact it, so it goes through the same per-host limiter as every
    # other outbound request in the platform.
    dns = resolve_host(hostname, timeout_s=settings.enrich_dns_timeout_s)

    asn = None
    if dns.ips and settings.enrich_asn_enabled:
        asn = lookup_asn(dns.ips[0], timeout_s=settings.enrich_dns_timeout_s)

    cert = None
    if dns.ips:  # no point handshaking a host that does not resolve
        throttle_host(hostname)
        cert = fetch_cert(hostname, timeout_s=settings.enrich_tls_timeout_s)

    return _Enriched(row, dns, asn, cert)


def _seed_and_rearm() -> None:
    """Insert missing host rows and re-arm stale enrichments."""
    try:
        execute(_SEED_SQL)
        execute(_REARM_STALE_SQL, (settings.enrich_ttl_days,))
    except Exception as exc:  # noqa: BLE001 - seeding must not break the stage
        log.warning("enrich_seed_failed", error=str(exc))


def _favicon_for(hostname: str) -> int | None:
    """Carry the triage favicon hash onto the host row for pivoting.

    ``urls.favicon_mmh3`` is already populated by triage; copying it here means
    the pivot's ``shared_favicon`` edge works off a single table.
    """
    from pkintel.db import fetch_one

    try:
        row = fetch_one(
            """
            SELECT favicon_mmh3 FROM urls
            WHERE host = %s AND favicon_mmh3 IS NOT NULL
            ORDER BY triaged_at DESC NULLS LAST
            LIMIT 1
            """,
            (hostname,),
        )
    except Exception:  # noqa: BLE001
        return None
    return row["favicon_mmh3"] if row else None


def _discover_from_sans(results: list[_Enriched]) -> int:
    """Feed unseen certificate SAN names back in as fresh candidates.

    A campaign's certificate frequently lists every lookalike the operator
    owns. Those siblings often appear in no public feed at all, so this is one
    of the few places the platform discovers infrastructure entirely on its own
    rather than reacting to somebody else's report.
    """
    candidates: set[str] = set()
    for res in results:
        if not (res.cert and res.cert.ok):
            continue
        own = res.row["hostname"].lower()
        for name in res.cert.names:
            if name and name != own and "." in name and "*" not in name:
                candidates.add(name)

    if not candidates:
        return 0

    try:
        with connection() as conn, conn.cursor() as cur:
            cur.execute(
                "INSERT INTO sources (name, kind) VALUES (%s, %s) "
                "ON CONFLICT (name) DO UPDATE SET kind = EXCLUDED.kind RETURNING id",
                ("cert_san_pivot", "ct"),
            )
            source_id = cur.fetchone()["id"]
    except Exception as exc:  # noqa: BLE001
        log.warning("enrich_source_upsert_failed", error=str(exc))
        return 0

    rows = []
    for name in sorted(candidates):
        try:
            canon = canonical_url(f"https://{name}")
            h = host_of(canon)
        except Exception:  # noqa: BLE001
            continue
        if not h:
            continue
        priority = compute_priority(
            canon, source_name="urlscan", priority_brands=settings.priority_brands
        )
        rows.append((canon, url_hash(canon), h, source_id, priority))

    if not rows:
        return 0

    try:
        execute_many(_INSERT_DISCOVERED, rows)
    except Exception as exc:  # noqa: BLE001
        log.warning("enrich_discovery_insert_failed", error=str(exc))
        return 0

    log.info("enrich_discovered_siblings", count=len(rows))
    record_audit(_ACTOR, "san_discovery", target="cert_san_pivot", discovered=len(rows))
    return len(rows)


def run_once(worker_id: str = "enrich-1", limit: int = 200, workers: int | None = None) -> int:
    """Enrich a batch of pending hosts. Returns the number enriched."""
    if not settings.enrich_enabled:
        return 0

    _seed_and_rearm()

    # `hosts` has no priority column, so ordering must be explicit.
    rows = claim_rows(
        table="hosts",
        ready_col="enrich_state",
        ready_value="pending",
        busy_value="enriching",
        worker_id=worker_id,
        limit=limit,
        order_by="id",
    )
    if not rows:
        return 0

    n_workers = workers if workers is not None else settings.enrich_workers
    ok_params: list[dict] = []
    err_params: list[tuple] = []
    results: list[_Enriched] = []

    for row, res, exc in map_concurrent(
        _enrich_one, rows, workers=n_workers, stage="enrich"
    ):
        if exc is not None:
            log.warning("enrich_row_error", hostname=row.get("hostname"), error=str(exc))
            err_params.append((str(exc)[:500], row["id"]))
            continue

        results.append(res)
        dns, asn, cert = res.dns, res.asn, res.cert

        # A host that resolves to nothing is still a useful (negative) fact —
        # record it as enriched rather than as an error, so we do not retry it
        # every cycle. The reaper and the TTL handle genuine transients.
        ok_params.append(
            {
                "id": row["id"],
                "ip": dns.ips[0] if dns.ips else None,
                "ips": dns.ips,
                "asn": asn.asn if asn else None,
                "asn_name": asn.asn_name if asn else None,
                "country": asn.country if asn else None,
                "cert_sha256": cert.sha256 if cert else None,
                "cert_issuer": cert.issuer if cert else None,
                "cert_names": cert.names if cert else [],
                "cert_not_before": cert.not_before if cert else None,
                "cert_not_after": cert.not_after if cert else None,
                "nameservers": dns.nameservers,
                "favicon_mmh3": _favicon_for(row["hostname"]),
                "enrich_error": (dns.error or (cert.error if cert else None)),
            }
        )

    if ok_params:
        with connection() as conn, conn.cursor() as cur:
            cur.executemany(_UPDATE_ENRICHED, ok_params)
    if err_params:
        execute_many(_UPDATE_ERROR, err_params)

    discovered = _discover_from_sans(results)

    with_cert = sum(1 for p in ok_params if p["cert_sha256"])
    with_ip = sum(1 for p in ok_params if p["ip"])
    log.info(
        "enrich_run_complete",
        worker=worker_id,
        claimed=len(rows),
        enriched=len(ok_params),
        errors=len(err_params),
        with_ip=with_ip,
        with_cert=with_cert,
        siblings_discovered=discovered,
        workers=n_workers,
    )
    record_audit(
        _ACTOR,
        "enrich_batch",
        target=worker_id,
        enriched=len(ok_params),
        with_cert=with_cert,
        discovered=discovered,
    )
    return len(ok_params)


__all__ = ["run_once"]
