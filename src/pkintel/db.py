"""Database layer — the work queue lives here.

Postgres *is* the queue. Workers claim rows with
``SELECT ... FOR UPDATE SKIP LOCKED`` so many workers can drain a state machine
concurrently without stepping on each other and without a broker. See
:func:`claim_rows`.

Everything is synchronous psycopg3 over a connection pool; the pipeline is I/O
bound and single-node, so threads + a pool is simpler and more robust than
async-everywhere. FastAPI calls these from its threadpool.
"""

from __future__ import annotations

import contextlib
from collections.abc import Iterator, Sequence
from pathlib import Path
from typing import Any

import psycopg
from psycopg.rows import dict_row
from psycopg_pool import ConnectionPool

from pkintel.config import settings
from pkintel.logging import get_logger

log = get_logger(__name__)

_pool: ConnectionPool | None = None


def get_pool() -> ConnectionPool:
    global _pool
    if _pool is None:
        _pool = ConnectionPool(
            conninfo=settings.db_dsn,
            min_size=settings.db_pool_min,
            max_size=settings.db_pool_max,
            kwargs={
                "row_factory": dict_row,
                "autocommit": False,
                # Bound how long a single connection attempt can block. Without
                # this, an unreachable database causes every caller — including
                # the /metrics scrape and the /health endpoint — to hang for the
                # OS TCP timeout, turning a database blip into an apparent total
                # outage of the observability surface.
                "connect_timeout": settings.db_connect_timeout_s,
            },
            # Bound how long a caller waits for a free pooled connection.
            timeout=settings.db_pool_timeout_s,
            open=True,
        )
    return _pool


def close_pool() -> None:
    global _pool
    if _pool is not None:
        _pool.close()
        _pool = None


@contextlib.contextmanager
def connection() -> Iterator[psycopg.Connection]:
    """Yield a pooled connection; commit on success, rollback on error."""
    pool = get_pool()
    with pool.connection() as conn:
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise


def fetch_all(sql: str, params: Sequence[Any] | None = None) -> list[dict[str, Any]]:
    with connection() as conn, conn.cursor() as cur:
        cur.execute(sql, params)
        return cur.fetchall()


def fetch_one(sql: str, params: Sequence[Any] | None = None) -> dict[str, Any] | None:
    with connection() as conn, conn.cursor() as cur:
        cur.execute(sql, params)
        return cur.fetchone()


def execute(sql: str, params: Sequence[Any] | None = None) -> int:
    with connection() as conn, conn.cursor() as cur:
        cur.execute(sql, params)
        return cur.rowcount


def claim_rows(
    table: str,
    *,
    ready_col: str,
    ready_value: str,
    busy_value: str,
    worker_id: str,
    limit: int = 10,
    extra_where: str = "",
    returning: str = "*",
    order_by: str = "priority DESC, id",
) -> list[dict[str, Any]]:
    """Atomically claim up to ``limit`` rows from a state-machine table.

    Flips ``ready_col`` from ``ready_value`` to ``busy_value`` and stamps
    ``locked_by``/``locked_at`` in a single statement, using SKIP LOCKED so
    concurrent workers never collide. Returns the claimed rows.

    ``table`` / ``ready_col`` / ``order_by`` are interpolated (trusted, internal
    callers only — never user input); row *values* are always parameterised.

    Ordering
    --------
    Defaults to ``priority DESC, id`` — highest-priority work first, FIFO within
    a priority band. This matters: the previous ``ORDER BY id`` was strict FIFO,
    so a certstream lookalike hit minutes old queued behind every stale URL in
    the table, and the freshest, most actionable intelligence was worked *last*.
    Tables without a ``priority`` column must pass ``order_by="id"``.
    """
    where = f"{ready_col} = %(ready)s"
    if extra_where:
        where += f" AND ({extra_where})"
    sql = f"""
        WITH claimed AS (
            SELECT id FROM {table}
            WHERE {where}
            ORDER BY {order_by}
            FOR UPDATE SKIP LOCKED
            LIMIT %(limit)s
        )
        UPDATE {table} t
        SET {ready_col} = %(busy)s,
            locked_by = %(worker)s,
            locked_at = now()
        FROM claimed
        WHERE t.id = claimed.id
        RETURNING {returning}
    """
    params = {
        "ready": ready_value,
        "busy": busy_value,
        "limit": limit,
        "worker": worker_id,
    }
    with connection() as conn, conn.cursor() as cur:
        cur.execute(sql, params)
        return cur.fetchall()


def execute_many(sql: str, rows: Sequence[Sequence[Any]]) -> int:
    """Run ``sql`` once per row inside a SINGLE transaction/round-trip batch.

    The runners previously issued one ``execute()`` per row, and each
    ``execute()`` opens its own pooled connection *and* its own transaction —
    so a 50-row triage batch cost 100+ transactions (one per update, one per
    audit). At 64-way concurrency that becomes the bottleneck. ``executemany``
    with a pipelined psycopg3 connection collapses it to one.
    """
    if not rows:
        return 0
    with connection() as conn, conn.cursor() as cur:
        cur.executemany(sql, rows)
        return cur.rowcount


# --------------------------------------------------------------------------- reaper
# (table, state column, busy value, ready value to restore, lease setting,
#  reap-counter column)
#
# The counter column matters: `urls` runs TWO independent state machines
# (triage and kithunt) over the same row. Sharing one `reap_count` between them
# meant two triage reaps plus one kithunt reap tripped the poison threshold and
# parked a perfectly healthy row in 'error' — a stage being flaky poisoned rows
# for a stage that was fine. Migration 006 adds the split columns; this is what
# makes them do something.
_REAPABLE: tuple[tuple[str, str, str, str, str, str], ...] = (
    ("urls", "triage_state", "triaging", "new", "reaper_lease_triage_s", "reap_count_triage"),
    (
        "urls",
        "kithunt_state",
        "hunting",
        "pending",
        "reaper_lease_kithunt_s",
        "reap_count_kithunt",
    ),
    ("kits", "analysis_state", "analyzing", "stored", "reaper_lease_analyze_s", "reap_count"),
    ("takedowns", "status", "sending", "draft", "reaper_lease_takedown_s", "reap_count"),
    ("hosts", "enrich_state", "enriching", "pending", "reaper_lease_enrich_s", "reap_count"),
)


def reap_stuck_rows() -> dict[str, int]:
    """Return rows abandoned by dead workers to their ready state.

    Why this exists
    ---------------
    ``claim_rows`` flips a row to a busy state and stamps ``locked_at``, but
    nothing ever released it. A worker killed by OOM, SIGKILL, a power cut, or a
    ``systemctl restart`` mid-batch left its rows pinned in
    ``triaging``/``hunting``/``analyzing``/``sending`` **permanently**. Nothing
    logged it and nothing retried them, so the queue leaked a few rows per crash
    and slowly bled out while every dashboard still looked green.

    A row is reaped when its lease (``settings.reaper_lease_*_s``) has expired.
    Leases are set well above the slowest legitimate run of each stage so we
    never reap live work.

    Poison rows: a row that repeatedly kills its worker would loop forever, so
    after ``settings.reaper_max_reaps`` we park it in ``error`` instead.
    Returns ``{"urls.triage_state": n, ...}`` counts of rows recovered.
    """
    if not settings.reaper_enabled:
        return {}

    recovered: dict[str, int] = {}
    for table, col, busy, ready, lease_attr, count_col in _REAPABLE:
        lease_s = getattr(settings, lease_attr)
        sql = f"""
            UPDATE {table}
            SET {col} = CASE
                    WHEN {count_col} + 1 >= %(max_reaps)s THEN 'error'
                    ELSE %(ready)s
                END,
                {count_col} = {count_col} + 1,
                locked_by = NULL,
                locked_at = NULL
            WHERE {col} = %(busy)s
              AND locked_at IS NOT NULL
              AND locked_at < now() - make_interval(secs => %(lease)s)
            RETURNING id, {count_col} AS reap_count
        """
        params = {
            "busy": busy,
            "ready": ready,
            "lease": lease_s,
            "max_reaps": settings.reaper_max_reaps,
        }
        try:
            with connection() as conn, conn.cursor() as cur:
                cur.execute(sql, params)
                rows = cur.fetchall()
        except Exception as exc:  # noqa: BLE001 - the reaper must never take the pipeline down
            log.warning("reaper_failed", table=table, column=col, error=str(exc))
            continue

        if rows:
            poisoned = sum(1 for r in rows if r["reap_count"] >= settings.reaper_max_reaps)
            recovered[f"{table}.{col}"] = len(rows)
            log.warning(
                "reaped_stuck_rows",
                table=table,
                column=col,
                count=len(rows),
                poisoned=poisoned,
                lease_s=lease_s,
            )
            record_audit(
                "reaper",
                "reaped",
                target=f"{table}.{col}",
                count=len(rows),
                poisoned=poisoned,
            )
            try:
                from pkintel.metrics import rows_reaped

                rows_reaped.labels(queue=f"{table}.{col}").inc(len(rows))
            except Exception:  # noqa: BLE001, S110 - metrics must never break the reaper
                pass
    return recovered


def queue_depths() -> dict[str, int]:
    """Snapshot of every queue's depth. Feeds Prometheus gauges and /health."""
    sql = """
        SELECT 'triage_new'      AS q, count(*) AS n FROM urls  WHERE triage_state = 'new'
        UNION ALL SELECT 'triage_busy',   count(*) FROM urls  WHERE triage_state = 'triaging'
        UNION ALL SELECT 'kithunt_pending', count(*) FROM urls WHERE kithunt_state = 'pending'
        UNION ALL SELECT 'kithunt_busy',  count(*) FROM urls  WHERE kithunt_state = 'hunting'
        UNION ALL SELECT 'analyze_stored', count(*) FROM kits WHERE analysis_state = 'stored'
        UNION ALL SELECT 'analyze_busy',  count(*) FROM kits  WHERE analysis_state = 'analyzing'
        UNION ALL SELECT 'takedown_draft', count(*) FROM takedowns WHERE status = 'draft'
        UNION ALL SELECT 'takedown_sent',  count(*) FROM takedowns WHERE status = 'sent'
        UNION ALL SELECT 'enrich_pending', count(*) FROM hosts WHERE enrich_state = 'pending'
        UNION ALL SELECT 'enrich_busy',    count(*) FROM hosts WHERE enrich_state = 'enriching'
    """
    try:
        return {r["q"]: r["n"] for r in fetch_all(sql)}
    except Exception as exc:  # noqa: BLE001
        log.warning("queue_depths_failed", error=str(exc))
        return {}


def record_audit(actor: str, action: str, target: str | None = None, **detail: Any) -> None:
    """Append to the accountability log. Best-effort; never raises into callers."""
    import json

    try:
        execute(
            "INSERT INTO audit_log (actor, action, target, detail) VALUES (%s, %s, %s, %s)",
            (actor, action, target, json.dumps(detail, default=str)),
        )
    except Exception as exc:  # pragma: no cover - audit must not break the pipeline
        log.warning("audit_write_failed", error=str(exc))


def run_migrations(migrations_dir: str | Path | None = None) -> list[str]:
    """Apply every ``*.sql`` migration in order, tracked in ``schema_migrations``."""
    if migrations_dir:
        directory = Path(migrations_dir)
    elif Path("db/migrations").exists():
        directory = Path("db/migrations")
    else:
        directory = Path(__file__).resolve().parents[2] / "db" / "migrations"

    files = sorted(directory.glob("*.sql"))
    applied: list[str] = []

    with connection() as conn, conn.cursor() as cur:
        cur.execute(
            "CREATE TABLE IF NOT EXISTS schema_migrations "
            "(filename TEXT PRIMARY KEY, applied_at TIMESTAMPTZ NOT NULL DEFAULT now())"
        )
        cur.execute("SELECT filename FROM schema_migrations")
        done = {r["filename"] for r in cur.fetchall()}

    for f in files:
        if f.name in done:
            continue
        sql = f.read_text()
        with connection() as conn, conn.cursor() as cur:
            cur.execute(sql)
            cur.execute("INSERT INTO schema_migrations (filename) VALUES (%s)", (f.name,))
        applied.append(f.name)
        log.info("migration_applied", filename=f.name)

    return applied
