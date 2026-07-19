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
            kwargs={"row_factory": dict_row, "autocommit": False},
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
) -> list[dict[str, Any]]:
    """Atomically claim up to ``limit`` rows from a state-machine table.

    Flips ``ready_col`` from ``ready_value`` to ``busy_value`` and stamps
    ``locked_by``/``locked_at`` in a single statement, using SKIP LOCKED so
    concurrent workers never collide. Returns the claimed rows.

    ``table`` / ``ready_col`` are interpolated (trusted, internal callers only —
    never user input); row *values* are always parameterised.
    """
    where = f"{ready_col} = %(ready)s"
    if extra_where:
        where += f" AND ({extra_where})"
    sql = f"""
        WITH claimed AS (
            SELECT id FROM {table}
            WHERE {where}
            ORDER BY id
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
    directory = Path(migrations_dir or Path(__file__).resolve().parents[2] / "db" / "migrations")
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
