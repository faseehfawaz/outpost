"""
Runner for the phishing-kit hunting pipeline.

Now uses a thread pool to probe multiple URLs concurrently, matching the triage
architecture.  Each URL spawns ~10 HTTP requests to common archive paths, so
without concurrency the kithunt stage spends 99% of its time blocked on I/O.
"""

from pkintel.config import settings
from pkintel.db import claim_rows, execute, record_audit
from pkintel.kithunter.collect import hunt
from pkintel.logging import get_logger
from pkintel.pool import map_concurrent

log = get_logger(__name__)

_ACTOR = "kithunt"


def _hunt_one(url_row: dict) -> str:
    """Probe a single URL for kit archives.  Runs inside a pool thread.

    Returns the new kithunt_state string.  Exceptions propagate to
    ``map_concurrent`` which wraps them for the caller.
    """
    url_id = url_row["id"]

    # We only hunt URLs that are confirmed phish and have been triaged
    if not url_row.get("is_phish") or url_row.get("triage_state") != "triaged":
        execute(
            "UPDATE urls SET kithunt_state = 'skipped', kithunt_at = now(), locked_by = NULL, locked_at = NULL WHERE id = %s",
            (url_id,),
        )
        return "skipped"

    try:
        result = hunt(url_row)

        new_state = "collected" if result.collected else "exhausted"
        attempts = url_row.get("kithunt_attempts", 0) + 1

        execute(
            """
            UPDATE urls 
            SET kithunt_state = %s, 
                kithunt_attempts = %s, 
                kithunt_at = now(),
                locked_by = NULL,
                locked_at = NULL
            WHERE id = %s
            """,
            (new_state, attempts, url_id),
        )

        # Signature is record_audit(actor, action, target=None, **detail).
        # This previously passed a dict as `action` (a TEXT column), so
        # psycopg raised "can't adapt type 'dict'", which record_audit's own
        # try/except swallowed — EVERY kit-hunt audit row was silently lost.
        record_audit(
            _ACTOR,
            "kithunt_complete",
            target=str(url_id),
            collected=result.collected,
            kit_sha256=getattr(result, "kit_sha256", None),
        )

        return new_state

    except Exception as e:
        log.exception("Error during kit hunt for URL ID %s: %s", url_id, e)
        execute(
            "UPDATE urls SET kithunt_state = 'error', kithunt_at = now(), locked_by = NULL, locked_at = NULL WHERE id = %s",
            (url_id,),
        )
        record_audit(_ACTOR, "kithunt_error", target=str(url_id), error=str(e))
        raise


def run_once(worker_id: str = "kithunt-1", limit: int = 50) -> int:
    """
    Run the kit hunter worker once with concurrent probing.

    Claims URLs with kithunt_state='pending', then probes them concurrently
    using a thread pool (sized by settings.kithunt_workers, default 8).
    """
    urls = claim_rows(
        "urls",
        ready_col="kithunt_state",
        ready_value="pending",
        busy_value="hunting",
        worker_id=worker_id,
        limit=limit,
        extra_where="is_phish = true AND triage_state = 'triaged'",
    )
    if not urls:
        return 0

    workers = getattr(settings, "kithunt_workers", 8)
    processed_count = 0

    for row, result, exc in map_concurrent(
        fn=_hunt_one,
        items=urls,
        workers=workers,
        stage="kithunt",
    ):
        if exc:
            log.debug("kithunt_worker_error", url_id=row["id"], error=str(exc))
        processed_count += 1

    return processed_count
