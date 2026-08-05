"""
IOC API endpoints.
"""

from datetime import datetime

from fastapi import APIRouter, Query

from pkintel.db import fetch_all
from pkintel.models import IOCEntry

router = APIRouter()

# Public IOC feed. One complete, static statement — deliberately not assembled
# from fragments. Three things this has to get right, all of which have broken
# before:
#
# 1. FAN-OUT. A kit can belong to more than one actor cluster, so the
#    `kit_actor` join multiplies rows: an indicator came back N times and the
#    LIMIT then silently truncated real data. `DISTINCT ON (i.id)` collapses it
#    back to one row per indicator.
#
# 2. ORDERING. Postgres requires the DISTINCT ON expression to lead ORDER BY.
#    `i.id DESC` satisfies that *and* gives newest-first, because
#    `indicators.id` is a BIGSERIAL and so id order is insertion order. A
#    previous revision ordered by `i.created_at` — a column this table does not
#    have — and every request 500'd.
#
# 3. STATIC TEXT. tests/test_schema_consistency.py parses SQL literals straight
#    out of the source and validates every table and column against the
#    migrations, with no database. It skips any literal containing `{}` (an
#    f-string/format fragment is not parseable SQL). Building the WHERE clause
#    by concatenation therefore made this query invisible to the one test that
#    would have caught the bug above. The NULL-guard idiom below keeps the
#    statement whole and constant, so it stays covered.
_IOC_SQL = """
    SELECT DISTINCT ON (i.id)
           i.type             AS kind,
           i.redacted_display AS value,
           k.sha256           AS kit_sha256,
           a.label            AS actor_label,
           u.brand            AS brand,
           k.collected_at     AS first_seen
    FROM indicators i
    JOIN kits k ON i.kit_id = k.id
    LEFT JOIN urls u ON k.url_id = u.id
    LEFT JOIN kit_actor ka ON k.id = ka.kit_id
    LEFT JOIN actors a ON ka.actor_id = a.id
    WHERE (%s::text IS NULL OR i.type = %s::text)
      AND (%s::timestamptz IS NULL OR k.collected_at >= %s::timestamptz)
    ORDER BY i.id DESC
    LIMIT %s
"""


@router.get("", response_model=list[IOCEntry])
async def get_ioc_feed(
    type: str | None = None, since: datetime | None = None, limit: int = Query(100, le=1000)
) -> list[IOCEntry]:
    """
    Retrieve JSON IOC feed. Redacted by default for public consumption.

    Values are redacted at write time (``indicators.redacted_display``);
    ``full_value_encrypted`` is never read on this path.
    """
    rows = fetch_all(_IOC_SQL, (type, type, since, since, limit))
    return [IOCEntry(**row) for row in rows]
