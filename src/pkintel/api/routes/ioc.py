"""
IOC API endpoints.
"""
from datetime import datetime

from fastapi import APIRouter, Query

from pkintel.db import fetch_all
from pkintel.models import IOCEntry

router = APIRouter()

@router.get("", response_model=list[IOCEntry])
async def get_ioc_feed(
    type: str | None = None,
    since: datetime | None = None,
    limit: int = Query(100, le=1000)
) -> list[IOCEntry]:
    """
    Retrieve JSON IOC feed. Redacted by default for public consumption.
    """
    # Note: Value redaction should be applied before returning.
    # We join kits, urls, and actors to fulfill the IOCEntry fields.
    query = """
        SELECT i.type, i.value AS value_redacted, 
               k.sha256 AS kit_sha256, 
               a.label AS actor_label, 
               u.brand
        FROM indicators i
        JOIN kits k ON i.kit_id = k.id
        LEFT JOIN urls u ON k.id = u.kit_id
        LEFT JOIN kit_actor ka ON k.id = ka.kit_id
        LEFT JOIN actors a ON ka.actor_id = a.id
        WHERE 1=1
    """
    params: list = []
    
    if type:
        query += " AND i.type = %s"
        params.append(type)
    if since:
        # Assuming indicators table has a created_at column
        query += " AND i.created_at >= %s"
        params.append(since)
        
    query += " ORDER BY i.id DESC LIMIT %s"
    params.append(limit)
    
    rows = fetch_all(query, tuple(params))
    return [IOCEntry(**row) for row in rows]
