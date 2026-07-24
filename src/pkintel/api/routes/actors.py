"""
Actors API endpoints.
"""

from fastapi import APIRouter, HTTPException

from pkintel.db import fetch_all, fetch_one
from pkintel.models import ActorCard, ActorDetail, ActorKitItem

router = APIRouter()


@router.get("", response_model=list[ActorCard])
async def list_actors() -> list[ActorCard]:
    """
    List all recorded actors.
    """
    query = "SELECT * FROM actors ORDER BY last_seen DESC"
    rows = fetch_all(query)
    return [ActorCard(**row) for row in rows]


@router.get("/{actor_id}", response_model=ActorDetail)
async def get_actor(actor_id: int) -> ActorDetail:
    """
    Retrieve detailed info for a single actor including associated kits and indicators.
    """
    query = "SELECT * FROM actors WHERE id = %s"
    row = fetch_one(query, (actor_id,))
    if not row:
        raise HTTPException(status_code=404, detail="Actor not found")

    kits_query = """
        SELECT k.sha256, k.collected_at, u.brand
        FROM kit_actor ka
        JOIN kits k ON ka.kit_id = k.id
        LEFT JOIN urls u ON k.url_id = u.id
        WHERE ka.actor_id = %s
        ORDER BY k.collected_at DESC NULLS LAST
    """
    kit_rows = fetch_all(kits_query, (actor_id,))
    kits = [ActorKitItem(**k) for k in kit_rows]

    ind_query = """
        SELECT DISTINCT i.redacted_display
        FROM kit_actor ka
        JOIN indicators i ON ka.kit_id = i.kit_id
        WHERE ka.actor_id = %s
    """
    ind_rows = fetch_all(ind_query, (actor_id,))
    indicators = [r["redacted_display"] for r in ind_rows]

    return ActorDetail(**row, kits=kits, indicators=indicators)
