"""
Actors API endpoints.
"""
from typing import List
from fastapi import APIRouter, HTTPException

from pkintel.db import fetch_all, fetch_one
from pkintel.models import ActorCard

router = APIRouter()

@router.get("", response_model=List[ActorCard])
async def list_actors() -> List[ActorCard]:
    """
    List all recorded actors.
    """
    query = "SELECT * FROM actors ORDER BY last_seen DESC"
    rows = fetch_all(query)
    return [ActorCard(**row) for row in rows]

@router.get("/{actor_id}", response_model=ActorCard)
async def get_actor(actor_id: int) -> ActorCard:
    """
    Retrieve a single actor by ID.
    """
    query = "SELECT * FROM actors WHERE id = %s"
    row = fetch_one(query, (actor_id,))
    if not row:
        raise HTTPException(status_code=404, detail="Actor not found")
    return ActorCard(**row)
