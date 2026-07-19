"""
Feeds API endpoints.
"""
from typing import List, Dict, Any
from fastapi import APIRouter

from pkintel.db import fetch_all, fetch_one

router = APIRouter()

@router.get("/live")
async def get_live_feeds() -> List[Dict[str, Any]]:
    """
    Get currently live phishing URLs.
    """
    query = """
        SELECT url, brand, phish_score, first_seen
        FROM urls
        WHERE is_phish = true AND is_live = true
        ORDER BY first_seen DESC
    """
    return fetch_all(query)

@router.get("/stats")
async def get_stats() -> Dict[str, int]:
    """
    Get pipeline statistics.
    """
    stats = {}
    stats["total_urls"] = fetch_one("SELECT count(*) as c FROM urls")["c"]
    stats["phish_count"] = fetch_one("SELECT count(*) as c FROM urls WHERE is_phish = true")["c"]
    stats["kits_collected"] = fetch_one("SELECT count(*) as c FROM kits")["c"]
    stats["actors_identified"] = fetch_one("SELECT count(*) as c FROM actors")["c"]
    stats["takedowns_sent"] = fetch_one("SELECT count(*) as c FROM takedowns WHERE status = 'sent'")["c"]
    return stats

@router.get("/recent")
async def get_recent_triaged() -> List[Dict[str, Any]]:
    """
    Get most recent 50 triaged URLs.
    """
    query = """
        SELECT url, brand, is_phish, triage_state, triaged_at
        FROM urls
        WHERE triage_state = 'triaged'
        ORDER BY triaged_at DESC
        LIMIT 50
    """
    return fetch_all(query)
