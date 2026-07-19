"""Uniform runner entry point for the fingerprint/cluster subsystem.

Every subsystem exposes ``run_once(worker_id, limit) -> int`` so the CLI can
drive them all identically. Clustering, however, is a **global** operation over
the entire corpus rather than a per-row work-queue drain: there is nothing to
claim. ``limit`` is therefore accepted for interface uniformity but ignored (a
partial recluster would produce an inconsistent graph). The default ``limit=0``
signals "no per-row cap applies".
"""

from __future__ import annotations

from pkintel.fingerprint.cluster import recluster
from pkintel.logging import get_logger

log = get_logger(__name__)


def run_once(worker_id: str = "cluster-1", limit: int = 0) -> int:
    """Recluster the whole kit graph. Returns the number of actors produced.

    ``limit`` is intentionally unused — see the module docstring.
    """
    summary = recluster(worker_id=worker_id)
    return summary["actors"]
