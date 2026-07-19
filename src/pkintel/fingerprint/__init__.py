"""Fingerprint / cluster subsystem — the actor-attribution engine.

Builds the kit-similarity graph (``kit_edges``) from per-kit fingerprints and
exfil indicators, then resolves its connected components into stable ``actors``.

Public surface (see the runner contract):
    run_once(worker_id="cluster-1", limit=0) -> int   # number of actors produced

Importing this package is side-effect-free (no DB, no network).
"""

from __future__ import annotations

from pkintel.fingerprint.cluster import recluster
from pkintel.fingerprint.runner import run_once

__all__ = ["run_once", "recluster"]
