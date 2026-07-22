"""Ingest subsystem — pull candidate phishing URLs from public feeds.

The ingest worker polls a set of public, free feeds (URLhaus, OpenPhish,
urlscan.io, Certificate Transparency via crt.sh, community GitHub lists),
canonicalises + deduplicates the URLs, and enqueues brand-new ones into the
``urls`` state machine for the triage worker to pick up.

Everything here is **passive and read-only against the feeds**: we only fetch
what the feed publishes, politely and rate-limited (see :mod:`pkintel.http`).

Import-safety: importing this package (or any submodule) must never touch the
database or the network. ``run_once`` is re-exported as a thin wrapper that
imports the heavyweight :mod:`pkintel.ingest.runner` lazily, so ``import
pkintel.ingest`` stays cheap and side-effect free.
"""

from __future__ import annotations


def run_once(worker_id: str = "ingest-1", limit: int = 500) -> int:
    """Run one ingest cycle. See :func:`pkintel.ingest.runner.run_once`.

    Thin re-export that defers importing the DB/HTTP-heavy runner until called,
    keeping ``import pkintel.ingest`` free of side effects.
    """
    from pkintel.ingest.runner import run_once as _run_once

    return _run_once(worker_id=worker_id, limit=limit)


__all__ = ["run_once"]
