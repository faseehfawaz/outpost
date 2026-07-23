"""Triage subsystem.

For each newly-ingested URL, fetch it politely and decide "is this a phish, and
against whom?", producing a 0..100 score, a brand, human-readable reasons, and
favicon/logo fingerprints. Phish are handed on to the kit hunter; everything
else is marked out of scope.

The runner contract (:func:`run_once`) is re-exported here so the CLI can drive
every subsystem uniformly. Importing this package is side-effect free — no DB or
network access happens until ``run_once`` is called.
"""

from __future__ import annotations

from pkintel.triage.runner import run_once

__all__ = ["run_once"]
