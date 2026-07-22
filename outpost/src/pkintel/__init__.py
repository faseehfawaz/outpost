"""pkintel — phishing-kit intelligence pipeline.

Five independently demo-able subsystems glued by a Postgres spine:

    ingest      -> pulls candidate URLs from public feeds
    triage      -> decides "is this a phish, and against whom?"
    kithunter   -> opportunistically collects *exposed* kit archives
    analyzer    -> statically dissects kits (NEVER executed, no-network)
    fingerprint -> hashes + clusters kits into actors (union-find)
    takedown    -> resolves abuse contacts, reports, tracks
    api         -> public read-only FastAPI over the spine

Every module is written to the non-negotiables in docs/SCOPE_AND_ETHICS.md.
"""

__version__ = "0.1.0"
