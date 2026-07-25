"""Work-queue priority for freshly ingested URLs. Pure, no I/O.

The problem
-----------
``claim_rows`` ordered strictly by ``id``, i.e. FIFO by insertion. With ~10k
bulk URLs/cycle arriving from Phishing.Database and PhishStats, a Certificate
Transparency hit for ``adcb-secure-login.com`` — issued ninety seconds ago,
targeting a priority UAE brand, and quite possibly not yet serving content —
landed at the *back* of a queue thousands deep. The freshest and most
actionable intelligence was consistently triaged last, often hours later, by
which time the fast-moving campaigns had already rotated.

The fix
-------
A 0-100 priority stamped at ingest, ordered ``priority DESC, id``. FIFO still
applies *within* a band, so nothing starves — a low-priority URL is never
skipped, only overtaken by something more urgent.

Weighting rationale
-------------------
* **Source freshness (0-40)** dominates. A CT-log certificate is seconds old and
  is the earliest possible signal. A GitHub blocklist entry may be weeks old and
  already dead — by the time it reaches us, someone else has reported it.
* **Priority-brand hostname match (+35)** — a UAE brand in the hostname is the
  single strongest reason for *us* specifically to look, given the platform's
  UAE-first mandate.
* **Any known-brand match (+15)** — worth prioritising, but not our mandate.
* **Credential-path hints (+10)** — ``/login``, ``/signin``, ``/verify`` in the
  path suggest a live harvesting page rather than a parked domain.
* **Suspicious TLD (+5)** — the free/cheap TLDs that dominate phishing.
"""

from __future__ import annotations

from urllib.parse import urlsplit

# Freshness by feed. Higher = the feed tells us about a URL sooner after it goes
# live, so triaging it promptly has more value.
SOURCE_FRESHNESS: dict[str, int] = {
    "certstream": 40,  # live cert issuance — seconds old, often pre-deployment
    "crtsh": 32,  # CT via polling — minutes to hours old
    "urlscan": 28,  # community scans, near real-time
    "threatfox": 22,
    "urlhaus": 20,
    "openphish": 18,
    "phishstats": 12,
    "phishing.database": 8,  # bulk repo, frequently stale
    "github": 6,  # community text lists, frequently stale
    "manual": 45,  # an analyst asked for this specifically
}

DEFAULT_FRESHNESS = 10

# Path fragments that suggest an actual credential-harvesting page.
CREDENTIAL_PATH_HINTS = (
    "login",
    "signin",
    "sign-in",
    "verify",
    "secure",
    "account",
    "auth",
    "update",
    "confirm",
    "webscr",
    "wallet",
)

# TLDs disproportionately represented in phishing (free or near-free registration).
SUSPICIOUS_TLDS = (
    ".tk", ".ml", ".ga", ".cf", ".gq",  # Freenom family
    ".xyz", ".top", ".buzz", ".click", ".link",
    ".rest", ".cyou", ".icu", ".sbs", ".cfd",
    ".zip", ".mov",  # confusable with file extensions
)

WEIGHTS = {
    "priority_brand_host": 35,
    "known_brand_host": 15,
    "credential_path": 10,
    "suspicious_tld": 5,
}


def _slug(text: str) -> str:
    """Collapse to alphanumerics so ``emirates-nbd`` matches ``emiratesnbd``."""
    return "".join(ch for ch in text.lower() if ch.isalnum())


def compute_priority(
    url: str,
    *,
    source_name: str,
    priority_brands: list[str],
    known_brands: list[str] | None = None,
) -> int:
    """Return a 0-100 work-queue priority for ``url``. Pure and deterministic.

    ``source_name`` should match a key in :data:`SOURCE_FRESHNESS` (adapter
    ``.name``); unknown sources get :data:`DEFAULT_FRESHNESS` rather than 0, so
    a newly added feed is never silently starved.
    """
    score = SOURCE_FRESHNESS.get(source_name.lower(), DEFAULT_FRESHNESS)

    try:
        parts = urlsplit(url)
        host = (parts.hostname or "").lower()
        path = (parts.path or "").lower()
    except Exception:  # noqa: BLE001 - a malformed URL still deserves a base priority
        return max(0, min(100, score))

    host_slug = _slug(host)

    # Brand in the hostname. Priority (UAE) brands win outright; we do not add
    # both bonuses, since a priority brand is by definition also a known brand.
    if any(_slug(b) and _slug(b) in host_slug for b in priority_brands):
        score += WEIGHTS["priority_brand_host"]
    elif known_brands and any(_slug(b) and _slug(b) in host_slug for b in known_brands):
        score += WEIGHTS["known_brand_host"]

    if any(hint in path for hint in CREDENTIAL_PATH_HINTS):
        score += WEIGHTS["credential_path"]

    if any(host.endswith(tld) for tld in SUSPICIOUS_TLDS):
        score += WEIGHTS["suspicious_tld"]

    return max(0, min(100, score))
