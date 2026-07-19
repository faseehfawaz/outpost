"""Combine triage signals into a 0..100 phishing score.

Pure function, no I/O — deterministic given its inputs, which makes it directly
unit-testable. Contributions are additive and non-negative, then clamped to
``[0, 100]``; this guarantees the monotonicity property "more signals never
lowers the score" that triage relies on for stable prioritisation.

Weighting rationale (strongest first):

* off-domain password POST (45) — the near-definitive credential-harvest tell;
* login form present at all (12) — a password field on the page;
* known brand impersonation (15), + priority/UAE brand bonus (8);
* favicon matches a known brand hash (20), + bonus (5) when it corroborates the
  text-detected brand;
* phishing-keyword density (3 per distinct hit, capped at 6 hits => 18);
* logo pHash matches a known brand logo (15);
* the page is live (5) — a live phish is more actionable.

A page is flagged ``is_phish`` when its score meets
``settings.triage_phish_threshold`` (default 50). Concretely, the two dominant
signals together (off-domain password POST + a login form, 57) clear the
threshold on their own, as intended.
"""

from __future__ import annotations

from pkintel.config import settings
from pkintel.models import TriageResult
from pkintel.triage.forms import FormSignal

WEIGHTS: dict[str, int] = {
    "offdomain_password_post": 45,
    "password_form": 12,
    "brand": 15,
    "priority_brand": 8,        # extra, on top of "brand"
    "favicon_known": 20,
    "favicon_brand_match": 5,   # extra, when favicon brand == detected brand
    "keyword_each": 3,
    "keyword_cap_hits": 6,      # count no more than this many keyword hits
    "logo_match": 15,
    "live": 5,
}


def score(
    *,
    is_live: bool,
    brand: str | None = None,
    brand_is_priority: bool = False,
    favicon_brand: str | None = None,
    form: FormSignal | None = None,
    keyword_hits: int = 0,
    logo_match: bool = False,
    reasons: list[str] | None = None,
    threshold: int | None = None,
) -> TriageResult:
    """Fold triage signals into a :class:`TriageResult`.

    ``reasons`` seeds the human-readable explanation list (e.g. brand-match
    reasons from :func:`pkintel.triage.brand.detect_brand`); scoring appends its
    own. ``threshold`` overrides ``settings.triage_phish_threshold`` for tests.
    """
    explain: list[str] = list(reasons or [])
    total = 0

    if form is not None and form.has_password_field:
        total += WEIGHTS["password_form"]
        explain.append("login form with a password field")
        if form.posts_offdomain:
            total += WEIGHTS["offdomain_password_post"]
            explain.append("password form posts to an off-domain host")

    if brand:
        total += WEIGHTS["brand"]
        explain.append(f"brand impersonation: {brand}")
        if brand_is_priority:
            total += WEIGHTS["priority_brand"]
            explain.append(f"priority (UAE) brand: {brand}")

    if favicon_brand:
        total += WEIGHTS["favicon_known"]
        explain.append(f"favicon matches known brand hash: {favicon_brand}")
        if brand and favicon_brand == brand:
            total += WEIGHTS["favicon_brand_match"]
            explain.append("favicon corroborates the detected brand")

    if keyword_hits > 0:
        capped = min(keyword_hits, WEIGHTS["keyword_cap_hits"])
        total += capped * WEIGHTS["keyword_each"]
        explain.append(f"phishing keyword density ({keyword_hits} hits)")

    if logo_match:
        total += WEIGHTS["logo_match"]
        explain.append("logo pHash matches a known brand logo")

    if is_live:
        total += WEIGHTS["live"]
        explain.append("page is live")

    total = max(0, min(100, total))
    limit = settings.triage_phish_threshold if threshold is None else threshold

    return TriageResult(
        is_phish=total >= limit,
        score=total,
        brand=brand,
        reasons=explain,
        is_live=is_live,
    )
