"""Fold rendered-page signals into the triage score. Pure — no I/O.

:func:`pkintel.triage.score.score` handles the cheap static signals. This module
takes that result plus a :class:`~pkintel.triage.render.RenderResult` and adds
the signals only a real browser can observe. Keeping them separate preserves the
purity (and the unit tests) of the static scorer.

Why these weights
-----------------
The rendered signals are deliberately weighted *higher* than their static
equivalents, because they are much harder for an attacker to fake and much
harder for a benign site to trip accidentally:

* **Observed off-origin credential POST (50).** The renderer watched the page
  actually contact an external endpoint. This is not an inference from source
  code — it is behaviour. It is the strongest single signal in the platform.
* **Known exfil channel contacted (45).** A page that talks to
  ``api.telegram.org`` or a Discord webhook is not ambiguous.
* **Screenshot matches a real brand login page (40).** Defeats the image-only
  clone that carries no brand text anywhere in the DOM — invisible to static
  triage, unmistakable to a perceptual hash.
* **Password field appears only after JS (30).** The static fetch saw no
  password input and the rendered page has one. That gap *is* the tell: benign
  sites rarely hide their login form behind a bundle, and phishing SPAs always
  do.
* **Cloaking detected (35).** The site served materially different content to
  different personas. Legitimate sites do not do this; anti-analysis kits do.

Scores remain clamped to 0-100, and the "more signals never lowers the score"
monotonicity property of the static scorer is preserved here too.
"""

from __future__ import annotations

from dataclasses import dataclass

from pkintel.models import TriageResult
from pkintel.triage.render import RenderResult

DEEP_WEIGHTS: dict[str, int] = {
    "observed_offdomain_post": 50,
    "known_exfil_channel": 45,
    "screenshot_brand_match": 40,
    "cloaking_detected": 35,
    "js_revealed_password_field": 30,
    "many_offorigin_hosts": 5,
}

# Hamming distance between two 16x16 pHashes below which two screenshots are
# considered the same page. 256-bit hash; 24 is ~9% of bits differing, which
# tolerates recompression and minor layout drift without merging distinct pages.
PHASH_MATCH_THRESHOLD = 24

# Known exfil destinations. Contacting any of these from a login page is
# effectively conclusive.
KNOWN_EXFIL_HOSTS: frozenset[str] = frozenset(
    {
        "api.telegram.org",
        "discord.com",
        "discordapp.com",
        "webhook.site",
        "formspree.io",
        "api.mailgun.net",
        "hooks.slack.com",
    }
)


@dataclass
class BrandScreenshot:
    """A reference screenshot pHash for a legitimate brand login page."""

    brand: str
    phash: str


def hamming(a: str, b: str) -> int | None:
    """Hamming distance between two hex pHash strings, or None if incomparable."""
    if not a or not b or len(a) != len(b):
        return None
    try:
        return bin(int(a, 16) ^ int(b, 16)).count("1")
    except ValueError:
        return None


def match_brand_screenshot(
    phash: str | None,
    references: list[BrandScreenshot],
    threshold: int = PHASH_MATCH_THRESHOLD,
) -> tuple[str, int] | None:
    """Closest brand whose reference screenshot matches, or ``None``.

    Returns ``(brand, distance)``. Pure — references are supplied by the caller
    so this stays testable without touching disk or the DB.
    """
    best: tuple[str, int] | None = None
    for ref in references:
        dist = hamming(phash or "", ref.phash)
        if dist is None or dist > threshold:
            continue
        if best is None or dist < best[1]:
            best = (ref.brand, dist)
    return best


def deep_score(
    base: TriageResult,
    render: RenderResult,
    *,
    static_had_password_field: bool = False,
    brand_references: list[BrandScreenshot] | None = None,
    cloaking_score: float | None = None,
    cloak_threshold: float = 0.35,
    threshold: int | None = None,
) -> TriageResult:
    """Return a new :class:`TriageResult` with rendered signals folded in.

    ``base`` is left untouched (this returns a copy), so a caller can compare
    static-vs-deep verdicts and measure what rendering actually bought — which
    is the honest way to justify the browser pool's CPU cost.
    """
    from pkintel.config import settings

    result = base.model_copy(deep=True)
    total = result.score
    reasons = list(result.reasons)

    if not render.ok:
        # Rendering failed (dead page, timeout, browser unavailable). Do not
        # penalise — absence of evidence is not evidence. Static score stands.
        return result

    # --- observed network behaviour ---------------------------------------
    offorigin_posts = [e for e in render.exfil_endpoints if e.startswith("POST ")]
    if offorigin_posts and render.has_password_field:
        total += DEEP_WEIGHTS["observed_offdomain_post"]
        reasons.append(
            f"rendered page POSTs to an off-origin endpoint with a password field "
            f"({len(offorigin_posts)} observed)"
        )

    contacted_exfil = [h for h in render.network_hosts if h in KNOWN_EXFIL_HOSTS]
    if contacted_exfil:
        total += DEEP_WEIGHTS["known_exfil_channel"]
        reasons.append(f"contacts known exfil channel: {', '.join(sorted(contacted_exfil))}")

    if len(render.network_hosts) >= 15:
        total += DEEP_WEIGHTS["many_offorigin_hosts"]
        reasons.append(f"contacts {len(render.network_hosts)} off-origin hosts")

    # --- visual clone detection -------------------------------------------
    match = match_brand_screenshot(render.screenshot_phash, brand_references or [])
    if match:
        brand, dist = match
        total += DEEP_WEIGHTS["screenshot_brand_match"]
        reasons.append(f"screenshot matches {brand} login page (pHash distance {dist})")
        if not result.brand:
            # An image-only clone has no brand text at all; the screenshot is
            # the only thing that identifies the target.
            result.brand = brand

    # --- the JS-reveal gap -------------------------------------------------
    if render.has_password_field and not static_had_password_field:
        total += DEEP_WEIGHTS["js_revealed_password_field"]
        reasons.append("password field present only after JavaScript execution")

    # --- cloaking ----------------------------------------------------------
    if cloaking_score is not None and cloaking_score >= cloak_threshold:
        total += DEEP_WEIGHTS["cloaking_detected"]
        reasons.append(f"serves different content by persona (cloaking score {cloaking_score:.2f})")

    result.score = max(0, min(100, total))
    result.reasons = reasons
    limit = settings.triage_phish_threshold if threshold is None else threshold
    result.is_phish = result.score >= limit
    return result
