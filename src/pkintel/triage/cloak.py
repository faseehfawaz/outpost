"""Cloaking detection by multi-persona fetch.

The evasion this defeats
------------------------
Serious phishing kits ship an anti-bot layer (``antibot.php``, ``blocker.php``)
whose entire job is to serve *different content to different visitors*. A
typical kit shows the credential-harvesting page only to a visitor that looks
like a real victim — right country, mobile browser, arriving from the SMS link —
and shows a 404, a redirect to the real bank, or a blank page to everything
else. Security scanners, crawlers and datacenter IP ranges get the decoy.

Outpost fetches with an honest research User-Agent from a fixed IP. To a kit
with any anti-bot layer at all, we are the most obvious scanner on the internet.
Our static triage sees the decoy, scores it 0, and files a live credential
harvester away as uninteresting. This is a **silent false-negative machine** —
the better the kit, the more certainly we miss it.

The signal
----------
We cannot (and must not) fake being a victim: no residential proxies, no
spoofing a real person's identity, no defeating the protection. What we *can*
do is fetch the same URL two or three times with different, honest personas and
compare what comes back.

**The disagreement is itself the signal.** A legitimate site serves
substantially the same content to a mobile browser and a desktop browser —
responsive CSS changes layout, not text. A cloaking kit serves materially
different *content*. So a high content-distance between personas is strong
evidence of an anti-bot layer, which is strong evidence of a phishing kit,
**without ever needing to see the page the victim sees.**

That inverts the attacker's advantage: the very mechanism that hides the kit
from us is what exposes it.

Ethics
------
Every persona keeps the contactable research URL in its User-Agent, so we remain
identifiable and are not pretending to be a specific real person or product
build. We do not use proxies to fake geography. Each persona fetch goes through
the per-host throttle, so N personas against one host are spaced exactly as N
ordinary requests would be — this costs the victim server no more than a normal
triage pass with a slightly higher request count, and the count is capped.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

import httpx

from pkintel.config import settings
from pkintel.http import polite_get
from pkintel.logging import get_logger

log = get_logger(__name__)

_MAX_BYTES = 512 * 1024  # plenty to compare structure; caps hostile bodies
_FETCH_TIMEOUT_S = 10.0


@dataclass(frozen=True)
class Persona:
    """One honest browsing identity used for comparison.

    ``label`` is recorded in the reasons list so an analyst can see which pair
    of personas disagreed, not merely that they did.
    """

    label: str
    user_agent: str
    accept_language: str = "en-US,en;q=0.9"


def _research_suffix() -> str:
    """Keep the contactable research marker on every persona.

    We change the *shape* of the client we present, never our identity. The kit
    can still see exactly who we are and how to contact us.
    """
    return " (+outpost-research; contact security@heapleap.tech)"


def build_personas() -> list[Persona]:
    """The persona set. Ordered cheapest-signal-first.

    Mobile-vs-desktop is the highest-yield pair: UAE phishing arrives by SMS, so
    kits overwhelmingly gate on a mobile User-Agent and serve a decoy to desktop.
    """
    suffix = _research_suffix()
    return [
        Persona(
            label="mobile_ae",
            user_agent=(
                "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) "
                "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1"
                + suffix
            ),
            accept_language="ar-AE,ar;q=0.9,en;q=0.8",
        ),
        Persona(
            label="desktop",
            user_agent=(
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                "(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36" + suffix
            ),
            accept_language="en-US,en;q=0.9",
        ),
        Persona(
            label="research",
            user_agent=settings.user_agent,
            accept_language="en-US,en;q=0.9",
        ),
    ]


# --------------------------------------------------------------------------- diffing
_TAG_RE = re.compile(r"<[^>]+>")
_WS_RE = re.compile(r"\s+")
# Values that legitimately differ between two fetches of the *same* page and
# would otherwise masquerade as cloaking: CSRF tokens, session ids, cache
# busters, timestamps, nonces.
_NOISE_RE = re.compile(
    r"(?i)(csrf|nonce|token|session|sid|_t|ts|cb|v)=[\w\-.%]+|"
    r"\b[0-9a-f]{16,}\b|"
    r"\b\d{10,13}\b"
)


def visible_text(html: str | None) -> str:
    """Strip tags and normalise whitespace/noise to comparable visible text.

    Comparing raw HTML would flag every page with a rotating CSRF token as
    cloaking. Comparing *visible text* isolates the thing that actually matters:
    did the visitor get shown something different.
    """
    if not html:
        return ""
    text = re.sub(r"(?is)<(script|style|noscript)[^>]*>.*?</\1>", " ", html)
    text = _TAG_RE.sub(" ", text)
    text = _NOISE_RE.sub(" ", text)
    return _WS_RE.sub(" ", text).strip().lower()


def _shingles(text: str, k: int = 5) -> set[str]:
    """Word k-shingles — order-sensitive enough to catch reordered boilerplate."""
    words = text.split()
    if len(words) < k:
        return {" ".join(words)} if words else set()
    return {" ".join(words[i : i + k]) for i in range(len(words) - k + 1)}


def content_distance(a: str | None, b: str | None) -> float:
    """Normalised distance in ``[0, 1]`` between two page bodies. Pure.

    ``0.0`` = identical visible text, ``1.0`` = nothing in common. Jaccard
    distance over word shingles: robust to reformatting and minor edits, but
    sharply sensitive to one page being a login form and the other a 404.
    """
    ta, tb = visible_text(a), visible_text(b)
    if not ta and not tb:
        return 0.0
    if not ta or not tb:
        return 1.0  # one persona got content, the other got nothing
    sa, sb = _shingles(ta), _shingles(tb)
    if not sa and not sb:
        return 0.0
    union = sa | sb
    if not union:
        return 0.0
    return 1.0 - (len(sa & sb) / len(union))


@dataclass
class PersonaFetch:
    label: str
    status: int | None = None
    final_url: str = ""
    html: str | None = None
    error: str | None = None


@dataclass
class CloakResult:
    """Outcome of a multi-persona comparison."""

    score: float = 0.0
    fetches: list[PersonaFetch] = field(default_factory=list)
    reasons: list[str] = field(default_factory=list)
    # The persona that saw the richest content — the one worth rendering.
    best_persona: str | None = None

    @property
    def is_cloaking(self) -> bool:
        return self.score >= settings.cloak_diff_threshold


def _fetch_as(client: httpx.Client, url: str, persona: Persona) -> PersonaFetch:
    """One throttled fetch under one persona. Errors captured, never raised."""
    try:
        resp = polite_get(
            client,
            url,
            timeout=_FETCH_TIMEOUT_S,
            headers={
                "User-Agent": persona.user_agent,
                "Accept-Language": persona.accept_language,
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            },
        )
    except Exception as exc:  # noqa: BLE001 - an unreachable persona is data, not a crash
        return PersonaFetch(label=persona.label, error=str(exc)[:300])

    ctype = resp.headers.get("content-type", "").lower()
    html = None
    if not ctype or any(t in ctype for t in ("html", "text", "xml")):
        raw = resp.content[:_MAX_BYTES]
        html = raw.decode(resp.encoding or "utf-8", "replace")

    return PersonaFetch(
        label=persona.label,
        status=resp.status_code,
        final_url=str(resp.url),
        html=html,
    )


def detect_cloaking(
    client: httpx.Client,
    url: str,
    personas: list[Persona] | None = None,
) -> CloakResult:
    """Fetch ``url`` under each persona and score the disagreement between them.

    Returns a :class:`CloakResult` whose ``score`` is the **maximum** pairwise
    content distance. Max rather than mean on purpose: a kit that cloaks against
    exactly one persona (the common case — mobile gets the phish, everything
    else gets the decoy) would be diluted into invisibility by averaging.
    """
    result = CloakResult()
    if not settings.cloak_detect_enabled:
        return result

    personas = personas or build_personas()
    for persona in personas:
        result.fetches.append(_fetch_as(client, url, persona))

    live = [f for f in result.fetches if f.error is None and f.html]
    if len(live) < 2:
        # Not enough comparable responses to say anything. Absence of evidence.
        return result

    # Richest content = most visible text. That persona is the one worth
    # spending a browser render on.
    result.best_persona = max(live, key=lambda f: len(visible_text(f.html))).label

    worst = 0.0
    for i in range(len(live)):
        for j in range(i + 1, len(live)):
            a, b = live[i], live[j]
            dist = content_distance(a.html, b.html)
            if dist > worst:
                worst = dist
            if dist >= settings.cloak_diff_threshold:
                result.reasons.append(
                    f"{a.label} and {b.label} were served different content (distance {dist:.2f})"
                )
            # A status-code split is an even blunter tell than a content diff.
            if a.status != b.status and {a.status, b.status} & {403, 404, 410}:
                result.reasons.append(
                    f"{a.label} got HTTP {a.status} but {b.label} got HTTP {b.status}"
                )
                worst = max(worst, 0.8)
            # Redirecting one persona to a different host is classic decoying.
            if a.final_url and b.final_url:
                from urllib.parse import urlsplit

                ha, hb = urlsplit(a.final_url).netloc, urlsplit(b.final_url).netloc
                if ha and hb and ha != hb:
                    result.reasons.append(f"{a.label} was redirected to {ha} but {b.label} to {hb}")
                    worst = max(worst, 0.9)

    result.score = round(min(1.0, worst), 3)
    if result.is_cloaking:
        log.info(
            "cloaking_detected",
            url=url,
            score=result.score,
            best_persona=result.best_persona,
            reasons=result.reasons[:3],
        )
    return result
