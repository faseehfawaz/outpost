"""Brand-lookalike matching: homoglyph, typo, and combosquat detection. Pure.

This is the matcher behind the CT firehose. It has to run against every DNS
name in every certificate issued on the public internet — call it 400/sec
sustained, with bursts well above that — so it is built to reject the common
case fast and only do expensive work on plausible candidates.

What the crt.sh poller could not catch
--------------------------------------
``pkintel.ingest.ct`` matched a ``%brand%`` SQL LIKE, so it found substring
matches and nothing else. All of these evaded it:

* **Homoglyphs**   ``emirat3snbd``, ``adcb`` with a Cyrillic ``с``, ``rn`` for ``m``
* **Typos**        ``emiratesnbcl``, ``eimratesnbd``, ``adbc``
* **Combosquats**  ``emiratesnbd-secure-verify``  (this one it *did* catch)
* **Splits**       ``emirates.nbd.login.example.com``

Matching strategy, cheapest test first
--------------------------------------
1. **Exact substring** on the separator-stripped host — catches combosquats,
   which are the bulk of real phishing infrastructure. O(n).
2. **Homoglyph normalisation** then substring — folds visually confusable
   characters to a canonical form and retries. O(n).
3. **Bounded edit distance** against each host label — only for labels of
   comparable length to the brand, and only after the cheap tests miss.

False-positive control
----------------------
The brand's own domain family is excluded (``emiratesnbd.ae`` is not a phish),
and short brands are protected: ``du`` (2 chars) and ``FAB`` (3) would match
enormous numbers of innocent domains under edit distance, so brands shorter
than :data:`MIN_FUZZY_LEN` are matched by exact substring on a label boundary
only. Without that guard the ``du`` brand alone would flag a large fraction of
the internet.
"""

from __future__ import annotations

from functools import lru_cache

# Visually confusable character folding. Maps each variant to a canonical form,
# so `emirat3snbd`, `emiratesnbd` and `ｅmiratesnbd` all normalise identically.
HOMOGLYPHS: dict[str, str] = {
    # digit/letter substitutions
    "0": "o",
    "1": "l",
    "3": "e",
    "4": "a",
    "5": "s",
    "6": "g",
    "7": "t",
    "8": "b",
    "9": "g",
    "2": "z",
    # Cyrillic lookalikes (the classic IDN attack)
    "а": "a",
    "е": "e",
    "о": "o",
    "р": "p",
    "с": "c",
    "у": "y",
    "х": "x",
    "і": "i",
    "ѕ": "s",
    "ԁ": "d",
    "ᴏ": "o",
    "ɑ": "a",
    # Greek
    "α": "a",
    "ο": "o",
    "ρ": "p",
    "ν": "v",
    "τ": "t",
    # fullwidth
    "ａ": "a",
    "ｂ": "b",
    "ｃ": "c",
    "ｄ": "d",
    "ｅ": "e",
    "ｍ": "m",
    "ｎ": "n",
    "ｏ": "o",
    "ｒ": "r",
    "ｓ": "s",
    "ｔ": "t",
}

# Multi-character confusables, applied before single-char folding.
DIGRAPHS: tuple[tuple[str, str], ...] = (
    ("rn", "m"),  # rn -> m is the single most effective typosquat in practice
    ("vv", "w"),
    ("cl", "d"),
    ("nn", "m"),
)

# Brands shorter than this are matched by exact label-boundary substring only.
# Fuzzy-matching a 2-3 character brand generates overwhelming false positives.
MIN_FUZZY_LEN = 5

# Words attackers bolt onto a brand. Their presence alongside a brand token is
# strong corroboration, and on its own upgrades a weak match to a reportable one.
LURE_TOKENS: frozenset[str] = frozenset(
    {
        "login",
        "signin",
        "secure",
        "verify",
        "verification",
        "account",
        "update",
        "confirm",
        "auth",
        "online",
        "banking",
        "service",
        "support",
        "alert",
        "suspend",
        "unlock",
        "recover",
        "portal",
        "access",
        "id",
        "web",
        "mobile",
        "app",
        "customer",
        "care",
    }
)

# Registrable-suffix-ish labels we should not treat as the brand's own SLD.
_COMMON_SECOND_LEVEL = frozenset({"com", "co", "net", "org", "gov", "edu", "ac"})


def _slug(text: str) -> str:
    """Reduce to lowercase alphanumerics only."""
    return "".join(ch for ch in text.lower() if ch.isalnum())


def normalize_homoglyphs(text: str) -> str:
    """Fold visually confusable characters to a canonical form. Pure."""
    s = text.lower()
    for src, dst in DIGRAPHS:
        s = s.replace(src, dst)
    return "".join(HOMOGLYPHS.get(ch, ch) for ch in s)


def edit_distance_within(a: str, b: str, max_dist: int) -> int | None:
    """Levenshtein distance, or ``None`` if it provably exceeds ``max_dist``.

    Banded Ukkonen variant: only cells within ``max_dist`` of the diagonal are
    computed, so this is O(len(a) * max_dist) rather than O(len(a) * len(b)).
    At firehose volume that difference is the whole ballgame.
    """
    la, lb = len(a), len(b)
    if abs(la - lb) > max_dist:
        return None
    if a == b:
        return 0

    prev = list(range(lb + 1))
    for i in range(1, la + 1):
        curr = [i] + [0] * lb
        lo = max(1, i - max_dist)
        hi = min(lb, i + max_dist)
        if lo > 1:
            curr[lo - 1] = max_dist + 1
        for j in range(lo, hi + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            curr[j] = min(prev[j] + 1, curr[j - 1] + 1, prev[j - 1] + cost)
        for j in range(hi + 1, lb + 1):
            curr[j] = max_dist + 1
        if min(curr[lo : hi + 1] or [max_dist + 1]) > max_dist:
            return None
        prev = curr

    return prev[lb] if prev[lb] <= max_dist else None


@lru_cache(maxsize=4096)
def _host_parts(host: str) -> tuple[str, ...]:
    return tuple(host.split("."))


class BrandMatcher:
    """Matches hostnames against a brand list. Construct once, reuse forever."""

    def __init__(self, brands: list[str], max_edit_distance: int | None = None) -> None:
        from pkintel.config import settings

        self.brands = list(brands)
        self.max_edit = (
            max_edit_distance
            if max_edit_distance is not None
            else settings.typosquat_max_edit_distance
        )
        # Precompute per brand: slug, homoglyph-normalised slug, fuzzy eligibility.
        self._prepared: list[tuple[str, str, str, bool]] = []
        for brand in self.brands:
            slug = _slug(brand)
            if not slug:
                continue
            self._prepared.append(
                (brand, slug, normalize_homoglyphs(slug), len(slug) >= MIN_FUZZY_LEN)
            )

    # -- helpers -----------------------------------------------------------
    @staticmethod
    def _is_own_domain(host: str, slug: str) -> bool:
        """True if ``host`` belongs to the brand's own domain family.

        ``emiratesnbd.ae`` and ``www.emiratesnbd.ae`` are the real bank; only the
        registrable label is checked, so ``emiratesnbd.evil.com`` is NOT
        excluded (there the brand appears as a subdomain of somebody else).
        """
        labels = host.split(".")
        if len(labels) < 2:
            return False
        # Walk back past ccTLD-style suffixes: co.ae, com.au, ...
        idx = -2
        if len(labels) >= 3 and labels[-2] in _COMMON_SECOND_LEVEL:
            idx = -3
        try:
            return labels[idx] == slug
        except IndexError:
            return False

    @staticmethod
    def _has_lure(host: str) -> bool:
        return any(tok in host for tok in LURE_TOKENS)

    @staticmethod
    def _short_brand_hit(host: str, slug: str) -> bool:
        """Boundary-anchored containment test for brands under MIN_FUZZY_LEN.

        A plain substring test is far too loose for a 2-4 character brand. The
        brand ``du`` appears inside ``schedule``, ``education``, ``produce`` and
        ``duckduckgo`` — matching those would swamp the triage queue with
        garbage and starve the real hits, which is precisely the failure this
        guard exists to prevent.

        So the slug must sit at the **start or end of a token** (tokens being
        the host split on ``.`` and ``-``), not buried mid-word:

            du-account-verify.xyz  -> token "du"          -> hit
            adcbsecure.com         -> "adcb" starts token -> hit
            schedule-app.io        -> "du" is mid-token   -> no
            education.com          -> "du" is mid-token   -> no
            duckduckgo.com         -> starts token, but no lure token -> no

        Callers additionally require a lure token, so ``duckduckgo.com`` is
        rejected on that second test.
        """
        for raw in host.replace("-", ".").replace("_", ".").split("."):
            token = _slug(raw)
            if not token:
                continue
            if token.startswith(slug) or token.endswith(slug):
                return True
        return False

    # -- the matcher -------------------------------------------------------
    def match(self, host: str) -> tuple[str, str] | None:
        """Return ``(brand, reason)`` if ``host`` impersonates a brand, else None.

        ``reason`` is one of ``combosquat``, ``homoglyph``, ``typo``. It is
        recorded so an analyst can see *why* something was flagged rather than
        having to re-derive it.
        """
        host = host.strip().lower().lstrip("*.").rstrip(".")
        if not host or " " in host or "." not in host:
            return None

        labels = _host_parts(host)
        condensed = _slug(host)
        normalized = normalize_homoglyphs(condensed)

        for brand, slug, norm_slug, fuzzy_ok in self._prepared:
            if self._is_own_domain(host, slug):
                continue

            # 1. cheapest: exact substring on the separator-stripped host
            if slug in condensed:
                # Short brands need BOTH a token-boundary hit and a lure token,
                # or they match a large fraction of the internet.
                if not fuzzy_ok and not (
                    self._short_brand_hit(host, slug) and self._has_lure(host)
                ):
                    continue
                return brand, "combosquat"

            # 2. homoglyph-folded substring
            if norm_slug in normalized:
                if not fuzzy_ok and not (
                    self._short_brand_hit(normalize_homoglyphs(host), norm_slug)
                    and self._has_lure(host)
                ):
                    continue
                return brand, "homoglyph"

            # 3. bounded edit distance, per label. Only for brands long enough
            #    that a 1-2 edit neighbourhood is not absurdly crowded.
            if not fuzzy_ok:
                continue
            for label in labels[:-1]:  # skip the TLD
                lab = _slug(label)
                if not lab or abs(len(lab) - len(slug)) > self.max_edit:
                    continue
                dist = edit_distance_within(lab, slug, self.max_edit)
                if dist is not None and dist > 0:
                    return brand, "typo"
                # also try the homoglyph-folded label
                lab_n = normalize_homoglyphs(lab)
                dist = edit_distance_within(lab_n, norm_slug, self.max_edit)
                if dist is not None and dist > 0:
                    return brand, "homoglyph"

        return None
