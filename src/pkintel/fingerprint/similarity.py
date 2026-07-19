"""Pairwise kit-similarity primitives — pure, side-effect-free.

These functions are the heart of the actor-attribution engine. They take small
fingerprint objects (a dataclass or a plain dict) plus each kit's list of exfil
indicators and decide whether an *edge* should exist between two kits, and why.

Nothing here touches the database, the network, or the filesystem, so every rule
is unit-testable in isolation by feeding in literal dicts. The DB-facing
orchestration lives in :mod:`pkintel.fingerprint.cluster`.

Edge rules (any one is sufficient to draw an edge; a pair may yield several):
  * ``shared_exfil``   — the two kits report to the same exfil channel
                         (identical ``(type, value_hash)``). Strongest signal:
                         two kits phoning home to the same Telegram bot / webhook
                         / dropbox address are almost certainly one operator.
  * ``jaccard``        — Jaccard similarity of the file-sha sets is >= threshold
                         *and* the raw overlap is >= ``min_shared_files`` (so a
                         high ratio between two tiny kits doesn't fire on one
                         coincidentally shared file).
  * ``shared_antibot`` — identical anti-bot blocklist hash (kits ship the same
                         curated bot/crawler denylist — a very sticky artifact).
  * ``shared_author``  — a byte-identical author/handle string appears in both.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping

from pkintel.models import EdgeReason

# Edge tuple shape produced everywhere in this subsystem.
Edge = tuple[str, float, dict]


@dataclass(frozen=True)
class KitFingerprint:
    """The minimal per-kit signal set the graph builder compares on.

    Mirrors a row of the ``fingerprints`` table joined to its ``kits`` id. Kept
    deliberately tiny so a whole corpus fits comfortably in memory.
    """

    id: int
    file_sha_set: set[str] = field(default_factory=set)
    antibot_hash: str | None = None
    author_strings: list[str] = field(default_factory=list)
    token_hash: str | None = None


# ---------------------------------------------------------------------------
# Coercion helpers (accept dataclass *or* dict for ergonomic call sites/tests)
# ---------------------------------------------------------------------------
def _get(obj: Any, name: str, default: Any = None) -> Any:
    if isinstance(obj, Mapping):
        return obj.get(name, default)
    return getattr(obj, name, default)


def _as_sha_set(obj: Any) -> set[str]:
    raw = _get(obj, "file_sha_set", None) or ()
    return {s for s in raw if s}


def _as_author_set(obj: Any) -> set[str]:
    raw = _get(obj, "author_strings", None) or ()
    return {s.strip() for s in raw if s and s.strip()}


def _indicator_key(ind: Any) -> tuple[str, str] | None:
    """Normalise an indicator (dict, tuple, or object) to ``(type, value_hash)``.

    Only the *type* and the *hash* are used for matching — never the full,
    unredacted exfil value (ethics: hashes/partials only leave this process).
    """
    if isinstance(ind, tuple):
        if len(ind) >= 2 and ind[0] and ind[1]:
            return (str(ind[0]), str(ind[1]))
        return None
    t = _get(ind, "type")
    h = _get(ind, "value_hash")
    # pydantic IndicatorType is a str-Enum; str() gives the wire value.
    if t is None or not h:
        return None
    return (str(getattr(t, "value", t)), str(h))


def _indicator_keys(indicators: Iterable[Any]) -> set[tuple[str, str]]:
    keys: set[tuple[str, str]] = set()
    for ind in indicators or ():
        k = _indicator_key(ind)
        if k is not None:
            keys.add(k)
    return keys


# ---------------------------------------------------------------------------
# Pure metrics
# ---------------------------------------------------------------------------
def jaccard(set_a: Iterable[Any], set_b: Iterable[Any]) -> float:
    """Jaccard index ``|A ∩ B| / |A ∪ B|``.

    Two empty sets are defined here to return ``0.0`` (no evidence of a link),
    not ``1.0`` — an empty fileset is the absence of a signal, never a match.
    """
    a, b = set(set_a), set(set_b)
    union = a | b
    if not union:
        return 0.0
    return len(a & b) / len(union)


def shared_exfil(
    indicators_a: Iterable[Any], indicators_b: Iterable[Any]
) -> list[tuple[str, str]]:
    """Return the sorted ``(type, value_hash)`` pairs both kits report to.

    An exfil channel two kits have in common is the single most reliable link
    between them, so this is surfaced as its own function for reuse and testing.
    """
    common = _indicator_keys(indicators_a) & _indicator_keys(indicators_b)
    return sorted(common)


def edges_for_pair(
    kit_a_fp: Any,
    kit_b_fp: Any,
    indicators_a: Iterable[Any],
    indicators_b: Iterable[Any],
    *,
    jaccard_threshold: float,
    min_shared_files: int,
) -> list[Edge]:
    """Return every edge justified between two kits (possibly none).

    Each element is ``(reason, weight, detail)`` where ``reason`` is an
    :class:`~pkintel.models.EdgeReason` value, ``weight`` is a rough confidence
    in ``[0, 1]``, and ``detail`` is a small JSON-serialisable dict of evidence
    (hashes/counts only — never raw exfil values).
    """
    edges: list[Edge] = []

    # 1. Shared exfil channel — strongest link.
    common_exfil = shared_exfil(indicators_a, indicators_b)
    if common_exfil:
        edges.append(
            (
                EdgeReason.shared_exfil.value,
                1.0,
                {"channels": [list(k) for k in common_exfil], "count": len(common_exfil)},
            )
        )

    # 2. File-set overlap (Jaccard), gated on an absolute overlap floor.
    sha_a, sha_b = _as_sha_set(kit_a_fp), _as_sha_set(kit_b_fp)
    overlap = len(sha_a & sha_b)
    if overlap >= min_shared_files:
        j = jaccard(sha_a, sha_b)
        if j >= jaccard_threshold:
            edges.append(
                (
                    EdgeReason.jaccard.value,
                    round(float(j), 4),
                    {"jaccard": round(float(j), 4), "shared_files": overlap},
                )
            )

    # 3. Identical anti-bot blocklist.
    ab_a = _get(kit_a_fp, "antibot_hash")
    ab_b = _get(kit_b_fp, "antibot_hash")
    if ab_a and ab_b and ab_a == ab_b:
        edges.append(
            (EdgeReason.shared_antibot.value, 1.0, {"antibot_hash": str(ab_a)})
        )

    # 4. Shared author / handle string.
    common_authors = _as_author_set(kit_a_fp) & _as_author_set(kit_b_fp)
    if common_authors:
        edges.append(
            (
                EdgeReason.shared_author.value,
                1.0,
                {"authors": sorted(common_authors)},
            )
        )

    return edges
