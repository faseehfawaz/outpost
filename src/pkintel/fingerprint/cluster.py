"""Build the kit-similarity graph and resolve it into actors.

This is the differentiator of the pipeline: many tools *collect* phishing kits;
few *attribute* them. :func:`recluster` is a global, idempotent rebuild — it

  1. loads every kit fingerprint and its exfil indicators,
  2. finds candidate pairs cheaply via inverted indexes (so we never compare two
     kits that share *no* signal — avoiding an O(n²) sweep over the corpus),
  3. scores each candidate pair with the pure rules in :mod:`.similarity`,
  4. UPSERTs the surviving edges into ``kit_edges``,
  5. runs union-find over all kits + edges to get connected components,
  6. materialises one ``actors`` row per component (singletons included) with a
     **stable** label keyed on a deterministic component signature, and
  7. rewrites ``kit_actor`` with per-kit aggregated edge reasons.

Import-safe: importing this module touches neither the DB nor the network; all
I/O happens inside :func:`recluster`.
"""

from __future__ import annotations

import itertools
from collections import defaultdict
from typing import Any

from psycopg.types.json import Jsonb

from pkintel.config import settings
from pkintel.db import connection, record_audit
from pkintel.fingerprint.similarity import KitFingerprint, edges_for_pair
from pkintel.fingerprint.unionfind import connected_components
from pkintel.logging import get_logger

log = get_logger(__name__)

# A file sha shared by more kits than this is treated as a non-discriminating
# commodity artifact (jQuery, a blank favicon, bootstrap.css, ...) and is NOT
# used to generate candidate pairs — including it would both reintroduce the
# O(n²) blow-up the inverted index exists to prevent and manufacture spurious
# edges. Strong identity signals (exfil channel, anti-bot hash, author string)
# are never capped this way.
_MAX_COMMODITY_FILE_BUCKET = 200


# ---------------------------------------------------------------------------
# Loading (I/O)
# ---------------------------------------------------------------------------
def _load_kits(cur) -> dict[int, dict[str, Any]]:
    """Return ``{kit_id: {...fingerprint + kit + brand...}}`` for fingerprinted kits."""
    cur.execute(
        """
        SELECT f.kit_id,
               k.sha256,
               k.collected_at,
               u.brand,
               f.antibot_hash,
               f.author_strings,
               f.file_sha_set,
               f.token_hash
        FROM fingerprints f
        JOIN kits k ON k.id = f.kit_id
        LEFT JOIN urls u ON u.id = k.url_id
        """
    )
    kits: dict[int, dict[str, Any]] = {}
    for r in cur.fetchall():
        kits[r["kit_id"]] = {
            "sha256": r["sha256"],
            "collected_at": r["collected_at"],
            "brand": r["brand"],
            "antibot_hash": r["antibot_hash"],
            "author_strings": list(r["author_strings"] or []),
            "file_sha_set": set(r["file_sha_set"] or []),
            "token_hash": r["token_hash"],
        }
    return kits


def _load_indicators(cur, kit_ids: set[int]) -> dict[int, list[tuple[str, str]]]:
    """Return ``{kit_id: [(type, value_hash), ...]}`` for the given kits."""
    out: dict[int, list[tuple[str, str]]] = defaultdict(list)
    if not kit_ids:
        return out
    cur.execute("SELECT kit_id, type, value_hash FROM indicators")
    for r in cur.fetchall():
        kid = r["kit_id"]
        if kid in kit_ids and r["value_hash"]:
            out[kid].append((str(r["type"]), str(r["value_hash"])))
    return out


# ---------------------------------------------------------------------------
# Candidate generation (pure, given the loaded data)
# ---------------------------------------------------------------------------
def _candidate_pairs(
    kits: dict[int, dict[str, Any]],
    indicators: dict[int, list[tuple[str, str]]],
) -> set[tuple[int, int]]:
    """Inverted-index sweep → the set of kit pairs worth scoring.

    We bucket kits by each *candidate signal* (anti-bot hash, author string,
    exfil ``(type, value_hash)``, and file sha) and emit the intra-bucket pairs.
    Two kits that never co-occur in any bucket share no signal and are skipped.
    """
    by_antibot: dict[str, list[int]] = defaultdict(list)
    by_author: dict[str, list[int]] = defaultdict(list)
    by_exfil: dict[tuple[str, str], list[int]] = defaultdict(list)
    by_file: dict[str, list[int]] = defaultdict(list)

    for kid, k in kits.items():
        ab = k["antibot_hash"]
        if ab:
            by_antibot[ab].append(kid)
        for a in k["author_strings"]:
            a = (a or "").strip()
            if a:
                by_author[a].append(kid)
        for sha in k["file_sha_set"]:
            if sha:
                by_file[sha].append(kid)
        for key in indicators.get(kid, ()):  # (type, value_hash)
            by_exfil[key].append(kid)

    pairs: set[tuple[int, int]] = set()

    def _emit(buckets, cap: int | None = None) -> None:
        for members in buckets.values():
            if len(members) < 2:
                continue
            if cap is not None and len(members) > cap:
                continue
            for a, b in itertools.combinations(sorted(set(members)), 2):
                pairs.add((a, b))

    # Strong identity signals: never capped.
    _emit(by_antibot)
    _emit(by_author)
    _emit(by_exfil)
    # Commodity files: capped to keep noise/complexity in check.
    _emit(by_file, cap=_MAX_COMMODITY_FILE_BUCKET)

    return pairs


def _fp(kit_id: int, k: dict[str, Any]) -> KitFingerprint:
    return KitFingerprint(
        id=kit_id,
        file_sha_set=k["file_sha_set"],
        antibot_hash=k["antibot_hash"],
        author_strings=k["author_strings"],
        token_hash=k["token_hash"],
    )


def _compute_edges(
    kits: dict[int, dict[str, Any]],
    indicators: dict[int, list[tuple[str, str]]],
) -> dict[tuple[int, int, str], tuple[float, dict]]:
    """Score every candidate pair → ``{(kit_a, kit_b, reason): (weight, detail)}``.

    Keys are canonicalised so ``kit_a < kit_b`` (satisfying the table CHECK) and
    unique per reason (satisfying the UNIQUE constraint).
    """
    thr = settings.cluster_jaccard_threshold
    min_files = settings.cluster_min_shared_files
    edges: dict[tuple[int, int, str], tuple[float, dict]] = {}

    for a, b in _candidate_pairs(kits, indicators):
        lo, hi = (a, b) if a < b else (b, a)
        for reason, weight, detail in edges_for_pair(
            _fp(lo, kits[lo]),
            _fp(hi, kits[hi]),
            indicators.get(lo, ()),
            indicators.get(hi, ()),
            jaccard_threshold=thr,
            min_shared_files=min_files,
        ):
            edges[(lo, hi, reason)] = (weight, detail)
    return edges


# ---------------------------------------------------------------------------
# Persistence (I/O)
# ---------------------------------------------------------------------------
def _write_edges(cur, kit_ids: set[int], edges) -> None:
    """UPSERT computed edges and drop edges among loaded kits that no longer hold."""
    for (a, b, reason), (weight, detail) in edges.items():
        cur.execute(
            """
            INSERT INTO kit_edges (kit_a, kit_b, reason, weight, detail)
            VALUES (%s, %s, %s, %s, %s)
            ON CONFLICT (kit_a, kit_b, reason)
            DO UPDATE SET weight = EXCLUDED.weight, detail = EXCLUDED.detail
            """,
            (a, b, reason, float(weight), Jsonb(detail)),
        )

    # Remove stale edges between kits we just reclustered (both endpoints loaded)
    # that were not re-derived this run.
    if not kit_ids:
        return
    ids = list(kit_ids)
    cur.execute(
        "SELECT id, kit_a, kit_b, reason FROM kit_edges WHERE kit_a = ANY(%s) AND kit_b = ANY(%s)",
        (ids, ids),
    )
    stale = [r["id"] for r in cur.fetchall() if (r["kit_a"], r["kit_b"], r["reason"]) not in edges]
    if stale:
        cur.execute("DELETE FROM kit_edges WHERE id = ANY(%s)", (stale,))


def _component_signature(kits: dict[int, dict[str, Any]], members: list[int]) -> str:
    """Deterministic, order-independent id for a component: its min kit sha256."""
    return min(kits[m]["sha256"] for m in members)


def _parse_actor_n(label: str) -> int:
    """Extract N from an ``"Actor #N"`` label, else -1."""
    prefix = "Actor #"
    if label.startswith(prefix):
        tail = label[len(prefix) :]
        if tail.isdigit():
            return int(tail)
    return -1


def _materialise_actors(
    cur,
    kits: dict[int, dict[str, Any]],
    comp_of: dict[int, int],
    reasons_by_kit: dict[int, set[str]],
) -> int:
    """Create/update one actor per component and rewrite ``kit_actor``.

    Labels are stable across runs: an actor row stores its component signature
    (min kit sha256) in ``notes`` as ``"sig:<sha>"``; a component whose signature
    matches an existing actor reuses that actor's label, so ``"Actor #7"`` keeps
    referring to the same operator even as kits are added. New components get the
    next monotonic number; components that no longer exist are deleted (their
    ``kit_actor`` links cascade away).
    """
    # Group kits into components.
    members_by_comp: dict[int, list[int]] = defaultdict(list)
    for kid, cid in comp_of.items():
        members_by_comp[cid].append(kid)

    # Existing actors keyed by their stored signature.
    cur.execute("SELECT id, label, notes FROM actors")
    existing_by_sig: dict[str, dict[str, Any]] = {}
    max_n = 0
    for r in cur.fetchall():
        max_n = max(max_n, _parse_actor_n(r["label"]))
        notes = r["notes"] or ""
        if notes.startswith("sig:"):
            existing_by_sig[notes[4:]] = {"id": r["id"], "label": r["label"]}

    kept_actor_ids: set[int] = set()
    counter = max_n
    n_actors = 0

    # Deterministic processing order (by signature) so new-number assignment is
    # itself reproducible for a given corpus.
    comps = sorted(
        members_by_comp.values(),
        key=lambda ms: _component_signature(kits, ms),
    )

    for members in comps:
        n_actors += 1
        sig = _component_signature(kits, members)
        brands = sorted({kits[m]["brand"] for m in members if kits[m]["brand"]})
        collected = [kits[m]["collected_at"] for m in members if kits[m]["collected_at"]]
        first_seen = min(collected) if collected else None
        last_seen = max(collected) if collected else None
        kit_count = len(members)
        notes = f"sig:{sig}"

        existing = existing_by_sig.get(sig)
        if existing is not None:
            actor_id = existing["id"]
            cur.execute(
                """
                UPDATE actors
                SET kit_count = %s, brands = %s, first_seen = %s,
                    last_seen = %s, notes = %s, updated_at = now()
                WHERE id = %s
                """,
                (kit_count, brands, first_seen, last_seen, notes, actor_id),
            )
        else:
            counter += 1
            label = f"Actor #{counter}"
            cur.execute(
                """
                INSERT INTO actors (label, first_seen, last_seen, kit_count, brands, notes)
                VALUES (%s, %s, %s, %s, %s, %s)
                RETURNING id
                """,
                (label, first_seen, last_seen, kit_count, brands, notes),
            )
            actor_id = cur.fetchone()["id"]

        kept_actor_ids.add(actor_id)

        # Rewrite kit_actor for this component's kits.
        for m in members:
            reasons = sorted(reasons_by_kit.get(m, set()))
            cur.execute(
                "DELETE FROM kit_actor WHERE kit_id = %s",
                (m,),
            )
            cur.execute(
                """
                INSERT INTO kit_actor (kit_id, actor_id, edge_reasons)
                VALUES (%s, %s, %s)
                """,
                (m, actor_id, reasons),
            )

    # Delete actors whose component no longer exists (kit_actor cascades).
    if kept_actor_ids:
        cur.execute("DELETE FROM actors WHERE id <> ALL(%s)", (list(kept_actor_ids),))
    else:
        cur.execute("DELETE FROM actors")

    return n_actors


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
def recluster(worker_id: str = "cluster-1") -> dict[str, int]:
    """Rebuild the whole similarity graph and actor set. Returns a summary dict.

    Global operation (not per-row): loads all fingerprints, recomputes edges and
    actors atomically in one transaction. Safe to run repeatedly; labels are
    stable across runs.

    :returns: ``{"actors": int, "kits": int, "edges": int}``
    """
    with connection() as conn, conn.cursor() as cur:
        kits = _load_kits(cur)
        kit_ids = set(kits)
        indicators = _load_indicators(cur, kit_ids)

        edges = _compute_edges(kits, indicators)

        # Aggregate the reasons touching each kit (for kit_actor.edge_reasons).
        reasons_by_kit: dict[int, set[str]] = defaultdict(set)
        for a, b, reason in edges:
            reasons_by_kit[a].add(reason)
            reasons_by_kit[b].add(reason)

        _write_edges(cur, kit_ids, edges)

        comp_of = connected_components(kit_ids, [(a, b) for (a, b, _reason) in edges])
        n_actors = _materialise_actors(cur, kits, comp_of, reasons_by_kit)

    summary = {"actors": n_actors, "kits": len(kits), "edges": len(edges)}
    log.info("recluster_done", **summary)
    record_audit(worker_id, "recluster", target=None, **summary)
    return summary
