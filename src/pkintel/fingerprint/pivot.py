"""Infrastructure pivoting — cluster campaigns without ever collecting a kit.

The problem with kit-only clustering
------------------------------------
``pkintel.fingerprint.cluster`` links actors through kit-file similarity: TLSH
fuzzy hashes, Jaccard over file sets, shared anti-bot blocklists. That is
excellent evidence *when it exists*. The catch is that it requires landing an
exposed ``.zip`` on the attacker's server, which is rare and getting rarer —
open directories and forgotten archives are the exception, not the rule.

With 4,000+ URLs ingested, 12 confirmed phish and only a handful of collected
kits, the actor graph is effectively empty. The clustering subsystem is
sophisticated and, in practice, near-inert.

The pivot
---------
Attackers reuse *infrastructure* far more than they reuse code. One operator
running a campaign against Emirates NBD typically:

* parks dozens of lookalike domains on **one IP** or one small block;
* registers them through **one registrar** in one burst;
* obtains certificates from **one issuer**, often in a single batch, sometimes
  with sibling domains listed as SANs on the *same certificate*;
* serves the **same favicon** across all of them;
* exfiltrates to the **same Telegram bot or Discord webhook**.

Every one of those is observable from a URL alone — no kit required. This
module builds ``host_edges`` from them, so a single confirmed phish pulls its
whole sibling infrastructure into view. In practice this is the difference
between "we found 12 phishing URLs" and "we found 3 campaigns totalling 12
URLs, one of which has 40 more domains we had not yet triaged".

Guarding against the shared-hosting trap
----------------------------------------
The obvious failure mode: Cloudflare fronts millions of sites, and a naive
"same IP => same actor" rule would merge the entire internet into one actor and
produce a graph that is both useless and actively misleading.

Two defences, both required:

1. **Fan-out caps.** An IP with more than ``pivot_max_hosts_per_ip`` distinct
   phishing hosts is shared hosting or a CDN, not a campaign. We skip it
   entirely rather than emit low-quality edges.
2. **Weighted reasons.** Not all shared infrastructure is equal evidence. A
   shared TLS certificate (the same cert literally covering both hostnames) is
   near-conclusive. A shared ASN is barely a hint. Weights reflect that, and
   the clusterer requires a minimum combined weight before it will join two
   hosts.
"""

from __future__ import annotations

import ipaddress
from collections import defaultdict
from dataclasses import dataclass

from pkintel.config import settings
from pkintel.db import execute_many, fetch_all
from pkintel.logging import get_logger

log = get_logger(__name__)

_ACTOR = "pivot"

# Evidence weights. A campaign link needs MIN_EDGE_WEIGHT in total, so weak
# signals must corroborate each other while strong ones stand alone.
EDGE_WEIGHTS: dict[str, float] = {
    "shared_cert": 1.0,  # same certificate covers both names — near-conclusive
    "shared_exfil": 1.0,  # same Telegram bot / Discord webhook — conclusive
    "shared_ip": 0.7,  # same host, subject to the fan-out cap
    "shared_favicon": 0.5,  # same (non-generic) favicon hash
    "shared_registrar": 0.2,  # weak alone; meaningful when it corroborates
    "shared_asn": 0.15,  # weakest — an ASN can hold millions of sites
}

MIN_EDGE_WEIGHT = 0.7

# Favicon hashes so common they carry no signal (default framework icons,
# blank/placeholder images). Linking on these would merge unrelated hosts.
GENERIC_FAVICON_HASHES: frozenset[int] = frozenset({0, -1})

_UPSERT_EDGE = """
    INSERT INTO host_edges (host_a, host_b, reason, weight, detail)
    VALUES (%s, %s, %s, %s, %s::jsonb)
    ON CONFLICT (host_a, host_b, reason)
    DO UPDATE SET weight = EXCLUDED.weight, seen_at = now()
"""


@dataclass(frozen=True)
class Edge:
    """One piece of evidence linking two hosts."""

    host_a: str
    host_b: str
    reason: str
    weight: float
    detail: str = "{}"


def canonical_pair(a: str, b: str) -> tuple[str, str] | None:
    """Order a host pair canonically, or ``None`` if degenerate.

    ``host_edges`` has ``CHECK (host_a < host_b)`` so each unordered pair has
    exactly one row per reason. Enforcing it here means the DB constraint is a
    backstop rather than a source of runtime errors.
    """
    a, b = (a or "").strip().lower(), (b or "").strip().lower()
    if not a or not b or a == b:
        return None
    return (a, b) if a < b else (b, a)


def _is_routable(ip: str | None) -> bool:
    """Reject private/loopback/reserved IPs — they link nothing meaningful."""
    if not ip:
        return False
    try:
        addr = ipaddress.ip_address(str(ip).split("/")[0])
    except ValueError:
        return False
    return not (addr.is_private or addr.is_loopback or addr.is_reserved or addr.is_multicast)


def edges_from_groups(
    groups: dict[str, list[str]],
    reason: str,
    *,
    max_group_size: int,
    detail_key: str = "value",
) -> list[Edge]:
    """Turn ``{shared_value: [hosts]}`` into pairwise edges. Pure.

    Groups larger than ``max_group_size`` are dropped whole: past that size the
    shared attribute describes shared *hosting*, not a shared *operator*, and
    emitting O(n^2) edges for a CDN would both swamp the table and corrupt the
    clustering. Dropping is the honest choice — we have no evidence of a link,
    so we assert none.
    """
    weight = EDGE_WEIGHTS.get(reason, 0.1)
    out: list[Edge] = []
    for value, hosts in groups.items():
        uniq = sorted(set(hosts))
        if len(uniq) < 2:
            continue
        if len(uniq) > max_group_size:
            log.debug(
                "pivot_group_too_large",
                reason=reason,
                value=str(value)[:80],
                size=len(uniq),
                cap=max_group_size,
            )
            continue
        import json

        detail = json.dumps({detail_key: str(value)[:200], "group_size": len(uniq)})
        for i in range(len(uniq)):
            for j in range(i + 1, len(uniq)):
                pair = canonical_pair(uniq[i], uniq[j])
                if pair:
                    out.append(Edge(pair[0], pair[1], reason, weight, detail))
    return out


# --------------------------------------------------------------------------- collectors
def _group_by_ip() -> dict[str, list[str]]:
    rows = fetch_all(
        """
        SELECT h.hostname, host(h.ip) AS ip
        FROM hosts h
        JOIN urls u ON u.host = h.hostname
        WHERE h.ip IS NOT NULL AND u.is_phish = true
        """
    )
    groups: dict[str, list[str]] = defaultdict(list)
    for r in rows:
        if _is_routable(r["ip"]):
            groups[r["ip"]].append(r["hostname"])
    return groups


def _group_by_cert() -> dict[str, list[str]]:
    rows = fetch_all(
        """
        SELECT hostname, cert_sha256
        FROM hosts
        WHERE cert_sha256 IS NOT NULL AND cert_sha256 <> ''
        """
    )
    groups: dict[str, list[str]] = defaultdict(list)
    for r in rows:
        groups[r["cert_sha256"]].append(r["hostname"])
    return groups


def _group_by_favicon() -> dict[str, list[str]]:
    """Group by favicon hash, taken from triage rather than host enrichment.

    ``urls.favicon_mmh3`` is populated for every triaged URL, so this works even
    for hosts we never enriched via RDAP.
    """
    rows = fetch_all(
        """
        SELECT DISTINCT host, favicon_mmh3
        FROM urls
        WHERE favicon_mmh3 IS NOT NULL AND is_phish = true
        """
    )
    groups: dict[str, list[str]] = defaultdict(list)
    for r in rows:
        fav = r["favicon_mmh3"]
        if fav in GENERIC_FAVICON_HASHES:
            continue
        groups[str(fav)].append(r["host"])
    return groups


def _group_by_registrar() -> dict[str, list[str]]:
    rows = fetch_all(
        """
        SELECT h.hostname, h.registrar
        FROM hosts h
        JOIN urls u ON u.host = h.hostname
        WHERE h.registrar IS NOT NULL AND h.registrar <> '' AND u.is_phish = true
        """
    )
    groups: dict[str, list[str]] = defaultdict(list)
    for r in rows:
        groups[r["registrar"].strip().lower()].append(r["hostname"])
    return groups


def _group_by_asn() -> dict[str, list[str]]:
    rows = fetch_all(
        """
        SELECT h.hostname, h.asn
        FROM hosts h
        JOIN urls u ON u.host = h.hostname
        WHERE h.asn IS NOT NULL AND u.is_phish = true
        """
    )
    groups: dict[str, list[str]] = defaultdict(list)
    for r in rows:
        groups[str(r["asn"])].append(r["hostname"])
    return groups


def _group_by_exfil() -> dict[str, list[str]]:
    """Group hosts sharing an exfil channel — the strongest link available.

    Two hosts posting credentials to the same Telegram bot are the same
    operator; there is no innocent explanation. Uses ``value_hash`` so we link
    on the secret without ever handling or comparing the secret itself.
    """
    rows = fetch_all(
        """
        SELECT DISTINCT u.host, i.value_hash
        FROM indicators i
        JOIN kits k ON k.id = i.kit_id
        JOIN urls u ON u.id = k.url_id
        WHERE i.type IN ('telegram_token', 'telegram_chat', 'discord_webhook', 'email')
        """
    )
    groups: dict[str, list[str]] = defaultdict(list)
    for r in rows:
        groups[r["value_hash"]].append(r["host"])
    return groups


# --------------------------------------------------------------------------- runner
def build_edges() -> list[Edge]:
    """Collect every pivot edge from current DB state. No writes."""
    edges: list[Edge] = []

    edges += edges_from_groups(
        _group_by_cert(), "shared_cert", max_group_size=100, detail_key="cert_sha256"
    )
    edges += edges_from_groups(
        _group_by_exfil(), "shared_exfil", max_group_size=100, detail_key="value_hash"
    )
    edges += edges_from_groups(
        _group_by_ip(), "shared_ip", max_group_size=settings.pivot_max_hosts_per_ip, detail_key="ip"
    )
    edges += edges_from_groups(
        _group_by_favicon(), "shared_favicon", max_group_size=150, detail_key="favicon_mmh3"
    )
    edges += edges_from_groups(
        _group_by_registrar(), "shared_registrar", max_group_size=300, detail_key="registrar"
    )
    edges += edges_from_groups(
        _group_by_asn(),
        "shared_asn",
        max_group_size=settings.pivot_max_hosts_per_asn,
        detail_key="asn",
    )
    return edges


def campaign_components(edges: list[Edge], min_weight: float = MIN_EDGE_WEIGHT) -> dict[str, int]:
    """Union-find over edges whose *combined* weight clears ``min_weight``.

    Weights for the same pair accumulate across reasons, so two hosts sharing a
    registrar (0.2) *and* an ASN (0.15) *and* a favicon (0.5) total 0.85 and
    join — while either weak signal alone correctly does not.

    Returns ``{host: campaign_id}``. Pure.
    """
    combined: dict[tuple[str, str], float] = defaultdict(float)
    for e in edges:
        combined[(e.host_a, e.host_b)] += e.weight

    parent: dict[str, str] = {}

    def find(x: str) -> str:
        parent.setdefault(x, x)
        while parent[x] != x:
            parent[x] = parent[parent[x]]  # path compression
            x = parent[x]
        return x

    def union(a: str, b: str) -> None:
        ra, rb = find(a), find(b)
        if ra != rb:
            parent[rb] = ra

    for (a, b), weight in combined.items():
        if weight >= min_weight:
            union(a, b)

    roots: dict[str, int] = {}
    out: dict[str, int] = {}
    for host in sorted(parent):
        root = find(host)
        if root not in roots:
            roots[root] = len(roots) + 1
        out[host] = roots[root]
    return out


def persist_edges(edges: list[Edge]) -> int:
    """Upsert edges into ``host_edges``. Returns rows written."""
    if not edges:
        return 0
    rows = [(e.host_a, e.host_b, e.reason, e.weight, e.detail) for e in edges]
    execute_many(_UPSERT_EDGE, rows)
    return len(rows)


def run_once(worker_id: str = "pivot-1", limit: int = 0) -> int:
    """Rebuild the infrastructure pivot graph. Returns campaigns identified.

    Global operation over the whole corpus, like ``fingerprint.runner`` — there
    is no per-row queue to drain, so ``limit`` is accepted for interface
    uniformity and ignored.
    """
    if not settings.pivot_enabled:
        return 0

    edges = build_edges()
    written = persist_edges(edges)
    components = campaign_components(edges)
    campaigns = len(set(components.values())) if components else 0

    by_reason: dict[str, int] = defaultdict(int)
    for e in edges:
        by_reason[e.reason] += 1

    log.info(
        "pivot_run_complete",
        worker=worker_id,
        edges=written,
        hosts_linked=len(components),
        campaigns=campaigns,
        by_reason=dict(by_reason),
    )
    return campaigns
