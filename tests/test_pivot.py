"""Tests for infrastructure pivoting (pkintel.fingerprint.pivot).

Pure functions only — no DB. The shared-hosting trap is the important half:
a naive "same IP => same actor" rule would merge every Cloudflare-fronted site
on the internet into one actor and produce a graph that is worse than useless.
"""

from __future__ import annotations

from pkintel.fingerprint.pivot import (
    EDGE_WEIGHTS,
    MIN_EDGE_WEIGHT,
    Edge,
    campaign_components,
    canonical_pair,
    edges_from_groups,
)


# --------------------------------------------------------------------------- canonical_pair
def test_canonical_pair_orders_consistently():
    assert canonical_pair("b.com", "a.com") == ("a.com", "b.com")
    assert canonical_pair("a.com", "b.com") == ("a.com", "b.com")


def test_canonical_pair_rejects_degenerate():
    assert canonical_pair("a.com", "a.com") is None
    assert canonical_pair("", "a.com") is None
    assert canonical_pair("a.com", "") is None


def test_canonical_pair_normalises_case():
    assert canonical_pair("B.COM", "a.com") == ("a.com", "b.com")


# --------------------------------------------------------------------------- grouping
def test_group_of_two_makes_one_edge():
    edges = edges_from_groups({"1.2.3.4": ["a.com", "b.com"]}, "shared_ip", max_group_size=100)
    assert len(edges) == 1
    assert edges[0].host_a == "a.com"
    assert edges[0].host_b == "b.com"
    assert edges[0].reason == "shared_ip"
    assert edges[0].weight == EDGE_WEIGHTS["shared_ip"]


def test_group_of_n_makes_n_choose_2_edges():
    hosts = ["a.com", "b.com", "c.com", "d.com"]
    edges = edges_from_groups({"1.2.3.4": hosts}, "shared_ip", max_group_size=100)
    assert len(edges) == 6  # 4 choose 2


def test_singleton_group_makes_no_edges():
    assert edges_from_groups({"1.2.3.4": ["a.com"]}, "shared_ip", max_group_size=100) == []


def test_duplicate_hosts_in_group_are_collapsed():
    edges = edges_from_groups(
        {"1.2.3.4": ["a.com", "a.com", "b.com"]}, "shared_ip", max_group_size=100
    )
    assert len(edges) == 1


def test_shared_hosting_trap_is_avoided():
    """A CDN IP with 500 hosts must produce ZERO edges, not 124,750."""
    hosts = [f"site{i}.com" for i in range(500)]
    edges = edges_from_groups({"104.21.0.1": hosts}, "shared_ip", max_group_size=200)
    assert edges == []


def test_cap_is_inclusive_boundary():
    hosts = [f"s{i}.com" for i in range(10)]
    assert edges_from_groups({"ip": hosts}, "shared_ip", max_group_size=10) != []
    assert edges_from_groups({"ip": hosts}, "shared_ip", max_group_size=9) == []


# --------------------------------------------------------------------------- clustering
def test_strong_signal_alone_joins():
    """A shared certificate is near-conclusive and must cluster on its own."""
    edges = [Edge("a.com", "b.com", "shared_cert", EDGE_WEIGHTS["shared_cert"])]
    comp = campaign_components(edges)
    assert comp["a.com"] == comp["b.com"]


def test_weak_signal_alone_does_not_join():
    """A shared ASN is nearly meaningless — an ASN can hold millions of sites."""
    edges = [Edge("a.com", "b.com", "shared_asn", EDGE_WEIGHTS["shared_asn"])]
    comp = campaign_components(edges)
    # Either not clustered at all, or in separate components.
    assert comp.get("a.com") != comp.get("b.com") or not comp


def test_weak_signals_accumulate_to_join():
    """registrar (0.2) + asn (0.15) + favicon (0.5) = 0.85 >= 0.7 -> same campaign."""
    edges = [
        Edge("a.com", "b.com", "shared_registrar", EDGE_WEIGHTS["shared_registrar"]),
        Edge("a.com", "b.com", "shared_asn", EDGE_WEIGHTS["shared_asn"]),
        Edge("a.com", "b.com", "shared_favicon", EDGE_WEIGHTS["shared_favicon"]),
    ]
    total = sum(e.weight for e in edges)
    assert total >= MIN_EDGE_WEIGHT
    comp = campaign_components(edges)
    assert comp["a.com"] == comp["b.com"]


def test_two_weak_signals_still_below_threshold():
    """registrar (0.2) + asn (0.15) = 0.35 < 0.7 -> must NOT join."""
    edges = [
        Edge("a.com", "b.com", "shared_registrar", EDGE_WEIGHTS["shared_registrar"]),
        Edge("a.com", "b.com", "shared_asn", EDGE_WEIGHTS["shared_asn"]),
    ]
    comp = campaign_components(edges)
    assert comp.get("a.com") != comp.get("b.com") or not comp


def test_transitive_clustering():
    """a-b and b-c strongly linked => a, b, c are one campaign."""
    edges = [
        Edge("a.com", "b.com", "shared_cert", 1.0),
        Edge("b.com", "c.com", "shared_exfil", 1.0),
    ]
    comp = campaign_components(edges)
    assert comp["a.com"] == comp["b.com"] == comp["c.com"]


def test_separate_campaigns_stay_separate():
    edges = [
        Edge("a.com", "b.com", "shared_cert", 1.0),
        Edge("x.com", "y.com", "shared_cert", 1.0),
    ]
    comp = campaign_components(edges)
    assert comp["a.com"] == comp["b.com"]
    assert comp["x.com"] == comp["y.com"]
    assert comp["a.com"] != comp["x.com"]
    assert len(set(comp.values())) == 2


def test_empty_input():
    assert campaign_components([]) == {}


def test_campaign_ids_are_deterministic():
    edges = [
        Edge("a.com", "b.com", "shared_cert", 1.0),
        Edge("x.com", "y.com", "shared_cert", 1.0),
    ]
    assert campaign_components(edges) == campaign_components(edges)


def test_the_scenario_this_module_exists_for():
    """One confirmed phish drags in its whole sibling infrastructure.

    Kit-only clustering sees nothing here: no kit was ever collected. Pivoting
    on a shared cert plus a shared IP surfaces the entire campaign.
    """
    edges = edges_from_groups(
        {"cert-abc": ["adcb-login.com", "adcb-verify.com", "adcb-secure.com"]},
        "shared_cert",
        max_group_size=100,
    ) + edges_from_groups(
        {"5.6.7.8": ["adcb-secure.com", "emiratesnbd-login.com"]},
        "shared_ip",
        max_group_size=200,
    )
    comp = campaign_components(edges)
    # All four hosts land in one campaign, from URLs alone.
    assert len(set(comp.values())) == 1
    assert len(comp) == 4
