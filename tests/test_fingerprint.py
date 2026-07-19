"""Unit tests for the fingerprint/cluster subsystem — pure functions only.

No database, no network. Everything below feeds literal dicts/dataclasses into
the pure similarity, union-find and metrics helpers. The DB-facing orchestration
in ``cluster.py`` is exercised by integration tests (marked, DB-gated) elsewhere.
"""

from __future__ import annotations

import math

from pkintel.fingerprint.similarity import (
    KitFingerprint,
    edges_for_pair,
    jaccard,
    shared_exfil,
)
from pkintel.fingerprint.unionfind import UnionFind, connected_components
from pkintel.fingerprint.metrics import evaluate
from pkintel.models import EdgeReason


# ---------------------------------------------------------------------------
# jaccard
# ---------------------------------------------------------------------------
def test_jaccard_basic_values():
    assert jaccard({"a", "b", "c", "d"}, {"a", "b"}) == 0.5
    assert jaccard({"a", "b"}, {"a", "b"}) == 1.0
    assert jaccard({"a"}, {"b"}) == 0.0
    # 2 shared of 4 unioned -> 0.5
    assert math.isclose(jaccard({"a", "b", "c"}, {"b", "c", "d"}), 2 / 4)


def test_jaccard_empty_sets_are_zero_not_one():
    assert jaccard(set(), set()) == 0.0
    assert jaccard(set(), {"x"}) == 0.0


def test_jaccard_accepts_any_iterable():
    assert jaccard(["a", "a", "b"], ["b", "c"]) == 1 / 3


# ---------------------------------------------------------------------------
# shared_exfil
# ---------------------------------------------------------------------------
def test_shared_exfil_matches_type_and_hash():
    a = [{"type": "telegram_token", "value_hash": "H1"},
         {"type": "email", "value_hash": "H2"}]
    b = [{"type": "telegram_token", "value_hash": "H1"},
         {"type": "email", "value_hash": "OTHER"}]
    assert shared_exfil(a, b) == [("telegram_token", "H1")]


def test_shared_exfil_type_must_also_match():
    a = [{"type": "telegram_token", "value_hash": "H1"}]
    b = [{"type": "discord_webhook", "value_hash": "H1"}]  # same hash, diff type
    assert shared_exfil(a, b) == []


def test_shared_exfil_accepts_tuples():
    a = [("email", "H9")]
    b = [("email", "H9"), ("smtp", "Hx")]
    assert shared_exfil(a, b) == [("email", "H9")]


# ---------------------------------------------------------------------------
# edges_for_pair
# ---------------------------------------------------------------------------
def _fp(kid, *, files=(), antibot=None, authors=()):
    return KitFingerprint(
        id=kid,
        file_sha_set=set(files),
        antibot_hash=antibot,
        author_strings=list(authors),
    )


def test_edge_fires_on_shared_antibot():
    a = _fp(1, antibot="AB123")
    b = _fp(2, antibot="AB123")
    edges = edges_for_pair(a, b, [], [], jaccard_threshold=0.6, min_shared_files=3)
    reasons = {r for r, _w, _d in edges}
    assert EdgeReason.shared_antibot.value in reasons


def test_no_edge_when_antibot_hashes_differ_or_null():
    assert edges_for_pair(_fp(1, antibot="X"), _fp(2, antibot="Y"),
                          [], [], jaccard_threshold=0.6, min_shared_files=3) == []
    assert edges_for_pair(_fp(1, antibot=None), _fp(2, antibot=None),
                          [], [], jaccard_threshold=0.6, min_shared_files=3) == []


def test_edge_fires_on_high_jaccard_above_threshold():
    files_a = {"s1", "s2", "s3", "s4"}
    files_b = {"s1", "s2", "s3", "s5"}  # 3 shared / 5 union = 0.6
    edges = edges_for_pair(_fp(1, files=files_a), _fp(2, files=files_b),
                           [], [], jaccard_threshold=0.6, min_shared_files=3)
    jac = [(w, d) for r, w, d in edges if r == EdgeReason.jaccard.value]
    assert jac, "expected a jaccard edge"
    weight, detail = jac[0]
    assert math.isclose(weight, 0.6)
    assert detail["shared_files"] == 3


def test_no_jaccard_edge_below_threshold():
    files_a = {"s1", "s2", "s3", "s4"}
    files_b = {"s1", "s2", "x", "y", "z"}  # 2 shared / 7 union ~= 0.286
    edges = edges_for_pair(_fp(1, files=files_a), _fp(2, files=files_b),
                           [], [], jaccard_threshold=0.6, min_shared_files=2)
    assert EdgeReason.jaccard.value not in {r for r, _w, _d in edges}


def test_no_jaccard_edge_when_overlap_below_min_shared_files():
    # Ratio is 1.0 but only two files overlap; min_shared_files=3 blocks it.
    files = {"s1", "s2"}
    edges = edges_for_pair(_fp(1, files=files), _fp(2, files=files),
                           [], [], jaccard_threshold=0.6, min_shared_files=3)
    assert EdgeReason.jaccard.value not in {r for r, _w, _d in edges}


def test_edge_fires_on_shared_author():
    a = _fp(1, authors=["Mr Robot", "x"])
    b = _fp(2, authors=[" Mr Robot "])  # whitespace-normalised match
    edges = edges_for_pair(a, b, [], [], jaccard_threshold=0.6, min_shared_files=3)
    author_edges = [d for r, _w, d in edges if r == EdgeReason.shared_author.value]
    assert author_edges and author_edges[0]["authors"] == ["Mr Robot"]


def test_shared_exfil_edge_and_multiple_reasons_together():
    a = _fp(1, antibot="AB", files={"s1", "s2", "s3"})
    b = _fp(2, antibot="AB", files={"s1", "s2", "s3"})
    inds = [{"type": "email", "value_hash": "H"}]
    edges = edges_for_pair(a, b, inds, inds, jaccard_threshold=0.6, min_shared_files=3)
    reasons = {r for r, _w, _d in edges}
    assert reasons == {
        EdgeReason.shared_exfil.value,
        EdgeReason.jaccard.value,
        EdgeReason.shared_antibot.value,
    }


def test_no_edge_between_unrelated_kits():
    a = _fp(1, files={"a1", "a2"}, antibot="ABC", authors=["alice"])
    b = _fp(2, files={"b1", "b2"}, antibot="XYZ", authors=["bob"])
    ind_a = [{"type": "email", "value_hash": "Ha"}]
    ind_b = [{"type": "email", "value_hash": "Hb"}]
    assert edges_for_pair(a, b, ind_a, ind_b,
                          jaccard_threshold=0.6, min_shared_files=1) == []


# ---------------------------------------------------------------------------
# UnionFind
# ---------------------------------------------------------------------------
def test_unionfind_transitive_merges():
    uf = UnionFind()
    uf.union(1, 2)
    uf.union(2, 3)
    assert uf.connected(1, 3)
    assert uf.find(1) == uf.find(2) == uf.find(3)
    assert not uf.connected(1, 4)  # 4 is its own set


def test_unionfind_union_reports_whether_merged():
    uf = UnionFind()
    assert uf.union(1, 2) is True
    assert uf.union(1, 2) is False  # already connected


def test_unionfind_groups():
    uf = UnionFind()
    uf.union("a", "b")
    uf.add("c")
    groups = {frozenset(v) for v in uf.groups().values()}
    assert frozenset({"a", "b"}) in groups
    assert frozenset({"c"}) in groups


# ---------------------------------------------------------------------------
# connected_components
# ---------------------------------------------------------------------------
def test_connected_components_small_graph():
    nodes = [1, 2, 3, 4, 5]
    edges = [(1, 2), (2, 3), (4, 5)]
    comp = connected_components(nodes, edges)
    # 1-2-3 share a component; 4-5 share another.
    assert comp[1] == comp[2] == comp[3]
    assert comp[4] == comp[5]
    assert comp[1] != comp[4]
    # component id is the minimum member (stable / order-independent).
    assert comp[3] == 1
    assert comp[5] == 4


def test_connected_components_singletons_and_edge_tuple_extra_fields():
    nodes = [10, 20, 30]
    # Edges may carry extra fields (reason, weight...); only first two matter.
    edges = [(10, 20, "jaccard", 0.9)]
    comp = connected_components(nodes, edges)
    assert comp[10] == comp[20] == 10
    assert comp[30] == 30  # isolated node -> its own component


def test_connected_components_order_independent():
    a = connected_components([1, 2, 3], [(3, 2), (2, 1)])
    b = connected_components([1, 2, 3], [(1, 2), (2, 3)])
    assert a == b


# ---------------------------------------------------------------------------
# metrics.evaluate
# ---------------------------------------------------------------------------
def test_evaluate_with_components_mapping():
    # Predicted components: {1,2} together, 3 separate.
    components = {1: 1, 2: 1, 3: 3}
    labeled = [
        (1, 2, True),   # TP  (truly same, predicted same)
        (1, 3, False),  # TN  (truly diff, predicted diff)
        (2, 3, True),   # FN  (truly same, predicted diff)
    ]
    m = evaluate(labeled, components)
    assert (m["tp"], m["fp"], m["fn"], m["tn"]) == (1, 0, 1, 1)
    assert m["precision"] == 1.0
    assert m["recall"] == 0.5
    assert math.isclose(m["f1"], 2 * 1.0 * 0.5 / 1.5, rel_tol=1e-4)


def test_evaluate_with_explicit_predictions():
    labeled = [
        ("k1", "k2", True, True),    # TP
        ("k1", "k3", False, True),   # FP
        ("k2", "k3", True, False),   # FN
        ("k4", "k5", False, False),  # TN
    ]
    m = evaluate(labeled)
    assert (m["tp"], m["fp"], m["fn"], m["tn"]) == (1, 1, 1, 1)
    assert m["precision"] == 0.5
    assert m["recall"] == 0.5
    assert m["f1"] == 0.5


def test_evaluate_perfect_and_zero_cases():
    perfect = [(1, 2, True, True), (3, 4, False, False)]
    m = evaluate(perfect)
    assert m["precision"] == m["recall"] == m["f1"] == 1.0

    # No predicted positives -> precision defined as 0.0, no ZeroDivisionError.
    none_pred = [(1, 2, True, False)]
    z = evaluate(none_pred)
    assert z["precision"] == 0.0
    assert z["recall"] == 0.0
    assert z["f1"] == 0.0
