"""Disjoint-set union (union-find) and connected-components — pure.

The similarity graph is sparse and we only ever ask one question of it: which
kits fall into the same connected component? Union-find answers that in
near-linear time with path compression + union by rank, and — unlike a library
dependency — the component labelling here is made deterministic on purpose so
that actor identities stay stable across reclustering runs.
"""

from __future__ import annotations

from collections.abc import Hashable, Iterable
from typing import Any


class UnionFind:
    """Disjoint-set forest with path compression and union by rank.

    Nodes are any hashable value and are added lazily on first reference.
    """

    __slots__ = ("parent", "rank")

    def __init__(self) -> None:
        self.parent: dict[Hashable, Hashable] = {}
        self.rank: dict[Hashable, int] = {}

    def add(self, x: Hashable) -> None:
        """Register ``x`` as its own singleton set (no-op if already present)."""
        if x not in self.parent:
            self.parent[x] = x
            self.rank[x] = 0

    def find(self, x: Hashable) -> Hashable:
        """Return the canonical representative of ``x``'s set (path-compressed)."""
        self.add(x)
        root = x
        while self.parent[root] != root:
            root = self.parent[root]
        # Compress the path so future finds are O(1) amortised.
        while self.parent[x] != root:
            self.parent[x], x = root, self.parent[x]
        return root

    def union(self, a: Hashable, b: Hashable) -> bool:
        """Merge the sets containing ``a`` and ``b``.

        Returns ``True`` if a merge actually happened, ``False`` if they were
        already in the same set.
        """
        ra, rb = self.find(a), self.find(b)
        if ra == rb:
            return False
        if self.rank[ra] < self.rank[rb]:
            ra, rb = rb, ra
        self.parent[rb] = ra
        if self.rank[ra] == self.rank[rb]:
            self.rank[ra] += 1
        return True

    def connected(self, a: Hashable, b: Hashable) -> bool:
        """True iff ``a`` and ``b`` are in the same set."""
        return self.find(a) == self.find(b)

    def groups(self) -> dict[Hashable, list[Hashable]]:
        """Return ``{representative: [members...]}`` for every known node."""
        out: dict[Hashable, list[Hashable]] = {}
        for node in self.parent:
            out.setdefault(self.find(node), []).append(node)
        return out


def connected_components(
    nodes: Iterable[Hashable],
    edges: Iterable[Any],
) -> dict[Hashable, Hashable]:
    """Map every node to a deterministic component id.

    ``edges`` is any iterable whose items expose their two endpoints as the
    first two elements (``(a, b)`` or ``(a, b, ...)``). Isolated ``nodes`` become
    their own singleton components.

    The component id is the *minimum node* in the component, which makes the
    labelling independent of insertion/union order — a property the actor
    materialiser relies on for stability.
    """
    uf = UnionFind()
    for n in nodes:
        uf.add(n)
    for edge in edges:
        a, b = edge[0], edge[1]
        uf.add(a)
        uf.add(b)
        uf.union(a, b)

    # Reduce each set to its minimum member as the stable component id.
    comp_min: dict[Hashable, Hashable] = {}
    members: dict[Hashable, list[Hashable]] = {}
    for node in uf.parent:
        members.setdefault(uf.find(node), []).append(node)
    for root, group in members.items():
        cid = min(group)
        for node in group:
            comp_min[node] = cid
    return comp_min
