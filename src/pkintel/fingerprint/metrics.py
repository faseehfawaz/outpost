"""Clustering quality metrics — pure.

Attribution is only worth anything if we can say how good it is. This module
scores predicted clustering against a **hand-labelled** ground-truth set of kit
pairs. Producing and maintaining that hand-labelled set — a few dozen pairs an
analyst has personally adjudicated as "same actor" / "different actor" — is
itself a project deliverable: it is the only honest way to report precision and
recall instead of asserting the pipeline "works".

Everything here is pure and DB-free so it can run in CI over a checked-in
fixture of labelled pairs.
"""

from __future__ import annotations

from typing import Any, Hashable, Iterable, Mapping


def _predicted_same(
    a: Hashable,
    b: Hashable,
    components: Mapping[Hashable, Hashable] | None,
    explicit: Any,
) -> bool:
    """Resolve the predicted "same actor?" verdict for a pair.

    Prefer an explicit per-pair prediction when the caller supplied a 4-tuple;
    otherwise derive it from a ``components`` map (two kits are predicted to be
    the same actor iff they landed in the same connected component).
    """
    if explicit is not None:
        return bool(explicit)
    if components is None:
        raise ValueError(
            "evaluate() needs either 4-tuples (a, b, truth, predicted) "
            "or a `components` mapping to derive predictions from"
        )
    # A kit absent from the map is its own singleton component.
    return components.get(a, ("__a__", a)) == components.get(b, ("__b__", b))


def evaluate(
    labeled_pairs: Iterable[tuple],
    components: Mapping[Hashable, Hashable] | None = None,
) -> dict[str, float | int]:
    """Compute precision / recall / F1 for "same actor" over labelled pairs.

    ``labeled_pairs`` items are either:
      * ``(kit_a, kit_b, truth_bool)`` — needs ``components`` to predict, or
      * ``(kit_a, kit_b, truth_bool, predicted_bool)`` — self-contained.

    The positive class is "same actor". Returns a dict with the confusion-matrix
    counts and precision/recall/F1 (each ``0.0`` when undefined, e.g. no
    predicted positives ⇒ precision 0.0).
    """
    tp = fp = fn = tn = 0
    for row in labeled_pairs:
        a, b, truth = row[0], row[1], bool(row[2])
        explicit = row[3] if len(row) > 3 else None
        pred = _predicted_same(a, b, components, explicit)
        if truth and pred:
            tp += 1
        elif not truth and pred:
            fp += 1
        elif truth and not pred:
            fn += 1
        else:
            tn += 1

    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0

    return {
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "tn": tn,
        "support": tp + fn,           # number of true "same actor" pairs
        "predicted_positive": tp + fp,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
    }
