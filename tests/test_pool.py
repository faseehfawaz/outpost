"""Tests for the bounded concurrency helper (pkintel.pool).

Two contracts the pipeline depends on:
  1. an exception in one item must NOT abort the batch (per-row isolation was a
     property of the old sequential runners and must survive the rewrite);
  2. concurrency must be bounded, so a 50k-URL batch cannot materialise 50k
     futures and exhaust memory before a single fetch returns.
"""

from __future__ import annotations

import threading
import time

from pkintel.pool import Counter, map_concurrent


def test_all_items_processed():
    out = list(map_concurrent(lambda x: x * 2, range(50), workers=8))
    assert len(out) == 50
    assert sorted(r for _, r, _ in out) == [i * 2 for i in range(50)]
    assert all(e is None for _, _, e in out)


def test_exception_is_returned_not_raised():
    """One bad item must not take down the batch."""

    def flaky(x: int) -> int:
        if x == 3:
            raise ValueError("boom")
        return x

    out = list(map_concurrent(flaky, range(10), workers=4))
    assert len(out) == 10  # all ten still reported

    errors = [(item, e) for item, _, e in out if e is not None]
    assert len(errors) == 1
    assert errors[0][0] == 3
    assert isinstance(errors[0][1], ValueError)

    good = sorted(r for _, r, e in out if e is None)
    assert good == [0, 1, 2, 4, 5, 6, 7, 8, 9]


def test_actually_runs_concurrently():
    """20 x 100ms sleeps across 10 workers should take ~200ms, not ~2s."""
    started = time.monotonic()
    out = list(map_concurrent(lambda _: time.sleep(0.1), range(20), workers=10))
    elapsed = time.monotonic() - started
    assert len(out) == 20
    assert elapsed < 1.0, f"took {elapsed:.2f}s — not running concurrently"


def test_inflight_is_bounded():
    """max_inflight must cap concurrent futures regardless of input size."""
    live = 0
    peak = 0
    lock = threading.Lock()

    def track(_):
        nonlocal live, peak
        with lock:
            live += 1
            peak = max(peak, live)
        time.sleep(0.005)
        with lock:
            live -= 1
        return None

    list(map_concurrent(track, range(500), workers=4, max_inflight=8))
    assert peak <= 8, f"peak in-flight {peak} exceeded max_inflight=8"


def test_empty_input():
    assert list(map_concurrent(lambda x: x, [], workers=4)) == []


def test_workers_floor_of_one():
    """workers<1 must not crash ThreadPoolExecutor (which rejects 0)."""
    out = list(map_concurrent(lambda x: x, range(5), workers=0))
    assert len(out) == 5


def test_counter_is_threadsafe():
    c = Counter()
    threads = [
        threading.Thread(target=lambda: [c.incr() for _ in range(1000)]) for _ in range(8)
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert c.value == 8000
