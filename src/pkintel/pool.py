"""Bounded concurrency helper shared by every pipeline stage.

Why this exists
---------------
The pipeline was fully sequential: ``pkintel run all --loop`` walked six stages
one after another in a single process, and triage fetched URLs **one at a time**
through a single client. Each URL cost a per-host throttle wait plus a network
round-trip, so a 50-URL batch took 5-10 minutes and the box sat at roughly one
busy thread out of twelve. Throughput was ~400-600 URLs/hour.

Almost all of that time is spent blocked on a socket, not computing. Threads are
therefore the right tool — and the right number of them is far more than the
core count, because they are nearly all asleep.

Ethics note (important)
-----------------------
Concurrency here is **across different hosts**, never against the same one.
:class:`pkintel.http._HostThrottle` is process-wide, thread-safe, and reserves
its slot *before* sleeping, so N threads hitting the same host still queue up at
exactly ``per_host_min_interval_s`` apart. No rate limit in
``docs/SCOPE_AND_ETHICS.md`` is relaxed by this module; we simply stop idling
between unrelated hosts. A single victim server sees precisely the same request
pattern it saw before.
"""

from __future__ import annotations

import threading
from collections.abc import Callable, Iterable, Iterator
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from typing import TypeVar

from pkintel.logging import get_logger

log = get_logger(__name__)

T = TypeVar("T")
R = TypeVar("R")


def map_concurrent(
    fn: Callable[[T], R],
    items: Iterable[T],
    *,
    workers: int,
    stage: str = "pool",
    max_inflight: int | None = None,
) -> Iterator[tuple[T, R | None, Exception | None]]:
    """Apply ``fn`` to ``items`` across ``workers`` threads, yielding as they finish.

    Yields ``(item, result, error)`` triples. **Exceptions are returned, never
    raised**, so one hostile server cannot abort a whole batch — this preserves
    the per-row isolation the sequential runners had.

    Results arrive in completion order, not input order. Every caller here
    writes to Postgres keyed by row id, so ordering is irrelevant.

    ``max_inflight`` bounds how many futures exist at once (defaults to
    ``workers * 4``). Without it, submitting a 50,000-URL batch would
    materialise 50,000 futures up front and blow up memory before a single
    fetch completed.
    """
    if workers < 1:
        workers = 1
    if max_inflight is None:
        max_inflight = workers * 4

    it = iter(items)
    pending: dict = {}
    submitted = 0
    completed = 0

    with ThreadPoolExecutor(max_workers=workers, thread_name_prefix=stage) as ex:
        # Prime the pump.
        for item in it:
            pending[ex.submit(fn, item)] = item
            submitted += 1
            if len(pending) >= max_inflight:
                break

        while pending:
            done, _ = wait(list(pending), return_when=FIRST_COMPLETED)
            for fut in done:
                item = pending.pop(fut)
                completed += 1
                try:
                    yield item, fut.result(), None
                except Exception as exc:  # noqa: BLE001 - isolate, never abort the batch
                    yield item, None, exc

                # Backfill one slot per completion to keep the pool saturated.
                for nxt in it:
                    pending[ex.submit(fn, nxt)] = nxt
                    submitted += 1
                    break

    log.debug("pool_drained", stage=stage, submitted=submitted, completed=completed)


class Counter:
    """Thread-safe integer counter for tallying results across worker threads."""

    __slots__ = ("_n", "_lock")

    def __init__(self) -> None:
        self._n = 0
        self._lock = threading.Lock()

    def incr(self, by: int = 1) -> int:
        with self._lock:
            self._n += by
            return self._n

    @property
    def value(self) -> int:
        with self._lock:
            return self._n
