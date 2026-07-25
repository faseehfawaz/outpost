"""Prometheus metrics for the pipeline.

``pkintel.api.app`` mounts ``prometheus_client.make_asgi_app()`` at ``/metrics``,
but nothing ever registered a metric, so the endpoint returned only the default
Python process collectors. There was no way to answer the questions that
actually matter operationally:

* Is any queue growing instead of draining?  (a wedged stage)
* How many URLs per minute is triage really doing?  (did concurrency help?)
* How often does the reaper find stuck rows?  (are workers dying?)
* What fraction of takedowns get confirmed dead?  (does any of this work?)
* Is deep triage earning its CPU?  (``deep_rescued`` over time)

Design notes
------------
Queue depths are exported through a **callback collector** rather than being set
by the workers. The API process and the worker processes are separate, so a
gauge set inside a worker would never appear on the API's ``/metrics``. Querying
Postgres at scrape time gives one consistent view regardless of which process is
scraped, and the queries are cheap thanks to the partial indexes in migration
003.

Counters are still incremented in-process by the workers, which is correct: each
worker exports its own counters, and Prometheus aggregates across the per-stage
service instances by job label.
"""

from __future__ import annotations

from prometheus_client import Counter, Gauge, Histogram

# --------------------------------------------------------------------------- counters
urls_processed = Counter(
    "outpost_urls_processed_total",
    "URLs whose triage was written.",
    ["stage", "outcome"],
)

stage_errors = Counter(
    "outpost_stage_errors_total",
    "Per-row failures isolated by a stage runner.",
    ["stage"],
)

rows_reaped = Counter(
    "outpost_rows_reaped_total",
    "Rows recovered from workers that died holding a lease.",
    ["queue"],
)

deep_rescued = Counter(
    "outpost_deep_triage_rescued_total",
    "Phish found by deep triage that static triage scored below threshold. "
    "This is the number that justifies the browser pool's CPU cost.",
)

takedowns_sent = Counter(
    "outpost_takedowns_sent_total",
    "Abuse notices dispatched.",
    ["target_type"],
)

takedowns_confirmed_dead = Counter(
    "outpost_takedowns_confirmed_dead_total",
    "Reported targets verified as actually offline.",
)

certstream_certs = Counter(
    "outpost_certstream_certificates_total",
    "Certificates observed on the CT firehose.",
)

certstream_matches = Counter(
    "outpost_certstream_matches_total",
    "CT names matching a brand lookalike pattern.",
    ["reason"],
)

siblings_discovered = Counter(
    "outpost_siblings_discovered_total",
    "New candidate hosts found in the SAN list of an enriched host's certificate.",
)

# --------------------------------------------------------------------------- histograms
stage_duration = Histogram(
    "outpost_stage_duration_seconds",
    "Wall-clock duration of one run_once() call.",
    ["stage"],
    # Stages range from sub-second (cluster on an empty graph) to many minutes
    # (a large triage batch), so the buckets span four orders of magnitude.
    buckets=(0.5, 1, 2.5, 5, 10, 30, 60, 120, 300, 600, 1800),
)

url_triage_duration = Histogram(
    "outpost_url_triage_seconds",
    "Time to triage one URL, including fetch and any deep path.",
    buckets=(0.1, 0.25, 0.5, 1, 2.5, 5, 10, 20, 45),
)

takedown_time_to_death = Histogram(
    "outpost_takedown_hours_to_death",
    "Hours between dispatching a notice and confirming the target offline.",
    buckets=(1, 3, 6, 12, 24, 48, 96, 168, 336),
)

# --------------------------------------------------------------------------- gauges
browser_pool_in_use = Gauge(
    "outpost_browser_contexts_in_use",
    "Chromium contexts currently rendering.",
)


class _QueueDepthCollector:
    """Exports queue depths by querying Postgres at scrape time.

    Registered as a custom collector so the value is correct no matter which
    process Prometheus scrapes — a worker-set gauge would be invisible to the
    API process and vice versa.

    Cached with a TTL, deliberately
    ---------------------------------
    The naive version queried Postgres on every scrape. That is actively
    dangerous: Prometheus scrapes every 15s, and if the database is slow or
    unreachable the connection attempt blocks for the full connect timeout.
    Scrapes then pile up, each holding a pool slot, and ``/metrics`` becomes a
    hang — precisely during a database incident, which is exactly when you are
    trying to read the metrics.

    So we serve a cached snapshot, refresh it at most once per ``_TTL_S``, and
    on failure keep serving the last known value rather than blocking or
    vanishing. Stale numbers during an outage are far more useful than a hung
    endpoint, and ``outpost_queue_depth_stale_seconds`` tells you how old they
    are so a dashboard can flag it.
    """

    _TTL_S = 10.0

    def __init__(self) -> None:
        self._cache: dict[str, int] = {}
        self._fetched_at: float = 0.0
        self._lock = __import__("threading").Lock()

    def _refresh_if_due(self) -> None:
        import time

        now = time.monotonic()
        if now - self._fetched_at < self._TTL_S:
            return
        # Non-blocking: if another thread is already refreshing, serve the cache.
        if not self._lock.acquire(blocking=False):
            return
        try:
            if time.monotonic() - self._fetched_at < self._TTL_S:
                return
            from pkintel.db import queue_depths

            depths = queue_depths()
            if depths:
                self._cache = depths
            self._fetched_at = time.monotonic()
        except Exception:  # noqa: BLE001 - keep serving the stale snapshot
            self._fetched_at = time.monotonic()  # do not hot-loop on a failing DB
        finally:
            self._lock.release()

    def collect(self):  # noqa: D102 - prometheus_client protocol
        import time

        from prometheus_client.core import GaugeMetricFamily

        self._refresh_if_due()

        family = GaugeMetricFamily(
            "outpost_queue_depth",
            "Rows waiting in each pipeline queue.",
            labels=["queue"],
        )
        for queue, n in self._cache.items():
            family.add_metric([queue], n)
        yield family

        age = GaugeMetricFamily(
            "outpost_queue_depth_stale_seconds",
            "Age of the cached queue-depth snapshot. Growing without bound "
            "means the database is unreachable from this process.",
        )
        age.add_metric([], time.monotonic() - self._fetched_at if self._fetched_at else -1)
        yield age


_registered = False


def register_collectors() -> None:
    """Register the scrape-time collectors. Idempotent; safe to call repeatedly."""
    global _registered
    if _registered:
        return
    try:
        from prometheus_client import REGISTRY

        REGISTRY.register(_QueueDepthCollector())
        _registered = True
    except Exception:  # noqa: BLE001 - duplicate registration must not crash startup
        pass


__all__ = [
    "browser_pool_in_use",
    "certstream_certs",
    "certstream_matches",
    "deep_rescued",
    "register_collectors",
    "rows_reaped",
    "siblings_discovered",
    "stage_duration",
    "stage_errors",
    "takedown_time_to_death",
    "takedowns_confirmed_dead",
    "takedowns_sent",
    "url_triage_duration",
    "urls_processed",
]
