"""Polite HTTP client shared by ingest, triage and the kit hunter.

Two politeness guarantees baked in at this layer so no caller can forget them:

  * an honest, contactable User-Agent (we are not hiding — see config);
  * a per-host minimum interval between requests, because the phishing sites we
    touch are usually *hacked legitimate servers* whose owner is a victim.

Everything else (timeouts, redirect policy) is centralised here too.
"""

from __future__ import annotations

import threading
import time
from urllib.parse import urlsplit

import httpx

from pkintel.config import settings
from pkintel.logging import get_logger

log = get_logger(__name__)


class _HostThrottle:
    """Process-wide per-host rate limiter (thread-safe)."""

    def __init__(self, min_interval_s: float) -> None:
        self._min = min_interval_s
        self._last: dict[str, float] = {}
        self._lock = threading.Lock()

    def wait(self, host: str) -> None:
        with self._lock:
            now = time.monotonic()
            last = self._last.get(host, 0.0)
            delay = self._min - (now - last)
            # reserve the slot before sleeping so concurrent callers queue
            self._last[host] = max(now, last + self._min)
        if delay > 0:
            time.sleep(delay)


_throttle = _HostThrottle(settings.per_host_min_interval_s)


def polite_client(**kwargs) -> httpx.Client:
    headers = {"User-Agent": settings.user_agent, **kwargs.pop("headers", {})}
    return httpx.Client(
        headers=headers,
        timeout=kwargs.pop("timeout", settings.http_timeout_s),
        follow_redirects=kwargs.pop("follow_redirects", True),
        limits=httpx.Limits(max_connections=settings.http_max_connections),
        **kwargs,
    )


def polite_get(
    client: httpx.Client,
    url: str,
    *,
    min_interval_s: float | None = None,
    **kwargs,
) -> httpx.Response:
    """GET with per-host throttling. Prefer this over ``client.get`` directly."""
    host = urlsplit(url).netloc
    throttle = _throttle if min_interval_s is None else _HostThrottle(min_interval_s)
    throttle.wait(host)
    return client.get(url, **kwargs)
