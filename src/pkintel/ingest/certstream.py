"""Certificate Transparency firehose — the earliest possible phishing signal.

Why replace the crt.sh poller
-----------------------------
``pkintel.ingest.ct`` polls crt.sh once per cycle, per brand. That has three
problems the module's own docstring already conceded:

* **Latency.** A poll every ~14 minutes against a service that indexes CT logs
  on its own schedule means a lookalike certificate is minutes-to-hours old
  before we see it.
* **Reliability.** crt.sh is a single community-run instance that rate-limits
  aggressively and returns 502s under load. Our adapter silently swallows those
  (``if resp.status_code != 200: continue``), so an outage looks like "no new
  domains" rather than an error.
* **Coverage.** It only finds what a ``%brand%`` LIKE query matches, so
  homoglyph and heavy-typo variants (``emirat3snbd``, ``emiratesnbcl``) are
  invisible to it.

The firehose subscribes to the live CT aggregate stream instead. Every
certificate issued anywhere on the public web arrives within seconds. At
~200-400 certs/sec we can afford to run every single one through a matcher
locally — this box has eleven idle threads and CPU is not the constraint.

Operationally this is the biggest single detection upgrade in the platform: we
see the attacker's domain **at certificate issuance**, which is typically
minutes-to-hours *before* the phishing page is served to a victim. Compare that
to URLhaus/OpenPhish, which by construction only list URLs somebody has already
been phished by.

Runs as its own long-lived service (``outpost-certstream.service``); it is a
push stream, not a poll, so it does not fit the ``run_once`` batch contract.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import time
from collections.abc import Iterable

from pkintel.config import settings
from pkintel.db import connection, record_audit
from pkintel.ingest.normalize import canonical_url, host_of, url_hash
from pkintel.ingest.priority import compute_priority
from pkintel.ingest.typosquat import BrandMatcher
from pkintel.logging import get_logger

log = get_logger(__name__)

_INSERT_SQL = """
    INSERT INTO urls (url, url_hash, host, source_id, priority)
    VALUES (%s, %s, %s, %s, %s)
    ON CONFLICT (url_hash) DO UPDATE SET last_seen = now()
"""

_UPSERT_SOURCE_SQL = """
    INSERT INTO sources (name, kind) VALUES (%s, %s)
    ON CONFLICT (name) DO UPDATE SET kind = EXCLUDED.kind
    RETURNING id
"""

SOURCE_NAME = "certstream"


def extract_names(message: dict) -> list[str]:
    """Pull all DNS names out of a certstream ``certificate_update`` message. Pure.

    The wire format nests them at
    ``data.leaf_cert.all_domains``; we tolerate its absence rather than assuming,
    because the public aggregators have changed this shape before.
    """
    if message.get("message_type") != "certificate_update":
        return []
    data = message.get("data")
    if not isinstance(data, dict):
        return []
    leaf = data.get("leaf_cert")
    if not isinstance(leaf, dict):
        return []
    names = leaf.get("all_domains")
    if not isinstance(names, list):
        return []
    out = []
    for n in names:
        if isinstance(n, str) and n:
            out.append(n.strip().lower().lstrip("*.").rstrip("."))
    return out


class CertstreamIngestor:
    """Consumes the CT firehose and upserts brand-lookalike hosts.

    Keeps a small in-memory dedupe window because a single certificate covers
    many SANs and popular domains get reissued constantly; without it we would
    hammer Postgres with upserts that all resolve to ``DO UPDATE last_seen``.
    """

    def __init__(self, dedupe_window: int = 100_000) -> None:
        self.matcher = BrandMatcher(settings.priority_brands)
        self._seen: dict[str, float] = {}
        self._dedupe_window = dedupe_window
        self._source_id: int | None = None
        self.stats = {"certs": 0, "names": 0, "matched": 0, "inserted": 0}
        self._last_report = time.monotonic()

    # -- persistence -------------------------------------------------------
    def _get_source_id(self) -> int:
        if self._source_id is None:
            with connection() as conn, conn.cursor() as cur:
                cur.execute(_UPSERT_SOURCE_SQL, (SOURCE_NAME, "ct"))
                self._source_id = cur.fetchone()["id"]
        return self._source_id

    def _dedupe(self, host: str) -> bool:
        """True if this host is new to the current window."""
        if host in self._seen:
            return False
        if len(self._seen) >= self._dedupe_window:
            # Drop the oldest half. Cheap, and precision here does not matter —
            # a false "new" only costs one idempotent upsert.
            cutoff = sorted(self._seen.values())[len(self._seen) // 2]
            self._seen = {k: v for k, v in self._seen.items() if v > cutoff}
        self._seen[host] = time.monotonic()
        return True

    def persist(self, matches: Iterable[tuple[str, str, str]]) -> int:
        """Upsert ``(host, brand, reason)`` matches. Returns rows written."""
        rows = []
        for host, brand, reason in matches:
            url = f"https://{host}"
            try:
                canon = canonical_url(url)
                h = host_of(canon)
            except Exception:  # noqa: BLE001
                continue
            if not h:
                continue
            priority = compute_priority(
                canon,
                source_name=SOURCE_NAME,
                priority_brands=settings.priority_brands,
            )
            rows.append((canon, url_hash(canon), h, self._get_source_id(), priority))
            log.info("certstream_match", host=host, brand=brand, reason=reason, priority=priority)

        if not rows:
            return 0
        with connection() as conn, conn.cursor() as cur:
            cur.executemany(_INSERT_SQL, rows)
        self.stats["inserted"] += len(rows)
        return len(rows)

    # -- stream handling ---------------------------------------------------
    def handle_message(self, raw: str) -> int:
        """Process one raw websocket frame. Returns matches persisted."""
        try:
            message = json.loads(raw)
        except (json.JSONDecodeError, TypeError):
            return 0

        names = extract_names(message)
        if not names:
            return 0

        self.stats["certs"] += 1
        self.stats["names"] += len(names)

        matches = []
        for host in names:
            if not self._dedupe(host):
                continue
            hit = self.matcher.match(host)
            if hit:
                brand, reason = hit
                self.stats["matched"] += 1
                matches.append((host, brand, reason))

        self._report()
        return self.persist(matches) if matches else 0

    def _report(self, every_s: float = 60.0) -> None:
        now = time.monotonic()
        if now - self._last_report < every_s:
            return
        elapsed = now - self._last_report
        log.info(
            "certstream_stats",
            certs_per_s=round(self.stats["certs"] / elapsed, 1),
            certs=self.stats["certs"],
            names=self.stats["names"],
            matched=self.stats["matched"],
            inserted=self.stats["inserted"],
        )
        record_audit("certstream", "stats", target=SOURCE_NAME, **self.stats)
        self.stats = {"certs": 0, "names": 0, "matched": 0, "inserted": 0}
        self._last_report = now


async def _consume(ingestor: CertstreamIngestor) -> None:
    """One connection's lifetime. Raises on disconnect so the caller can retry."""
    import websockets

    url = settings.certstream_url
    log.info("certstream_connecting", url=url)
    # ping_interval keeps NAT/proxy paths from silently dropping an idle socket;
    # max_size guards against a hostile oversized frame.
    async with websockets.connect(
        url, ping_interval=20, ping_timeout=20, max_size=8 * 1024 * 1024
    ) as ws:
        log.info("certstream_connected", url=url)
        async for raw in ws:
            try:
                ingestor.handle_message(raw)
            except Exception as exc:  # noqa: BLE001 - one bad frame must not drop the stream
                log.warning("certstream_message_error", error=str(exc))


async def run_forever() -> None:
    """Connect, consume, and reconnect with exponential backoff, forever.

    The public certstream aggregators drop connections routinely; treating a
    disconnect as fatal would mean silently losing the highest-value feed until
    someone noticed. Backoff is capped so we recover promptly once it returns.
    """
    ingestor = CertstreamIngestor()
    backoff = settings.certstream_reconnect_s
    max_backoff = 300.0

    while True:
        try:
            await _consume(ingestor)
            backoff = settings.certstream_reconnect_s  # clean exit: reset
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # noqa: BLE001
            log.warning("certstream_disconnected", error=str(exc), retry_in_s=round(backoff, 1))
            await asyncio.sleep(backoff)
            backoff = min(backoff * 2, max_backoff)
        else:
            log.info("certstream_stream_ended", retry_in_s=round(backoff, 1))
            await asyncio.sleep(backoff)


def main() -> None:
    """Entrypoint for ``pkintel run certstream`` / outpost-certstream.service."""
    if not settings.certstream_enabled:
        log.info("certstream_disabled")
        return
    with contextlib.suppress(KeyboardInterrupt):
        asyncio.run(run_forever())
