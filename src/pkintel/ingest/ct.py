"""Certificate Transparency adapter — crt.sh polling for brand lookalikes.

Attackers routinely obtain TLS certificates for lookalike domains
(``emiratesnbd-login.com``, ``secure-emirates-nbd.net``) *before* they stand up
the phishing page. Watching CT logs therefore surfaces phishing infrastructure
early. For each priority brand we query crt.sh for certificates whose common
name / SANs contain the brand's slug, keep only names that *look like
lookalikes* (not the brand's own domain family), and yield ``https://<host>``.

NOTE: In production the right tool is a certstream firehose — a small Go client
subscribed to ``settings.certstream_url`` (``wss://certstream.calidog.io/``)
streaming every new certificate in real time. That is the recommended upgrade.
This crt.sh poller is the **zero-dependency default**: it needs no extra
services and no websocket client, at the cost of freshness and volume. It is
deliberately conservative on volume (per-brand cap, de-duplicated, official
domain families excluded).
"""

from __future__ import annotations

from collections.abc import Iterable, Iterator, Sequence
from typing import Any
from urllib.parse import quote

import httpx

from pkintel.ingest.base import polite_fetch


def brand_slug(brand: str) -> str:
    """Collapse a brand name to an alphanumeric slug (``"Emirates NBD"`` -> ``"emiratesnbd"``)."""
    return "".join(ch for ch in brand.lower() if ch.isalnum())


def crtsh_query_url(brand: str) -> str:
    """Build the crt.sh JSON query URL for a brand (SQL-LIKE ``%slug%``).

    ``%25`` is the URL-encoding of ``%`` (crt.sh treats ``q`` as a LIKE
    pattern), so this matches the slug as a substring of any CN/SAN.
    """
    slug = brand_slug(brand)
    return f"https://crt.sh/?q=%25{quote(slug)}%25&output=json"


def looks_like_lookalike(host: str, slug: str) -> bool:
    """True if ``host`` embeds ``slug`` but is *not* the brand's own domain.

    Conservative combosquat/typosquat heuristic (pure):
      * the slug must appear in the host with separators (``-``, ``.``) removed,
        so ``emirates-nbd.com`` still matches slug ``emiratesnbd``;
      * but if the registrable label (the SLD) is *exactly* the slug we treat
        the whole domain family — ``emiratesnbd.com`` and any subdomain of it —
        as the brand's own and exclude it.
    """
    h = host.strip().lower().lstrip("*.").rstrip(".")
    labels = h.split(".")
    if len(labels) < 2:
        return False
    condensed = h.replace("-", "").replace(".", "")
    if slug not in condensed:
        return False
    sld = labels[-2]
    if sld == slug:  # official domain family (brand.tld or *.brand.tld)
        return False
    return True


def parse_crtsh_json(payload: Any, slug: str) -> Iterator[str]:
    """Yield lookalike hostnames from a crt.sh JSON array. Pure, de-duplicated.

    Each crt.sh entry may carry a ``common_name`` and a newline-separated
    ``name_value`` (the SANs). Wildcards are unwrapped to their base name.
    """
    if not isinstance(payload, list):
        return
    seen: set[str] = set()
    for entry in payload:
        if not isinstance(entry, dict):
            continue
        names: list[str] = []
        cn = entry.get("common_name")
        if isinstance(cn, str) and cn:
            names.append(cn)
        nv = entry.get("name_value")
        if isinstance(nv, str) and nv:
            names.extend(nv.splitlines())
        for name in names:
            host = name.strip().lower().lstrip("*.").rstrip(".")
            if not host or " " in host or host in seen:
                continue
            if looks_like_lookalike(host, slug):
                seen.add(host)
                yield host


import time
from pkintel.logging import get_logger

log = get_logger(__name__)

# Circuit breaker state across runs in process
_CIRCUIT_OPEN_UNTIL: float = 0.0
_CONSECUTIVE_FAILURES: int = 0
_MAX_CONSECUTIVE_FAILURES: int = 3
_COOLDOWN_SECONDS: float = 1800.0  # 30 minutes


class CTAdapter:
    """Feed adapter that polls crt.sh for lookalikes of the priority brands."""

    name = "crtsh"
    kind = "ct"

    def __init__(self, brands: Sequence[str], per_brand_cap: int = 50) -> None:
        self.brands = list(brands)
        self.per_brand_cap = per_brand_cap

    def fetch(self, client: httpx.Client) -> Iterable[str]:
        global _CIRCUIT_OPEN_UNTIL, _CONSECUTIVE_FAILURES
        now = time.time()
        if now < _CIRCUIT_OPEN_UNTIL:
            log.warning("crtsh_circuit_open", remaining_s=int(_CIRCUIT_OPEN_UNTIL - now))
            return

        emitted: set[str] = set()
        failed_count = 0
        total_attempts = 0

        for brand in self.brands:
            slug = brand_slug(brand)
            if not slug:
                continue
            total_attempts += 1
            resp = polite_fetch(client, crtsh_query_url(brand))
            if resp is None or resp.status_code != 200:
                failed_count += 1
                continue
            try:
                payload = resp.json()
            except Exception:  # noqa: BLE001 - malformed body must not abort the run
                failed_count += 1
                continue
            count = 0
            for host in parse_crtsh_json(payload, slug):
                if host in emitted:
                    continue
                emitted.add(host)
                yield "https://" + host
                count += 1
                if count >= self.per_brand_cap:
                    break

        if total_attempts > 0 and failed_count == total_attempts:
            _CONSECUTIVE_FAILURES += 1
            log.warning("crtsh_all_failed", consecutive=_CONSECUTIVE_FAILURES)
            if _CONSECUTIVE_FAILURES >= _MAX_CONSECUTIVE_FAILURES:
                _CIRCUIT_OPEN_UNTIL = time.time() + _COOLDOWN_SECONDS
                log.warning("crtsh_circuit_opened", cooldown_s=_COOLDOWN_SECONDS)
        elif emitted:
            _CONSECUTIVE_FAILURES = 0
