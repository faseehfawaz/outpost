"""AlienVault OTX (Open Threat Exchange) feed adapter — phishing pulse search API.

AlienVault OTX provides a public pulse search endpoint that requires no API key.
We query recent phishing pulses and extract indicator items with type 'URL',
'hostname', or 'domain'.
"""

from __future__ import annotations

from collections.abc import Iterable, Iterator
from typing import Any

import httpx

from pkintel.ingest.base import polite_fetch
from pkintel.logging import get_logger

log = get_logger(__name__)

SEARCH_URL = (
    "https://otx.alienvault.com/api/v1/search/pulses?q=phishing&limit=50&sort=-created"
)
MAX_PAGES = 3


def parse_otx_json(payload: Any) -> Iterator[str]:
    """Yield indicator URLs from an AlienVault OTX search response payload. Pure.

    Filters indicators where ``type`` is 'URL', 'hostname', or 'domain'.
    For 'domain' and 'hostname' indicators without a scheme, constructs
    ``http://{indicator}/``.
    """
    if not isinstance(payload, dict):
        return
    results = payload.get("results")
    if not isinstance(results, list):
        return
    for pulse in results:
        if not isinstance(pulse, dict):
            continue
        indicators = pulse.get("indicators")
        if not isinstance(indicators, list):
            continue
        for ind in indicators:
            if not isinstance(ind, dict):
                continue
            ind_type = str(ind.get("type", "")).strip().upper()
            indicator_val = str(ind.get("indicator", "")).strip()
            if not indicator_val:
                continue
            if ind_type == "URL":
                yield indicator_val
            elif ind_type in ("HOSTNAME", "DOMAIN"):
                if indicator_val.startswith(("http://", "https://")):
                    yield indicator_val
                else:
                    stripped = indicator_val.strip("/")
                    yield f"http://{stripped}/"


class OTXAdapter:
    """Feed adapter for AlienVault OTX phishing pulse search API."""

    name = "otx"
    kind = "otx"

    def fetch(self, client: httpx.Client) -> Iterable[str]:
        current_url = SEARCH_URL
        for _ in range(MAX_PAGES):
            resp = polite_fetch(client, current_url)
            if resp is None or resp.status_code != 200:
                break
            try:
                payload = resp.json()
            except Exception as exc:  # noqa: BLE001
                log.warning("otx_json_parse_error", url=current_url, error=str(exc))
                break

            yield from parse_otx_json(payload)

            if not isinstance(payload, dict):
                break
            next_url = payload.get("next")
            if not next_url or not isinstance(next_url, str):
                break
            next_url = next_url.strip()
            if not next_url:
                break
            if next_url.startswith("/"):
                current_url = f"https://otx.alienvault.com{next_url}"
            else:
                current_url = next_url
