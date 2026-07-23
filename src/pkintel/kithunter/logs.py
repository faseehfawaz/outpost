"""Exposed victim-log sightings — the most ethics-sensitive code in the repo.

WHY THIS MODULE EXISTS, AND WHY IT NEVER KEEPS CONTENTS
=======================================================
Phishing kits often write harvested victim credentials to a plaintext results
log (``result.txt``, ``log.txt`` …) left readable in the deployed directory.
That file contains **real people's** passwords, OTPs and card data. Non-negotiable
#3 of ``docs/SCOPE_AND_ETHICS.md`` is *never retain victim data*.

So when we notice such a file we do the **minimum** required to prove it exists
and to give an abuse desk something to correlate against, and nothing more:

  * we read AT MOST :data:`MAX_LOG_SNIFF_BYTES` bytes — only enough to hash;
  * we compute a ``content_sha256`` (of the sniffed bytes) and an ``approx_size``;
  * we record **existence + hash + size** in ``victim_log_sightings``;
  * we IMMEDIATELY drop the bytes and stamp ``deleted_at = now()``.

There is deliberately **no code path** in this module that writes the log's
*contents* to the database, to object storage, to disk, or to a log line. The
only thing ever derived from the bytes is the pure ``(sha256, length)`` pair
produced by :func:`summarize_log_bytes`; grep this file and you will find the
raw bytes are never passed anywhere else. The value we store is a hash — proof
that we saw the file *and* proof that we did not keep it.

We never *use* the credentials, never parse them, never report their content —
only the fact of exposure (to the host and aeCERT, handled by the takedown
subsystem via ``reported_to``).
"""

from __future__ import annotations

import httpx

from pkintel.db import execute, record_audit
from pkintel.http import polite_get
from pkintel.logging import get_logger
from pkintel.redact import sha256_hex

log = get_logger(__name__)

# Hard ceiling on how many bytes of a victim log we will ever pull off the wire
# or hash. A prefix hash is a perfectly stable existence fingerprint; we have no
# need — and no right — to read the whole file.
MAX_LOG_SNIFF_BYTES = 64 * 1024


def summarize_log_bytes(data: bytes) -> tuple[str, int]:
    """Pure: reduce raw log bytes to ``(content_sha256, byte_count)``.

    This is the ONLY thing ever derived from a victim log's bytes. It returns a
    hash and a count — never the content — and stores nothing. Keeping it pure
    and separate makes the ethics guarantee testable without a network or DB.
    """
    return sha256_hex(data), len(data)


def _advertised_size(resp: httpx.Response, sniffed_len: int) -> int:
    """Best-effort true size from response headers, else the sniffed length.

    Prefers ``Content-Range`` (the server's total when it honoured our ranged
    request), then ``Content-Length``. Falls back to what we actually read.
    """
    content_range = resp.headers.get("content-range", "")
    if "/" in content_range:
        total = content_range.rsplit("/", 1)[-1].strip()
        if total.isdigit():
            return int(total)
    content_length = resp.headers.get("content-length", "")
    if content_length.isdigit():
        return int(content_length)
    return sniffed_len


def note_exposed_log(client: httpx.Client, url_id: int, log_url: str) -> bool:
    """Record the *existence* of an exposed results log, keeping no content.

    Fetches at most :data:`MAX_LOG_SNIFF_BYTES` (requested via a ``Range`` header
    and hard-capped again on our side), and only if the server serves it
    (HTTP 200/206). Writes existence + hash + approximate size to
    ``victim_log_sightings`` and immediately discards the bytes.

    Returns True if a sighting was recorded, False otherwise (not present, error,
    empty). Never raises into the caller.
    """
    try:
        resp = polite_get(
            client,
            log_url,
            headers={"Range": f"bytes=0-{MAX_LOG_SNIFF_BYTES - 1}"},
        )
    except httpx.HTTPError as exc:
        log.debug("log_probe_failed", url=log_url, error=str(exc))
        return False

    if resp.status_code not in (200, 206):
        return False

    # Bounded slice: even if the server ignored our Range header we hash only the
    # first MAX_LOG_SNIFF_BYTES and never look at (or keep) the rest.
    sniffed = resp.content[:MAX_LOG_SNIFF_BYTES]
    if not sniffed:
        return False

    content_sha256, sniffed_len = summarize_log_bytes(sniffed)
    approx_size = _advertised_size(resp, sniffed_len)

    # Existence + hash + size ONLY. reported_to defaults to '{}'; deleted_at is
    # stamped now() to assert on the record that we retained no local copy.
    execute(
        """
        INSERT INTO victim_log_sightings
            (url_id, observed_url, content_sha256, approx_size, reported_to, deleted_at)
        VALUES (%s, %s, %s, %s, '{}', now())
        """,
        (url_id, log_url, content_sha256, approx_size),
    )
    record_audit(
        "kithunter",
        "probe",
        log_url,
        kind="victim_log",
        url_id=url_id,
        content_sha256=content_sha256,
        approx_size=approx_size,
        note="exposed results log recorded as existence+hash only; contents discarded",
    )
    log.info(
        "victim_log_sighted",
        url_id=url_id,
        observed_url=log_url,
        content_sha256=content_sha256,
        approx_size=approx_size,
    )
    # Drop the bytes explicitly; they are never persisted anywhere.
    del sniffed
    return True
