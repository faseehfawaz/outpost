"""Opportunistic kit collection — the fetching layer, with hard ethics caps.

For a confirmed phish this walks the URL's directory chain and tries to collect
the attacker's *exposed* kit archive: an open directory listing, or a small fixed
set of same-directory ``.zip`` guesses, plus a probe for exposed victim logs.

Every safety rail from ``docs/SCOPE_AND_ETHICS.md`` #5 is enforced here in code:

  * **Hard attempt cap** — no more than ``settings.kithunt_max_attempts_per_host``
    HTTP requests are ever made per :func:`hunt` call. *Every* request (dir fetch,
    archive probe, log probe) counts against it. No permutations, no fuzzing.
  * **Rate limited** — every request is spaced by at least
    ``settings.kithunt_request_interval_s`` per host (see :data:`_spacer`) and
    goes through the polite, honestly-identified client.
  * **Size guarded** — archives are streamed and aborted the moment they exceed
    ``settings.kithunt_max_archive_bytes``; we never buffer an unbounded body.
  * **Static only** — collected bytes are quarantined via
    :func:`pkintel.storage.get_storage`; nothing here executes or unpacks a kit.
  * **No victim data** — logs are handled by :func:`pkintel.kithunter.logs.note_exposed_log`,
    which keeps existence + hash only.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass
from urllib.parse import urlsplit

import httpx

from pkintel.config import settings
from pkintel.db import execute, record_audit
from pkintel.http import polite_client, polite_get
from pkintel.kithunter.logs import note_exposed_log
from pkintel.kithunter.opendir import find_archives, is_open_directory, parse_listing
from pkintel.kithunter.paths import archive_candidates, walk_up_dirs
from pkintel.logging import get_logger
from pkintel.redact import sha256_hex
from pkintel.storage import get_storage

log = get_logger(__name__)

# Archive magic numbers. We verify a downloaded body actually *looks* like an
# archive before quarantining it, so a soft-404 HTML page never lands in the
# kit store. (We validate the container shape only; we never unpack here.)
_ZIP_MAGICS = (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")
_GZIP_MAGIC = b"\x1f\x8b"
_RAR_MAGICS = (b"Rar!\x1a\x07\x00", b"Rar!\x1a\x07\x01\x00")


class _HostSpacer:
    """Process-wide per-host minimum spacing (thread-safe).

    The foundation's :func:`pkintel.http.polite_get` instantiates a *fresh*
    throttle whenever ``min_interval_s`` is passed, so that path cannot enforce
    spacing across calls. To honour the kit-hunter's own (stricter) interval we
    keep this small persistent spacer and wait on it before every request; the
    underlying ``polite_get`` still supplies the honest client + baseline
    throttle. Belt and suspenders, on purpose, for the most sensitive collector.
    """

    def __init__(self, min_interval_s: float) -> None:
        self._min = min_interval_s
        self._last: dict[str, float] = {}
        self._lock = threading.Lock()

    def wait(self, host: str) -> None:
        with self._lock:
            now = time.monotonic()
            last = self._last.get(host, 0.0)
            delay = self._min - (now - last)
            self._last[host] = max(now, last + self._min)
        if delay > 0:
            time.sleep(delay)


_spacer = _HostSpacer(settings.kithunt_request_interval_s)


@dataclass
class HuntResult:
    """Outcome of one :func:`hunt` call."""

    collected: bool
    attempts: int
    kit_sha256: str | None = None
    archive_url: str | None = None
    logs_noted: int = 0


def looks_like_archive(data: bytes) -> bool:
    """Pure: True if ``data`` begins with a zip / gzip / rar magic number."""
    if data.startswith(_ZIP_MAGICS):
        return True
    if data.startswith(_GZIP_MAGIC):
        return True
    return data.startswith(_RAR_MAGICS)


def _archive_name(url: str) -> str:
    """Basename of an archive URL, e.g. ``.../a/b/kit.zip`` -> ``kit.zip``."""
    return urlsplit(url).path.rsplit("/", 1)[-1] or url


def _get(client: httpx.Client, url: str) -> httpx.Response | None:
    """Throttled, polite GET. Returns None on any transport error."""
    _spacer.wait(urlsplit(url).netloc)
    try:
        return polite_get(client, url, min_interval_s=settings.kithunt_request_interval_s)
    except httpx.HTTPError as exc:
        log.debug("request_failed", url=url, error=str(exc))
        return None


def _download_archive(client: httpx.Client, url: str) -> bytes | None:
    """Stream ``url`` with a hard size guard; return bytes or None.

    Aborts (returns None) if the advertised Content-Length or the streamed byte
    count exceeds ``settings.kithunt_max_archive_bytes``. Never buffers more than
    the cap.
    """
    cap = settings.kithunt_max_archive_bytes
    _spacer.wait(urlsplit(url).netloc)
    try:
        with client.stream("GET", url) as resp:
            if resp.status_code != 200:
                return None
            advertised = resp.headers.get("content-length", "")
            if advertised.isdigit() and int(advertised) > cap:
                log.warning("archive_too_large", url=url, advertised=int(advertised), cap=cap)
                return None
            buf = bytearray()
            for chunk in resp.iter_bytes():
                buf.extend(chunk)
                if len(buf) > cap:
                    log.warning("archive_too_large", url=url, streamed=len(buf), cap=cap)
                    return None
            return bytes(buf)
    except httpx.HTTPError as exc:
        log.debug("download_failed", url=url, error=str(exc))
        return None


def _try_collect_archive(client: httpx.Client, url_row: dict, archive_url: str) -> str | None:
    """Download, validate, quarantine and record one candidate archive.

    Returns the archive sha256 on success, else None. On success the bytes are
    stored via object storage and a ``kits`` row is inserted
    (``ON CONFLICT (sha256) DO NOTHING`` so re-collection is idempotent).
    """
    data = _download_archive(client, archive_url)
    if data is None or not looks_like_archive(data):
        return None

    sha256 = sha256_hex(data)
    stored_key = get_storage().put(sha256, data)
    execute(
        """
        INSERT INTO kits
            (url_id, sha256, size, stored_key, source_archive_name, file_count, analysis_state)
        VALUES (%s, %s, %s, %s, %s, NULL, 'stored')
        ON CONFLICT (sha256) DO NOTHING
        """,
        (url_row["id"], sha256, len(data), stored_key, _archive_name(archive_url)),
    )
    record_audit(
        "kithunter",
        "collect",
        url_row.get("url"),
        archive_url=archive_url,
        sha256=sha256,
        size=len(data),
        stored_key=stored_key,
    )
    log.info(
        "kit_collected",
        url_id=url_row["id"],
        archive_url=archive_url,
        sha256=sha256,
        size=len(data),
    )
    return sha256


def hunt(url_row: dict) -> HuntResult:
    """Opportunistically collect an exposed kit for one confirmed-phish URL.

    Walks the directory chain of ``url_row['url']``. For each directory: fetch
    it; if it is an open listing, try the archives it links; otherwise try the
    fixed same-directory archive guesses. Then probe the fixed victim-log names.
    Stops the instant the per-host attempt cap is reached or a kit is collected.
    """
    url = url_row["url"]
    url_id = url_row["id"]
    cap = settings.kithunt_max_attempts_per_host

    attempts = 0
    logs_noted = 0
    tried_archives: set[str] = set()
    tried_logs: set[str] = set()

    client = polite_client()
    try:
        for dir_url in walk_up_dirs(url):
            if attempts >= cap:
                break

            attempts += 1
            resp = _get(client, dir_url)
            status = resp.status_code if resp is not None else None
            record_audit("kithunter", "probe", url, target_url=dir_url, kind="dir", status=status)

            if resp is not None and resp.status_code == 200 and is_open_directory(resp.text):
                candidates = find_archives(parse_listing(resp.text, dir_url))
            else:
                candidates = archive_candidates(dir_url, settings.kithunt_archive_names)

            for archive_url in candidates:
                if attempts >= cap:
                    break
                if archive_url in tried_archives:
                    continue
                tried_archives.add(archive_url)
                attempts += 1
                sha256 = _try_collect_archive(client, url_row, archive_url)
                if sha256 is not None:
                    return HuntResult(
                        collected=True,
                        attempts=attempts,
                        kit_sha256=sha256,
                        archive_url=archive_url,
                        logs_noted=logs_noted,
                    )

            for log_name in settings.kithunt_log_names:
                if attempts >= cap:
                    break
                log_url = dir_url + log_name
                if log_url in tried_logs:
                    continue
                tried_logs.add(log_url)
                attempts += 1
                if note_exposed_log(client, url_id, log_url):
                    logs_noted += 1

        return HuntResult(collected=False, attempts=attempts, logs_noted=logs_noted)
    finally:
        client.close()
