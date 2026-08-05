"""Analyzer runner — claims stored kits and analyses them inside a sandbox.

Threat model
------------
Every byte this stage touches was authored by an attacker and fetched from
attacker-controlled infrastructure. Extraction, decompression and PHP parsing
are all adversarial-input parsers, so they run in a container that is:

    --network none          no egress, no lateral movement, no callback
    --read-only             root filesystem immutable
    --tmpfs /tmp            the only writable path, size-capped and noexec
    --cap-drop ALL          no capabilities
    --security-opt no-new-privileges
    --memory / --cpus       bounded (decompression bombs)
    --pids-limit            bounded (fork bombs)
    timeout=                bounded wall clock (parser hangs)

This is the only genuinely hard boundary in the pipeline. The in-process guards
in ``safe_extract`` (zip-slip, size caps) and ``deobfuscate`` (linear-time
pattern, decompression caps, cooperative deadline) are all still there and
still correct — but they are defence in depth, not the boundary.

History: for a long time this module did all of the above *in-process on the
host*, while the README, the config and ``docker-compose.yml`` all described a
container that no code ever launched. ``analyzer_image``, ``analyzer_timeout_s``,
``analyzer_mem_limit`` and ``analyzer_cpu_limit`` were dead settings. That gap
is what this module now closes.

The container speaks one protocol: argv is a path to an archive, stdout is a
single ``AnalysisResult`` JSON document, exit code is 0 on success. See
``pkintel.analyzer.container_main``.
"""

from __future__ import annotations

import shutil
import subprocess
import traceback

from pkintel.config import settings
from pkintel.crypto import encrypt_indicator
from pkintel.db import claim_rows, execute, execute_many
from pkintel.logging import get_logger
from pkintel.models import AnalysisResult
from pkintel.storage import get_storage

log = get_logger(__name__)


class SandboxUnavailableError(RuntimeError):
    """No container runtime is available to isolate kit analysis."""


def _runtime_binary() -> str:
    """Resolve the container runtime, preferring the configured one.

    Podman is listed first in the default because it runs rootless: the worker
    then needs no membership of the ``docker`` group, which is root-equivalent
    on the host and was previously granted for a sandbox that did not exist.
    """
    configured = (settings.analyzer_runtime or "").strip()
    candidates = [configured] if configured else ["podman", "docker"]
    for name in candidates:
        path = shutil.which(name)
        if path:
            return path
    raise SandboxUnavailableError(
        f"no container runtime found (tried: {', '.join(c for c in candidates if c)}). "
        "Install podman (preferred, rootless) or docker, build the sandbox image with "
        "`make analyzer-image`, or set PKINTEL_ANALYZER_RUNTIME."
    )


def _sandbox_argv(runtime: str, host_archive: str) -> list[str]:
    """Build the hardened `run` invocation. Pure, so it is directly testable."""
    return [
        runtime,
        "run",
        "--rm",
        "--interactive=false",
        # --- isolation -----------------------------------------------------
        "--network",
        "none",
        "--read-only",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        # --- resource bounds ----------------------------------------------
        "--memory",
        settings.analyzer_mem_limit,
        "--cpus",
        str(settings.analyzer_cpu_limit),
        "--pids-limit",
        str(settings.analyzer_pids_limit),
        # Only writable path. noexec/nosuid so nothing unpacked can be run even
        # if some future code path tried to.
        #
        # S108 flags "/tmp" as an insecure temp path. It is not one here: this
        # is a path INSIDE the container's own mount namespace, not on the host,
        # and the whole point of the flag is to make it a private, size-capped,
        # noexec tmpfs. There is no shared-tmp race to have.
        "--tmpfs",
        f"/tmp:rw,noexec,nosuid,size={settings.analyzer_tmpfs_size}",  # noqa: S108
        # --- the kit, read-only -------------------------------------------
        "--volume",
        f"{host_archive}:/in/archive.zip:ro",
        settings.analyzer_image,
        "/in/archive.zip",
    ]


def analyze_in_sandbox(host_archive: str) -> AnalysisResult:
    """Run one archive through the sandbox and return its parsed result.

    Raises :class:`SandboxUnavailableError` if no runtime exists, and
    ``subprocess.TimeoutExpired`` if the container blows its wall-clock budget
    (the runtime kills the container; ``--rm`` cleans it up).
    """
    runtime = _runtime_binary()
    argv = _sandbox_argv(runtime, host_archive)

    proc = subprocess.run(  # noqa: S603 - argv is fully constructed, never shell
        argv,
        capture_output=True,
        timeout=settings.analyzer_timeout_s,
        check=False,
    )

    if proc.returncode != 0:
        # stderr only. stdout may carry full (unredacted) indicator values, and
        # this path frequently ends up in an error column and a log line.
        stderr = proc.stderr.decode("utf-8", "replace")[:2000]
        raise RuntimeError(f"sandbox exited {proc.returncode}: {stderr}")

    try:
        return AnalysisResult.model_validate_json(proc.stdout)
    except Exception as exc:
        raise RuntimeError(f"sandbox produced unparseable output: {exc}") from exc


def _persist(kit_id: int, result: AnalysisResult) -> None:
    """Write one analysis result. Batched — this used to be a query per file."""
    execute(
        "UPDATE kits SET analysis_state = 'analyzed', analyzed_at = now(), "
        "file_count = %s, analysis_error = NULL WHERE id = %s",
        (result.file_count, kit_id),
    )

    execute_many(
        "INSERT INTO kit_files (kit_id, path, sha256, tlsh, normalized_token_hash, "
        "size, mime, is_obfuscated) VALUES (%s, %s, %s, %s, %s, %s, %s, %s) "
        "ON CONFLICT DO NOTHING",
        [
            (
                kit_id,
                f.path,
                f.sha256,
                f.tlsh,
                f.normalized_token_hash,
                f.size,
                f.mime,
                f.is_obfuscated,
            )
            for f in result.files
        ],
    )

    # full_value is encrypted here, on the host, and never stored in plaintext.
    # See pkintel.crypto — fail-closed if no key is configured.
    execute_many(
        "INSERT INTO indicators (kit_id, type, value_hash, redacted_display, "
        "full_value_encrypted, confidence, found_in_path, meta) "
        "VALUES (%s, %s, %s, %s, %s, %s, %s, %s) ON CONFLICT DO NOTHING",
        [
            (
                kit_id,
                ind.type.value,
                ind.value_hash,
                ind.redacted_display,
                encrypt_indicator(ind.full_value),
                ind.confidence,
                ind.found_in_path,
                "{}",
            )
            for ind in result.indicators
        ],
    )

    fp = result.fingerprint
    execute(
        "INSERT INTO fingerprints (kit_id, fileset_hash, antibot_hash, token_hash, "
        "author_strings, file_sha_set) VALUES (%s, %s, %s, %s, %s, %s) "
        "ON CONFLICT DO NOTHING",
        (
            kit_id,
            fp.fileset_hash,
            fp.antibot_hash,
            fp.token_hash,
            fp.author_strings,
            fp.file_sha_set,
        ),
    )

    # Existence + path only. Contents are never read, fetched or stored — see
    # docs/SCOPE_AND_ETHICS.md.
    if result.victim_log_paths:
        execute_many(
            "INSERT INTO victim_log_sightings (url_id, observed_url, content_sha256) "
            "SELECT k.url_id, %s, NULL FROM kits k WHERE k.id = %s",
            [(path, kit_id) for path in result.victim_log_paths],
        )


def run_once(worker_id: str = "analyze-1", limit: int = 5) -> int:
    """Claim and analyse stored kits. Returns the number successfully analysed."""
    kits = claim_rows(
        "kits",
        ready_col="analysis_state",
        ready_value="stored",
        busy_value="analyzing",
        worker_id=worker_id,
        limit=limit,
        order_by="id",
    )
    if not kits:
        return 0

    # Fail the whole batch fast and loudly if the sandbox is missing, rather
    # than marking every kit 'error' one at a time with an identical message.
    # Rows stay in 'analyzing' and the reaper returns them once it is fixed.
    try:
        _runtime_binary()
    except SandboxUnavailableError as exc:
        log.error("analyzer_sandbox_unavailable", error=str(exc), claimed=len(kits))
        return 0

    storage = get_storage()
    processed = 0

    for kit in kits:
        kit_id = kit["id"]
        stored_key = kit["stored_key"]

        try:
            log.info("analyzing_kit", kit_id=kit_id, stored_key=stored_key)

            archive_path = storage.local_path(stored_key)
            if archive_path is None or not archive_path.exists():
                raise ValueError(f"archive not found in storage: {stored_key}")

            result = analyze_in_sandbox(str(archive_path.resolve()))
            if not result.ok:
                raise RuntimeError(result.error or "sandbox reported failure")

            _persist(kit_id, result)
            processed += 1
            log.info(
                "kit_analyzed",
                kit_id=kit_id,
                files=result.file_count,
                indicators=len(result.indicators),
                victim_logs=len(result.victim_log_paths),
            )

        except subprocess.TimeoutExpired:
            msg = f"sandbox timed out after {settings.analyzer_timeout_s}s"
            log.warning(
                "kit_analysis_timeout", kit_id=kit_id, timeout_s=settings.analyzer_timeout_s
            )
            execute(
                "UPDATE kits SET analysis_state = 'error', analysis_error = %s WHERE id = %s",
                (msg, kit_id),
            )
        except Exception as exc:  # noqa: BLE001 - one bad kit must not stop the batch
            log.error("kit_analysis_failed", kit_id=kit_id, error=str(exc))
            execute(
                "UPDATE kits SET analysis_state = 'error', analysis_error = %s WHERE id = %s",
                (traceback.format_exc()[:4000], kit_id),
            )

    try:
        from pkintel.metrics import stage_errors, urls_processed

        urls_processed.labels(stage="analyze", outcome="analyzed").inc(processed)
        stage_errors.labels(stage="analyze").inc(len(kits) - processed)
    except Exception:  # noqa: BLE001, S110 - metrics must never break the pipeline
        pass

    return processed


__all__ = ["SandboxUnavailableError", "analyze_in_sandbox", "run_once"]
