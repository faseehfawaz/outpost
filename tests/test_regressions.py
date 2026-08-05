"""Regression tests for bugs that reached production.

Every test here corresponds to a specific defect that shipped. They are grouped
in one file on purpose: it is a short, readable list of the ways this codebase
has actually broken, which is more useful than the same tests scattered across
the modules they guard.

Each test names the bug, what it cost, and why the assertion is shaped the way
it is. If one of these ever fails, the failure message should be enough to
understand the original incident without reading git history.
"""

from __future__ import annotations

import base64
import time
import zlib

import pytest

from pkintel.analyzer.deobfuscate import (
    _CHAIN_RE,
    _MAX_DECODED,
    _MAX_FILE_SIZE,
    deobfuscate,
)

# ---------------------------------------------------------------------------
# ReDoS — pkintel.analyzer.deobfuscate
# ---------------------------------------------------------------------------
# Kit archives are attacker-authored: a hostile .php file is an INPUT to this
# pipeline, not an edge case. Both defects below were remotely triggerable by
# leaving a crafted file in an open directory, and both hung an analyzer worker
# with no timeout. The reaper then recycled the kit into the next worker, so a
# single ~60-byte file could wedge the entire analyzer pool.
#
# The pattern must be LINEAR in input length. These tests assert wall-clock
# bounds, which is unusual and deliberate: the property under test is
# complexity, and there is no way to assert that structurally.


@pytest.mark.timeout(10)
def test_redos_exponential_backslash_payload():
    """Unterminated literal + N backslashes must not blow up exponentially.

    Original pattern: ``(?:\\\\.|(?!(?P=q)).)*``. Both branches could match a
    backslash, so the engine explored 2^N ways to split them. Measured 3.7 s at
    N=32 and x2.6 per two additional backslashes — about six hours at N=50.

    N=200 here is far past the point the old pattern became unusable; it should
    complete in microseconds.
    """
    for n in (32, 64, 200):
        payload = "eval('" + ("\\" * n) + "X"
        started = time.monotonic()
        _CHAIN_RE.search(payload)
        elapsed = time.monotonic() - started
        assert elapsed < 1.0, f"{n} backslashes took {elapsed:.2f}s — exponential ReDoS is back"


@pytest.mark.timeout(30)
def test_redos_quadratic_long_body_payload():
    """Match cost must grow linearly, not quadratically, with body length.

    The fix for the exponential case left an unbounded ``\\w*`` in the
    function-name group. ``search()`` retries at every offset, and inside a long
    body each retry ran ``\\w*`` to end-of-string then backtracked looking for
    ``(``. Measured x4.00 per doubling — 10.7 s at 40 KB, extrapolating to ~44 h
    at the file-size cap.

    Doubling the input should roughly double the time. We allow 2.5x to absorb
    scheduler noise; a quadratic pattern shows ~4x and fails clearly.
    """
    timings = []
    for n in (20_000, 40_000, 80_000):
        payload = "eval('" + ("A" * n)
        started = time.monotonic()
        _CHAIN_RE.search(payload)
        timings.append(max(time.monotonic() - started, 1e-6))

    for i in range(1, len(timings)):
        ratio = timings[i] / timings[i - 1]
        assert ratio < 2.5, (
            f"doubling input multiplied time by {ratio:.1f}x "
            f"(timings={[round(t, 4) for t in timings]}) — quadratic behaviour is back"
        )


@pytest.mark.timeout(30)
def test_redos_worst_case_at_file_size_cap():
    """A file at the size cap must still be processed in seconds, not hours."""
    payload = "eval('" + ("A" * (_MAX_FILE_SIZE - 10))
    started = time.monotonic()
    _CHAIN_RE.search(payload)
    elapsed = time.monotonic() - started
    assert elapsed < 15.0, f"worst case at the {_MAX_FILE_SIZE} byte cap took {elapsed:.1f}s"


@pytest.mark.timeout(30)
def test_deobfuscate_timeout_actually_fires():
    """``timeout_s`` must bound wall clock.

    The previous implementation wrapped the work in ``ThreadPoolExecutor`` +
    ``future.result(timeout=...)``, which cannot work: CPython's ``re`` does not
    release the GIL (so the calling thread is never scheduled to raise), and
    ``with ThreadPoolExecutor(...)`` calls ``shutdown(wait=True)`` on exit (so
    even a timeout that fired would then block). Measured: a 1.2 MB payload with
    ``timeout_s=3`` ran past 44 s.
    """
    payload = "<?php " + "eval(gzinflate(base64_decode('" + ("A" * 500_000)
    started = time.monotonic()
    result = deobfuscate(payload, max_rounds=25, timeout_s=2)
    elapsed = time.monotonic() - started

    assert elapsed < 15.0, f"timeout_s=2 overran to {elapsed:.1f}s — the budget is not enforced"
    assert isinstance(result, str)


def test_deobfuscate_skips_oversized_files():
    """Above the cap we return the source untouched rather than parsing it."""
    oversized = "x" * (_MAX_FILE_SIZE + 1)
    assert deobfuscate(oversized) is oversized


# ---------------------------------------------------------------------------
# Decompression bombs — same module
# ---------------------------------------------------------------------------


@pytest.mark.timeout(30)
def test_decompression_bomb_is_capped():
    """1 GB of nulls from a ~1 MB blob must raise, not allocate.

    ``zlib.decompress()`` with no ``max_length`` inflated attacker-controlled
    data unbounded, in-process, with no memory limit.
    """
    from pkintel.analyzer.deobfuscate import _DECODERS

    compressor = zlib.compressobj(9, zlib.DEFLATED, -zlib.MAX_WBITS)
    bomb = compressor.compress(b"\x00" * (1024 * 1024 * 1024)) + compressor.flush()
    assert len(bomb) < 5 * 1024 * 1024, "test bomb should be small"

    with pytest.raises(Exception, match="cap exceeded"):
        _DECODERS["gzinflate"](bomb)


def test_decompression_cap_allows_legitimate_payloads():
    """The cap must not break real kits — only pathological ones."""
    from pkintel.analyzer.deobfuscate import _DECODERS

    source = b"<?php echo 'legitimate kit source'; " * 100
    compressor = zlib.compressobj(9, zlib.DEFLATED, -zlib.MAX_WBITS)
    blob = compressor.compress(source) + compressor.flush()
    assert _DECODERS["gzinflate"](blob) == source
    assert len(source) < _MAX_DECODED


def test_deobfuscate_still_decodes_real_chains():
    """The ReDoS hardening must not cost us decoding ability.

    A pattern that is safe but no longer matches ``eval(gzinflate(base64_decode(
    '...')))`` would silently gut indicator extraction, which is a worse outcome
    than the hang it was fixing.
    """
    plain = "<?php $bot = '123'; ?>"
    compressor = zlib.compressobj(9, zlib.DEFLATED, -zlib.MAX_WBITS)
    blob = compressor.compress(plain.encode()) + compressor.flush()
    encoded = base64.b64encode(blob).decode()

    nested = f"eval(gzinflate(base64_decode('{encoded}')));"
    assert plain in deobfuscate(nested, max_rounds=5)

    simple = f"eval(base64_decode('{base64.b64encode(b'hello').decode()}'));"
    assert "hello" in deobfuscate(simple, max_rounds=2)


# ---------------------------------------------------------------------------
# SQL that references columns which do not exist
# ---------------------------------------------------------------------------


def test_ioc_query_columns_exist_in_schema():
    """The public IOC feed must only reference real columns.

    A revision added ``ORDER BY i.created_at`` to this query. ``indicators`` has
    no ``created_at`` column, so every request to ``/api/ioc`` — the published
    threat-intel feed, the platform's primary output — returned 500.

    ``tests/test_schema_consistency.py`` validates this generically, but it
    skipped for months because sqlglot was undeclared. This is the specific,
    dependency-free backstop.
    """
    import re

    from pkintel.api.routes.ioc import _IOC_SQL

    migrations = __import__("pathlib").Path(__file__).resolve().parents[1] / "db" / "migrations"
    schema_sql = "\n".join(p.read_text() for p in sorted(migrations.glob("*.sql")))

    match = re.search(r"CREATE TABLE indicators \((.*?)\n\);", schema_sql, re.S)
    assert match, "could not locate the indicators table in the migrations"
    columns = set(re.findall(r"^\s{4}(\w+)", match.group(1), re.M))
    columns |= set(
        re.findall(r"ALTER TABLE indicators ADD COLUMN (?:IF NOT EXISTS )?(\w+)", schema_sql)
    )

    referenced = set(re.findall(r"\bi\.(\w+)", _IOC_SQL))
    missing = referenced - columns
    assert not missing, f"IOC query references non-existent indicators column(s): {sorted(missing)}"


def test_ioc_query_is_a_single_static_string():
    """The query must stay one constant, parseable statement.

    A revision built it by concatenating fragments around a CTE. That produced
    source-level literals which are not valid SQL, and
    ``test_schema_consistency`` skips any literal containing ``{}`` — so
    fragment-building makes the query invisible to the check that would catch
    the bug above. Keeping it static is what keeps it covered.
    """
    from pkintel.api.routes.ioc import _IOC_SQL

    assert "{" not in _IOC_SQL and "}" not in _IOC_SQL, (
        "IOC SQL contains format placeholders, so test_schema_consistency will skip it"
    )
    assert _IOC_SQL.count("SELECT") == 1, "query should be one statement, not assembled fragments"


# ---------------------------------------------------------------------------
# Reaper — per-stage poison counters
# ---------------------------------------------------------------------------


def test_reaper_uses_per_stage_counters_for_urls():
    """``urls`` runs two state machines; they must not share a poison counter.

    With a single ``reap_count``, two triage reaps plus one kithunt reap tripped
    ``reaper_max_reaps`` and parked a healthy row in 'error' — one flaky stage
    poisoning rows on behalf of a stage that was fine.
    """
    from pkintel.db import _REAPABLE

    counters = {(table, col): count_col for table, col, _, _, _, count_col in _REAPABLE}
    assert counters[("urls", "triage_state")] == "reap_count_triage"
    assert counters[("urls", "kithunt_state")] == "reap_count_kithunt"
    assert counters[("urls", "triage_state")] != counters[("urls", "kithunt_state")]


def test_reaper_counter_columns_exist_in_schema():
    """Every counter column the reaper writes must exist in the migrations."""
    import pathlib
    import re

    from pkintel.db import _REAPABLE

    migrations = pathlib.Path(__file__).resolve().parents[1] / "db" / "migrations"
    schema_sql = "\n".join(p.read_text() for p in sorted(migrations.glob("*.sql")))

    for table, _col, _busy, _ready, _lease, count_col in _REAPABLE:
        pattern = rf"ALTER TABLE {table} ADD COLUMN IF NOT EXISTS {count_col}\b"
        created_inline = re.search(
            rf"CREATE TABLE {table} \(.*?\b{count_col}\b.*?\n\);", schema_sql, re.S
        )
        assert re.search(pattern, schema_sql) or created_inline, (
            f"reaper writes {table}.{count_col}, which no migration creates"
        )


# ---------------------------------------------------------------------------
# Chromium renderer sandbox
# ---------------------------------------------------------------------------


def test_chromium_sandbox_is_not_disabled():
    """``--no-sandbox`` must never be passed to the render pool.

    This pool navigates to live attacker infrastructure and executes its
    JavaScript. The renderer sandbox is what keeps a V8/Blink memory-safety bug
    from becoming code execution as the user holding the DB credentials, the
    SMTP password and the indicator encryption key.

    If Chromium will not start, enable unprivileged user namespaces on the host
    (``kernel.unprivileged_userns_clone=1``). Do not re-add the flag.
    """
    from pkintel.triage.render import _get_launch_kwargs

    args = _get_launch_kwargs()["args"]
    assert "--no-sandbox" not in args, (
        "--no-sandbox re-added: attacker JavaScript would run without renderer isolation"
    )
    assert "--disable-setuid-sandbox" not in args


def test_chromium_env_extends_rather_than_replaces():
    """Playwright's ``env`` REPLACES the environment; it must be extended.

    Passing a bare dict launched Chromium with no PATH, no HOME and no XDG_*.
    """
    import os

    from pkintel.triage.render import _get_launch_kwargs

    env = _get_launch_kwargs()["env"]
    assert env.get("CHROME_CRASHPAD_PIPE_NAME") == ""
    if "PATH" in os.environ:
        assert env.get("PATH") == os.environ["PATH"], "host environment was replaced, not extended"


# ---------------------------------------------------------------------------
# Analyzer sandbox
# ---------------------------------------------------------------------------


def test_analyzer_sandbox_argv_is_hardened():
    """The container invocation must carry every isolation flag we claim.

    For a long time the README, the config and docker-compose all described a
    ``--network none`` non-root read-only container, while the code extracted
    and deobfuscated kits in-process on the host. These assertions are the link
    between the documentation and reality.
    """
    from pkintel.analyzer.runner import _sandbox_argv

    argv = _sandbox_argv("/usr/bin/podman", "/tmp/kit.zip")
    joined = " ".join(argv)

    assert "--network none" in joined, "sandbox must have no network access"
    assert "--read-only" in joined, "sandbox root filesystem must be immutable"
    assert "--cap-drop ALL" in joined
    assert "no-new-privileges" in joined
    assert "--memory" in argv
    assert "--pids-limit" in argv
    assert "/tmp/kit.zip:/in/archive.zip:ro" in joined, "kit must be mounted read-only"
    assert "noexec" in joined, "the writable tmpfs must be noexec"


def test_analyzer_reports_missing_runtime_clearly():
    """A missing container runtime must be a loud, actionable error.

    Never a silent fallback to host-side analysis — that is the failure mode
    this whole change set exists to remove.
    """
    import pkintel.analyzer.runner as runner_mod
    from pkintel.analyzer.runner import SandboxUnavailableError, _runtime_binary

    original = runner_mod.shutil.which
    runner_mod.shutil.which = lambda _name: None
    try:
        with pytest.raises(SandboxUnavailableError, match="no container runtime"):
            _runtime_binary()
    finally:
        runner_mod.shutil.which = original
