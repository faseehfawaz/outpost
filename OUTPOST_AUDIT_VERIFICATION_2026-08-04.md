# Outpost — Remediation Verification

**Date:** 4 August 2026
**Verifies:** the fix pass against `OUTPOST_AUDIT_2026-08-04.md`
**Excluded by request:** P0-1 (credential rotation)
**Method:** `git diff HEAD` on every claimed file + execution tests of the security-critical paths. Nothing below is inferred from the changelog.

---

## Scoreboard

| | Count |
|---|---|
| ✅ Verified fixed | 14 |
| ⚠️ Partially fixed — residual risk remains | 4 |
| 🔴 New regression introduced | 2 |
| ❌ Claimed fixed, not in the diff | 3 |
| ⬜ Not claimed, still open | 7 |

Good pass overall. The zip-bomb caps, the XSS fix, the kithunter race and the exponential ReDoS are all genuinely dead — I tried to break them and couldn't. Four things need another look, and one is shipping a broken public endpoint.

---

# 🔴 Regressions — introduced by the fix pass

## R-1 · `/api/ioc` is now broken — the public IOC feed will 500

`src/pkintel/api/routes/ioc.py` (P2-25 fix)

The new query selects and orders by `i.created_at`:

```sql
WITH dedup AS (
    SELECT DISTINCT ON (i.id) ..., i.created_at
    FROM indicators i ...
)
SELECT ... FROM dedup ORDER BY created_at DESC LIMIT %s
```

**`indicators` has no `created_at` column.** Verified against every migration:

```
indicators columns: id, kit_id, type, value_hash, redacted_display,
                    full_value_encrypted, confidence, found_in_path, meta
```

`006_audit_fixes.sql` doesn't add it either. Every request to `/api/ioc` — the published threat-intel feed, the thing the whole platform exists to produce — will raise `UndefinedColumn` and return 500.

There's a second, independent problem in the same change. The query is built by string concatenation, and the CTE is opened before the conditional `AND` clauses are appended and closed after. The resulting source-level string literals are not valid SQL, which `test_schema_consistency.py` flags directly:

```
src/pkintel/api/routes/ioc.py:24 ParseError: Expecting ). Line 16, Col: 21.
src/pkintel/api/routes/ioc.py:50 ParseError: Invalid expression / Unexpected token.
```

**Fix — add the column and build the query in one piece:**

```sql
-- migration 007
ALTER TABLE indicators ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ NOT NULL DEFAULT now();
CREATE INDEX IF NOT EXISTS idx_indicators_created_at ON indicators (created_at DESC);
```

```python
where = ["TRUE"]
params: list = []
if type:
    where.append("i.type = %s"); params.append(type)
if since:
    where.append("k.collected_at >= %s"); params.append(since)
params.append(limit)

query = f"""
    SELECT DISTINCT ON (i.id)
           i.type AS kind, i.redacted_display AS value, k.sha256 AS kit_sha256,
           a.label AS actor_label, u.brand, k.collected_at AS first_seen
    FROM indicators i
    JOIN kits k ON i.kit_id = k.id
    LEFT JOIN urls u ON k.url_id = u.id
    LEFT JOIN kit_actor ka ON k.id = ka.kit_id
    LEFT JOIN actors a ON ka.actor_id = a.id
    WHERE {" AND ".join(where)}
    ORDER BY i.id DESC
    LIMIT %s
"""
```

`DISTINCT ON (i.id)` with `ORDER BY i.id DESC` is self-consistent and needs no timestamp at all — which sidesteps the migration if you'd rather not add one.

## R-2 · Clustering lost its strongest signal

`src/pkintel/fingerprint/cluster.py` (P1-20 fix)

```python
cur.execute("""
    SELECT i.kit_id, i.type, i.value_hash FROM indicators i
    JOIN kits k ON k.id = i.kit_id
    WHERE k.analyzed_at >= now() - interval '24 hours'
""")
```

This filters the **evidence**, not the work. `shared_exfil` carries weight 1.0 — it's one of only two signals the design calls conclusive. Under this filter, two kits sharing the same Telegram bot are only ever linked if **both** were analysed within the same rolling 24-hour window. A kit analysed three days ago and one analysed today will never join, no matter how conclusive the overlap.

Since a campaign's whole point is that it runs for weeks, this quietly removes most of the linking power the pivot subsystem was built for.

The audit asked for incremental re-clustering of *touched components* — load recently-analysed kits to decide **which** components to rebuild, then load the **full** indicator set for those components:

```python
recent = {r["id"] for r in cur.execute(
    "SELECT id FROM kits WHERE analyzed_at >= now() - interval '24 hours'").fetchall()}
if not recent:
    return
# expand to every kit already sharing a component with a recent kit
affected = expand_components(recent)
cur.execute("SELECT kit_id, type, value_hash FROM indicators WHERE kit_id = ANY(%s)", (list(affected),))
```

`_emit(by_exfil, cap=...)` is a reasonable addition — keep it. Note `_load_fingerprints` still does a full scan; only the indicator load was changed.

---

# ⚠️ Partially fixed — residual risk

## W-1 · P0-3 ReDoS: exponential blowup killed, quadratic path remains, timeout doesn't work

**The good part is real.** The disjoint-branch rewrite works exactly as intended:

| backslashes | before | after |
|---|---|---|
| 24 | 0.079 s | 0.0000 s |
| 28 | 0.544 s | 0.0000 s |
| 32 | 3.71 s | 0.0000 s |

The original attack is dead. Nested-func and no-quote variants are all sub-millisecond too.

**But a quadratic path opened up.** An unterminated quote with a long *benign* body:

| body length | time |
|---|---|
| 10,000 | 0.64 s |
| 20,000 | 2.56 s |
| 40,000 | 10.28 s (**×4.02** per doubling — clean O(n²)) |

Extrapolating to the 5 MB `_MAX_FILE_SIZE` ceiling: **≈ 44 hours** for a single file that passes the size check.

The cause is `search()` retrying `(?:@?\s*[A-Za-z_]\w*\s*\(\s*){1,8}` at each offset, where `\w*` greedily consumes to end-of-string before backtracking to look for `(`. Anchor the function-name part so it can't restart mid-body:

```python
(?P<funcs>(?:@?[ \t]*[A-Za-z_]\w*[ \t]*\([ \t]*){1,8})
```

Dropping `\s` → `[ \t]` (newlines can't appear inside a PHP call prefix anyway) plus removing `re.DOTALL` cuts the retry surface dramatically. Also lower `_MAX_FILE_SIZE` — 5 MB of PHP is already pathological; 1 MB is generous.

**The timeout that was supposed to catch exactly this does not work.** Verified empirically — a 1.2 MB payload (under the cap, so not skipped) with `timeout_s=3`:

```
payload 1200036 bytes (< 5MB cap, so NOT skipped)
exit=124   # still running after 44s
```

Two independent reasons:

1. **Python's `re` does not release the GIL.** The worker thread holds it for the whole match, so the main thread can't even be scheduled to raise `TimeoutError`.
2. **`with ThreadPoolExecutor(...)` calls `shutdown(wait=True)` on exit.** Even if the timeout did fire, `return source` from inside the `with` block blocks on `__exit__` until the runaway thread finishes.

A timeout that can't fire is worse than no timeout, because it reads like protection. Use a real one:

```python
import regex  # pip install regex — stdlib `re` has no timeout parameter
_CHAIN_RE = regex.compile(..., regex.VERBOSE)
m = _CHAIN_RE.search(text, timeout=5.0)   # raises TimeoutError, actually works
```

Or run deobfuscation in a **process** (`ProcessPoolExecutor` + `future.cancel()` / `pool.terminate()`), which is killable. If you implement the P0-2 container, the container's own `--timeout` solves it for free.

Add the regression test the audit asked for — it's the cheap insurance here:

```python
@pytest.mark.timeout(5)
def test_deobfuscate_redos_payloads():
    assert deobfuscate("eval('" + "\\" * 60 + "X") is not None
    assert deobfuscate("eval('" + "A" * 200_000) is not None
```

## W-2 · P0-4: the actual finding is untouched

The changelog describes P0-4 as "Chromium Environment: Preserved host environment". That's the *secondary* half — and it is correctly fixed (`{**os.environ, "CHROME_CRASHPAD_PIPE_NAME": ""}` ✅).

The finding itself was that Chromium renders live attacker pages with its sandbox off. Still there:

```
src/pkintel/triage/render.py:186:            "--no-sandbox",
```

With `render_enabled=True` and `render_min_score=10`, this process navigates to attacker-controlled infrastructure and executes their JavaScript with no renderer isolation, as the `outpost` user that holds the DB credentials, the SMTP password and the Fernet key. Remove the flag; if Chromium then won't launch on Arch, enable unprivileged user namespaces (`sysctl kernel.unprivileged_userns_clone=1`) rather than putting the flag back.

## W-3 · P0-2: risk reduced, core issue unchanged

| Item | Status |
|---|---|
| Docker socket removed from `docker-compose.yml` | ✅ real improvement |
| `container_main.py` created | ✅ exists, and is well-written |
| `analyzer/runner.py` calls it | ❌ file unchanged — still extracts + deobfuscates **in-process on the host** |
| `usermod -aG docker outpost` removed from `setup-elitedesk.sh` | ❌ still at line 89 (`deploy/` has no diff at all) |
| `analyzer_container/Dockerfile` fixed | ❌ unchanged; still never copies an entrypoint that resolves |
| README/docs claims corrected | ❌ still describes `--network none`, non-root, read-only, 30-second timeout |

`container_main.py`'s own docstring says "(future work)", which is accurate. So the gap between documentation and behaviour — the thing that made this finding severe — is still open, and it's now the reason W-1's missing timeout matters so much.

The docker-group line is the one to pull today; it's a one-line change granting root-equivalence for a feature that doesn't exist:

```bash
sed -i '/usermod -aG docker outpost/d' deploy/setup-elitedesk.sh
gpasswd -d outpost docker   # on the running box
```

## W-4 · Migration 006 back-fill targets a state that doesn't exist

```sql
UPDATE urls SET kithunt_state = 'waiting'
WHERE triage_state IN ('new', 'pending') AND kithunt_state = 'pending';
```

`triage_state` is `new | triaging | triaged | error` — there is no `'pending'`. Rows currently mid-flight in `'triaging'` are missed.

```sql
WHERE triage_state IN ('new', 'triaging', 'error') AND kithunt_state = 'pending'
```

Low impact — the `extra_where` guard on `claim_rows` already closes the hole independently, which is the right belt-and-braces. Worth correcting so the back-fill does what it says.

---

# ❌ Claimed in the changelog, absent from the diff

These three are listed as done. `git diff HEAD` shows the files were never modified.

## X-1 · P1-14 — query batching (all three sites unchanged)

```
$ git diff --stat HEAD -- src/pkintel/ingest/runner.py src/pkintel/analyzer/runner.py
(no output)
```

- `ingest/runner.py:138` — still `cur.execute(_INSERT_SQL, ...)` per URL, ~30,000 round trips per cycle
- `analyzer/runner.py:91` — still `execute(...)` per kit file, one connection + transaction each
- `enrich/runner.py:273` — `_favicon_for(row["hostname"])` still called per host

`enrich/runner.py` received exactly one line, and it was P1-15's seed filter. The `execute_many` helper this needs already exists and is used elsewhere.

## X-2 · P2-32 — `reap_count` split is inert

`006_audit_fixes.sql` adds `reap_count_triage` / `reap_count_kithunt` and seeds them ✅. But `src/pkintel/db.py` is unmodified, so `reap_stuck_rows()` still reads and writes the shared `reap_count`:

```
src/pkintel/db.py:209   WHEN reap_count + 1 >= %(max_reaps)s THEN 'error'
src/pkintel/db.py:212   reap_count = reap_count + 1,
```

Two new columns that nothing reads or writes. Parameterise `_REAPABLE` with a per-entry counter column name and interpolate it into the reaper SQL.

## X-3 · P0-2 — docker group removal

Covered in W-3. `deploy/` has no diff.

---

# ⬜ Not claimed, still open

Not in the changelog, so presumably deliberate — flagging so the list stays honest. **P1-7 is the one that will bite first.**

| # | Finding | Why it matters |
|---|---|---|
| **P1-7** | `outpost@*.service`: `ReadWritePaths=/opt/heapleap/logs` doesn't exist (with `ProtectSystem=strict` the unit **refuses to start**); `StartLimitIntervalSec`/`StartLimitBurst` are in `[Service]`, must be `[Unit]` — crash-loop protection is silently absent | Units fail to start; verify with `systemd-analyze verify` |
| **P1-8** | `outpost-pipeline` + `outpost-ct` + `outpost.target` all run overlapping stages; setup script tells you to enable the conflicting set | Doubles/triples outbound requests to victim servers |
| **P1-9** | 12 processes × `db_pool_max=20` = 240 potential connections vs `max_connections = 100` | Pool timeouts that look like network faults |
| **P1-10** | Worker metrics never exported — no `start_http_server`, `ops/prometheus.yml` scrapes only `api:8000` | *The new certstream liveness counter (P2-21) inherits this — it increments into a registry nobody scrapes* |
| **P1-12** | `uv.lock` still missing `cryptography`, `dnspython`, `playwright` | `uv sync` yields an env where indicator encryption silently no-ops |
| **P1-17** | `chmod -R 755 /opt/heapleap`, `.env` perms unset, Postgres password `outpost` | SMTP password + Fernet key world-readable |
| **P2-30/31** | `MemoryMax=8G` × 10 units on 32 GB; `storage.py` unbounded `rglob` on cache miss | Tuning |

---

# 🧪 The test suite is not covering this

The reported run — **295 passed, 1 skipped** — is accurate, but the skip is load-bearing.

`tests/test_schema_consistency.py` starts with `pytest.importorskip("sqlglot")`, and **`sqlglot` appears in neither `pyproject.toml` nor `uv.lock`**. So it has never run in CI or locally. That is the "1 Skipped".

It is also precisely the test written to catch R-1. Its own docstring says so:

> The single worst bug found in this codebase was `SELECT value FROM indicators ...` — the `indicators` table has no `value` column ... This test catches that entire class of bug with no database at all.

Installing `sqlglot` and running it:

```
FAILED tests/test_schema_consistency.py::test_all_sql_parses_as_postgres
  E  src/pkintel/api/routes/ioc.py:24 ParseError: Expecting ). Line 16, Col: 21.
  E  src/pkintel/api/routes/ioc.py:50 ParseError: Invalid expression / Unexpected token.
```

It catches the regression on the first run.

**Fix:**

```toml
dev = [ ..., "sqlglot>=25.0", "pytest-timeout>=2.3" ]
```

Then change `importorskip` to a hard import so this test can never silently disappear again — a guard that skips itself is not a guard. Add `pytest-timeout` for the ReDoS regression test in W-1.

Also still uncovered: no test exercises `/api/ioc` (which is why R-1 shipped), and none feeds a ReDoS payload to `deobfuscate`.

---

# Suggested next pass

**Today**
1. R-1 — restore `/api/ioc`; add `sqlglot` to dev deps and make the schema test mandatory
2. W-2 — drop `--no-sandbox`
3. W-3 — `sed -i '/usermod -aG docker outpost/d'` + `gpasswd -d outpost docker`
4. P1-7 — fix the systemd units; confirm with `systemd-analyze verify` and `systemctl status outpost@triage`

**This week**
5. W-1 — anchor the `funcs` group, drop `DOTALL`, lower `_MAX_FILE_SIZE`, swap in `regex` with a real timeout, add the regression test
6. R-2 — expand-components instead of filtering evidence by time
7. X-1 / X-2 — the three `execute_many` sites; wire the reaper to the new columns
8. W-4 — correct the back-fill `WHERE`
9. P1-12 — `uv lock` + `uv lock --check` in CI

**Then**
10. Decide P0-2: wire `container_main.py` into `analyzer/runner.py`, or correct README/docs to describe what the code actually does
11. P1-9, P1-10, P1-17

---

## Credit where it's due

Verified working, and I did try to break them:

- **P0-5 zip-bomb caps.** A 1 MB blob inflating to 1 GB raised `ValueError: decompression cap exceeded` in 0.08 s on all three decoders. Clean.
- **P0-3's core fix.** 3.71 s → 0.0000 s on the original payload. The disjoint-branch rewrite is the correct fix, well commented.
- **P1-6.** Migration + `extra_where` guard + lock clearing on all three exit paths. Belt and braces, and the guard alone would have been enough.
- **P1-16.** `escapeHtml` applied at every interpolation in `research.js`, including the ones that looked numeric.
- **P2-23.** Six new exfil channels *and* the O(n²) dedup swapped for a set. The regexes are tight — `SG.`, `re_`, and the Slack `T…/B…` shape are all correctly anchored.
- **P2-28.** Multi-stage Dockerfile drops `build-essential` and `docker.io` from the runtime image.
- **`start.sh`.** Signal trap, `wait -n`, and bring-down-the-sibling — better than what the audit asked for.

The two regressions both come from the same place: a SQL change made without a schema check, in a repo that already contains the schema check but had it silently skipping. Turning that test on is the single highest-value fix in this list.
