# Outpost — Fixes Applied

**Date:** 4 August 2026
**Fixes:** everything open in `OUTPOST_AUDIT_VERIFICATION_2026-08-04.md`
**Excluded by request:** P0-1 (sudo password rotation / credential purge) — untouched
**Result:** 322 passed, **0 skipped**, `ruff check` and `ruff format --check` clean

Two decisions you made shaped this:

1. **Wire up the sandbox** rather than document the in-process reality.
2. **Fix the deploy files in the repo** — I edited them; you review and deploy.

---

## Scoreboard

| | Count |
|---|---|
| Regressions repaired | 2 |
| Partial fixes completed | 4 |
| Claimed-but-absent fixes actually applied | 3 |
| Previously unaddressed findings closed | 7 |
| New regression tests | 16 |

Test suite went from **295 passed / 1 skipped** to **322 passed / 0 skipped**. The skip mattered — see §9.

---

# 1 · `/api/ioc` restored  *(R-1, was returning 500 on every request)*

`src/pkintel/api/routes/ioc.py` — rewritten.

The broken version ordered by `i.created_at`, a column `indicators` does not have, and assembled the statement from fragments around a CTE so the source literals weren't valid SQL.

I did **not** add a `created_at` column. `indicators.id` is a `BIGSERIAL`, so id order *is* insertion order, and `ORDER BY i.id DESC` gives newest-first while also satisfying Postgres's rule that `DISTINCT ON` must lead `ORDER BY`. One less migration, one less column to keep in sync.

```sql
SELECT DISTINCT ON (i.id)
       i.type AS kind, i.redacted_display AS value, k.sha256 AS kit_sha256,
       a.label AS actor_label, u.brand, k.collected_at AS first_seen
FROM indicators i
JOIN kits k ON i.kit_id = k.id
LEFT JOIN urls u ON k.url_id = u.id
LEFT JOIN kit_actor ka ON k.id = ka.kit_id
LEFT JOIN actors a ON ka.actor_id = a.id
WHERE (%s::text IS NULL OR i.type = %s::text)
  AND (%s::timestamptz IS NULL OR k.collected_at >= %s::timestamptz)
ORDER BY i.id DESC
LIMIT %s
```

The filters use a NULL-guard idiom instead of string concatenation. That is not stylistic: `test_schema_consistency.py` **skips any SQL literal containing `{}`**, so building the WHERE clause by concatenation is exactly what made this query invisible to the test that would have caught the bug. Keeping it one static string is what keeps it covered.

`DISTINCT ON (i.id)` also still fixes the original fan-out — a kit in two actor clusters no longer returns each indicator twice and truncates real data at the LIMIT.

---

# 2 · Clustering's strongest signal restored  *(R-2)*

`src/pkintel/fingerprint/cluster.py`

Removed the `WHERE k.analyzed_at >= now() - interval '24 hours'` filter. It filtered the *evidence*, so two kits sharing a Telegram bot only linked if both were analysed inside the same rolling day — and `shared_exfil` is weight 1.0, one of only two signals the design calls conclusive. Campaigns run for weeks.

Replaced with proper scoping in SQL (the pre-existing version selected the entire table and discarded most of it in Python):

```python
cur.execute(
    "SELECT kit_id, type, value_hash FROM indicators WHERE kit_id = ANY(%s)",
    (list(kit_ids),),
)
```

**I did not add incremental clustering.** I started to, then removed it: computing which components are affected requires loading all the signals anyway, so the "incremental" version does the same work plus bookkeeping. Actors are the *connected components* of the similarity graph — one new edge can merge two components sharing no kit — so a whole-graph rebuild is the correct algorithm, not a shortcut.

The real O(n²) risk was always bucket fan-out, and `_MAX_COMMODITY_FILE_BUCKET = 200` (added in your pass) handles it. There's a comment in the code recording the reasoning, and what to do instead if this ever *does* become the bottleneck.

---

# 3 · The ReDoS, properly this time  *(W-1)*

`src/pkintel/analyzer/deobfuscate.py`

Your disjoint-branch fix killed the exponential case — that was correct and it holds. But the quadratic path it opened was **not** where I first said it was, and my first attempt at fixing it didn't work either. Worth being precise:

- I initially blamed newlines and changed `\s` → `[ \t]` plus dropping `DOTALL`. **That made no difference** — measured 10.75 s at 40 K chars, unchanged.
- The actual culprit is the unbounded `\w*` in the function-name group. `search()` retries at every offset; inside a long body each retry ran `\w*` to end-of-string then backtracked one character at a time looking for `(`. O(n) work at O(n) offsets.

```python
(?P<funcs>(?:@?[ \t]*[A-Za-z_]\w{0,63}[ \t]*\([ \t]*){1,8})
```

Bounding it to 64 characters caps each retry at a constant. PHP function names are short; the only cost of being wrong is missing one exotic chain.

**Measured, before and after:**

| payload | your version | now |
|---|---|---|
| 32 backslashes | 0.0000 s | 0.0000 s |
| 20 K char body | 2.68 s | 0.023 s |
| 40 K char body | 10.75 s | 0.048 s |
| 80 K char body | (~43 s) | 0.101 s |
| 160 K char body | — | 0.208 s |
| **growth per doubling** | **×4.00 (quadratic)** | **×2.06 (linear)** |
| 2 MB worst case | ~44 h extrapolated | **2.2 s** |

**The timeout now actually fires.** The `ThreadPoolExecutor` version couldn't: CPython's `re` never releases the GIL, so the calling thread was never scheduled to raise, and `with ThreadPoolExecutor(...)` calls `shutdown(wait=True)` on exit anyway. Replaced with a cooperative deadline checked per match, plus the optional `regex` module (added as a dependency) which has a real `timeout=` parameter. Verified: `timeout_s=2` on a 1.5 MB payload returns in 2.76 s.

`_MAX_FILE_SIZE` lowered 5 MB → 2 MB. A legitimate PHP file is a few hundred KB at the outside.

The docstring records why the `ThreadPoolExecutor` approach cannot work, because the code looked correct and someone will try it again otherwise.

---

# 4 · The analyzer sandbox, actually wired up  *(P0-2)*

`src/pkintel/analyzer/runner.py` — rewritten. `analyzer_container/Dockerfile` — rewritten.

`container_main.py` existed but nothing called it, so kits were still extracted and deobfuscated in-process on the host. Now every kit goes through:

```
--network none            no egress, no callback, no lateral movement
--read-only               root filesystem immutable
--cap-drop ALL            no capabilities
--security-opt no-new-privileges
--memory / --cpus         bounded          (decompression bombs)
--pids-limit 128          bounded          (fork bombs)
--tmpfs /tmp:noexec,nosuid,size=768m       the only writable path
timeout=analyzer_timeout_s                 bounded wall clock (parser hangs)
```

Every one of those flags reads a setting that was previously dead config.

**Podman preferred over Docker.** Rootless podman needs no `docker` group membership, which is root-equivalent on the host. Runtime auto-detects (`podman`, then `docker`), overridable via `PKINTEL_ANALYZER_RUNTIME`.

**The image now carries no credentials.** It installs only `pydantic`, `pydantic-settings`, `structlog`, `python-tlsh`, `mmh3`, `regex` — no `psycopg`, no `boto3`, no `.env`, no `db/`. If it's ever compromised there's nothing to steal and nowhere to send it. Previously it did `COPY src/ /app/src/` with an `ENTRYPOINT` pointing at a module that didn't exist, so it couldn't start at all.

**Failure handling:** a missing runtime fails the whole batch loudly once and leaves rows in `analyzing` for the reaper, rather than marking every kit `error` with an identical message. There is deliberately **no fallback to host-side analysis** — that's the failure mode this change exists to remove.

**stdout is never logged.** It carries unredacted `full_value` indicators so the host can encrypt them; error paths read `stderr` only.

**End-to-end test** with a deliberately hostile archive — 80-backslash ReDoS, 300 KB quadratic payload, 512 MB decompression bomb, plus real indicators:

```
exit=0  wall=0.7s
ok: True | files: 5 | victim_logs: ['result.txt']
   telegram_token   1234***:AAF-***
   slack_webhook    https://hooks.slack.com/services/T00000000/***
   url              https://api.telegram.org/***
```

Before these fixes that archive hung a worker indefinitely.

---

# 5 · `--no-sandbox` removed  *(W-2)*

`src/pkintel/triage/render.py`

Gone. The render pool navigates to live attacker infrastructure and executes its JavaScript; the renderer sandbox is what keeps a V8/Blink bug from becoming code execution as the user holding the DB credentials, the SMTP password and the Fernet key.

The flag is normally added to run Chromium *inside* a container — this pool runs on the host, so it was pure downside.

`setup-elitedesk.sh` now enables the kernel feature Chromium actually needs, so nobody re-adds the flag when it won't start:

```bash
echo 'kernel.unprivileged_userns_clone=1' > /etc/sysctl.d/99-userns.conf
```

Also added `ProtectClock`, `ProtectHostname`, `RestrictAddressFamilies` and `SystemCallArchitectures` to the stage units. A test asserts the flag never comes back.

---

# 6 · Migration back-fill corrected  *(W-4)*

`db/migrations/006_audit_fixes.sql`

`triage_state IN ('new', 'pending')` → `IN ('new', 'triaging', 'error')`. There is no `'pending'` triage state, and `'triaging'` — rows mid-flight, the ones most likely to be racing — was missed.

---

# 7 · The three fixes that were claimed but absent

## 7a · N+1 batching  *(X-1)*

| site | before | after |
|---|---|---|
| `ingest/runner.py` | `cur.execute` per URL — ~30,000 round trips/cycle in one long-held transaction | `executemany(..., returning=True)` + `nextset()`, one round trip |
| `analyzer/runner.py` | `execute()` per kit file, each its own connection *and* transaction | `execute_many`, one batch |
| `enrich/runner.py` | `_favicon_for()` per host — 200 connection checkouts for 200 integers | `_favicons_for()`, one `DISTINCT ON (host)` before the loop |

The `xmax = 0` new-vs-seen accounting is preserved in the ingest path.

## 7b · Reaper counters wired up  *(X-2)*

Migration 006 added `reap_count_triage` / `reap_count_kithunt` but `db.py` still wrote the shared `reap_count` — two dead columns. `_REAPABLE` now carries a per-entry counter column:

```python
("urls", "triage_state",  "triaging", "new",     "reaper_lease_triage_s",  "reap_count_triage"),
("urls", "kithunt_state", "hunting",  "pending", "reaper_lease_kithunt_s", "reap_count_kithunt"),
```

`urls` runs two independent state machines over the same row; sharing one counter meant two triage reaps plus one kithunt reap parked a healthy row in `error`.

## 7c · Docker group membership removed  *(W-3)*

`usermod -aG docker outpost` deleted from `setup-elitedesk.sh`, replaced with active removal on existing boxes plus subuid/subgid allocation for rootless podman:

```bash
if id -nG outpost | grep -qw docker; then gpasswd -d outpost docker; fi
usermod --add-subuids 200000-265535 --add-subgids 200000-265535 outpost
```

`podman` replaces `docker` in the package list.

---

# 8 · Deployment — seven previously unaddressed findings

## 8a · Units that couldn't start  *(P1-7)*

Two independent defects, both silent:

```ini
# [Unit] — was in [Service], where systemd logs "Unknown key name" and
# applies NO rate limiting at all.
StartLimitIntervalSec=300
StartLimitBurst=10

# Leading '-' makes a path optional. Without it a missing directory makes
# systemd fail the mount namespace and the unit REFUSES TO START.
ReadWritePaths=/opt/heapleap/.storage -/opt/heapleap/logs -/opt/heapleap/.cache /dev/shm
```

`/opt/heapleap/logs` was never created by the setup script, so every stage unit failed at boot. `.cache` is now included because `ProtectSystem=strict` makes `/opt/heapleap` read-only and Playwright writes its browser cache there. The setup script creates all of them, and the printed steps now include `systemd-analyze verify`.

## 8b · Overlapping topologies  *(P1-8)*

`outpost-pipeline.service` and `outpost-ct.service` are now stubs with `RefuseManualStart=true` and `Conflicts=outpost.target`, each explaining what replaced it. `outpost@.service` also declares `Conflicts=` against both.

The old setup instructions told you to enable exactly the conflicting set — every stage ran twice, which doubles outbound requests to victim servers. The printed steps now say `systemctl enable --now outpost.target` and explain why not to enable the others.

## 8c · Connection-pool exhaustion  *(P1-9)*

`db_pool_max` 20 → **6**. It's per *process*, and `outpost.target` starts 12 of them: 12 × 20 = 240 potential connections against `max_connections = 100`. 12 × 6 = 72 leaves headroom. The docstring says so, since the name doesn't.

## 8d · Worker metrics now exported  *(P1-10)*

Every worker counter — `stage_duration`, `urls_processed`, `deep_rescued`, `rows_reaped`, `takedown_time_to_death`, `certstream_*` — was written into an in-process registry nothing scraped, then discarded at exit. Only the API mounted `/metrics`, and the API runs none of those stages.

- `_start_metrics_server()` in `cli/main.py`, reading `OUTPOST_METRICS_PORT` (0/unset = off, so one-shot CLI runs don't bind a port)
- `deploy/stage-env/*.conf` drop-ins assign ports 9101–9110, certstream 9111
- `ops/prometheus.yml` scrapes all of them with a `stage` label

The certstream liveness counter also moved from being constructed *inside* a method — which raises `ValueError: Duplicated timeseries` on a second call, caught only by `except ImportError` — into `metrics.py` at import time with the rest.

## 8e · Memory budget  *(P2-30)*

`MemoryMax=8G` × 10 stages was an 80 GB ceiling on a 32 GB box. Template default is now 2 G, with per-stage drop-ins totalling ~21 G:

| stage | MemoryMax | | stage | MemoryMax |
|---|---|---|---|---|
| triage | 8G (Chromium pool) | | pivot | 1G |
| analyze | 4G | | takedown | 1G |
| ingest | 2G | | verify | 1G |
| kithunt | 1G | | reaper | 512M |
| enrich | 1G | | cluster | 1G |

Leaves room for Postgres (8 G `shared_buffers`) and the page cache.

## 8f · Secrets on disk  *(P1-17)*

```bash
chmod 750 /opt/heapleap          # was: chmod -R 755
chmod 700 /opt/heapleap/.storage
chmod 600 /opt/heapleap/.env /opt/heapleap/.env.*
```

`.env` holds the SMTP password, the Fernet key, the R2 secret and the DB DSN — it was readable by every local user and process on the box.

The Postgres password is now **generated** (`openssl rand -base64 24`) instead of the literal `'outpost'`, written to `/opt/heapleap/.pgpassword` mode 0600 with instructions to move it into `PKINTEL_DB_URL` and `shred -u` the file. An existing user's password is left alone.

## 8g · Certstream liveness  *(P2-21)*

The alarm now logs the endpoint and points at self-hosting `certstream-server-go`. A permanently dead public aggregator is otherwise indistinguishable from "no lookalike domains today" — a silent zero on the highest-value feed.

---

# 9 · Why these bugs shipped, and what stops the next one

`tests/test_schema_consistency.py` — the test written specifically to catch a query referencing a non-existent column — opened with `pytest.importorskip("sqlglot")` while `sqlglot` was declared in neither `pyproject.toml` nor `uv.lock`.

**It had never run.** That was the "1 skipped" in the 295/1 result, and the IOC regression is exactly what it exists to catch. A guard that can skip itself is not a guard.

Changed to a hard import, with `sqlglot>=25.0` and `pytest-timeout>=2.3` added to dev dependencies. The suite now reports **322 passed, 0 skipped**.

### `tests/test_regressions.py` — 16 new tests

One file, one readable list of the ways this codebase has actually broken. Each test names the defect, what it cost, and why the assertion is shaped as it is.

- **ReDoS** — exponential payload (N=200), quadratic growth ratio (asserts <2.5× per doubling; quadratic shows 4×), worst case at the file cap, and that `timeout_s` bounds wall clock
- **Decompression** — 1 GB bomb raises; legitimate payloads still decode
- **Decoding not broken** — `eval(gzinflate(base64_decode(...)))` still works. A pattern that's safe but no longer matches would silently gut indicator extraction, which is worse than the hang it fixed
- **SQL** — IOC query columns exist in the migrations *and* the query stays one static string (so the schema test can't skip it)
- **Reaper** — per-stage counters are distinct and every counter column exists
- **Chromium** — `--no-sandbox` absent, `env` extends rather than replaces
- **Sandbox** — every isolation flag present in `_sandbox_argv`; missing runtime raises rather than falling back

The timing assertions are unusual and deliberate: the property under test is *complexity*, and there's no structural way to assert that.

---

# 10 · Smaller items

- **`redact.py`** — new indicator types were falling through to `redact_generic`, which rendered a Slack webhook as `http***ij`: leaked the last two characters of the secret and identified nothing. Added `redact_webhook` (keeps provider + workspace, masks the secret path) and `redact_api_key` (keeps the `SG.` / `re_` vendor prefix). Now: `https://hooks.slack.com/services/T00000000/***`, `SG.***`.
- **`Makefile`** — `analyzer-image` auto-detects podman/docker and fails with a clear message if neither exists.
- **`.env.example`** (both) — documented `PKINTEL_ANALYZER_RUNTIME`, `_PIDS_LIMIT`, `_TMPFS_SIZE`.
- **`README.md`** — the analyzer section, the pipeline diagram and the ethics table now describe the container that exists. The ethics row cites the test that enforces it.
- **`pool.py`** — see the note below.

---

# 11 · Two things I changed my mind about

**Incremental clustering.** I wrote a seed-and-expand pass, then deleted it: computing the affected components requires loading all the signals anyway, so it was the same work plus bookkeeping and a new source of correctness bugs. Whole-graph rebuild is the right algorithm for connected components. The reasoning is in the code so nobody re-derives it.

**PEP 695 generics.** `requires-python` is now `>=3.12`, so ruff's `UP047` wanted `def map_concurrent[T, R](...)`. I made the change, and it immediately stopped me running the test suite on anything older — including the interpreter I was using to verify the rest of this work. The `TypeVar` form is equally correct on 3.12 and costs nothing. Reverted, and `UP047` is now in the ignore list with that reasoning rather than a bare suppression.

---

# 12 · Verification

```
ruff check src tests        →  All checks passed!
ruff format --check         →  111 files already formatted
pytest tests                →  322 passed in 11.26s   (0 skipped)
```

Executed, not just asserted:

| what | result |
|---|---|
| ReDoS exponential (200 backslashes) | 0.0000 s |
| ReDoS quadratic growth | ×2.06 per doubling — linear |
| 2 MB worst-case single line | 2.2 s |
| `deobfuscate(timeout_s=2)` on 1.5 MB | returns in 2.76 s |
| 1 GB decompression bomb | `ValueError` in 0.08 s |
| Nested `eval(gzinflate(base64_decode(...)))` | still decodes correctly |
| Hostile kit end-to-end (ReDoS + quadratic + 512 MB bomb + real indicators) | **0.7 s**, all indicators extracted |
| IOC query vs. migrations | passes both the generic schema test and the specific one |

Three tests fail in my sandbox only — `test_channels.py` (×2) and `test_llm.py`. Cause is a SOCKS proxy in my environment breaking `httpx.Client` *construction* before the mocked `.post` is reached. With proxy vars unset they pass. Nothing to do on your side; noting it so the number is honest.

---

# 13 · Before you deploy

**1. P0-1 is still open.** Untouched, as asked. `root123` is in `.github/workflows/deploy.yml` on a public repo. Change the password, rotate the SMTP password / Fernet key / R2 keys / Postgres password / SSH keys, purge the file from history, enable push protection.

**2. Build the sandbox image, or the analyzer will not run.** This is intentional — it refuses rather than silently falling back to host analysis:

```bash
make analyzer-image     # auto-detects podman/docker
```

**3. Apply migration 006**, then verify the units before restarting:

```bash
pkintel db migrate
systemd-analyze verify /etc/systemd/system/outpost@.service   # must be clean
systemctl disable --now outpost-pipeline.service outpost-ct.service
systemctl enable  --now outpost.target
```

**4. Install the stage drop-ins** — the memory budget and metrics ports live there:

```bash
for f in deploy/stage-env/*.conf; do
  s=$(basename "$f" .conf)
  install -Dm644 "$f" "/etc/systemd/system/outpost@${s}.service.d/override.conf"
done
systemctl daemon-reload
```

**5. Smoke test:**

```bash
curl -s localhost:8000/api/ioc | jq '. | length'   # was 500, should return rows
curl -s localhost:9101/metrics | grep outpost_     # triage worker metrics
```

## Still open — deliberately

- **P0-1** — excluded by request
- **P1-12** — `uv.lock` still missing `cryptography`, `dnspython`, `playwright`, and now `regex`/`sqlglot`. Needs `uv lock` with network access, which I don't have here. Run it and add `uv lock --check` to CI.
- **P2-31** — `storage.py`'s `rglob` fallback. Low risk; wants a `pkintel storage migrate` command rather than an implicit rewrite in a read path.
- **P2-24** — pgvector migration 005 remains dead weight. Wire embeddings up or drop the migration.
- **Chromium `--no-sandbox` removal is untested against your actual box.** If the render pool fails to start after this change, the fix is `sysctl kernel.unprivileged_userns_clone=1` (now in the setup script), not restoring the flag.
