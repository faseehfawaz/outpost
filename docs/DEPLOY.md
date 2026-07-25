# Deploying Outpost on the Arch box

Target: Arch Linux (i3), Intel 6C/12T, 32 GB RAM, 512 GB **SATA** SSD, always on.

Everything below is copy-paste. Run as your normal user unless a step says `sudo`.

> **Read this first.** Every SQL query is verified against the schema by an automated test, and 282 tests pass. But this code has **never run against a live database or the real internet**. Steps 1–4 deploy to a throwaway database first for exactly that reason. Do not skip to step 5.

---

## Step 0 — Unblock git (on your Mac)

```bash
rm -f "/Users/fazee/Documents/PROJECT ONE/.git/index.lock"
```

Then get the code onto the Arch box however you normally do (push and pull, or `rsync`).

---

## Step 1 — System packages

```bash
sudo pacman -Syu --needed \
    postgresql python python-pip git base-devel \
    chromium bind
```

`chromium` is the system browser (avoids Playwright's 400 MB download). `bind` provides DNS tools for troubleshooting.

---

## Step 2 — Python environment

```bash
cd /opt/heapleap
python -m venv venv
./venv/bin/pip install --upgrade pip setuptools wheel

# Skip Playwright's bundled Chromium — we use the pacman one
PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=1 ./venv/bin/pip install -e ".[dev,render]"
```

Verify:

```bash
./venv/bin/pkintel --help
./venv/bin/python -m pytest        # expect 282 passed
```

---

## Step 3 — Configuration

Generate the encryption key first. **Without it, attacker indicator values are not retained at all** (fail-closed by design — it never falls back to plaintext):

```bash
./venv/bin/python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

Create `/opt/heapleap/.env`:

```ini
PKINTEL_ENV=prod
PKINTEL_LOG_JSON=true

PKINTEL_DB_URL=postgresql://outpost:outpost@localhost:5432/outpost
PKINTEL_DB_POOL_MAX=20

# paste the key you just generated
PKINTEL_INDICATOR_ENC_KEY=

# concurrency (12 threads / 32 GB)
PKINTEL_TRIAGE_WORKERS=64
PKINTEL_ENRICH_WORKERS=32
PKINTEL_RENDER_BROWSERS=6

# use the pacman chromium, cache in RAM (SATA SSD)
PKINTEL_RENDER_EXECUTABLE=/usr/bin/chromium
PKINTEL_RENDER_TMPFS_DIR=/dev/shm/outpost-render
PKINTEL_RENDER_SCREENSHOT_DIR=/opt/heapleap/.storage/screenshots
PKINTEL_LOCAL_STORAGE_DIR=/opt/heapleap/.storage/kits

# KEEP THIS TRUE until you have watched a full cycle
PKINTEL_TAKEDOWN_DRY_RUN=true
PKINTEL_TAKEDOWN_FROM_EMAIL=security@heapleap.tech
PKINTEL_SMTP_HOST=smtp.gmail.com
PKINTEL_SMTP_PORT=587
PKINTEL_SMTP_USER=security@heapleap.tech
PKINTEL_SMTP_PASS=

PKINTEL_API_CORS_ORIGINS=["https://outpost.heapleap.tech","http://localhost:8000"]
```

```bash
chmod 600 /opt/heapleap/.env
```

---

## Step 4 — Test the migrations on a throwaway database

**This is the step that catches problems safely.**

```bash
sudo -u postgres initdb -D /var/lib/postgres/data --locale=C.UTF-8   # first time only
sudo systemctl enable --now postgresql

sudo -u postgres psql -c "CREATE USER outpost WITH PASSWORD 'outpost';"
sudo -u postgres createdb -O outpost outpost
sudo -u postgres createdb -O outpost outpost_test

# migrate the SCRATCH database first
PKINTEL_DB_URL=postgresql://outpost:outpost@localhost/outpost_test \
  ./venv/bin/pkintel db migrate
```

Expected: `Applied: 001_init.sql, 002_takedowns_lock.sql, 003_priority_reaper_pivot.sql, 004_host_enrichment.sql`

Re-run it — 003 and 004 are idempotent, so a second run must say `Already up to date.`

Now check every stage starts and exits cleanly against the empty scratch DB:

```bash
for s in ingest triage kithunt analyze cluster enrich pivot takedown verify; do
  echo "--- $s ---"
  PKINTEL_DB_URL=postgresql://outpost:outpost@localhost/outpost_test \
    ./venv/bin/pkintel run $s --once
done
```

Every stage should print a count and exit 0. **If anything errors here, stop and send me the output** — that is the bug this step exists to find.

---

## Step 5 — Set up the real database

```bash
./venv/bin/pkintel db migrate
./venv/bin/pkintel db seed
./venv/bin/pkintel db ping        # -> ok
./venv/bin/pkintel db queues      # all zeros
```

Importing your old Neon dump, if you want the history:

```bash
PGPASSWORD=outpost psql -h localhost -U outpost -d outpost -f deploy/outpost_dump.sql
./venv/bin/pkintel db migrate     # re-apply 003/004 on top of the imported data
```

---

## Step 6 — Tune Postgres for this box

```bash
sudo mkdir -p /var/lib/postgres/data/conf.d
sudo cp deploy/postgresql.tuned.conf /var/lib/postgres/data/conf.d/outpost.conf

# make sure the include is present exactly once
grep -q "include_dir = 'conf.d'" /var/lib/postgres/data/postgresql.conf || \
  echo "include_dir = 'conf.d'" | sudo tee -a /var/lib/postgres/data/postgresql.conf

sudo systemctl restart postgresql
```

Confirm it took:

```bash
psql -U outpost -d outpost -c "SHOW shared_buffers; SHOW random_page_cost;"
```

Expect `8GB` and `1.5`. If you see `128MB`, the include did not apply.

---

## Step 7 — Capture brand references (automatic)

This switches on two scoring signals that are otherwise silently off — `favicon_known` (+20) and `screenshot_brand_match` (+40). It fetches each brand's real login page once.

```bash
./venv/bin/pkintel refs capture
./venv/bin/pkintel refs list
```

If Chromium is not working yet, get the favicons now and screenshots later:

```bash
./venv/bin/pkintel refs capture --no-render
```

---

## Step 8 — Install the services

**First disable the old units.** `outpost-pipeline.service` runs
`pkintel run all --loop`, which executes *every* stage sequentially. If it stays
enabled alongside the new per-stage units you get two workers on the same
queues — not corruption (the `SKIP LOCKED` claim protects you), but duplicated
network requests against victim servers, which is an ethics problem as well as
a waste. `outpost-ct.service` is superseded by `outpost-certstream.service`.

```bash
sudo systemctl disable --now outpost-pipeline.service outpost-ct.service 2>/dev/null || true
sudo systemctl status outpost-pipeline outpost-ct    # both should be inactive/disabled
```

```bash
sudo cp deploy/outpost@.service deploy/outpost.target \
        deploy/outpost-certstream.service deploy/outpost-api.service \
        /etc/systemd/system/
sudo systemctl daemon-reload

# start ONE stage first and watch it
sudo systemctl enable --now outpost@triage
journalctl -fu outpost-triage
```

Look for `triage_run_complete` with a sane `urls_per_min`. When it looks right:

```bash
sudo systemctl enable --now outpost.target
systemctl status 'outpost@*' outpost-api outpost-certstream
```

---

## Step 9 — Watch it for a day

```bash
./venv/bin/pkintel db queues      # queues should DRAIN, not grow
curl -s localhost:8000/health | python -m json.tool
curl -s localhost:8000/metrics | grep outpost_
journalctl -fu outpost-triage
```

What to look for:

| Signal | Healthy | Bad |
|---|---|---|
| `triage_new` depth | falls over time | climbs steadily |
| `enrich_pending` | drains | stuck at same number |
| `deep_rescued` | occasionally > 0 | always 0 → check Chromium |
| `outpost_rows_reaped_total` | ~0 | climbing → workers dying |
| `outpost_queue_depth_stale_seconds` | < 15 | climbing → DB unreachable |

---

## Step 10 — Go live with takedowns

Only after a full clean day. First send to yourself:

```ini
PKINTEL_TAKEDOWN_DRY_RUN=false
PKINTEL_TAKEDOWN_OVERRIDE_RECIPIENT=your-own@email.com
```

```bash
sudo systemctl restart outpost@takedown
```

Read the actual emails. Check the defanging, the case IDs, the evidence. When you are happy, clear the override:

```ini
PKINTEL_TAKEDOWN_OVERRIDE_RECIPIENT=
```

After a couple of days the verifier will have real outcome numbers:

```bash
psql -U outpost -d outpost -c "
SELECT count(*) FILTER (WHERE status IN ('sent','resolved'))  AS sent,
       count(*) FILTER (WHERE target_dead_at IS NOT NULL)     AS confirmed_dead,
       round(percentile_cont(0.5) WITHIN GROUP (
         ORDER BY EXTRACT(EPOCH FROM (target_dead_at - sent_at))/3600
       )::numeric, 1) AS median_hours_to_death
FROM takedowns;"
```

---

## Rollback

```bash
sudo systemctl stop outpost.target
git checkout <previous-commit>
sudo systemctl start outpost.target
```

Migrations 003 and 004 only **add** columns, tables and indexes. Nothing is dropped or rewritten, so old code runs fine against the new schema — rollback needs no database change.

---

## Troubleshooting

**Stage exits immediately, count 0** — normal when the queue is empty. Check `pkintel db queues`.

**`deep_rescued` always 0**
```bash
/usr/bin/chromium --headless --dump-dom https://example.com | head
ls -la /dev/shm/outpost-render
```
If Chromium fails, set `PKINTEL_RENDER_ENABLED=false`. The pipeline degrades to static triage; nothing else breaks.

**Rows stuck in `triaging`**
```bash
./venv/bin/pkintel db reap
```
The reaper service does this every 5 minutes.

**`indicator_encryption: false` on /health** — `PKINTEL_INDICATOR_ENC_KEY` is unset or malformed. Clustering still works (it uses hashes), but full indicator values are not retained.

**Certstream reconnect loop** — the public aggregator is often flaky; it backs off automatically. Only worry if it never connects.

**Everything is slow** — confirm the Postgres tuning applied (Step 6) and that you are not still pointing at Neon over the network.
