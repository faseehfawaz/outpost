# Outpost — Performance & Capability Upgrade

Target node: Arch Linux (i3), Intel 6C/12T unlocked, 32 GB RAM, **512 GB SATA SSD**, 24/7.

---

## 1. Bugs fixed (Tier 0)

These were found by reading the source, not by running it. Several meant advertised features had **never worked once**.

| # | File | Defect | Consequence |
|---|------|--------|-------------|
| 1 | `kithunter/runner.py` | `record_audit("kithunt_complete", audit_meta)` passed a **dict as the `action` TEXT arg**. psycopg raised `can't adapt type 'dict'`, swallowed by `record_audit`'s own `try/except`. | **Every kit-hunt audit row silently lost.** Two call sites. |
| 2 | `takedown/runner.py` | `SELECT value FROM indicators WHERE type='telegram'`. There is no `value` column (`value_hash`/`redacted_display`/`full_value_encrypted`), and the enum is `telegram_token`/`telegram_chat`. | **Telegram takedowns never fired once.** |
| 3 | `analyzer/indicators.py` | Passed `full_value_encrypted=b""` — not a field on the `Indicator` model. Pydantic dropped it; `full_value` stayed `None`. | `indicators.full_value_encrypted` **always empty**. Abuse-desk evidence path dead. |
| 4 | `analyzer/runner.py` | Wrote `ind.full_value.encode("utf-8")` into a column named `_encrypted`. | Would have been **plaintext attacker tokens at rest**, contradicting `SCOPE_AND_ETHICS.md`. Now Fernet, fail-closed. |
| 5 | `db.py` | No stuck-row reaper. `claim_rows` set a busy state + `locked_at`; nothing released it. | Worker crash → rows pinned **forever**. Silent queue leak; dashboards stayed green. |
| 6 | `db.py` | `ORDER BY id` — strict FIFO. | A certstream hit minutes old queued behind thousands of stale URLs. **Freshest intel triaged last.** |
| 7 | `api/app.py` | `allow_origins=["*"]` + `allow_credentials=True` (invalid per Fetch spec, browsers reject it). No auth, no rate limit. | Internet-facing API; one client could saturate the DB pool the workers depend on. |
| 8 | `.gitignore` | Blanket `*.sql` also ignored `db/migrations/*.sql`. 001/002 predate the rule so stayed tracked. | **Every new migration invisible to git.** A fresh clone or redeploy would run an out-of-date schema with no warning. |
| 9 | `triage/score.py` | Docstring said threshold 50; config says 35. | Doc drift. |

---

## 2. Throughput (Tier 1)

**Before:** `pkintel run all --loop` ran six stages *sequentially in one process*, and triage fetched URLs *one at a time*. With a 3s per-host throttle plus a favicon round-trip, 50 URLs took 5–10 minutes. ~1 of 12 CPU threads busy. **~400–600 URLs/hour.**

**After:**

- `pkintel/pool.py` — bounded thread pool, exceptions returned not raised (per-row isolation preserved), `max_inflight` caps memory on huge batches.
- `triage/runner.py` — batch fanned across `triage_workers` (default **64**). Writes collapsed from 2N round-trips to 2 batched statements.
- Batch limits raised: triage 50→500, kithunt 10→60, analyze 5→30, takedown 20→100.
- `deploy/outpost@.service` — templated per-stage units, so stages run **concurrently** instead of blocking each other.

> **Ethics unchanged.** `_HostThrottle` is process-wide, thread-safe, and reserves its slot before sleeping. Concurrency happens across *different* hosts only. Any single victim server sees exactly the same request pattern as before. No cap in `SCOPE_AND_ETHICS.md` was relaxed.

---

## 3. Postgres (Tier 2) — `deploy/postgresql.tuned.conf`

Stock Postgres ships `shared_buffers=128MB` — it assumes a box ~1/50th this size.

**SATA-specific** (do *not* copy NVMe values):

- `random_page_cost = 1.5` — not 1.1. SATA's ~550 MB/s / ~90k IOPS ceiling means random access isn't free the way it is on NVMe; 1.1 over-encourages index scans the disk can't feed.
- `effective_io_concurrency = 32` — matches AHCI's 32-deep queue. An NVMe-style 200+ causes queue thrash.
- `max_wal_size = 8GB` + `checkpoint_completion_target = 0.9` — converts bursty ingest writes into a smooth trickle. Checkpoint storms are what SATA handles worst.

`synchronous_commit` stays **on** — this DB *is* the work queue and audit log; losing 0.5s of commits on a power cut means silently losing claimed work.

Also: `shared_buffers=8GB`, `effective_cache_size=20GB`, 12 parallel workers, aggressive autovacuum (`scale_factor=0.02` — `urls` is a queue table where every row is UPDATEd 2–3 times), `pg_stat_statements`, `jit=off`.

---

## 4. Detection depth (Tier 3)

### `triage/render.py` — headless Chromium pool
Closes the biggest recall gap. Static `httpx` triage scores **0** on JS-rendered SPA kits, image-only clones with no brand text, and runtime-assembled exfil URLs. Rendering yields post-JS DOM, screenshot pHash, and **observed network requests** — revealing the exfil endpoint from behaviour, not inference.

Read-only: never types, clicks, or submits. Never sends credentials, real or synthetic. Dialogs auto-dismissed, downloads disabled, `throttle_host()` honours the same rate limit.

**SATA:** Chromium caches go to `/dev/shm` (tmpfs). Eight browsers on a SATA SSD would queue behind each other's writes and age the drive for nothing. Costs ~2–4 GB RAM.

### `triage/deep.py` — rendered-signal scoring
Rendered signals weighted above static equivalents (harder to fake, harder to trip accidentally): observed off-origin credential POST **50**, known exfil channel **45**, screenshot matches real brand login **40**, cloaking **35**, password field appearing only after JS **30**.

### `ingest/certstream.py` + `ingest/typosquat.py` — CT firehose
Replaces crt.sh polling (slow, rate-limited, frequent 502s that look like "no new domains"). Live stream surfaces a lookalike domain **seconds after cert issuance — typically before the phishing page is served to anyone.**

Matcher handles homoglyphs (Cyrillic/Greek/fullwidth), digraphs (`rn`→`m`), bounded edit distance (banded Ukkonen), and combosquats. Short-brand guard: `du` is 2 chars and appears in `schedule`, `education`, `duckduckgo` — requires token-boundary hit **plus** a lure token. Benchmarked at 5000 hosts/sec on one thread.

### `ingest/priority.py`
0–100 priority stamped at ingest. Fresh CT hit on a UAE brand outranks a stale bulk-feed URL by ≥40 points. FIFO still applies within a band, so nothing starves.

---

## 5. Verification

**194 tests pass, zero failures** — all pre-existing tests plus 90+ new ones.

Two bugs were caught by the new tests during development:
- `schedule-app.io` false-positived on brand `du` → led to the token-boundary guard.
- A deep-score test asserted 60 when the correct answer was 90 (two independent signals legitimately stacking) → test was wrong, code was right.

```bash
pytest                          # all
pytest tests/test_typosquat.py  # includes firehose throughput budget
pytest tests/test_pool.py       # includes real concurrency proof
```

---

## 6. Deploying

```bash
# 0. clear the stale git lock (sandbox couldn't remove it)
rm -f "/Users/fazee/Documents/PROJECT ONE/.git/index.lock"

# 1. schema
pkintel db migrate                 # applies 003_priority_reaper_pivot.sql

# 2. indicator encryption key (REQUIRED or evidence is not retained — fail-closed)
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
# -> PKINTEL_INDICATOR_ENC_KEY=... in /opt/heapleap/.env

# 3. postgres
cp deploy/postgresql.tuned.conf /var/lib/postgres/data/conf.d/outpost.conf
# ensure postgresql.conf ends with: include_dir = 'conf.d'
systemctl restart postgresql

# 4. browser (Arch: use the system chromium, skip the 400 MB bundled download)
pacman -S chromium
PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=1 pip install -e ".[render]"
# -> PKINTEL_RENDER_EXECUTABLE=/usr/bin/chromium

# 5. services
cp deploy/outpost@.service deploy/outpost.target \
   deploy/outpost-certstream.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now outpost.target

# 6. watch
pkintel db queues
journalctl -fu outpost-triage
curl localhost:8000/health | jq
```

Per-stage tuning without touching other stages: `/opt/heapleap/.env.triage` → `PKINTEL_TRIAGE_WORKERS=96`.

---

## 7. Cloaking detection — `triage/cloak.py`

Serious kits ship an anti-bot layer whose job is to serve **different content to different visitors**: the credential page to a plausible victim (right country, mobile browser, SMS referrer), a 404 or a redirect to the real bank for everything else. Outpost fetches with an honest research UA from a fixed IP — to any such kit we are the most obvious scanner on the internet. Static triage sees the decoy, scores 0, and files a live harvester as uninteresting. **The better the kit, the more certainly we missed it.**

We can't and won't fake being a victim — no residential proxies, no impersonating a real person. Instead we fetch the same URL under 2–3 honest personas (mobile AE / desktop / research, each still carrying the contactable research marker) and compare.

**The disagreement is itself the signal.** Legitimate sites serve substantially the same *content* to mobile and desktop — responsive CSS changes layout, not text. A cloaking kit serves materially different content. So a high inter-persona distance is strong evidence of an anti-bot layer, and therefore of a kit, **without ever seeing the page the victim sees.** The mechanism that hides the kit from us is what exposes it.

Comparison is Jaccard distance over word-shingles of *visible text*, with CSRF tokens/nonces/timestamps stripped — otherwise every page with a rotating token would look like cloaking. Score is the **max** pairwise distance, not the mean: kits typically cloak against exactly one persona, and averaging would dilute that to invisibility. Status-code splits (one persona gets 403) and cross-host redirects are scored separately and harder.

---

## 8. Infrastructure pivot — `fingerprint/pivot.py`

**This was the highest-value remaining item.** Kit-based clustering needs a collected `.zip`, which is rare. With 4,000+ URLs, 12 confirmed phish and a handful of kits, the actor graph was effectively empty — a sophisticated subsystem sitting inert.

Attackers reuse *infrastructure* far more than code. One operator typically parks dozens of lookalikes on one IP, registers them through one registrar in a burst, gets certs from one issuer (often sibling domains as SANs on the *same cert*), serves one favicon, and exfiltrates to one Telegram bot. **All observable from a URL alone.**

Weighted evidence, because not all sharing is equal:

| Reason | Weight | Rationale |
|---|---|---|
| `shared_cert` | 1.0 | Same certificate covers both names — near-conclusive |
| `shared_exfil` | 1.0 | Same Telegram bot / webhook — no innocent explanation |
| `shared_ip` | 0.7 | Same host, subject to fan-out cap |
| `shared_favicon` | 0.5 | Same non-generic icon |
| `shared_registrar` | 0.2 | Weak alone; meaningful as corroboration |
| `shared_asn` | 0.15 | Weakest — an ASN can hold millions of sites |

Weights **accumulate per pair**, so registrar + ASN + favicon = 0.85 clears the 0.7 threshold while registrar + ASN = 0.35 correctly does not.

**The shared-hosting trap:** a naive "same IP ⇒ same actor" rule would merge every Cloudflare-fronted site into one actor. Any group exceeding its fan-out cap is dropped **whole** rather than emitting low-quality edges — we have no evidence of a link, so we assert none. There's a test asserting a 500-host CDN IP produces **zero** edges, not 124,750.

---

## 9. Takedown verification — `takedown/verify.py`

*"40+ notices filed"* is an **activity** metric — it measures how much email we sent, which is entirely within our own control and proves nothing. A notice that lands in a spam folder and one that kills a campaign in 20 minutes are indistinguishable under it.

The verifier re-probes each reported URL on a schedule and records when it actually died:

> 37 of 41 confirmed dead. Median time-to-death 6.2h. 4 still live after 48h, all escalated.

That's a claim about the world, not about our outbox.

**Conservative by design:** a false "dead" closes the case on a live phishing site, which is far worse than an extra probe. So 5xx is explicitly *ambiguous, not dead*, and a 200 with no inspectable body stays "live". Suspension pages are detected by marker text, because many hosts serve a 200 landing page rather than a 404.

**Escalation ladder** — each level is a bigger hammer with a slower response, so we only reach for it when the smaller one demonstrably failed, and each level waits progressively longer:

```
0  hosting abuse desk   →  1  registrar   →  2  registry/ASN   →  3  CERT + blocklists
```

`effectiveness_report()` exposes the outcome metrics for the dashboard.

---

## 10. Verification

**236 tests pass, zero failures, exit code 0.**

Bugs caught by the new tests during development:
- `schedule-app.io` false-positived on brand `du` → produced the token-boundary guard.
- A deep-score assertion expected 60 where 90 was correct (two independent signals legitimately stacking) → the test was wrong, the code was right.

New stages are wired into `PIPELINE_ORDER` (`pivot` after `cluster`, `verify` last) and into `outpost.target`.

---

## 11. Host enrichment — `pkintel/enrich/`

**The gap this closes.** Migration 003 added the pivot columns and `host_edges`, and `pivot.py` reads them — but *nothing populated them*. The only writer of `hosts.*` was the RDAP path in `takedown/rdap.py`, which runs late and only for URLs that actually reached takedown. So the pivot's two strongest signals, `shared_cert` (1.0) and `shared_ip` (0.7), had almost no data. The pivot could not do the job it exists for.

A confirmed-phish host now goes through a proper enrichment queue:

```
adcb-secure-login.com
  -> A     104.21.x.x, 172.67.x.x          (all records — fast-flux is invisible if you keep one)
  -> ASN   AS13335 CLOUDFLARENET (US)      via Team Cymru DNS (no API key)
  -> TLS   sha256:1f3a…, issuer "R3",
           SANs [adcb-verify.com, emiratesnbd-login.net, mashreq-secure.xyz]
  -> NS    ns1.somehost.com, ns2.somehost.com
```

**The SAN list is often the entire campaign in one field.** Operators routinely put every lookalike they own onto a single certificate, so one handshake against one known-bad host hands us the operator's whole portfolio — including domains that appear in **no public feed at all**. Those siblings are fed straight back into `urls` as fresh candidates. This is one of the few places the platform *discovers* infrastructure on its own rather than reacting to somebody else's report.

**Passivity.** DNS never touches the target at all. The TLS step completes a handshake, reads the certificate the server volunteers to every anonymous client, and disconnects **without sending an HTTP request** — strictly less contact than the GET triage already performs. It goes through the same per-host throttle. Cert validation is deliberately off: phishing hosts routinely have expired or mismatched certs, and we want to fingerprint what is *served*, not reject it.

**Staleness.** Attacker infrastructure rotates fast. Enrichment older than `enrich_ttl_days` (7) is re-armed, because linking today's hosts to last month's IPs actively *corrupts* the pivot graph rather than merely leaving it incomplete.

**Ordering is load-bearing** — `enrich` must precede `pivot` in `PIPELINE_ORDER`, or the pivot silently clusters on empty columns. There is a test asserting that ordering.

Migration `004_host_enrichment.sql` adds the state machine (`pending → enriching → enriched | error`), reaper support, and `hosts.ips[]` / `cert_not_before` / `nameservers`.

---

## 12. Still not built

- **Local LLM tie-breaker** — config keys exist (`llm_*`, band 20–45); no client module yet. Intended as an adjudicator for the ambiguous score band only, never for every URL.
- **Multi-channel dispatch** — GSB, PhishTank, APWG, Netcraft. Escalation level 3 currently reuses the host template rather than calling those APIs.
- **pgvector semantic kit similarity** — complements TLSH/Jaccard for kits that are related but not near-identical.
- **Favicon reference set** — `pivot.py`'s `shared_favicon` edge (0.5) and `deep.py`'s screenshot match (40) both depend on reference data that must be gathered by hand: `KNOWN_FAVICON_HASHES` in `triage/favicon.py` is a small hardcoded dict, and `render_screenshot_dir/reference/<Brand>.phash` is empty until you populate it. Both degrade silently and correctly (the signal just never fires) — but capturing the real login pages of your 14 priority brands is cheap and would immediately activate two scoring signals. **This is now the highest-value remaining item, and it is manual data collection rather than code.**
- **Clustering ground truth** — `fingerprint/metrics.py` computes precision/recall against hand-labelled kit pairs, and its own docstring calls maintaining that labelled set a project deliverable. It does not exist yet, so the platform currently cannot state how *accurate* its actor attribution is. Same applies to the new pivot edges.
