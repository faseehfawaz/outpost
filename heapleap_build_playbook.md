# heapleap — Cyber Defense Suite
## Architecture & Build Playbook

**Author:** Faseeh Padinjarathil
**Domain:** heapleap.tech
**Status:** Outpost live; four modules planned + one SOC lab
**Doc version:** v1.0

---

## 0. How to read this document

Each project below has the same five sections:

1. **Thesis** — what it does and why it is differentiated
2. **Architecture** — components, data flow, storage
3. **Build steps** — ordered, concrete, buildable
4. **Scope & ethics guardrails** — the boundaries that keep this legal and professional
5. **Resume + interview payload** — what this becomes on paper

Read section 1 (suite architecture) first. Everything else assumes the shared core exists.

**Build order — do not shuffle this:**

| Order | Project | Why here |
|---|---|---|
| 1 | Shared core refactor | Everything else depends on it |
| 2 | **Herald** (email auth) | Fastest to ship, ties to your resume's DNS/SPF/DKIM work, unlocks the research paper |
| 3 | **Atlas** (STIX/TAXII) | Pure value-add on data you already have |
| 4 | **Sentinel mini-SOC** | Adds the missing SOC vocabulary; consumes Atlas |
| 5 | **Horizon** (EASM) | Bigger build, feeds Outpost |
| 6 | **Mirage** (AI/LLM abuse) | The novel one; needs kit corpus volume first |

---

## 1. Suite Architecture

### 1.1 The core idea that makes this a *suite* and not five separate apps

Five standalone tools on one domain is a portfolio. **One platform with five capabilities sharing an entity graph is a product.** The difference is a canonical entity layer.

Every module reads and writes the same `domain`, `host`, and `org` records. That is the whole architectural trick:

```
                        ┌──────────────────────────┐
                        │   heapleap entity core   │
                        │  domains / hosts / orgs  │
                        └────────────┬─────────────┘
                                     │
        ┌──────────────┬─────────────┼─────────────┬──────────────┐
        │              │             │             │              │
   ┌────▼────┐   ┌─────▼─────┐  ┌────▼────┐   ┌────▼────┐   ┌─────▼─────┐
   │ Outpost │   │  Herald   │  │  Atlas  │   │ Horizon │   │  Mirage   │
   │ phish + │   │ email     │  │ intel   │   │ attack  │   │ AI/LLM    │
   │ takedown│   │ auth      │  │ producer│   │ surface │   │ abuse     │
   └─────────┘   └───────────┘  └─────────┘   └─────────┘   └───────────┘
```

**The narrative this enables** — and this is what you say in an interview:

> Horizon sees a certificate issued for `adcb-verify-secure.com` twelve minutes after it goes live. It resolves, so it hands the URL to Outpost. Outpost triages it at 78, collects the kit, and clusters it to a known actor. Atlas publishes the indicator as STIX inside the same cycle. Herald already knows ADCB's real domain has `p=reject`, so the email vector is closed — meaning this campaign is SMS or ad-driven, which changes the takedown target. Outpost files the abuse notice. My Sentinel workspace ingests the Atlas indicator and alerts if anything in my environment touches it.

One story, five modules, end to end. Nobody at your level has that.

### 1.2 Monorepo layout

Keep one repo. Recruiters and engineers both open exactly one link.

```
heapleap/
├── core/                        # shared library — the important part
│   ├── db/
│   │   ├── pool.py              # psycopg3 pool, single connection factory
│   │   ├── claim.py             # SELECT ... FOR UPDATE SKIP LOCKED helper
│   │   └── migrations/          # numbered .sql files, applied in order
│   ├── entities/
│   │   ├── domain.py            # canonical domain resolution + upsert
│   │   ├── host.py              # IP / ASN / geo
│   │   └── org.py               # brand / organisation
│   ├── net/
│   │   ├── http.py              # shared HTTPX client: UA, timeouts, retry, rate limit
│   │   ├── dns.py               # async resolver w/ cache + multi-resolver
│   │   └── ratelimit.py         # per-host token bucket
│   ├── audit.py                 # append-only audit log — every module writes here
│   ├── scope.py                 # AUTHORIZATION GATE (see §7.2) — enforced, not advisory
│   └── config.py                # pydantic-settings, env-driven
├── modules/
│   ├── outpost/                 # existing — refactor to import core
│   ├── herald/
│   ├── atlas/
│   ├── horizon/
│   └── mirage/
├── api/
│   └── main.py                  # one FastAPI app, mounts each module's router
├── web/
│   ├── shared/                  # nav shell, CSS tokens, chart helpers
│   └── <module>/                # per-module pages
├── labs/
│   └── sentinel-soc/            # the SOC lab lives here (see §6)
├── docs/
│   ├── SCOPE_AND_ETHICS.md
│   ├── ARCHITECTURE.md
│   └── research/
└── .github/workflows/
```

### 1.3 Shared data model

One Postgres database, one schema per module, plus a shared `core` schema.

```sql
CREATE SCHEMA core;

CREATE TABLE core.orgs (
    id            BIGSERIAL PRIMARY KEY,
    name          TEXT NOT NULL,
    sector        TEXT,              -- banking, telecom, government, aviation...
    country       TEXT DEFAULT 'AE',
    created_at    TIMESTAMPTZ DEFAULT now()
);

CREATE TABLE core.domains (
    id            BIGSERIAL PRIMARY KEY,
    domain        TEXT NOT NULL UNIQUE,   -- registrable domain, lowercased, IDNA-normalised
    etld1         TEXT NOT NULL,          -- public-suffix base
    org_id        BIGINT REFERENCES core.orgs(id),
    first_seen    TIMESTAMPTZ DEFAULT now(),
    last_seen     TIMESTAMPTZ DEFAULT now(),
    tags          TEXT[] DEFAULT '{}'     -- 'watchlist','lookalike','confirmed_phish'
);

CREATE TABLE core.hosts (
    id            BIGSERIAL PRIMARY KEY,
    ip            INET NOT NULL,
    asn           INTEGER,
    as_name       TEXT,
    country       TEXT,
    last_seen     TIMESTAMPTZ DEFAULT now(),
    UNIQUE (ip)
);

CREATE TABLE core.audit_log (
    id            BIGSERIAL PRIMARY KEY,
    module        TEXT NOT NULL,
    action        TEXT NOT NULL,
    target        TEXT,
    actor         TEXT DEFAULT 'system',
    metadata      JSONB DEFAULT '{}',
    created_at    TIMESTAMPTZ DEFAULT now()
);
CREATE INDEX ON core.audit_log (module, created_at DESC);
```

**Normalisation rule — enforce it in one place or you will get duplicate rows forever:**
lowercase → strip trailing dot → IDNA/punycode encode → derive eTLD+1 via the Public Suffix List (`tldextract`). Every module calls `core.entities.domain.canonicalise()`. No exceptions.

### 1.4 Shared execution pattern

Reuse the pattern already proven in Outpost. Every module's worker is:

```python
# core/db/claim.py
CLAIM = """
UPDATE {schema}.{table}
   SET state = 'processing', claimed_at = now()
 WHERE id IN (
     SELECT id FROM {schema}.{table}
      WHERE state = %(from_state)s
        AND (next_attempt_at IS NULL OR next_attempt_at <= now())
      ORDER BY priority DESC, id
      LIMIT %(batch)s
      FOR UPDATE SKIP LOCKED
 )
 RETURNING *;
"""
```

Same state machine, same lock semantics, five modules. That consistency is itself an architecture talking point: *"I chose a Postgres-backed work queue over Kafka because single-node throughput was three orders of magnitude below where a broker pays for itself, and `SKIP LOCKED` gives me the same at-least-once guarantee with zero extra infrastructure."*

### 1.5 Shared frontend shell

One nav, one theme, per-module pages:

```
heapleap.tech            → landing: the suite, the thesis, links to research
heapleap.tech/outpost    → existing command centre
heapleap.tech/herald     → domain lookup + UAE posture report
heapleap.tech/atlas      → feed docs, TAXII discovery, stats
heapleap.tech/horizon    → watchlist, exposure timeline
heapleap.tech/mirage     → AI-lure analysis, LLM-abuse stats
heapleap.tech/research   → published papers
```

Keep the terminal aesthetic, but **build a real landing page.** Right now heapleap.tech has no front door. A recruiter who is handed `outpost.heapleap.tech` sees one tool. A recruiter handed `heapleap.tech` should see a security company.

---

## 2. HERALD — Email Authentication Posture Scanner

> **Build this first.** It is the smallest build with the biggest return: it ships in ~2 weeks, it maps directly to the SPF/DKIM/DMARC work already on your resume, and it produces the research paper that gets you inbound attention.

### 2.1 Thesis

Give Herald a domain, and it answers one blunt question: **can an attacker send email that appears to come from this domain and land in a target's inbox?**

Free tools like MXToolbox exist. Herald differentiates on three axes:

1. **Verdict, not just a record dump.** Existing tools show you the SPF string. Herald tells you the SPF string is broken because it exceeds the 10-lookup limit and therefore evaluates to `permerror`, which most receivers treat as *no SPF at all*. That is the finding.
2. **Longitudinal.** Rescan monthly, store history, show posture drift. Nobody publishes trend data for this region.
3. **Regional corpus.** A curated, sector-tagged UAE domain set that becomes the research asset.

### 2.2 Architecture

```
   domain input
   (single / CSV / core.domains watchlist)
        │
        ▼
┌───────────────────┐
│  Resolver layer   │  async DNS, multi-resolver, TTL-aware cache
│  core/net/dns.py  │  (1.1.1.1 + 8.8.8.8 + authoritative)
└─────────┬─────────┘
          │
    ┌─────┴──────┬──────────┬──────────┬───────────┬──────────┐
    ▼            ▼          ▼          ▼           ▼          ▼
┌───────┐  ┌─────────┐ ┌────────┐ ┌─────────┐ ┌────────┐ ┌────────┐
│  SPF  │  │  DKIM   │ │ DMARC  │ │ MTA-STS │ │TLS-RPT │ │ DNSSEC │
│parser │  │selector │ │ parser │ │ +policy │ │        │ │  +BIMI │
│       │  │ probe   │ │        │ │  fetch  │ │        │ │        │
└───┬───┘  └────┬────┘ └───┬────┘ └────┬────┘ └───┬────┘ └───┬────┘
    └───────────┴──────────┴───────────┴──────────┴──────────┘
                            │
                            ▼
                  ┌──────────────────┐
                  │  Scoring engine  │  0–100 + grade + binary verdict
                  └────────┬─────────┘
                           │
              ┌────────────┼─────────────┐
              ▼            ▼             ▼
      herald.scans   herald.findings   remediation
                                        renderer
```

### 2.3 What each parser must actually check

This is where the depth lives. Get these right and the tool is genuinely better than most free scanners.

**SPF (`TXT` at apex)**

| Check | Finding |
|---|---|
| No `v=spf1` record | No SPF. Critical. |
| Two or more `v=spf1` records | `permerror` — SPF is entirely void. Critical, and very common. |
| `+all` | Anyone on the internet is authorised. Critical. |
| `?all` | Neutral — effectively no protection. High. |
| `~all` | Softfail — accepted but marked. Medium. |
| `-all` | Hardfail. Good. |
| DNS lookup count > 10 | RFC 7208 limit exceeded → `permerror` → SPF ignored by receivers. **High, and almost nobody checks this.** |
| Void lookups > 2 | `permerror`. High. |
| `ptr` mechanism present | Deprecated, unreliable. Low. |
| Record length > 255 chars per string | Must be split into multiple strings; malformed splits break it. Medium. |

Implement lookup counting by recursively walking `include:`, `redirect=`, `a`, `mx`, `exists:`, `ptr` and incrementing a counter — this recursion *is* the interesting engineering, and it's what makes the tool non-trivial.

**DKIM** — you cannot enumerate selectors from DNS, so probe a dictionary and report what you find:

```python
COMMON_SELECTORS = [
    "default", "mail", "dkim", "k1", "k2", "s1", "s2",
    "selector1", "selector2",          # Microsoft 365
    "google",                          # Google Workspace
    "zoho", "zmail",
    "mandrill", "mailchimp",
    "sendgrid", "smtpapi",
    "amazonses", "mxvault", "protonmail", "pm-bounces",
    "everlytickey1", "dkim1", "key1", "sig1",
]
```
Check: does `<selector>._domainkey.<domain>` return a `v=DKIM1` record; is `p=` empty (revoked key — a live finding); is the RSA modulus < 2048 bits (weak); is `k=` an unexpected algorithm.

Be honest in the output: *"no common selector found"* ≠ *"no DKIM."* Say that explicitly in the report. Overclaiming is how a research paper gets torn apart.

**DMARC (`TXT` at `_dmarc.<domain>`)** — the decisive one:

| Policy | Real-world meaning |
|---|---|
| absent | Spoofable. Receivers have no instruction. |
| `p=none` | Monitoring only. **Still spoofable.** This is the most common false sense of security. |
| `p=quarantine` | Spoofed mail goes to junk. Partial. |
| `p=reject` | Spoofed mail is refused. Protected. |

Also parse: `pct=` (a `p=reject; pct=10` only enforces on 10% of mail — a finding), `sp=` (subdomain policy; `p=reject` with `sp=none` leaves every subdomain wide open — an excellent, under-reported finding), `adkim=`/`aspf=` (relaxed vs strict alignment), `rua=`/`ruf=` (is anyone even collecting reports?).

**MTA-STS** — TXT at `_mta-sts.<domain>`, then HTTPS fetch of `https://mta-sts.<domain>/.well-known/mta-sts.txt`. Parse `mode: enforce|testing|none`. This is your only outbound HTTP request; everything else is DNS.

**Plus:** TLS-RPT (`_smtp._tls`), BIMI (`default._bimi`), DNSSEC (DS/RRSIG presence).

### 2.4 Scoring model

```python
SCORE_WEIGHTS = {
    "dmarc_reject_full":     40,   # p=reject, pct=100
    "dmarc_quarantine":      25,
    "dmarc_none_with_rua":   10,
    "spf_hardfail":          25,   # -all
    "spf_softfail":          15,   # ~all
    "dkim_strong":           20,   # >=2048-bit key found
    "dkim_weak":             12,   # 1024-bit
    "alignment_strict":       5,   # adkim=s and aspf=s
    "mta_sts_enforce":        5,
    "tls_rpt":                2,
    "dnssec":                 3,
}
PENALTIES = {
    "spf_permerror":        -20,   # >10 lookups or duplicate records
    "spf_plus_all":         -30,
    "dmarc_sp_none":        -10,   # subdomains unprotected
    "dmarc_pct_below_100":  -10,
}
```

**Critical design decision — the score does not override the verdict.** A domain can score 55 and still be trivially spoofable. Emit both:

```json
{
  "domain": "example.ae",
  "score": 55,
  "grade": "C",
  "verdict": "SPOOFABLE",
  "verdict_reason": "DMARC policy is p=none; receivers have no instruction to reject unauthenticated mail claiming this domain.",
  "findings": [ ... ]
}
```

A single-number score hides binary risk. The verdict field is what a CISO reads. Design for the reader.

### 2.5 Build steps

1. **Schema.** `herald.scans` (domain_id, scanned_at, score, grade, verdict, raw JSONB), `herald.findings` (scan_id, code, severity, title, evidence, remediation), `herald.selectors_seen` (cache which selectors worked per domain so rescans are cheap).
2. **DNS layer** in `core/net/dns.py`: `dnspython` + `asyncio`, TTL-respecting cache, query two public resolvers and flag disagreement (that catches split-horizon and propagation issues — a nice differentiator).
3. **SPF parser + recursive lookup counter.** Write unit tests against hand-built fixture records first: valid, `+all`, duplicate, 11-lookup chain, void-lookup overflow. This is the piece most likely to have bugs.
4. **DKIM selector prober** with the dictionary, key-length extraction, and result caching.
5. **DMARC parser** covering every tag, not just `p=`.
6. **MTA-STS / TLS-RPT / BIMI / DNSSEC checks.**
7. **Scoring engine** as a pure function: `dict of parsed records → (score, grade, verdict, findings[])`. Pure functions are testable; make this one exhaustively tested.
8. **Remediation renderer.** For each finding code, a copy-paste-ready fix. Example for `DMARC_ABSENT`: the exact TXT record to publish, plus the staged rollout advice (`p=none` with `rua` → monitor 30 days → `p=quarantine; pct=10` → ramp → `p=reject`). *That remediation quality is what makes a security person respect the tool.*
9. **API + UI.** `GET /api/herald/scan?domain=` and a lookup page with a result card, findings table, and history sparkline.
10. **Batch runner** — Typer CLI: `heapleap herald scan --file uae_domains.csv --concurrency 20`. Rate-limit DNS politely.
11. **Monthly rescan job** via GitHub Actions cron → this builds the longitudinal dataset that makes the research repeatable and citable.

### 2.6 Scope & ethics guardrails

- **Everything is passive.** DNS queries and one HTTPS GET for the MTA-STS policy file. You are reading public records that exist to be read. This is the safest module in the suite.
- **Never send test mail to a domain you do not own.** Do not "verify spoofability" by actually spoofing a third party. That crosses from research into unauthorised activity, and it is the single fastest way to turn a portfolio into a liability. Validate the logic against your own test domain only. Put this sentence in the README.
- **Do not publish a ranked list of spoofable named organisations.** See §2.7 — this matters more than it sounds.

### 2.7 The research paper: *"The State of UAE Email Spoofability, 2026"*

This is the highest-leverage single artefact in this entire document. Done well, it gets shared by exactly the people who hire you. Done carelessly, it is a phishing target list with your name on it.

**Methodology — write this down before you scan:**

1. **Define the sampling frame explicitly and publish it.** Not "top companies" — something defensible and reproducible: e.g. *all constituents of the ADX and DFM indices as of [date]*, or *the .ae domains of institutions in [defined sector list]*. State inclusion and exclusion criteria, the date of collection, and the resolver used.
2. **Sector-tag every domain** (banking, telecom, government, healthcare, education, aviation, logistics, retail). Sector breakdowns are the interesting finding; the aggregate number is the headline.
3. **Scan once, then rescan at +30 and +90 days.** Movement over time is a much stronger paper than a snapshot.
4. **Report the metrics that matter:** % with any DMARC, % at `p=reject`, % at `p=none` (the false-security number — this will be your headline), % with broken SPF from lookup overflow, % with `sp=none`, % with MTA-STS.

**Disclosure protocol — follow this exactly:**

1. Scan. Identify affected organisations.
2. **Notify privately first.** Email each affected org's published security or abuse contact (`security@`, `abuse@`, or the contact in their RDAP record) with their specific findings and remediation. Keep a log with timestamps — that log is itself an interview artefact.
3. **Wait a disclosure window** — 45 to 90 days is the accepted norm. Say in the notification when you intend to publish and what you intend to publish.
4. **Publish aggregates only.** *"63% of surveyed UAE banking domains have no enforcing DMARC policy"* is publishable research. *"Here is the list of 47 banks you can spoof"* is a gift to phishers, regardless of intent.
5. **Name only the good.** Positively naming organisations with strong posture is safe, generous, and gets you shared by those organisations. Never name the weak.
6. **Publish the scanner and the methodology** so the work is reproducible. Reproducibility is what separates research from a blog post.

Write the disclosure protocol into the paper itself. A hiring manager reading a paper that opens with a considered disclosure policy learns more about your judgment than the results section ever will.

### 2.8 Resume payload

> **Herald — Email Authentication Posture Scanner** | heapleap.tech/herald
> Built an async DNS analysis engine evaluating SPF (with RFC 7208 recursive lookup-limit validation), DKIM selector discovery and key strength, DMARC policy and alignment, MTA-STS, TLS-RPT and DNSSEC across N UAE domains; produced a weighted posture score with prescriptive remediation, and authored a longitudinal regional study under a coordinated disclosure protocol.

---

## 3. ATLAS — Threat Intelligence Producer (STIX 2.1 / TAXII 2.1)

### 3.1 Thesis

Outpost currently *consumes* eight threat feeds. Atlas makes it *produce* one.

That flip is the entire point. Anyone can subscribe to URLhaus. Very few juniors can say *"I operate a TAXII 2.1 server publishing STIX 2.1 objects with an indicator decay model, and here is the collection URL you can plug into your SIEM right now."* It is a small build on data you already have, and it changes how you are perceived: intel consumer → intel producer.

**Differentiator: indicator decay.** The universal complaint about community feeds is staleness — dead URLs from six months ago still firing alerts. Atlas ships confidence decay and hard expiry from day one, and you say so in the docs. That single design choice signals you have actually thought about how intel gets *used* downstream, not just produced.

### 3.2 Architecture

```
   Outpost internal tables
   (urls, kits, actors, indicators, hosts)
              │
              ▼
   ┌──────────────────────┐
   │  Normaliser          │  internal row → STIX 2.1 object
   │  modules/atlas/stix/ │  (python `stix2` library)
   └──────────┬───────────┘
              │
              ▼
   ┌──────────────────────┐
   │  Enrichment layer    │  ATT&CK mapping, TLP marking,
   │                      │  confidence, valid_from/valid_until
   └──────────┬───────────┘
              │
              ▼
   ┌──────────────────────┐        ┌────────────────────────┐
   │  atlas.stix_objects  │◄───────│  Decay job (hourly)     │
   │  (JSONB + indexes)   │        │  confidence--, revoke   │
   └──────────┬───────────┘        └────────────────────────┘
              │
   ┌──────────┴────────────────────────────────┐
   ▼                    ▼                      ▼
TAXII 2.1 API      Export formats         Detection content
/taxii2/...        CSV / JSON / txt       Sigma rules, MISP feed
```

### 3.3 STIX object mapping

Map your existing entities onto the standard. This table is the design doc:

| Outpost entity | STIX 2.1 type | Notes |
|---|---|---|
| Confirmed phish URL | `indicator` | pattern: `[url:value = 'https://…']`, `indicator_types: ['malicious-activity']` |
| The URL itself | `url` (SCO) | referenced observable |
| Phishing kit family | `malware` | `is_family: true`, `malware_types: ['webshell','phishing-kit']` |
| Actor cluster (DSU) | `threat-actor` | name from cluster id, `resource_level: 'individual'` unless evidence says otherwise |
| Host / IP / ASN | `infrastructure` + `ipv4-addr` | `infrastructure_types: ['hosting-malware','phishing']` |
| Targeted brand | `identity` | `identity_class: 'organization'`, `sectors: ['financial-services']` |
| Exfil channel (Telegram/Discord/SMTP) | `infrastructure` | **redacted values only** — never publish live tokens |
| Kit file hash (TLSH/SHA-256) | `file` (SCO) | `hashes: {'SHA-256': …, 'TLSH': …}` |
| Technique used | `attack-pattern` | external ref to MITRE ATT&CK |

**Relationships** — this is what makes the feed a *graph* instead of a list:

```
indicator      --indicates-->  malware
threat-actor   --uses-->       malware
threat-actor   --uses-->       infrastructure
malware        --targets-->    identity
indicator      --based-on-->   url (SCO)
malware        --uses-->       attack-pattern
```

**ATT&CK mapping** for phishing infrastructure — start with these and *verify each ID against the current ATT&CK release before publishing*, since technique IDs and sub-technique numbering do change between versions:

- `T1566.002` — Phishing: Spearphishing Link
- `T1583.001` — Acquire Infrastructure: Domains
- `T1585.002` — Establish Accounts: Email Accounts
- `T1656` — Impersonation
- `T1102` — Web Service (Telegram/Discord as C2 or exfil transport)
- `T1567` — Exfiltration Over Web Service

### 3.4 Confidence and decay model

```python
# confidence at publication, derived from Outpost triage
def initial_confidence(triage_score: int, kit_collected: bool) -> int:
    base = min(90, 30 + int(triage_score * 0.6))
    return min(95, base + 10) if kit_collected else base

# decay: halve the "distance to floor" every N days since last_seen_live
# floor of 10 keeps historical context without alerting on dead infra
def decayed_confidence(initial: int, days_since_seen: int, half_life: int = 14) -> int:
    floor = 10
    return int(floor + (initial - floor) * (0.5 ** (days_since_seen / half_life)))
```

Rules:
- `valid_until` = `last_seen_live + 90 days` on every indicator.
- When confidence decays below 20, set `revoked: true` and stop serving it in the default collection.
- Re-validate live status on a schedule; a URL that comes back up resets `last_seen_live`.

Document this model on the public feed page. It is two functions of code and it is the single most credible thing on the page.

### 3.5 TAXII 2.1 endpoints to implement

TAXII is a small, well-specified HTTP API. Implementing it in FastAPI is a day's work and looks far more impressive than it costs.

```
GET  /taxii2/                                   → discovery (API roots)
GET  /taxii2/api/                               → API root information
GET  /taxii2/api/collections/                   → list collections
GET  /taxii2/api/collections/{id}/              → collection metadata
GET  /taxii2/api/collections/{id}/objects/      → the objects (the important one)
GET  /taxii2/api/collections/{id}/objects/{oid}/
GET  /taxii2/api/collections/{id}/manifest/     → object manifest
```

Required behaviours: `Accept: application/taxii+json;version=2.1` content negotiation; filtering on `added_after`, `match[type]`, `match[id]`; pagination via `limit` + `next`; the `X-TAXII-Date-Added-First` / `-Last` response headers.

**Collections to publish:**

| Collection | Contents | Access |
|---|---|---|
| `uae-phishing-live` | Active, high-confidence phish targeting UAE brands | public, TLP:CLEAR |
| `phishing-kits` | Kit families, hashes, TLSH clusters | public, TLP:CLEAR |
| `actor-clusters` | Threat actor SDOs + relationships | API key |
| `full` | Everything including decayed/revoked | API key |

### 3.6 Bonus output: generate Sigma rules from your own intel

This is the flex. From your extracted indicators, auto-emit detection content:

```yaml
title: Connection to Known UAE-Targeting Phishing Infrastructure
id: <uuid>
status: experimental
description: Detects outbound connection to infrastructure attributed to phishing campaigns impersonating UAE financial brands
references:
  - https://heapleap.tech/atlas
author: Faseeh Padinjarathil
logsource:
  category: proxy
detection:
  selection:
    c-uri|contains:
      - '<generated from atlas indicators>'
  condition: selection
falsepositives:
  - Security researchers browsing to the site intentionally
level: high
tags:
  - attack.initial_access
  - attack.t1566.002
```

Ship a `/atlas/sigma` endpoint that renders the current ruleset. Now you are not just publishing indicators — you are publishing *detections*. That is threat-intel-engineering, and it is a job title that pays well.

### 3.7 Build steps

1. `pip install stix2` — do not hand-roll the JSON, the library enforces spec compliance.
2. Schema: `atlas.stix_objects (id TEXT PK, type TEXT, created TIMESTAMPTZ, modified TIMESTAMPTZ, added TIMESTAMPTZ, collection TEXT, confidence INT, revoked BOOL, obj JSONB)`. Index on `(collection, added)` and a GIN index on `obj`.
3. Write the normaliser: one function per Outpost entity type → STIX object. Deterministic IDs (STIX 2.1 supports UUIDv5 from a namespace + contributing properties) so re-runs do not duplicate objects.
4. Enrichment: TLP markings, `created_by_ref` identity for heapleap, ATT&CK external references, initial confidence.
5. Decay job: hourly GitHub Action or in-process scheduler.
6. TAXII router in FastAPI. Test against a real client — `taxii2-client` (Python) or import the collection into an OpenCTI or MISP instance and screenshot it working. **That screenshot goes in your portfolio.**
7. Simple exports: `/atlas/export/urls.txt`, `.csv`, `.json` — because most people just want a text file.
8. Sigma emitter.
9. Public docs page: what the feed contains, the decay model, how to add it to Sentinel / MISP / OpenCTI, TLP terms, and a licence (CC BY 4.0 or similar).
10. **Register it.** Submit to community feed indexes, post the collection URL where threat-intel people gather. A feed with real subscribers is a very different resume line from a feed with none.

### 3.8 Scope & ethics guardrails

- **Never publish live attacker credentials.** Telegram bot tokens, Discord webhooks, and SMTP credentials found in kits stay redacted in every output. Publishing them enables anyone to hijack the exfil channel — which is unauthorised access to a third-party service, no matter who the third party is.
- **Publish redacted, report unredacted.** Send the full token to the platform's abuse channel (Telegram, Discord, the ESP) so they can revoke it. That is the responsible path and it is a great story: *"I found 340 live exfil channels and reported every one to the platform for revocation."*
- **Attribution language must be hedged.** Your DSU clustering proves *code similarity*, not *identity*. Call them "clusters" (`CLUSTER-0042`), never real-world names. Over-attribution is the fastest way to lose credibility with actual intel professionals.
- **False positives will happen.** Publish a `report-a-false-positive` contact and a documented removal SLA. Then honour it.

### 3.9 Resume payload

> **Atlas — STIX/TAXII Threat Intelligence Feed** | heapleap.tech/atlas
> Operate a public TAXII 2.1 server publishing STIX 2.1 indicators, malware families, threat-actor clusters and infrastructure objects mapped to MITRE ATT&CK, with a confidence-decay and expiry model to eliminate stale-indicator noise; auto-generates Sigma detection rules from produced intelligence.

---

## 4. HORIZON — External Attack Surface Monitor

### 4.1 Thesis

Outpost finds phishing sites after they appear in someone else's feed. Horizon finds them **at certificate issuance** — often minutes after the attacker provisions the domain and typically hours to days before the URL surfaces in any public blocklist.

That is the "extraordinary" part you asked for, and it is achievable because you already run a Certificate Transparency listener. Horizon turns that stream from an ingestion source into a monitoring product with a defined watchlist, a typosquat generation engine, and an exposure timeline.

**The regional angle nobody has built:** a continuously-updated public timeline of newly-registered lookalike infrastructure targeting UAE institutions — Emirates NBD, ADCB, FAB, RTA, DEWA, UAE PASS, Etisalat, du, Emirates, Etihad, ADNOC. Not a one-off report. A live feed with a first-seen timestamp on every lookalike domain. That artefact does not currently exist publicly for this region.

### 4.2 Architecture — and the two-mode design that keeps it legal

**This is the most important architectural decision in the entire suite.** Horizon touches third-party infrastructure, so authorisation must be enforced in code, not in a README.

```
┌──────────────────────────────────────────────────────────────┐
│  core/scope.py — AUTHORISATION GATE                          │
│  Every probe call passes through here. No bypass path.       │
│                                                              │
│   is_authorised(domain, probe_type) -> bool                  │
│     PASSIVE probes  → always allowed (public data only)      │
│     ACTIVE probes   → allowed ONLY if domain in              │
│                       core.authorised_scope with a valid,    │
│                       unexpired authorisation record         │
└──────────────────────────────────────────────────────────────┘
```

```sql
CREATE TABLE core.authorised_scope (
    id             BIGSERIAL PRIMARY KEY,
    domain         TEXT NOT NULL,
    authorised_by  TEXT NOT NULL,       -- who granted it
    evidence_ref   TEXT NOT NULL,       -- link to written authorisation / bug bounty policy
    granted_at     TIMESTAMPTZ NOT NULL,
    expires_at     TIMESTAMPTZ NOT NULL,
    probe_types    TEXT[] NOT NULL,     -- which active probes are permitted
    UNIQUE (domain)
);
```

**Passive mode (default — any domain, no permission needed):**
- Certificate Transparency log stream
- DNS resolution (A, AAAA, CNAME, MX, TXT, NS)
- RDAP / WHOIS registration data
- Third-party passive scan APIs you query legitimately (Shodan, Censys, urlscan.io) — you are reading *their* data, not touching the target
- Public archives and blocklists

**Active mode (only for domains in `authorised_scope`):**
- Direct HTTP fingerprinting
- Port scanning
- Path enumeration / exposed-file checks
- TLS handshake inspection

Put your own domains in `authorised_scope` on day one so you can demo active mode. Add client domains only with written authorisation attached to `evidence_ref`.

**Why this matters:** unauthorised scanning of third-party systems is a criminal matter in the UAE under the federal cybercrime law, and it is illegal in most jurisdictions you would want to work in. Building the gate into the architecture — and being able to point at it — converts your biggest liability into your strongest maturity signal. When an interviewer asks "how do you know you're not breaking the law?", the answer *"there is a database table and a hard gate; the active code path is unreachable for unauthorised domains"* is the answer a security architect gives.

### 4.3 Component: lookalike domain generation

For every watched brand domain, generate candidate permutations, then check which ones actually exist:

| Technique | `adcb.com` → |
|---|---|
| Typo / fat-finger | `adbc.com`, `adcv.com`, `adcbb.com` |
| Character omission | `adc.com`, `acb.com` |
| Homoglyph | `аdcb.com` (Cyrillic а), `adcb.com` with Unicode lookalikes |
| TLD swap | `adcb.net`, `adcb.online`, `adcb.ae.com` |
| Hyphenation / combosquat | `adcb-login.com`, `adcb-secure.net`, `secure-adcb.com` |
| Keyword append | `adcbverify.com`, `adcbupdate.com`, `myadcb.com` |
| Bitsquatting | single-bit flips of each character |
| Subdomain deception | `adcb.com.verify-login.net` ← the brand appears in the *subdomain* of an attacker domain |

That last row is the most-used real-world technique and the one most generators miss. Catch it by scanning the **full CT-observed hostname** for brand tokens, not just the registrable domain.

Prior art exists (`dnstwist`, `urlcrazy`) — study it, but write your own generator tuned to UAE brand tokens: `uaepass`, `emiratesnbd`, `rta`, `dewa`, `adnoc`, `etisalat`, `moi`, `ica`, `mohre`, `tasjeel`, `salik`, `dubaipolice`, plus Arabic-transliteration variants. The regional tuning is the contribution.

### 4.4 Component: subdomain takeover detection

Detect, report, **never claim.**

Detection logic (fully passive):
1. Resolve CNAME for each known subdomain of a watched domain.
2. If the CNAME target is a known SaaS provider pattern (`*.s3.amazonaws.com`, `*.github.io`, `*.herokuapp.com`, `*.azurewebsites.net`, `*.cloudfront.net`, and so on) **and** the target does not resolve, or returns the provider's known "unclaimed resource" fingerprint → flag as a takeover *candidate*.
3. Record evidence: the CNAME chain, the NXDOMAIN or fingerprint string, a timestamp.
4. **Stop there.** Do not register the bucket, claim the GitHub Pages site, or provision the Heroku app — even to "prove" it. Registering a resource that resolves someone else's DNS to you is exactly the unauthorised act the law targets, and "I was demonstrating the vulnerability" is not a defence anyone wants to test.

The NXDOMAIN evidence is sufficient for a credible report. Report it to the domain owner via their published security contact.

### 4.5 Component: exposure monitoring

For watched domains, track over time:
- **New subdomains** appearing in CT (with first-seen timestamps)
- **Certificate expiry** — flag < 14 days
- **Deprecated TLS** (TLS 1.0/1.1) and weak ciphers — from passive Censys/Shodan data for third parties; direct handshake only for authorised scope
- **Newly-resolving lookalikes** → auto-forward to Outpost triage
- **Registrar / nameserver / hosting changes** on watched domains (can indicate compromise or hijack)
- **ASN and geography drift** for critical hosts

### 4.6 Build steps

1. **Build `core/scope.py` first.** Before any probe code exists. The gate must predate the thing it gates, or you will bolt it on badly later.
2. Schema: `horizon.watchlist`, `horizon.assets` (discovered subdomains/hosts), `horizon.findings`, `horizon.timeline` (append-only event log).
3. Harden the CT stream consumer: reconnect with backoff, deduplicate, persist stream position so a restart does not lose coverage.
4. Brand-token matcher over full CT hostnames, with a scoring function for match confidence (exact token > fuzzy > substring).
5. Lookalike generator (the table in §4.3), plus a resolver check to filter to domains that actually exist.
6. Registration enrichment via RDAP: creation date, registrar, nameservers. A domain registered three days ago that mimics a bank is a very strong signal — surface `age_days` prominently.
7. Passive scan API integrations (Censys / Shodan / urlscan free tiers), with response caching to stay inside quotas.
8. Subdomain takeover *detector* (detect-only, per §4.4).
9. Findings engine + severity model.
10. **Integration: Horizon → Outpost.** A newly-resolving lookalike is pushed into Outpost's `urls` table at elevated priority. This is the wiring that makes the suite real — build it early and demo it.
11. UI: a live timeline (`first seen → resolved → cert issued → triaged → takedown filed`) per lookalike. That timeline visualisation is the screenshot that sells the whole project.

### 4.7 Scope & ethics guardrails

- No active probing outside `core.authorised_scope`. Enforced in code.
- Detect-only for takeovers. Never claim a dangling resource.
- Respect API terms of service and rate limits on every third-party data source.
- Public watchlist covers **brands you are protecting**, not organisations you are auditing without their knowledge. Framing matters: Horizon watches for *attackers impersonating* Emirates NBD. It does not audit Emirates NBD's infrastructure.
- Publish the scope policy on the Horizon page so anyone can see where your line is.

### 4.8 Resume payload

> **Horizon — External Attack Surface & Brand Infrastructure Monitor** | heapleap.tech/horizon
> Real-time Certificate Transparency monitoring detecting lookalike infrastructure targeting UAE financial, government and telecom brands at point of certificate issuance; includes a homoglyph/combosquat permutation engine, RDAP registration-age enrichment, and detect-only subdomain-takeover identification, with active probing gated by an enforced authorisation-scope control.

---

## 5. MIRAGE — AI-Generated Lure Detection & LLM Abuse Telemetry

### 5.1 Thesis

Two modules, one theme: **what happens when attackers use LLMs.**

- **Module A — AI-generated lure classification.** Estimate whether a phishing page or email body is stylistically consistent with LLM generation. Moderately novel; be honest about its limits.
- **Module B — LLM abuse telemetry in phishing kits.** Scan collected kits for embedded LLM API keys, SDK imports, and prompt strings. **This is the genuinely novel one and the one nobody is publishing regionally.** Attackers are increasingly baking LLM calls into kits for dynamic lure generation, live translation, and victim-response chat. Finding those, quantifying them, and reporting leaked keys to providers is original security research.

Build Module B first. It is easier, more novel, and more publishable.

### 5.2 Module B architecture — LLM abuse telemetry

```
   Outpost kit archives (quarantined, never executed)
                    │
                    ▼
   ┌────────────────────────────────┐
   │  Static scanner                │
   │  (extends existing deobfuscator)│
   └────────────────┬───────────────┘
                    │
       ┌────────────┼─────────────┬──────────────┐
       ▼            ▼             ▼              ▼
   API key      SDK import    Prompt string   Endpoint
   patterns     detection     detection       detection
       │            │             │              │
       └────────────┴──────┬──────┴──────────────┘
                           ▼
              ┌────────────────────────┐
              │  mirage.llm_findings   │  redacted storage
              └───────────┬────────────┘
                          │
              ┌───────────┴────────────┐
              ▼                        ▼
      Public statistics      Private provider reports
      (aggregate only)       (full key, for revocation)
```

**What to detect:**

| Signal | Example |
|---|---|
| Provider API key patterns | Provider-specific key prefixes and lengths — match by regex, store **hash + first/last 4 only** |
| SDK imports | `openai`, `anthropic`, `google.generativeai` in PHP/Python/JS kit code |
| API endpoints | Hardcoded model-inference endpoint hostnames in kit source |
| Prompt strings | Instructional English blocks near a network call — "write a convincing email as…", "translate the following into…" |
| Response handling | Code parsing a chat-completion JSON envelope |

**Handling found keys — the protocol that makes this legitimate research rather than credential collection:**

1. **Never call the key.** Not once, not "just to check if it's live." Using someone else's API credential is unauthorised access, full stop.
2. Store only `sha256(key)` + a masked display form (`sk-…abcd`). Your existing `indicators.redacted_display` pattern already does this — reuse it.
3. Report the full key **once**, directly to the provider's security/abuse channel, so they can revoke it. Log the report.
4. Purge the full value from your systems after reporting. Keep the hash for deduplication.
5. Publish aggregates only: *"of 412 kits analysed, 6.3% contained hardcoded inference-API credentials; 89% of those were provider X."*

That is a legitimate, publishable, first-of-its-kind regional finding, and the protocol above is what makes it defensible.

### 5.3 Module A architecture — AI-generated lure classification

**Be intellectually honest about this one, in the code, the UI, and the interview.** There is no reliable ground truth for "was this text LLM-generated." Detectors in this space have well-documented false-positive problems, particularly against non-native English writing — which is exactly the population that historically wrote phishing lures. Overclaiming here will get you challenged by anyone who knows the literature.

**The honest framing:** Mirage estimates *stylistic consistency with machine-generated text*. It does not prove origin. Every output is a probability with a confidence interval and a caveat. Say that on the page.

**Dataset construction (weak labels, transparently described):**
- *Human-baseline class*: phishing lure text from corpora collected before widespread LLM availability.
- *Suspected-LLM class*: recent lures with multiple machine-text indicators.
- *Control class*: legitimate transactional email/page copy from brands, for false-positive measurement.
- Publish class sizes, collection dates, and the labelling heuristic. Publish the FPR on the control class — *especially* if it is bad. Reporting your own weaknesses is a credibility multiplier.

**Features (start engineered and interpretable, not a black box):**
- Perplexity and burstiness against a small local language model
- Sentence-length variance (machine text is noticeably more uniform)
- Grammatical error density (classic phish: high; LLM phish: near zero)
- Lexical diversity (type-token ratio)
- Template-artefact markers, boilerplate transition phrases
- HTML structural entropy; comment and whitespace patterns
- Presence of "assistant-voice" register markers

**Model:** gradient-boosted trees on engineered features first. Interpretable, fast, and you can *explain the top 10 features in an interview* — which is worth far more than two extra points of F1 from a fine-tuned transformer you cannot explain. Add the transformer later as a comparison, and report both.

**Evaluation:** report accuracy, precision, recall, F1, **and the false-positive rate on non-native-English legitimate text**, broken out separately. That last metric is the one a serious reviewer will look for.

### 5.4 Build steps

1. Extend the existing deobfuscation pipeline with an LLM-signal scanner (Module B). Reuses code you already have — fastest path to a result.
2. Schema: `mirage.llm_findings` (kit_id, signal_type, redacted_value, value_sha256, provider, reported_at), `mirage.assessments` (url_id, ai_likelihood, confidence, features JSONB, model_version).
3. Build the provider-reporting workflow and the purge job. Automate the log.
4. Publish Module B statistics on the Mirage page; update monthly.
5. Assemble the Module A corpus. Document every labelling decision.
6. Feature extraction pipeline; version it (`model_version` in every assessment row, so results stay reproducible).
7. Train, evaluate, publish the confusion matrix **including the failure modes**.
8. Surface an "AI-likelihood" badge on Outpost's phish detail view — with the caveat text attached to the badge itself, not buried in a footnote.
9. Write it up: *"LLM Abuse in Phishing Kits: Evidence from N Archives (2026)."*

### 5.5 Scope & ethics guardrails

- Never execute kit code. Static analysis only. (Already your standing rule — keep it.)
- Never use a discovered API key.
- Never publish live credentials; report and purge.
- Never present the AI-likelihood score as proof of origin.
- Do not build the inverse tool. You are building detection of AI-generated lures. Do not build, publish, or demo generation of them, even "for research" — that is an offensive capability and it will end conversations with employers rather than start them.

### 5.6 Resume payload

> **Mirage — LLM Abuse Telemetry in Phishing Kits** | heapleap.tech/mirage
> Static-analysis pipeline quantifying attacker adoption of large language models across N collected phishing kits — detecting embedded inference-API credentials, SDK usage and prompt artefacts — with a coordinated credential-revocation reporting workflow; plus an interpretable classifier estimating machine-generated lure text, published with full false-positive characterisation.

---

## 6. LAB — Microsoft Sentinel Mini-SOC

> This is **not** a heapleap product. It is a lab whose only job is to prove you speak SOC. Herald, Atlas, Horizon and Mirage prove you can build. This proves you can *operate* — which is what a Tier-1/Tier-2 SOC hiring manager is actually screening for.

### 6.1 Thesis

Every UAE SOC job description asks for the same three things you cannot currently evidence: **SIEM experience, KQL, and MITRE ATT&CK-mapped detection engineering.** This lab produces all three, plus incident-response writeups, in roughly three weeks of part-time work.

**The differentiator that ties everything together:** you ingest **your own Atlas TAXII feed** into Sentinel as a threat-intelligence source. Almost every candidate builds a Sentinel lab. Approximately none of them plug in a threat feed they built themselves and then alert on it. That single integration is the strongest twenty seconds of any interview you will have.

### 6.2 Architecture

```
┌─────────────────── Your lab tenant ───────────────────┐
│                                                        │
│  Entra ID          Windows VM         Linux VM         │
│  (sign-in +        (Sysmon + AMA)     (syslog,         │
│   audit logs)                          auditd)         │
│      │                  │                  │           │
│      └──────────────────┼──────────────────┘           │
│                         ▼                              │
│              ┌─────────────────────┐                   │
│              │ Log Analytics       │                   │
│              │ Workspace           │                   │
│              └──────────┬──────────┘                   │
│                         ▼                              │
│              ┌─────────────────────┐                   │
│              │ Microsoft Sentinel  │                   │
│              │  • Analytics rules  │◄──── Atlas TAXII  │
│              │  • Workbooks        │      (your feed!) │
│              │  • Incidents        │                   │
│              │  • Playbooks        │                   │
│              └──────────┬──────────┘                   │
│                         ▼                              │
│              Logic App playbook → enrich → notify      │
└────────────────────────────────────────────────────────┘
```

### 6.3 Cost control — read this before you deploy anything

Sentinel bills on data ingestion, and an unattended lab is the classic way to wake up to a four-figure bill.

| Control | Action |
|---|---|
| Daily cap | Set a daily ingestion cap on the Log Analytics workspace immediately after creating it. Non-negotiable. |
| Retention | Keep it at the minimum free retention period. You do not need 90 days for a lab. |
| Table filtering | Use Data Collection Rules to filter noisy event IDs at source. Sysmon unfiltered is a firehose. |
| VM lifecycle | Deallocate VMs when not actively testing. Use the smallest viable SKU. |
| Budget alert | Set an Azure Cost Management budget alert at a threshold you are comfortable with. |
| Free tier | Sentinel and Azure both offer trial/free allowances — start there and check current terms before you enable anything, since pricing and free-tier limits change. |

Then tear the lab down when the writeups are finished. The artefacts (queries, docs, screenshots, IR reports) are what matter — those live in Git, not in Azure.

### 6.4 Data sources, in build order

1. **Entra ID sign-in + audit logs** — free-ish, highest signal, and it maps directly to your existing M365 administration experience. Start here.
2. **Windows VM + Sysmon + Azure Monitor Agent** — install Sysmon with a well-known community configuration; it is the single richest endpoint telemetry source.
3. **Linux VM** — syslog + auditd, for SSH and privilege-escalation detections.
4. **Atlas threat intelligence** — connect your own TAXII 2.1 server via Sentinel's threat intelligence TAXII connector. Point it at `https://heapleap.tech/taxii2/api/collections/uae-phishing-live/`.
5. **Optional:** Azure Activity, NSG flow logs, Defender for Cloud alerts.

### 6.5 Detection content — build eight to ten, document every one

Each rule needs a written detection-engineering doc, not just a query. **The docs are the portfolio artefact.** Template:

```markdown
## DET-004 — Password Spray Against Entra ID

**ATT&CK:** T1110.003 (Brute Force: Password Spraying)
**Data source:** SigninLogs
**Hypothesis:** An attacker attempting many accounts with few passwords
  will produce a burst of failed sign-ins with error 50126, spread
  across a high number of distinct usernames from a low number of IPs.
**Logic:** see query below
**Threshold rationale:** why this number, and what tuning it against
  N days of baseline data showed
**Expected false positives:** misconfigured mail clients after a
  password change; a shared NAT egress; a load-tested app
**Tuning applied:** what you excluded and why
**Response playbook:** triage steps, containment, escalation criteria
**Validation:** how you proved it fires (simulation performed, date)
```

**Rules to build:**

| ID | Detection | ATT&CK | Source |
|---|---|---|---|
| DET-001 | Atypical / impossible travel sign-in | T1078 | SigninLogs |
| DET-002 | Successful sign-in after repeated failures | T1110 | SigninLogs |
| DET-003 | MFA fatigue — repeated push denials | T1621 | SigninLogs |
| DET-004 | Password spray | T1110.003 | SigninLogs |
| DET-005 | New OAuth application consent grant | T1528 | AuditLogs |
| DET-006 | LOLBin download (certutil / mshta / bitsadmin) | T1105, T1218 | Sysmon E1 |
| DET-007 | Office application spawning a script interpreter | T1204, T1059 | Sysmon E1 |
| DET-008 | SSH brute force followed by successful auth | T1110 | Syslog |
| DET-009 | **Connection to an Atlas threat indicator** | T1566.002 | TI map + logs |
| DET-010 | Rare process by hash (baseline anomaly) | T1204 | Sysmon E1 |

**Sample — DET-004, password spray:**

```kql
let window = 1h;
let distinct_user_threshold = 10;
SigninLogs
| where TimeGenerated > ago(window)
| where ResultType == 50126            // invalid username or password
| summarize
    FailedAttempts   = count(),
    TargetedAccounts = dcount(UserPrincipalName),
    Accounts         = make_set(UserPrincipalName, 50),
    Countries        = make_set(LocationDetails.countryOrRegion, 5)
    by IPAddress, AppDisplayName
| where TargetedAccounts >= distinct_user_threshold
| extend AttemptsPerAccount = round(todouble(FailedAttempts) / TargetedAccounts, 2)
| where AttemptsPerAccount < 5          // few passwords, many accounts = spray not brute force
| order by TargetedAccounts desc
```

**Sample — DET-009, your own feed firing:**

```kql
let lookback = 1d;
let ti_indicators =
    ThreatIntelligenceIndicator
    | where TimeGenerated > ago(14d)
    | where SourceSystem == "heapleap-atlas"
    | where Active == true and ConfidenceScore >= 50
    | summarize arg_max(TimeGenerated, *) by IndicatorId
    | project Url, ThreatType, ConfidenceScore, IndicatorId;
ti_indicators
| join kind=innerunique (
    CommonSecurityLog
    | where TimeGenerated > ago(lookback)
    | where isnotempty(RequestURL)
    | project TimeGenerated, SourceIP, DestinationIP, RequestURL, DeviceAction
) on $left.Url == $right.RequestURL
| project TimeGenerated, SourceIP, RequestURL, ThreatType, ConfidenceScore, DeviceAction
```

*"That rule is matching against indicators my own platform produced"* is the sentence you want to be able to say.

### 6.6 Validation — prove the rules actually fire

A detection you have never seen fire is a hypothesis, not a detection.

- Use **Atomic Red Team** to execute mapped test cases against your own lab VM.
- Run a controlled credential-stuffing simulation against **your own tenant test accounts only**.
- Record for each rule: the simulation run, the timestamp, whether it fired, time-to-alert, and any tuning that followed.

**Boundary, and state it in the repo:** every simulation runs against infrastructure you own inside your own tenant. Nothing in this lab touches a system you do not control. Put that sentence in the lab README.

### 6.7 SOAR playbook

Build one Logic App triggered on incident creation:

1. Extract entities (user, IP, URL) from the incident.
2. Enrich: query Atlas for the indicator, RDAP for the IP, and add a comment to the incident with the results.
3. Notify a Teams or Slack channel with a formatted incident card.
4. **Conditional containment behind an approval gate** — e.g. an approval action that, if approved by a human, disables the user account. Build the approval step deliberately and explain why in the doc: automated containment without a human gate is how a SOC takes its own business offline.

That approval-gate reasoning is a senior-sounding answer to a very common interview question.

### 6.8 Deliverables — the actual portfolio artefacts

Ship a `labs/sentinel-soc/` folder containing:

```
labs/sentinel-soc/
├── README.md                  # architecture, cost controls, scope statement
├── detections/
│   ├── DET-001-atypical-signin.md      (+ .kql)
│   ├── ...                             (one doc + one query per rule)
│   └── ATTACK-COVERAGE.md              # ATT&CK Navigator layer + heatmap screenshot
├── playbooks/
│   └── incident-enrichment-logicapp.json
├── workbooks/
│   └── soc-overview-workbook.json
├── incidents/
│   ├── IR-001-password-spray.md
│   ├── IR-002-oauth-consent-phish.md
│   └── IR-003-lolbin-execution.md
└── validation/
    └── simulation-log.md
```

**The three IR reports are the highest-value items in this entire lab.** Structure each as: executive summary → timeline (UTC, precise) → detection → triage steps and queries run → scope of impact → containment → root cause → lessons learned and detection improvements made. Hiring managers read these. They are the closest thing to a work sample for a SOC role that exists.

### 6.9 Resume payload

> **Security Operations Lab — Microsoft Sentinel** | github.com/faseehfawaz/heapleap
> Deployed a Microsoft Sentinel SOC ingesting Entra ID, Sysmon, and Linux auditd telemetry; authored 10 KQL analytics rules mapped to MITRE ATT&CK with documented tuning rationale and false-positive analysis; integrated a self-operated TAXII threat-intelligence feed for indicator matching; built a Logic Apps enrichment playbook with human-approval containment gating; validated detections via Atomic Red Team and produced three full incident-response reports.

Skills line to add: `Microsoft Sentinel, KQL, MITRE ATT&CK, NIST CSF, Sysmon, detection engineering, incident response, SOAR`

---

## 7. Cross-Cutting Concerns

### 7.1 Infrastructure and cost

You are already on a workable stack. Keep it and stay near-free:

| Layer | Service | Notes |
|---|---|---|
| Database | Neon Postgres | One database, schema per module. Watch the free-tier compute-hour limit; the CT stream is the main risk since it is long-running. |
| App hosting | Render | One web service (FastAPI, all routers) + background workers. |
| Object storage | Cloudflare R2 | Kit archives. No egress fees is the reason to prefer it here. |
| Scheduling | GitHub Actions cron | Already proven for the 14-minute pipeline. Free minutes on public repos. |
| DNS / CDN | Cloudflare | Free tier. |
| Long-running stream | Render background worker | CT stream needs a persistent process, not a cron. |

**Watch the free-tier ceilings.** Verify current limits before you scale up — every provider changes them. Add a `docs/COST.md` with your actual monthly spend. Being able to say *"the whole platform runs at roughly $X/month and here is the breakdown"* is a genuinely impressive answer for someone at your stage, because it shows you think about operating cost, not just code.

### 7.2 The scope and ethics document

You already have `SCOPE_AND_ETHICS.md` — your instinct there was correct. Expand it to cover the full suite and link it from every module page. Structure:

```markdown
# Scope and Ethics

## What this platform does
## What this platform explicitly does not do
   - never executes attacker code
   - never authenticates to, exploits, or brute-forces any system
   - never stores or transmits victim credentials
   - never sends test email impersonating a domain we do not own
   - never uses discovered third-party credentials
   - never claims dangling infrastructure, even to demonstrate a finding
   - never actively probes a domain outside the authorised scope table

## Authorisation model
   - passive vs active probe classification
   - core.authorised_scope: how authorisation is granted, recorded, expired
   - code-level enforcement (core/scope.py)

## Data handling
   - redaction of exfil channels and credentials
   - retention periods per data class
   - what is published vs what is held privately

## Coordinated disclosure policy
   - how we notify affected parties
   - disclosure window
   - what gets published (aggregates) vs what does not (named weak targets)

## False positives
   - contact address for disputes
   - removal SLA

## Legal
   - applicable law and how the above maps to it
   - contact: security@heapleap.tech
```

**On the law:** the UAE has a federal cybercrime law (Federal Decree-Law No. 34 of 2021) that criminalises unauthorised access to information systems, and related data-protection legislation applies to personal data you might encounter. Read the actual current text rather than relying on any summary — including this one — and if you are ever unsure whether a specific technique is on the right side of the line, treat that uncertainty as your answer and stay passive. Nothing in this playbook requires you to cross it, and every module has been designed so that the interesting engineering lives on the safe side.

### 7.3 Answering the hard interview questions

These will be asked. Prepare them now.

**"Your platform sends automated abuse emails. What happens when you're wrong?"**
Have a real answer: your false-positive rate, the confidence threshold required before a notice is dispatched, whether dispatch is human-reviewed, the rate limits per registrar, and your retraction process. **Recommended change: make automated dispatch human-in-the-loop or dry-run by default in the public build**, with auto-dispatch reserved for a high-confidence tier. Wrongly reporting a legitimate business can take it offline — that is real harm, and demonstrating that you have engineered for it is the entire answer.

**"Isn't directory probing unauthorised access?"**
Your answer: it retrieves content the server voluntarily serves to any anonymous visitor over standard HTTP, at a rate limit of N requests per host with M-second intervals, against hosts already independently classified as malicious by multiple public feeds; no authentication is attempted, no credential is submitted, no vulnerability is exploited. Then acknowledge honestly that it is the closest thing in the platform to a grey area, explain where you drew the line and why, and mention the controls. **Candid acknowledgement of a grey area beats a confident denial every time** — the second answer sounds like someone who has not thought about it.

**"How do you know your actor clusters are real?"**
They are code-similarity clusters, not identity attributions. Explain TLSH and Jaccard, explain what the clusters do and do not prove, and use `CLUSTER-0042` rather than a name. Hedged attribution is the professional norm.

**"Why Postgres instead of Kafka?"**
Throughput numbers, operational cost of a broker for a single-node system, and `FOR UPDATE SKIP LOCKED` giving equivalent at-least-once semantics. Then say what would make you change your mind — the volume at which you would migrate. Knowing the limits of your own design is the senior signal.

### 7.4 Sequencing against your three months

| Weeks | Build | Career |
|---|---|---|
| 0–1 | Core refactor; heapleap.tech landing page | Rewrite resume with Outpost at the top; portable summary; cut the "motherboard spoofing" line |
| 1–3 | **Herald** end to end | Begin Security+ or CySA+ study |
| 3–4 | UAE domain corpus + first scan + disclosure notifications sent | Sit the certification exam |
| 4–6 | **Atlas** (STIX + TAXII + decay + Sigma) | Publish Herald research after the disclosure window; post it properly on LinkedIn |
| 6–9 | **Sentinel mini-SOC** + Atlas integration + IR writeups | Start applying: MSSPs first (Help AG, CPX, DTS Solution, VaporVM), then Big-4 cyber, then bank SOCs |
| 9–12 | **Horizon** + the Horizon→Outpost integration | Attend security community events in person; GISEC and local chapter meetups are worth more than fifty cold applications |
| 12+ | **Mirage** Module B + writeup | Interview loop; keep publishing |

**If you only do three things from this document:** ship Herald, publish the research responsibly, and put Outpost on your resume. Those three, alone, change your candidacy.

### 7.5 The one-paragraph pitch

Memorise a version of this. It is your answer to "tell me about yourself."

> I run heapleap, a threat-intelligence and brand-protection platform. Outpost, the live module, ingests eight public feeds and a Certificate Transparency stream, triages candidate phishing endpoints against a multi-signal scoring model, collects exposed kits, fingerprints them with fuzzy hashing to cluster threat actors, and dispatches abuse notices to registrars — with a strict passive-research scope that never executes attacker code or retains victim data. Around it I have built an email-authentication posture scanner that produced the first regional study of DMARC enforcement, a TAXII server publishing my own indicators with a decay model, and a Sentinel workspace that consumes that feed operationally. I built the whole thing because I wanted to know what a real detection-to-takedown pipeline actually costs to run.

---

## 8. Quick Reference — What Each Module Proves

| Module | Proves you can |
|---|---|
| Outpost | Build and operate a production pipeline end to end |
| Herald | Do rigorous protocol-level analysis and publish research responsibly |
| Atlas | Work to standards (STIX/TAXII/ATT&CK) and think about downstream consumers |
| Horizon | Design and enforce authorisation controls; think about scope and law |
| Mirage | Do original research and handle sensitive findings correctly |
| Sentinel lab | Operate as a SOC analyst: KQL, detections, tuning, incident response |

Six things. Most graduates have one. That is the whole strategy.

---

*Document ends. Questions, corrections, and the parts you disagree with are all worth arguing out before you start building — the architecture is cheapest to change now.*
