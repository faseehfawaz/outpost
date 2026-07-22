<div align="center">

```
 ██████╗ ██╗   ██╗████████╗██████╗  ██████╗ ███████╗████████╗
██╔═══██╗██║   ██║╚══██╔══╝██╔══██╗██╔═══██╗██╔════╝╚══██╔══╝
██║   ██║██║   ██║   ██║   ██████╔╝██║   ██║███████╗   ██║   
██║   ██║██║   ██║   ██║   ██╔═══╝ ██║   ██║╚════██║   ██║   
╚██████╔╝╚██████╔╝   ██║   ██║     ╚██████╔╝███████║   ██║   
 ╚═════╝  ╚═════╝    ╚═╝   ╚═╝      ╚═════╝ ╚══════╝   ╚═╝   
```

**A continuously-running phishing-kit intelligence pipeline.**  
Hunt the kit. Dissect the code. Map the actor. File the takedown.

<br/>

[![Python](https://img.shields.io/badge/Python-3.12-3776AB?style=flat-square&logo=python&logoColor=white)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115-009688?style=flat-square&logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-16-336791?style=flat-square&logo=postgresql&logoColor=white)](https://postgresql.org)
[![Docker](https://img.shields.io/badge/Docker-Compose-2496ED?style=flat-square&logo=docker&logoColor=white)](https://docker.com)
[![License](https://img.shields.io/badge/License-MIT-22c55e?style=flat-square)](LICENSE)
[![Tests](https://img.shields.io/badge/Tests-107%20passing-22c55e?style=flat-square&logo=pytest&logoColor=white)](tests/)
[![Ethical](https://img.shields.io/badge/Passive%20Research%20Only-Ethical%20%26%20Legal-00ff88?style=flat-square)](docs/SCOPE_AND_ETHICS.md)

<br/>

[Live Dashboard](https://outpost.heapleap.tech) · [API Reference](https://outpost.heapleap.tech/docs) · [Ethics Policy](docs/SCOPE_AND_ETHICS.md)

</div>

---

## What it does

Most threat-intel tooling stops at the URL. Outpost goes further.

It watches public phishing feeds around the clock, and when a site scores as a confirmed phish, it checks whether the attacker made a common mistake — leaving their source archive exposed in an open directory. If they did, it grabs the zip, seals it in a no-network sandbox, and statically reads every PHP file to find exactly where stolen credentials get sent: a Telegram bot, a Discord webhook, a personal email address.

Those exfil channels are then hashed, clustered against every other kit we have ever seen, and linked to a threat actor profile. A redacted IOC feed goes public. Abuse reports go to the host, the registrar, and the relevant platform. The attacker's infrastructure gets smaller.

---

## The Pipeline

```
 PUBLIC FEEDS                INGEST                 TRIAGE
 ┌──────────────┐          ┌─────────┐           ┌──────────────┐
 │ URLhaus      │          │         │           │ Is it live?  │
 │ OpenPhish    │──────────│Normalize│──────────▶│ Brand match? │
 │ CT Logs      │          │ Dedupe  │           │ Score 0-100  │
 │ GitHub Lists │          │ Enqueue │           └──────┬───────┘
 └──────────────┘          └─────────┘                  │
                                                         │ score ≥ 50
                                                         ▼
 ACTOR GRAPH              KIT HUNTER              ANALYZER SANDBOX
 ┌──────────────┐          ┌──────────────┐       ┌──────────────────┐
 │ Cluster by   │          │ Open dir?    │       │ --network none   │
 │ fingerprint  │◀─────────│ *.zip probe  │──────▶│ non-root user    │
 │ & token hash │          │ Log files    │       │ read-only fs     │
 │ → Actor card │          └──────────────┘       │ static PHP read  │
 └──────┬───────┘                                 └──────────────────┘
        │
        ▼
 TAKEDOWN ENGINE           DASHBOARD               IOC FEED
 ┌──────────────┐          ┌──────────────┐       ┌──────────────────┐
 │ RDAP lookup  │          │ Live phish   │       │ Telegram tokens  │
 │ Host report  │          │ Actor cards  │──────▶│ Discord webhooks │
 │ Registrar    │          │ Real-time    │       │ Email drops      │
 │ Telegram     │          │ IOC feed     │       │ (all redacted)   │
 │ GSB / APWG   │          └──────────────┘       └──────────────────┘
 └──────────────┘
```

---

## Five Subsystems

Each subsystem is independently runnable and has its own test coverage. They share a single Postgres queue coordinated by `SELECT FOR UPDATE SKIP LOCKED` — no message broker required.

<br/>

**`01 · Ingest`** — Pulls candidate URLs from five public sources every cycle. URLhaus abuse reports, OpenPhish community feed, Certificate Transparency logs (filtered by brand keyword), urlscan.io, and a curated GitHub community list. Deduplicates by URL hash, rate-limited at the source.

**`02 · Triage`** — Visits each candidate. Checks if the page is live, reads the HTML to identify brand impersonation (PayPal, Apple, Emirates NBD, etc.), extracts login form structure, perceptual-hashes the favicon and logo, and produces a 0–100 confidence score. Anything above 50 proceeds.

**`03 · Kit Hunter`** — For confirmed phishing URLs, walks up the directory tree looking for exposed kit archives. It checks a short, fixed list of names — no fuzzing, no wordlists. If it finds a `.zip`, it checks the file magic, downloads it, stores it in Cloudflare R2, and records the SHA256.

**`04 · Analyzer`** — Extracts the archive inside a hardened Docker container (`--network none`, non-root, read-only filesystem, 30-second timeout). Reads every PHP file statically to extract exfiltration channels (Telegram tokens, Discord webhooks, SMTP credentials, exfil URLs). Computes a normalized token hash per file — stable across trivial obfuscation and variable renaming — using TLSH for fuzzy similarity.

**`05 · Fingerprint & Takedown`** — Clusters kits by Jaccard similarity on their file-hash sets and by shared exfil tokens. Generates actor profiles. Drafts and sends abuse reports to the hosting provider, domain registrar, and platform (Telegram, Google Safe Browsing, APWG eCrime Exchange).

---

## Quick Start

### Prerequisites
- Python 3.12+
- Docker & Docker Compose
- PostgreSQL 16 (or run it via Compose)

### Setup

```bash
git clone https://github.com/yourusername/outpost.git
cd outpost

# Create the virtual environment
uv venv .venv --python 3.12
uv pip install -e ".[dev]" --python .venv/bin/python

# Copy and fill in the environment file
cp .env.example .env

# Start Postgres
docker compose up -d db

# Apply the schema and register feed sources
pkintel db migrate
pkintel db seed
```

### Run the pipeline

```bash
# Run each stage once
pkintel run ingest
pkintel run triage
pkintel run kithunt
pkintel run analyze
pkintel run cluster
pkintel run takedown

# Or run everything in a continuous loop (every 30 seconds)
pkintel run all --loop --interval 30
```

### Start the API & Dashboard

```bash
# Terminal 1 — backend API
uvicorn pkintel.api.app:app --host 0.0.0.0 --port 8000

# Terminal 2 — pipeline loop
pkintel run all --loop --interval 30
```

Open **`http://localhost:8000`** — the dashboard is served directly from the API.

---

## API Reference

The FastAPI backend auto-generates docs at `/docs` (Swagger UI) and `/redoc`.

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/feeds/stats` | Pipeline totals: URLs, phish, kits, actors, takedowns |
| `GET` | `/api/feeds/live` | Currently live phishing URLs |
| `GET` | `/api/feeds/recent` | Last 50 triaged URLs |
| `GET` | `/api/actors` | All identified threat actor profiles |
| `GET` | `/api/actors/{id}` | Single actor with kit list |
| `GET` | `/api/ioc` | Redacted IOC feed (filterable by type, date) |
| `GET` | `/health` | Health check |
| `GET` | `/metrics` | Prometheus metrics |

---

## Project Structure

```
outpost/
├── src/pkintel/
│   ├── ingest/          # Feed adapters (URLhaus, OpenPhish, CT, GitHub, urlscan)
│   ├── triage/          # Brand detection, favicon hash, form analysis, scoring
│   ├── kithunter/       # Open-dir detection, zip probing, log sighting
│   ├── analyzer/        # Static PHP analysis, indicator extraction, TLSH inventory
│   ├── fingerprint/     # Similarity metrics, union-find clustering, actor graph
│   ├── takedown/        # RDAP enrichment, abuse report templates, email dispatch
│   ├── api/             # FastAPI app + routes (actors, ioc, feeds)
│   ├── cli/             # Typer CLI entry point
│   ├── config.py        # All settings via environment variables
│   ├── db.py            # SKIP LOCKED queue primitives
│   ├── models.py        # Pydantic data models
│   ├── redact.py        # Single path from raw indicator to public string
│   └── storage.py       # Cloudflare R2 / S3 object store
├── analyzer_container/  # Hardened Docker sandbox for kit analysis
├── frontend/            # Static dashboard (HTML / CSS / JS)
├── db/migrations/       # SQL schema (14 tables)
├── tests/               # 107 tests, 0 network calls
├── ops/                 # Prometheus scrape config
├── terraform/           # OCI + Cloudflare infrastructure as code
├── .github/workflows/   # CI (lint + test) and CD (build + deploy)
└── docs/
    └── SCOPE_AND_ETHICS.md
```

---

## Tests

```bash
pytest tests/ -v
```

```
tests/test_analyzer.py      ......     (6)   safe_extract, deobfuscate
tests/test_fingerprint.py   .......   (23)   similarity, clustering, union-find
tests/test_ingest.py        .......   (47)   all feed adapters, normalization
tests/test_kithunter.py     ......     (6)   paths, open-dir, archive detection
tests/test_redact.py        ..         (2)   redaction, hashing
tests/test_takedown.py      .....      (5)   RDAP, templates
tests/test_triage.py        ......    (18)   brand, score, forms, favicon

107 passed in 0.31s
```

Zero tests make network calls. All external dependencies are mocked.

---

## Deployment

Deployed at **`outpost.heapleap.tech`** (and hosted on [Render](https://outpost-27sb.onrender.com)) using:

| Layer | Service | Cost |
|-------|---------|------|
| Frontend & API | [Render](https://render.com) (Web Service) | Free |
| Database | [Neon](https://neon.tech) (Serverless PostgreSQL) | Free |
| Pipeline Workers | [GitHub Actions](https://github.com) (Scheduled Cron Runner) | Free |
| Kit Storage | [Supabase Storage](https://supabase.com) (S3-compatible bucket) | Free |

See the deployment guide in [`docs/DEPLOY.md`](docs/DEPLOY.md) for architectural details.

---

## Ethics & Legal

This is a **passive research tool**. Five hard rules are enforced in code, not just policy:

| Rule | How it is enforced |
|------|--------------------|
| Never execute a kit | Analyzer runs in `--network none` container, pure static reads only |
| Never use an extracted token | No code path makes outbound requests to extracted indicators |
| Never retain victim credentials | Kit hunter stores only SHA256 + byte count of log files, then deletes |
| Redact publicly | `redact.py` is the single path from raw value to any public-facing string |
| Passive collection only | `http.py` throttles per-host; fixed candidate list, no wordlists |

Read the full policy: [`docs/SCOPE_AND_ETHICS.md`](docs/SCOPE_AND_ETHICS.md)

---

## Tech Stack

| Component | Technology |
|-----------|-----------|
| Language | Python 3.12 |
| Web Framework | FastAPI + Uvicorn |
| Queue / DB | PostgreSQL 16 (`SKIP LOCKED`) |
| HTTP Client | HTTPX (async, rate-limited) |
| Archive Safety | Custom zip-slip / tar-slip / bomb guards |
| Fuzzy Hashing | TLSH |
| Clustering | Jaccard similarity + Union-Find |
| Frontend | Vanilla HTML / CSS / JS |
| Infrastructure | Docker Compose, Terraform (OCI + Cloudflare) |
| Observability | Prometheus + Grafana |
| CI/CD | GitHub Actions |

---

<div align="center">

**Built for the frontier, not the perimeter.**

*Passive research only — see [`docs/SCOPE_AND_ETHICS.md`](docs/SCOPE_AND_ETHICS.md)*

</div>
