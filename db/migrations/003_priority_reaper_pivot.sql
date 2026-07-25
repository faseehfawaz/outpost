-- 003 — Priority queueing, stuck-row recovery, and infrastructure pivot edges.
--
-- Three problems this fixes, in order of severity:
--
-- 1. STUCK ROWS (silent queue leak). `claim_rows` flips a row to a busy state
--    and stamps locked_by/locked_at, but nothing ever un-sticks it. A worker
--    that crashes (OOM, SIGKILL, power cut) leaves rows pinned in
--    'triaging'/'hunting'/'analyzing'/'sending' FOREVER. Over months the queue
--    silently drains to nothing while looking healthy. We add the indexes the
--    reaper needs to find them cheaply.
--
-- 2. STRICT FIFO. claim_rows ordered by `id`, so a certstream lookalike hit
--    (minutes old, highest value) queued behind thousands of stale URLs. We add
--    a `priority` column so the newest, most brand-relevant intel is worked
--    first. Higher = sooner.
--
-- 3. KIT-ONLY CLUSTERING. Actors were only linkable via collected kit files,
--    which requires actually landing a .zip — rare. `host_edges` lets us link
--    infrastructure (shared IP / ASN / TLS cert / favicon / exfil channel)
--    so campaigns cluster from URLs alone, with zero kits collected.

BEGIN;

-- ---------------------------------------------------------------------------
-- 1. Priority queueing
-- ---------------------------------------------------------------------------
ALTER TABLE urls ADD COLUMN IF NOT EXISTS priority INT NOT NULL DEFAULT 0;

-- NOTE: single string literal on purpose. Adjacent-literal concatenation is
-- valid Postgres but is not understood by every SQL parser, including the one
-- tests/test_schema_consistency.py uses to validate these migrations.
COMMENT ON COLUMN urls.priority IS 'Work-queue priority, higher first. Set at ingest from source trust + brand match + freshness. See pkintel.ingest.priority.compute_priority().';

-- Partial indexes matching exactly how claim_rows() queries, so the planner can
-- do an index-only scan of just the claimable rows instead of the whole table.
CREATE INDEX IF NOT EXISTS idx_urls_triage_priority
    ON urls (priority DESC, id)
    WHERE triage_state = 'new';

CREATE INDEX IF NOT EXISTS idx_urls_kithunt_priority
    ON urls (priority DESC, id)
    WHERE kithunt_state = 'pending';

-- ---------------------------------------------------------------------------
-- 2. Stuck-row recovery (the reaper)
-- ---------------------------------------------------------------------------
-- The reaper scans for rows in a busy state whose locked_at is older than a
-- lease. These partial indexes keep that scan O(stuck) rather than O(table).
CREATE INDEX IF NOT EXISTS idx_urls_triage_locked
    ON urls (locked_at)
    WHERE triage_state = 'triaging';

CREATE INDEX IF NOT EXISTS idx_urls_kithunt_locked
    ON urls (locked_at)
    WHERE kithunt_state = 'hunting';

CREATE INDEX IF NOT EXISTS idx_kits_locked
    ON kits (locked_at)
    WHERE analysis_state = 'analyzing';

CREATE INDEX IF NOT EXISTS idx_takedowns_locked
    ON takedowns (locked_at)
    WHERE status = 'sending';

-- Count how many times a row has been reaped. A row that repeatedly kills its
-- worker is poison — after N reaps we park it in 'error' instead of looping.
ALTER TABLE urls      ADD COLUMN IF NOT EXISTS reap_count INT NOT NULL DEFAULT 0;
ALTER TABLE kits      ADD COLUMN IF NOT EXISTS reap_count INT NOT NULL DEFAULT 0;
ALTER TABLE takedowns ADD COLUMN IF NOT EXISTS reap_count INT NOT NULL DEFAULT 0;

-- ---------------------------------------------------------------------------
-- 3. Takedown lifecycle — verification & escalation
-- ---------------------------------------------------------------------------
-- Previously a takedown was fire-and-forget: status went 'sent' and we never
-- checked whether the phish actually died. These columns let the verifier
-- re-probe the URL and escalate host -> registrar -> registry/ASN.
ALTER TABLE takedowns ADD COLUMN IF NOT EXISTS verify_after   TIMESTAMPTZ;
ALTER TABLE takedowns ADD COLUMN IF NOT EXISTS verify_count   INT NOT NULL DEFAULT 0;
ALTER TABLE takedowns ADD COLUMN IF NOT EXISTS target_dead_at TIMESTAMPTZ;
ALTER TABLE takedowns ADD COLUMN IF NOT EXISTS escalation_level INT NOT NULL DEFAULT 0;

CREATE INDEX IF NOT EXISTS idx_takedowns_verify
    ON takedowns (verify_after)
    WHERE status = 'sent' AND target_dead_at IS NULL;

-- Prevent the redraft loop: Phase 1 re-queried every cycle with
-- `LEFT JOIN takedowns WHERE t.id IS NULL`, so a URL whose insert partially
-- failed got retried forever. One row per (url, target_type) makes it idempotent.
--
-- Scoped to host/registrar only: those are singletons per URL. 'telegram' is
-- deliberately excluded because a kit can expose several bot tokens and each
-- one warrants its own notice to Telegram's abuse desk.
CREATE UNIQUE INDEX IF NOT EXISTS uq_takedowns_url_target
    ON takedowns (url_id, target_type)
    WHERE url_id IS NOT NULL AND target_type IN ('host', 'registrar');

-- ---------------------------------------------------------------------------
-- 4. Infrastructure pivot edges (cluster without needing a kit)
-- ---------------------------------------------------------------------------
-- Mirrors kit_edges, but over hosts. reason ∈
--   shared_ip | shared_asn | shared_cert | shared_favicon | shared_registrar
--   | shared_exfil | typo_family
CREATE TABLE IF NOT EXISTS host_edges (
    id       BIGSERIAL PRIMARY KEY,
    host_a   TEXT NOT NULL,
    host_b   TEXT NOT NULL,
    reason   TEXT NOT NULL,
    weight   REAL NOT NULL DEFAULT 1.0,
    detail   JSONB NOT NULL DEFAULT '{}'::jsonb,
    seen_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (host_a, host_b, reason),
    CHECK (host_a < host_b)      -- canonical ordering: one row per unordered pair+reason
);

CREATE INDEX IF NOT EXISTS idx_host_edges_a ON host_edges (host_a);
CREATE INDEX IF NOT EXISTS idx_host_edges_b ON host_edges (host_b);
CREATE INDEX IF NOT EXISTS idx_host_edges_reason ON host_edges (reason);

-- Enrichment we can pivot on. hosts already had ip/asn/registrar; add the TLS
-- and visual identifiers that link sibling phishing sites.
ALTER TABLE hosts ADD COLUMN IF NOT EXISTS cert_sha256   TEXT;
ALTER TABLE hosts ADD COLUMN IF NOT EXISTS cert_names    TEXT[] NOT NULL DEFAULT '{}';
ALTER TABLE hosts ADD COLUMN IF NOT EXISTS favicon_mmh3  BIGINT;
ALTER TABLE hosts ADD COLUMN IF NOT EXISTS first_seen    TIMESTAMPTZ NOT NULL DEFAULT now();

CREATE INDEX IF NOT EXISTS idx_hosts_ip       ON hosts (ip)          WHERE ip IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_hosts_asn      ON hosts (asn)         WHERE asn IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_hosts_cert     ON hosts (cert_sha256) WHERE cert_sha256 IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_hosts_favicon  ON hosts (favicon_mmh3) WHERE favicon_mmh3 IS NOT NULL;

-- ---------------------------------------------------------------------------
-- 5. Deep-triage artefacts (rendered DOM, screenshot, cloaking)
-- ---------------------------------------------------------------------------
ALTER TABLE urls ADD COLUMN IF NOT EXISTS screenshot_phash TEXT;
ALTER TABLE urls ADD COLUMN IF NOT EXISTS rendered        BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE urls ADD COLUMN IF NOT EXISTS cloaking_score  REAL;
ALTER TABLE urls ADD COLUMN IF NOT EXISTS exfil_endpoints JSONB NOT NULL DEFAULT '[]'::jsonb;
ALTER TABLE urls ADD COLUMN IF NOT EXISTS llm_verdict     JSONB;

CREATE INDEX IF NOT EXISTS idx_urls_screenshot_phash
    ON urls (screenshot_phash) WHERE screenshot_phash IS NOT NULL;

-- BRIN on time columns: the table is naturally time-ordered by insert, so BRIN
-- gives ~99% smaller indexes than btree for range scans on a 512GB SATA budget.
CREATE INDEX IF NOT EXISTS idx_urls_first_seen_brin ON urls USING BRIN (first_seen);
CREATE INDEX IF NOT EXISTS idx_audit_ts_brin        ON audit_log USING BRIN (ts);

COMMIT;
