-- pkintel schema — the spine.
--
-- Design notes:
--   * The work queue is Postgres itself: SELECT ... FOR UPDATE SKIP LOCKED over
--     the `urls` / `kits` state machines. No Kafka. One node, boring tech.
--   * Raw, messy indicator payloads go in JSONB; everything relational is typed.
--   * We NEVER store victim credentials. `indicators` holds attacker exfil
--     channels (redacted for display); a results-log we stumble on is recorded
--     as existence + hash only (see `victim_log_sightings`), never its contents.

BEGIN;

CREATE EXTENSION IF NOT EXISTS pgcrypto;   -- gen_random_uuid, digest

-- ---------------------------------------------------------------------------
-- Feeds
-- ---------------------------------------------------------------------------
CREATE TABLE sources (
    id            SERIAL PRIMARY KEY,
    name          TEXT NOT NULL UNIQUE,
    kind          TEXT NOT NULL,                 -- ct | urlhaus | openphish | urlscan | github | manual
    last_polled_at TIMESTAMPTZ,
    enabled       BOOLEAN NOT NULL DEFAULT TRUE,
    meta          JSONB NOT NULL DEFAULT '{}'::jsonb
);

-- ---------------------------------------------------------------------------
-- Candidate URLs  (the ingest/triage/kithunt state machine)
-- ---------------------------------------------------------------------------
-- triage_state:  new -> triaging -> triaged | error
-- kithunt_state: pending -> hunting -> collected | none | skipped | error
CREATE TABLE urls (
    id            BIGSERIAL PRIMARY KEY,
    url           TEXT NOT NULL,
    url_hash      TEXT NOT NULL UNIQUE,          -- sha256 of canonical url
    host          TEXT NOT NULL,
    source_id     INT REFERENCES sources(id),
    first_seen    TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen     TIMESTAMPTZ NOT NULL DEFAULT now(),
    http_status   INT,
    is_live       BOOLEAN,

    -- triage results
    triage_state  TEXT NOT NULL DEFAULT 'new',
    is_phish      BOOLEAN,
    phish_score   INT,                           -- 0..100
    brand         TEXT,
    triage_reasons JSONB NOT NULL DEFAULT '[]'::jsonb,
    favicon_mmh3  BIGINT,
    logo_phash    TEXT,
    triaged_at    TIMESTAMPTZ,

    -- kit-hunter results
    kithunt_state TEXT NOT NULL DEFAULT 'pending',
    kithunt_attempts INT NOT NULL DEFAULT 0,
    kithunt_at    TIMESTAMPTZ,

    locked_by     TEXT,                          -- worker id holding this row
    locked_at     TIMESTAMPTZ
);

CREATE INDEX idx_urls_triage_state  ON urls (triage_state)  WHERE triage_state IN ('new', 'triaging');
CREATE INDEX idx_urls_kithunt_state ON urls (kithunt_state) WHERE kithunt_state IN ('pending', 'hunting');
CREATE INDEX idx_urls_is_phish_live ON urls (is_phish, is_live);
CREATE INDEX idx_urls_brand         ON urls (brand);
CREATE INDEX idx_urls_host          ON urls (host);

-- ---------------------------------------------------------------------------
-- Hosts (enrichment: ASN, geo, registrar, RDAP abuse contact)
-- ---------------------------------------------------------------------------
CREATE TABLE hosts (
    id               BIGSERIAL PRIMARY KEY,
    hostname         TEXT NOT NULL UNIQUE,
    ip               INET,
    asn              INT,
    asn_name         TEXT,
    country          TEXT,
    registrar        TEXT,
    cert_issuer      TEXT,
    rdap_abuse_email TEXT,
    enriched_at      TIMESTAMPTZ
);

-- ---------------------------------------------------------------------------
-- Kits  (one collected archive)
-- ---------------------------------------------------------------------------
-- analysis_state: stored -> analyzing -> analyzed | error
CREATE TABLE kits (
    id             BIGSERIAL PRIMARY KEY,
    url_id         BIGINT REFERENCES urls(id),
    sha256         TEXT NOT NULL UNIQUE,          -- of the archive bytes
    size           BIGINT NOT NULL,
    stored_key     TEXT NOT NULL,                 -- object-storage key (quarantined)
    collected_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    file_count     INT,
    source_archive_name TEXT,
    analysis_state TEXT NOT NULL DEFAULT 'stored',
    analyzed_at    TIMESTAMPTZ,
    analysis_error TEXT,
    locked_by      TEXT,
    locked_at      TIMESTAMPTZ
);

CREATE INDEX idx_kits_analysis_state ON kits (analysis_state) WHERE analysis_state IN ('stored', 'analyzing');

-- ---------------------------------------------------------------------------
-- Kit files (inventory)
-- ---------------------------------------------------------------------------
CREATE TABLE kit_files (
    id            BIGSERIAL PRIMARY KEY,
    kit_id        BIGINT NOT NULL REFERENCES kits(id) ON DELETE CASCADE,
    path          TEXT NOT NULL,
    sha256        TEXT NOT NULL,
    tlsh          TEXT,                            -- fuzzy hash (null if too small/uniform)
    normalized_token_hash TEXT,                    -- PHP structural hash (renaming-resistant)
    size          BIGINT NOT NULL,
    mime          TEXT,
    is_obfuscated BOOLEAN NOT NULL DEFAULT FALSE,
    UNIQUE (kit_id, path)
);

CREATE INDEX idx_kit_files_kit    ON kit_files (kit_id);
CREATE INDEX idx_kit_files_sha    ON kit_files (sha256);
CREATE INDEX idx_kit_files_token  ON kit_files (normalized_token_hash);

-- ---------------------------------------------------------------------------
-- Indicators  (attacker exfil channels — REDACTED for display)
-- ---------------------------------------------------------------------------
CREATE TABLE indicators (
    id              BIGSERIAL PRIMARY KEY,
    kit_id          BIGINT NOT NULL REFERENCES kits(id) ON DELETE CASCADE,
    type            TEXT NOT NULL,   -- telegram_token|telegram_chat|discord_webhook|email|smtp|url
    value_hash      TEXT NOT NULL,   -- sha256 of the full value (the linkable key)
    redacted_display TEXT NOT NULL,  -- e.g. "12345***:AAF***" — safe to publish
    full_value_encrypted BYTEA,      -- for abuse-desk reporting only; never surfaced publicly
    confidence      REAL NOT NULL DEFAULT 1.0,
    found_in_path   TEXT,
    meta            JSONB NOT NULL DEFAULT '{}'::jsonb,
    UNIQUE (kit_id, type, value_hash)
);

CREATE INDEX idx_indicators_kit        ON indicators (kit_id);
CREATE INDEX idx_indicators_type_hash  ON indicators (type, value_hash);

-- ---------------------------------------------------------------------------
-- Fingerprints (one row per kit)
-- ---------------------------------------------------------------------------
CREATE TABLE fingerprints (
    id            BIGSERIAL PRIMARY KEY,
    kit_id        BIGINT NOT NULL UNIQUE REFERENCES kits(id) ON DELETE CASCADE,
    fileset_hash  TEXT,                 -- hash of sorted file-sha set
    antibot_hash  TEXT,                 -- hash of the anti-bot blocklist (strong link signal)
    token_hash    TEXT,                 -- hash of concatenated normalized-PHP token hashes
    author_strings TEXT[] NOT NULL DEFAULT '{}',
    file_sha_set  TEXT[] NOT NULL DEFAULT '{}',   -- for Jaccard on demand
    computed_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_fingerprints_antibot ON fingerprints (antibot_hash);
CREATE INDEX idx_fingerprints_fileset ON fingerprints (fileset_hash);

-- ---------------------------------------------------------------------------
-- Actors (connected components of the kit-similarity graph)
-- ---------------------------------------------------------------------------
CREATE TABLE actors (
    id          BIGSERIAL PRIMARY KEY,
    label       TEXT NOT NULL UNIQUE,        -- "Actor #7"
    first_seen  TIMESTAMPTZ,
    last_seen   TIMESTAMPTZ,
    kit_count   INT NOT NULL DEFAULT 0,
    brands      TEXT[] NOT NULL DEFAULT '{}',
    notes       TEXT,
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE kit_actor (
    kit_id       BIGINT NOT NULL REFERENCES kits(id) ON DELETE CASCADE,
    actor_id     BIGINT NOT NULL REFERENCES actors(id) ON DELETE CASCADE,
    edge_reasons TEXT[] NOT NULL DEFAULT '{}',
    PRIMARY KEY (kit_id, actor_id)
);

-- Edges of the similarity graph (kept so the network can be re-clustered/visualised).
CREATE TABLE kit_edges (
    id        BIGSERIAL PRIMARY KEY,
    kit_a     BIGINT NOT NULL REFERENCES kits(id) ON DELETE CASCADE,
    kit_b     BIGINT NOT NULL REFERENCES kits(id) ON DELETE CASCADE,
    reason    TEXT NOT NULL,     -- shared_exfil | jaccard | shared_antibot | shared_author
    weight    REAL NOT NULL DEFAULT 1.0,
    detail    JSONB NOT NULL DEFAULT '{}'::jsonb,
    UNIQUE (kit_a, kit_b, reason),
    CHECK (kit_a < kit_b)        -- canonical ordering, one row per unordered pair+reason
);

CREATE INDEX idx_kit_edges_a ON kit_edges (kit_a);
CREATE INDEX idx_kit_edges_b ON kit_edges (kit_b);

-- ---------------------------------------------------------------------------
-- Takedowns
-- ---------------------------------------------------------------------------
-- status: draft -> sent -> acknowledged -> resolved | rejected
CREATE TABLE takedowns (
    id           BIGSERIAL PRIMARY KEY,
    url_id       BIGINT REFERENCES urls(id),
    kit_id       BIGINT REFERENCES kits(id),
    target_type  TEXT NOT NULL,     -- host | registrar | telegram | gsb | apwg | cert
    contact      TEXT,
    subject      TEXT,
    body         TEXT,
    status       TEXT NOT NULL DEFAULT 'draft',
    sent_at      TIMESTAMPTZ,
    resolved_at  TIMESTAMPTZ,
    meta         JSONB NOT NULL DEFAULT '{}'::jsonb
);

CREATE INDEX idx_takedowns_status ON takedowns (status);

-- ---------------------------------------------------------------------------
-- Victim-log sightings — existence + hash ONLY. Never contents. (ethics)
-- ---------------------------------------------------------------------------
CREATE TABLE victim_log_sightings (
    id           BIGSERIAL PRIMARY KEY,
    url_id       BIGINT REFERENCES urls(id),
    observed_url TEXT NOT NULL,
    content_sha256 TEXT,           -- hash of what we saw, so we can prove we didn't keep it
    approx_size  BIGINT,
    reported_to  TEXT[] NOT NULL DEFAULT '{}',   -- e.g. {host, aeCERT}
    seen_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    deleted_at   TIMESTAMPTZ                       -- when we purged the local copy
);

-- ---------------------------------------------------------------------------
-- Immutable-ish audit log of every outbound/collection action (accountability)
-- ---------------------------------------------------------------------------
CREATE TABLE audit_log (
    id        BIGSERIAL PRIMARY KEY,
    ts        TIMESTAMPTZ NOT NULL DEFAULT now(),
    actor     TEXT NOT NULL,       -- worker/subsystem name
    action    TEXT NOT NULL,       -- fetch | probe | collect | report | delete ...
    target    TEXT,
    detail    JSONB NOT NULL DEFAULT '{}'::jsonb
);

CREATE INDEX idx_audit_ts ON audit_log (ts);

COMMIT;
