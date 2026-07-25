-- 004 — Host enrichment state machine.
--
-- Why this exists
-- ---------------
-- Migration 003 added the pivot columns (hosts.cert_sha256, .cert_names,
-- .favicon_mmh3) and the host_edges table, and pkintel.fingerprint.pivot reads
-- them to cluster campaigns from infrastructure. But nothing was *populating*
-- them: the only writer of hosts.* is the RDAP path in takedown/rdap.py, which
-- runs late in the pipeline and only for URLs that actually reached takedown.
--
-- Net effect: the pivot graph could only ever see a fraction of hosts, and the
-- two strongest pivot signals (shared TLS certificate, shared IP) were almost
-- entirely absent — the exact signals the pivot exists to exploit.
--
-- This adds a proper enrichment queue over `hosts` so every confirmed-phish
-- host gets resolved, fingerprinted and ASN-mapped, using the same
-- claim/lease/reap machinery as every other stage.

BEGIN;

-- ---------------------------------------------------------------------------
-- Enrichment state machine on hosts
-- ---------------------------------------------------------------------------
-- enrich_state: pending -> enriching -> enriched | error
ALTER TABLE hosts ADD COLUMN IF NOT EXISTS enrich_state TEXT NOT NULL DEFAULT 'pending';
ALTER TABLE hosts ADD COLUMN IF NOT EXISTS locked_by    TEXT;
ALTER TABLE hosts ADD COLUMN IF NOT EXISTS locked_at    TIMESTAMPTZ;
ALTER TABLE hosts ADD COLUMN IF NOT EXISTS reap_count   INT NOT NULL DEFAULT 0;
ALTER TABLE hosts ADD COLUMN IF NOT EXISTS enrich_error TEXT;

-- `hosts` has no priority column; claim_rows() must be called with
-- order_by="id" for this table.
CREATE INDEX IF NOT EXISTS idx_hosts_enrich_state
    ON hosts (id)
    WHERE enrich_state = 'pending';

CREATE INDEX IF NOT EXISTS idx_hosts_enrich_locked
    ON hosts (locked_at)
    WHERE enrich_state = 'enriching';

-- Re-enrichment: attacker infrastructure rotates constantly. A host enriched
-- three weeks ago tells us about three-week-old infrastructure, which is worse
-- than useless for pivoting because it links current hosts to stale IPs.
CREATE INDEX IF NOT EXISTS idx_hosts_enriched_at
    ON hosts (enriched_at)
    WHERE enrich_state = 'enriched';

-- ---------------------------------------------------------------------------
-- Additional pivot-relevant columns
-- ---------------------------------------------------------------------------
-- All IPs a hostname resolves to, not just the first. Fast-flux and
-- round-robin campaigns are invisible if we only keep one.
ALTER TABLE hosts ADD COLUMN IF NOT EXISTS ips           INET[] NOT NULL DEFAULT '{}';
ALTER TABLE hosts ADD COLUMN IF NOT EXISTS cert_not_before TIMESTAMPTZ;
ALTER TABLE hosts ADD COLUMN IF NOT EXISTS cert_not_after  TIMESTAMPTZ;
-- Certificates issued within minutes of each other, by the same issuer, for
-- lookalikes of the same brand, are near-certainly one batch by one operator.
ALTER TABLE hosts ADD COLUMN IF NOT EXISTS nameservers   TEXT[] NOT NULL DEFAULT '{}';

CREATE INDEX IF NOT EXISTS idx_hosts_cert_not_before
    ON hosts (cert_not_before) WHERE cert_not_before IS NOT NULL;

COMMIT;
