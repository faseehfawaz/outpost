-- 006_audit_fixes.sql
-- Fixes from OUTPOST_AUDIT_2026-08-04.md
-- P1-6:  kithunt_state default race condition
-- P1-13: missing index on takedowns.url_id
-- P2-32: split reap_count into per-stage counters

BEGIN;

-- P1-6: Change default so new URLs land in 'waiting' (not claimable by kithunter)
-- until triage explicitly sets kithunt_state = 'pending'.
ALTER TABLE urls ALTER COLUMN kithunt_state SET DEFAULT 'waiting';

-- Back-fill: any untriaged URL currently sitting in 'pending' was never meant
-- to be claimed by kithunter.  Move it to 'waiting'.
--
-- triage_state is one of: new | triaging | triaged | error.  An earlier draft
-- of this migration matched IN ('new', 'pending') -- 'pending' is not a triage
-- state at all, and 'triaging' (rows mid-flight, the ones most likely to be
-- racing right now) was missed.
UPDATE urls
SET kithunt_state = 'waiting'
WHERE triage_state IN ('new', 'triaging', 'error')
  AND kithunt_state = 'pending';

-- P1-13: Plain index on takedowns.url_id for the anti-join in takedown/runner.py
-- (the existing partial unique index uq_takedowns_url_target cannot serve this).
CREATE INDEX IF NOT EXISTS idx_takedowns_url_id ON takedowns (url_id);

-- P2-32: Split the shared reap_count into per-stage counters so triage and
-- kithunt reaps don't poison each other's poison-row parking threshold.
ALTER TABLE urls ADD COLUMN IF NOT EXISTS reap_count_triage  INTEGER NOT NULL DEFAULT 0;
ALTER TABLE urls ADD COLUMN IF NOT EXISTS reap_count_kithunt INTEGER NOT NULL DEFAULT 0;

-- Seed the new columns from the existing shared counter.
UPDATE urls SET reap_count_triage  = reap_count WHERE reap_count > 0;
UPDATE urls SET reap_count_kithunt = reap_count WHERE reap_count > 0;

COMMIT;
