-- When Stackurity first had each CVE: the first time a feed that covers
-- every published CVE, whatever the workspaces run, stored it. These are
-- FIRST's EPSS file (every scored CVE, daily) and CISA's KEV catalogue.
-- Advisory feeds are left out on purpose: which ones are synced follows the
-- workspaces' inventories, so their times would tell the public what
-- software the workspaces run. The row is written once and never updated.
--
-- CVEs already stored when this runs get the migration's time with
-- backfilled = true: they were added on or before it, at a time no longer
-- known. The public log lists only exact times.

SET LOCAL lock_timeout = '10s';
SELECT set_config('stackurity.scope', 'system', true);

CREATE TABLE cve_first_seen (
    cve         text PRIMARY KEY,
    first_seen  timestamptz NOT NULL,
    source      text NOT NULL CHECK (source IN ('epss', 'kev')),
    backfilled  boolean NOT NULL DEFAULT false
);
CREATE INDEX cve_first_seen_recent ON cve_first_seen (first_seen DESC) WHERE NOT backfilled;

INSERT INTO cve_first_seen (cve, first_seen, source, backfilled)
SELECT cve, now(), 'kev', true FROM known_exploited
ON CONFLICT (cve) DO NOTHING;
INSERT INTO cve_first_seen (cve, first_seen, source, backfilled)
SELECT cve, now(), 'epss', true FROM epss_scores
ON CONFLICT (cve) DO NOTHING;

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'stackurity_app') THEN
        GRANT SELECT, INSERT ON cve_first_seen TO stackurity_app;
    END IF;
END $$;
