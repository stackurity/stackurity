-- EPSS through every CVE of an advisory.
--
-- advisories.upstream: the ids an OSV record lists as "upstream".
-- Distribution advisories (DSA, RHSA, RLSA, SUSE-SU) name the CVEs they fix
-- there rather than in "aliases", often several (an RHSA can list
-- hundreds). Only the lowest CVE was kept, as the group key. Rows are filled
-- as each record is next stored by its feed's sync (a record with upstream
-- ids has a new content hash, so the sync rewrites it once).
--
-- findings.epss_cve: the CVE whose EPSS a finding uses, when it is not the
-- finding's key: the highest-scored among the key and its advisories'
-- aliases and upstream ids, chosen at prioritisation. Only the CVE is
-- stored, not its score, which FIRST changes daily for most CVEs; the score
-- is read by the CVE, the primary key of epss_scores.
--
-- Adding nullable or constant-default columns rewrites neither table.

SET LOCAL lock_timeout = '10s';
SELECT set_config('stackurity.scope', 'system', true);

ALTER TABLE advisories ADD COLUMN IF NOT EXISTS upstream text[] NOT NULL DEFAULT '{}';
ALTER TABLE findings ADD COLUMN IF NOT EXISTS epss_cve text;

-- The findings list's epss_min filter starts from the CVEs at or above the
-- minimum (few) and finds their findings by this expression, as it found
-- them by key (findings_key) before. epss_cve changes rarely, so updates of
-- a finding's priority still leave the index alone. Building it holds a
-- write lock on findings for a few seconds on a large installation.
CREATE INDEX IF NOT EXISTS findings_epss_cve ON findings ((COALESCE(epss_cve, key)));
