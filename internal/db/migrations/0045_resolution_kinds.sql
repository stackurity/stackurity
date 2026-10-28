-- Why a finding closed, machine-readable (internal/store/resolution.go).
-- Reports count only remediated and removed findings as remediation; a
-- finding closed because its advisory was withdrawn or changed, while the
-- installed version stayed the same, is not.
--
--   remediated          the installed version changed (upgrade, verified remediation plan)
--   removed             a complete inventory no longer lists the component
--   superseded          upgraded to a version that is still affected (the issue continues as another finding)
--   advisory_withdrawn  every advisory behind the finding was withdrawn by its source
--   advisory_changed    the advisory or lifecycle data no longer lists the installed version
--   not_evaluated       the row could no longer be evaluated
--   other               an older resolution that could not be classified
--
-- resolution_detail holds the facts: advisories, source, withdrawn_at,
-- package, version, plan_id, successor.
--
-- Adding columns with constant defaults rewrites nothing. If a lock is held
-- (a long report or backup), this gives up after 10 seconds per lock; run it
-- again in a quieter moment (a migration is one transaction).
SET LOCAL lock_timeout = '10s';
SELECT set_config('stackurity.scope', 'system', true);

ALTER TABLE findings ADD COLUMN resolution_kind text NOT NULL DEFAULT '',
    ADD COLUMN resolution_detail jsonb NOT NULL DEFAULT '{}';

-- Backfill, from the sentence the matcher wrote and the inventory history.
--
-- "fixed by remediation plan #N (upgraded to V)" and "upgraded to V" are
-- remediated, unless the same issue was open on the same asset, component
-- and location (on the new version) when the finding closed: then the
-- upgrade left it affected (superseded).
UPDATE findings f SET
    resolution_kind = CASE WHEN EXISTS (SELECT 1 FROM findings p
        JOIN inventory pi ON pi.id = p.inventory_id JOIN inventory fi ON fi.id = f.inventory_id AND fi.location = pi.location
        WHERE p.asset_id = f.asset_id AND p.component_id = f.component_id AND p.key = f.key AND p.kind = f.kind AND p.id <> f.id
          AND p.first_seen <= f.resolved_at AND (p.status = 'open' OR p.resolved_at > f.resolved_at))
      THEN 'superseded' ELSE 'remediated' END,
    resolution_detail = jsonb_strip_nulls(jsonb_build_object(
      'plan_id', (substring(f.resolution FROM '^fixed by remediation plan #([0-9]+)'))::bigint,
      'version', COALESCE(substring(f.resolution FROM '\(upgraded to (.*)\)$'), substring(f.resolution FROM '^upgraded to (.*)$'))))
WHERE f.status = 'resolved' AND (f.resolution LIKE 'fixed by remediation plan #%' OR f.resolution LIKE 'upgraded to %');

UPDATE findings f SET resolution_kind = 'removed'
WHERE f.status = 'resolved' AND f.resolution = 'component no longer installed';

-- "no longer affected (re-evaluated D)" was written by an evaluation of an
-- installed inventory row: the version did not change. Each inventory row
-- is one version, so the row still being installed when the finding closed
-- shows that. It is advisory_withdrawn when every advisory behind the
-- finding is withdrawn, advisory_changed otherwise (including lifecycle
-- data). A row already gone when it closed (never written that way) is
-- left as other.
WITH g AS (SELECT f.id, x.kind, x.resolution, x.detail
FROM findings f JOIN inventory i ON i.id = f.inventory_id JOIN components c ON c.id = f.component_id,
LATERAL (SELECT count(*) AS total, count(a.withdrawn) AS withdrawn, max(a.withdrawn) AS withdrawn_at, min(a.feed) AS feed,
    string_agg(DISTINCT CASE WHEN a.id LIKE 'UBUNTU-%' OR a.id LIKE 'USN-%' THEN 'Ubuntu'
      WHEN a.id LIKE 'GHSA-%' THEN 'GitHub'
      WHEN a.id LIKE 'DEBIAN-%' OR a.id LIKE 'DSA-%' OR a.id LIKE 'DLA-%' OR a.id LIKE 'DTSA-%' THEN 'Debian'
      WHEN a.id LIKE 'RHSA-%' OR a.id LIKE 'RHBA-%' OR a.id LIKE 'RHEA-%' THEN 'Red Hat'
      WHEN a.id LIKE 'SUSE-%' OR a.id LIKE 'openSUSE-%' THEN 'SUSE'
      WHEN a.id LIKE 'ALSA-%' THEN 'AlmaLinux'
      WHEN a.id LIKE 'RLSA-%' THEN 'Rocky Linux'
      WHEN a.id LIKE 'ALAS%' THEN 'Amazon Linux'
      ELSE regexp_replace(a.feed, '^[^:]*:', '') END, ' and ') FILTER (WHERE a.withdrawn IS NOT NULL) AS source
    FROM advisories a WHERE a.id = ANY(f.sources)) adv,
LATERAL (SELECT CASE WHEN f.kind = 'vulnerability' AND adv.total > 0 AND adv.withdrawn = adv.total
      THEN 'advisory_withdrawn' ELSE 'advisory_changed' END AS kind,
    COALESCE(NULLIF(f.evidence->>'osv_package', ''), c.name) AS package,
    CASE WHEN cardinality(f.sources) > 0 THEN array_to_string(f.sources, ', ') ELSE f.key END AS ids) k,
LATERAL (SELECT k.kind,
    CASE WHEN k.kind = 'advisory_withdrawn'
      THEN 'advisory withdrawn by ' || adv.source || ' on ' || to_char(adv.withdrawn_at AT TIME ZONE 'UTC', 'YYYY-MM-DD')
    WHEN f.kind = 'end_of_life' THEN 'lifecycle data updated: ' || k.package || ' ' || i.version || ' is no longer listed as end of life'
    ELSE 'advisory updated: ' || k.ids || ' no longer lists ' || k.package || ' ' || i.version END AS resolution,
    jsonb_strip_nulls(jsonb_build_object('advisories', CASE WHEN f.kind = 'vulnerability' THEN to_jsonb(f.sources) END,
      'source', CASE WHEN k.kind = 'advisory_withdrawn' THEN adv.source END,
      'feed', CASE WHEN k.kind = 'advisory_withdrawn' THEN adv.feed END,
      'withdrawn_at', CASE WHEN k.kind = 'advisory_withdrawn' THEN adv.withdrawn_at END,
      'package', k.package, 'version', i.version)) AS detail) x
WHERE f.status = 'resolved' AND f.resolution LIKE 'no longer affected%'
  AND (i.removed_at IS NULL OR i.removed_at > f.resolved_at))
UPDATE findings f SET resolution_kind = g.kind, resolution = g.resolution, resolution_detail = g.detail
FROM g WHERE f.id = g.id;

UPDATE findings SET resolution_kind = 'other' WHERE status = 'resolved' AND resolution_kind = '';

-- The finding's last 'resolved' event (written with the finding, so at the
-- same time) carries the kind too; its note keeps what was written then.
UPDATE finding_events e SET detail = e.detail || jsonb_build_object('resolution_kind', f.resolution_kind) || f.resolution_detail
FROM findings f
WHERE e.finding_id = f.id AND e.action = 'resolved' AND e.at = f.resolved_at AND f.status = 'resolved';
