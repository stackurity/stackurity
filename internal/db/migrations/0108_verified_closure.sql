-- Verified closure: tell a fix Stackurity saw from a finding that only
-- disappeared.
--
-- collections.absence_unverified marks an empty collection written because
-- Stackurity lost sight of an asset rather than because a check saw the
-- software gone: a GitHub repository no longer granted to the app, a GitLab
-- project that left the connected group, a registry image whose tags were
-- all deleted (it may still run somewhere). Findings closed by such a
-- collection get resolution kind 'disappeared', which is not remediation
-- (internal/store/resolution.go), instead of 'removed'.
--
-- resolution_detail also gains the proof of each new closure (see
-- ResolveRemovedFindings): from_version, collection_id, method, checked_at.
--
-- Adding a column with a constant default rewrites nothing. If a lock is
-- held, this gives up after 10 seconds per lock; run it again later.
SET LOCAL lock_timeout = '10s';
SELECT set_config('stackurity.scope', 'system', true);

ALTER TABLE collections ADD COLUMN absence_unverified boolean NOT NULL DEFAULT false;

-- Past collections of that kind: empty, absence-proving, and noted in
-- coverage history with the reason those three paths write.
UPDATE collections c SET absence_unverified = true
WHERE c.proves_absence AND c.observation_count = 0 AND EXISTS (SELECT 1 FROM coverage_history h
  WHERE h.collection_id = c.id AND h.status = 'skipped' AND (h.reason LIKE 'no longer granted to the Stackurity GitHub App%'
    OR h.reason LIKE 'no longer in the connected GitLab group%' OR h.reason LIKE 'deleted from the registry%'));

-- Findings those collections closed as 'removed': the removing collection is
-- the one whose time is the removal time of the finding's inventory row.
WITH d AS (SELECT f.id, c.id AS collection_id, c.method, c.observed_at
  FROM findings f JOIN inventory i ON i.id = f.inventory_id
  JOIN collections c ON c.asset_id = f.asset_id AND c.absence_unverified AND c.observed_at = i.removed_at
  WHERE f.status = 'resolved' AND f.resolution_kind = 'removed')
UPDATE findings f SET resolution_kind = 'disappeared',
  resolution = 'disappeared: Stackurity can no longer see this asset, so the fix was not verified',
  resolution_detail = f.resolution_detail || jsonb_build_object('collection_id', d.collection_id, 'method', d.method,
    'checked_at', d.observed_at)
FROM d WHERE d.id = f.id;

UPDATE finding_events e SET detail = e.detail || jsonb_build_object('resolution_kind', 'disappeared')
FROM findings f
WHERE e.finding_id = f.id AND e.action = 'resolved' AND e.at = f.resolved_at AND f.resolution_kind = 'disappeared';
