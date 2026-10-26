-- The findings list, its counts and the summary tiles read every open
-- finding. Rows are wide (evidence and priority factors), so a scan of the
-- table read hundreds of megabytes on a workspace with 130,000 findings and
-- took seconds.
--
-- findings_open_cover answers counts and the summary from the index alone
-- (an index-only scan): every column they filter, group or count on is in
-- it (key and fix_group for the action plan's unique issues), and
-- workspace_id is included for the row-level security check.
CREATE INDEX findings_open_cover ON findings (asset_id, priority, state, severity, kind, verification)
    INCLUDE (workspace_id, sos, fix_due, assignee_user_id, assignee_team_id, fix_group, key)
    WHERE status = 'open';

-- findings_open_order matches the list's default order exactly, so the first
-- page is read in order and stops after the page instead of sorting every
-- open finding. Keep it in step with the ORDER BY in store.ListFindings.
CREATE INDEX findings_open_order ON findings (
    sos DESC,
    priority,
    (COALESCE((evidence->>'known_exploited')::boolean, false)) DESC,
    (CASE severity WHEN 'critical' THEN 5 WHEN 'high' THEN 4 WHEN 'medium' THEN 3 WHEN 'low' THEN 2 WHEN 'unknown' THEN 1 ELSE 0 END) DESC,
    score DESC NULLS LAST,
    first_seen DESC,
    id
) WHERE status = 'open';

-- Small partial indexes for the summary's known-exploited and fix-available
-- counts, which otherwise read the evidence of every open finding.
CREATE INDEX findings_open_exploited ON findings (asset_id) INCLUDE (workspace_id)
    WHERE status = 'open' AND (evidence->>'known_exploited')::boolean;
CREATE INDEX findings_open_fixable ON findings (asset_id) INCLUDE (workspace_id)
    WHERE status = 'open' AND fixed_version <> '';
