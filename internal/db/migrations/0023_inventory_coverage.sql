-- Whether vulnerability intelligence covered a component is now recorded on
-- each inventory row instead of once per component. The installed version,
-- the distro release and the workspace are properties of the row, so a gap
-- found on one asset (an unparseable version, a release without advisories)
-- was cleared again when another asset or workspace with the same package
-- was evaluated, and the component then looked checked everywhere.
--
-- coverage is one of:
--   awaiting       inventoried, not evaluated yet (the default for new rows)
--   evaluated      matched against the feed named in coverage_feed
--   unsupported    no vulnerability source exists for it (coverage_reason says why)
--   not_evaluated  a source exists but could not be used (coverage_reason says why)
SELECT set_config('stackurity.scope', 'system', true);

ALTER TABLE inventory
    ADD COLUMN coverage        text NOT NULL DEFAULT 'awaiting'
        CHECK (coverage IN ('awaiting', 'evaluated', 'unsupported', 'not_evaluated')),
    ADD COLUMN coverage_reason text NOT NULL DEFAULT '',
    ADD COLUMN coverage_feed   text NOT NULL DEFAULT '',
    ADD COLUMN evaluated_at    timestamptz;

-- Carry the old per-component gaps over; everything else current was
-- evaluated by the previous release.
UPDATE inventory i SET
    coverage = CASE
        WHEN g.reason IS NULL THEN 'evaluated'
        WHEN g.reason LIKE 'no vulnerability source%' OR g.reason LIKE 'runtime installed outside%'
          OR g.reason LIKE 'Kubernetes component%' OR g.reason LIKE 'managed service%' THEN 'unsupported'
        ELSE 'not_evaluated' END,
    coverage_reason = COALESCE(g.reason, ''),
    evaluated_at = COALESCE(g.updated_at, now())
FROM inventory x LEFT JOIN evaluation_gaps g ON g.component_id = x.component_id
WHERE x.id = i.id AND i.removed_at IS NULL;

CREATE INDEX inventory_coverage_gaps ON inventory (component_id) WHERE removed_at IS NULL AND coverage IN ('unsupported', 'not_evaluated');

-- evaluation_gaps stays readable (reports and older queries use it) as a view
-- over current rows. security_invoker applies the reader's row-level security
-- to inventory, so a workspace only sees gaps from its own rows.
DROP TABLE evaluation_gaps;
CREATE VIEW evaluation_gaps WITH (security_invoker = true) AS
    SELECT component_id, min(coverage_reason) AS reason, max(evaluated_at) AS updated_at
    FROM inventory
    WHERE removed_at IS NULL AND coverage IN ('unsupported', 'not_evaluated')
    GROUP BY component_id;

-- The ecosystem strings (e.g. "Debian:12", "Ubuntu:Pro:22.04:LTS") a
-- vulnerability feed has advisories for. A release with none is reported as
-- not evaluated instead of clean. NULL until the feed next syncs.
ALTER TABLE feeds ADD COLUMN ecosystems text[];
