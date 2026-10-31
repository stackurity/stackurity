-- How each asset reports, and what Stackurity expects of it.
--
-- Until now every asset was marked stale 48 hours after its last report and
-- opened its own "Asset X has stopped reporting" incident, whether it was a
-- server whose agent had stopped or a repository scanned once from a laptop.
-- An asset now records its reporting source (the agent, a scan uploaded by
-- the CLI or CI, an integration, or a manual upload in the dashboard) and,
-- from its own history, when its next report is due:
--
--   report_source          the source of its latest report
--   report_integration_id  the integration that reports it, when known
--   report_override        a person's choice: auto, daily, weekly, one_off
--   report_runs            reports seen (an hour apart or more; up to 6);
--                          NULL until the server works it out
--   report_usual           the median gap between them (2 runs or more)
--   report_due_after       how long after its last report it is overdue;
--                          NULL when nothing is expected (scanned once,
--                          or no report at all)
--
-- The server fills report_runs, report_usual and report_due_after on its
-- next stale check or dispatcher cycle (store.RefreshReporting), so the
-- rules live in one place (Go). This migration only backfills the source,
-- and settles what the old rule left behind for assets a scan or upload
-- reported once, or only on one day: they are no longer stale (their results stay "as of"
-- their only report), and their open "stopped reporting" incidents are
-- resolved without a recovery message (resolution "one_off"). Other open
-- per-asset incidents are regrouped by the dispatcher on its next cycle.

SET LOCAL lock_timeout = '10s';
SELECT set_config('stackurity.scope', 'system', true);

ALTER TABLE assets
    ADD COLUMN report_source text NOT NULL DEFAULT ''
        CHECK (report_source IN ('', 'agent', 'scan', 'integration', 'manual')),
    ADD COLUMN report_integration_id bigint REFERENCES integrations(id) ON DELETE SET NULL,
    ADD COLUMN report_override text NOT NULL DEFAULT 'auto'
        CHECK (report_override IN ('auto', 'daily', 'weekly', 'one_off')),
    ADD COLUMN report_runs int,
    ADD COLUMN report_usual interval,
    ADD COLUMN report_due_after interval;

-- The source of each asset's latest report, from what the collection says:
-- the agent's method; a plugin or a server-side Git or image integration;
-- an upload with an API token (the CLI, CI, an agent's app scan); anything
-- else was uploaded in the dashboard.
UPDATE assets a SET report_source = l.src
FROM (SELECT DISTINCT ON (c.asset_id) c.asset_id,
        CASE WHEN c.method = 'agent' THEN 'agent'
             WHEN c.method IN ('plugin', 'repository') THEN 'integration'
             WHEN c.submitted_by IS NOT NULL THEN 'scan'
             WHEN c.method = 'scanner' THEN 'integration'
             ELSE 'manual' END AS src
      FROM collections c
      ORDER BY c.asset_id, c.received_at DESC, c.id DESC) l
WHERE l.asset_id = a.id;

UPDATE assets a SET report_integration_id = i.id
FROM integrations i
WHERE i.asset_id = a.id AND i.workspace_id = a.workspace_id AND a.report_source = 'integration';

-- A plugin's assets name the plugin in their collector id; the integration
-- is known when the workspace runs that plugin once.
UPDATE assets a SET report_integration_id = p.id
FROM (SELECT DISTINCT ON (c.asset_id) c.asset_id, c.collector_id
      FROM collections c WHERE c.method = 'plugin'
      ORDER BY c.asset_id, c.received_at DESC, c.id DESC) l,
     (SELECT workspace_id, config->>'plugin' AS plugin, min(id) AS id
      FROM integrations WHERE kind = 'plugin'
      GROUP BY workspace_id, config->>'plugin' HAVING count(*) = 1) p
WHERE l.asset_id = a.id AND a.report_integration_id IS NULL AND a.report_source = 'integration'
  AND p.workspace_id = a.workspace_id AND l.collector_id = 'plugin:' || p.plugin;

-- Assets a scan or upload reported once: without a cadence to learn
-- (store.Learned), fewer than 3 runs (reports an hour apart or more), or
-- all within a day of the first report, as when a scan is re-run by hand a
-- few times on the day it is set up.
CREATE TEMP TABLE once ON COMMIT DROP AS
SELECT a.id, a.workspace_id, a.collection_status = 'stale' AS was_stale
FROM assets a
WHERE a.merged_into IS NULL AND a.report_source IN ('scan', 'manual')
  AND NOT EXISTS (
    SELECT 1 FROM (
      SELECT count(*) FILTER (WHERE g.gap IS NULL OR g.gap >= interval '1 hour') AS runs,
             max(g.received_at) - min(g.received_at) AS span
      FROM (SELECT c.received_at, c.received_at - lag(c.received_at) OVER (ORDER BY c.received_at) AS gap
            FROM collections c WHERE c.asset_id = a.id) g) r
    WHERE r.runs >= 3 AND r.span >= interval '24 hours');

UPDATE assets a SET collection_status = CASE WHEN COALESCE((SELECT c.complete FROM collections c WHERE c.asset_id = a.id
        ORDER BY c.received_at DESC, c.id DESC LIMIT 1), true) THEN 'ok' ELSE 'partial' END
WHERE a.collection_status = 'stale' AND a.id IN (SELECT id FROM once);

-- Their findings were scored as stale (× 0.8): evaluate them again.
INSERT INTO jobs (workspace_id, kind, payload, dedupe_key, run_at)
SELECT workspace_id, 'evaluate', jsonb_build_object('asset_id', id), 'evaluate:asset:' || id, now()
FROM once WHERE was_stale
ON CONFLICT DO NOTHING;

-- resolved_notified: the dispatcher announces no recovery for it. A Jira,
-- PagerDuty or ServiceNow record still closes, saying why.
UPDATE incidents i SET status = 'resolved', resolved_at = now(), updated_at = now(), resolved_notified = true,
    detail = i.detail || jsonb_build_object('resolution', 'one_off', 'asset_kind', a.kind)
FROM assets a
WHERE i.status = 'open' AND i.kind = 'collection' AND i.key ~ '^asset:[0-9]+$'
  AND a.id = substring(i.key FROM 7)::bigint AND a.id IN (SELECT id FROM once);

-- The dispatcher and the stale check look for assets not worked out yet
-- every cycle, and for a recently closed reporting incident an asset was in.
CREATE INDEX assets_report_pending ON assets (id) WHERE report_runs IS NULL;
CREATE INDEX incidents_reporting_resolved ON incidents (resolved_at)
    WHERE kind = 'collection' AND status = 'resolved' AND key LIKE 'reporting:%';
