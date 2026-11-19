-- A record of each check of an organisation's software against vulnerability
-- data, so the compliance evidence pack can show how often it happened over
-- a period (docs/evaluation-runs.md). Until now only each component's latest
-- evaluation was kept (inventory.evaluated_at, inventory_evaluations) and
-- finished jobs were purged, so nothing could prove it after the fact.
--
--   feed_sync_runs    one row per sync of a vulnerability, release or
--                     lifecycle source (feeds hold only the latest outcome).
--                     Public intelligence, like feeds: no workspace data.
--   evaluation_runs   one row per evaluation run of a workspace: after a
--                     source changed (feed_sync), after a report (ingest),
--                     the daily full run (daily), and the scheduled check
--                     (scheduled, every 30 minutes) that confirms every source
--                     the workspace's software is checked against was read
--                     on schedule and no re-evaluation is waiting.
--
-- Both are kept 400 days (an audit year and a margin), pruned by the hourly
-- housekeeping task (store.PruneEvaluationRuns). Additive: two new tables.

SET LOCAL lock_timeout = '10s';
SELECT set_config('stackurity.scope', 'system', true);

CREATE TABLE feed_sync_runs (
    id            bigserial PRIMARY KEY,
    feed          text NOT NULL CHECK (feed <> '' AND length(feed) <= 200),
    started_at    timestamptz NOT NULL,
    finished_at   timestamptz NOT NULL DEFAULT now(),
    ok            boolean NOT NULL,
    -- Records the sync changed, and whether it handed components to
    -- re-evaluation.
    changed       integer NOT NULL DEFAULT 0,
    reevaluate    boolean NOT NULL DEFAULT false,
    -- A short class, never the error text (which may name URLs): timeout,
    -- canceled, error.
    error_class   text NOT NULL DEFAULT '' CHECK (length(error_class) <= 40)
);
CREATE INDEX feed_sync_runs_feed ON feed_sync_runs (feed, finished_at);
CREATE INDEX feed_sync_runs_finished ON feed_sync_runs (finished_at);

CREATE TABLE evaluation_runs (
    id               bigserial PRIMARY KEY,
    workspace_id     bigint NOT NULL DEFAULT stackurity_ws() REFERENCES workspaces(id) ON DELETE CASCADE,
    trigger          text NOT NULL CHECK (trigger IN ('feed_sync', 'ingest', 'daily', 'scheduled')),
    started_at       timestamptz NOT NULL,
    finished_at      timestamptz NOT NULL DEFAULT now(),
    -- The sources the run used, as [{"name": "osv:npm", "last_success": "..."}].
    feeds            jsonb NOT NULL DEFAULT '[]' CHECK (jsonb_typeof(feeds) = 'array'),
    assets_evaluated integer NOT NULL DEFAULT 0,
    findings_opened  integer NOT NULL DEFAULT 0,
    findings_closed  integer NOT NULL DEFAULT 0,
    ok               boolean NOT NULL,
    -- feed_stale, feed_failed, evaluation_backlog, timeout, canceled, error.
    error_class      text NOT NULL DEFAULT '' CHECK (length(error_class) <= 40)
);
CREATE INDEX evaluation_runs_period ON evaluation_runs (workspace_id, finished_at);
CREATE INDEX evaluation_runs_finished ON evaluation_runs (finished_at);
ALTER TABLE evaluation_runs ENABLE ROW LEVEL SECURITY, FORCE ROW LEVEL SECURITY;
CREATE POLICY ws ON evaluation_runs USING (workspace_id = stackurity_ws()) WITH CHECK (workspace_id = stackurity_ws());
CREATE POLICY sys ON evaluation_runs USING (stackurity_system()) WITH CHECK (stackurity_system());

-- Runs are a record: the application inserts and reads them, and deletes
-- them only when they are older than the retention period; it never
-- changes one.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'stackurity_app') THEN
        REVOKE UPDATE, TRUNCATE ON evaluation_runs, feed_sync_runs FROM stackurity_app;
    END IF;
END $$;
