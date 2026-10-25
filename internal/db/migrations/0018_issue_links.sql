-- Issue tracker channels (Jira). A channel of this kind keeps one issue per
-- incident in step with it, instead of posting one message per event.
ALTER TABLE channels DROP CONSTRAINT channels_kind_check;
ALTER TABLE channels ADD CONSTRAINT channels_kind_check CHECK (kind IN ('email', 'slack', 'teams', 'webhook', 'jira'));

-- The issue an incident has in a tracker channel, and what the issue was last
-- told (priority, counts, resolution), so changes are commented once. The row
-- is created before the issue, as a short claim (creating_until), so replicas
-- and retries never create two issues for one incident; the issue also
-- carries a label naming the workspace and incident, which is searched for
-- before creating in case a previous attempt created it but died before
-- recording it here. Deleting the channel keeps the link for the dashboard.
CREATE TABLE incident_issues (
    id               bigserial PRIMARY KEY,
    workspace_id     bigint NOT NULL DEFAULT stackurity_ws() REFERENCES workspaces(id) ON DELETE CASCADE,
    incident_id      bigint NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
    channel_id       bigint REFERENCES channels(id) ON DELETE SET NULL,
    tracker          text NOT NULL DEFAULT 'jira',
    issue_key        text NOT NULL DEFAULT '',   -- empty while being created
    issue_url        text NOT NULL DEFAULT '',
    synced_priority  text NOT NULL DEFAULT '',
    synced_findings  int NOT NULL DEFAULT 0,
    synced_assets    int NOT NULL DEFAULT 0,
    resolved_synced  boolean NOT NULL DEFAULT false,
    creating_until   timestamptz,
    created_at       timestamptz NOT NULL DEFAULT now(),
    updated_at       timestamptz NOT NULL DEFAULT now(),
    UNIQUE (channel_id, incident_id)
);
CREATE INDEX incident_issues_incident ON incident_issues (incident_id);
CREATE INDEX incident_issues_workspace ON incident_issues (workspace_id);
ALTER TABLE incident_issues ENABLE ROW LEVEL SECURITY, FORCE ROW LEVEL SECURITY;
CREATE POLICY ws ON incident_issues USING (workspace_id = stackurity_ws()) WITH CHECK (workspace_id = stackurity_ws());
CREATE POLICY sys ON incident_issues USING (stackurity_system()) WITH CHECK (stackurity_system());
