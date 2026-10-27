-- Two notification additions. Everything here is additive: one CHECK
-- constraint is widened and one table is created; no row is rewritten.

-- 1. Routes can send urgent messages only, with no daily or weekly summary.
ALTER TABLE routes DROP CONSTRAINT routes_mode_check;
ALTER TABLE routes ADD CONSTRAINT routes_mode_check
    CHECK (mode IN ('urgent_summary', 'urgent_only', 'daily', 'weekly'));

-- 2. Jira routes limited to a project. Such a route keeps its own issue per
-- incident, describing only that project's part of it (its findings,
-- assets, counts and links), built under a connection narrowed to the
-- project (stackurity.project) so row-level security enforces it. The
-- whole-incident issues of unscoped routes stay in incident_issues,
-- unchanged.
--
-- A row is created before its issue, as a short claim (creating_until), so
-- replicas and retries never create two issues for one incident; the issue
-- also carries a label naming the workspace, incident, route and project,
-- searched for before creating. The label differs from an unscoped issue's,
-- so the two never find each other's issue in a shared Jira project.
-- Deleting the route, its project or its channel deletes the rows: nothing
-- else describes the issue.
CREATE TABLE route_issues (
    id               bigserial PRIMARY KEY,
    workspace_id     bigint NOT NULL DEFAULT stackurity_ws() REFERENCES workspaces(id) ON DELETE CASCADE,
    route_id         bigint NOT NULL REFERENCES routes(id) ON DELETE CASCADE,
    project_id       bigint NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    channel_id       bigint NOT NULL REFERENCES channels(id) ON DELETE CASCADE,
    incident_id      bigint NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
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
    UNIQUE (route_id, project_id, channel_id, incident_id)
);
CREATE INDEX route_issues_incident ON route_issues (incident_id);
CREATE INDEX route_issues_workspace ON route_issues (workspace_id);
ALTER TABLE route_issues ENABLE ROW LEVEL SECURITY, FORCE ROW LEVEL SECURITY;
-- Like incident_issues (0032): tracker issues are for organisation-wide
-- roles and the dispatcher; a narrowed connection sees none and writes none.
CREATE POLICY ws ON route_issues
    USING (workspace_id = stackurity_ws() AND (SELECT stackurity_narrowed()) IS NOT TRUE)
    WITH CHECK (workspace_id = stackurity_ws() AND (SELECT stackurity_narrowed()) IS NOT TRUE);
CREATE POLICY sys ON route_issues USING (stackurity_system()) WITH CHECK (stackurity_system());

-- Every reference names a row of the same workspace (see 0025).
CREATE TRIGGER route_issues_route_id_same_ws BEFORE INSERT OR UPDATE OF route_id ON route_issues
    FOR EACH ROW EXECUTE FUNCTION stackurity_same_workspace('routes', 'route_id');
CREATE TRIGGER route_issues_project_id_same_ws BEFORE INSERT OR UPDATE OF project_id ON route_issues
    FOR EACH ROW EXECUTE FUNCTION stackurity_same_workspace('projects', 'project_id');
CREATE TRIGGER route_issues_channel_id_same_ws BEFORE INSERT OR UPDATE OF channel_id ON route_issues
    FOR EACH ROW EXECUTE FUNCTION stackurity_same_workspace('channels', 'channel_id');
CREATE TRIGGER route_issues_incident_id_same_ws BEFORE INSERT OR UPDATE OF incident_id ON route_issues
    FOR EACH ROW EXECUTE FUNCTION stackurity_same_workspace('incidents', 'incident_id');
