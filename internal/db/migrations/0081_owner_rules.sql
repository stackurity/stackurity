-- Owner rules (docs/design/owner-rules.md): who new issues are assigned to,
-- by project, asset and tech stack. Additive: one table, three columns on
-- findings and one partial index.
--
-- A rule names a scope (the organisation, one project or one asset), an
-- optional part of the stack (a layer such as "os" or "web_server", a
-- package name pattern, or both) and who owns it (a person, a team or
-- both). The most specific rule that matches an issue assigns it.
--
-- Findings remember how they were assigned: owner_rule_id is the rule that
-- assigned them, assignment_manual that a person did (rules never change
-- those), owner_checked_at when the rules last looked at them.
SELECT set_config('stackurity.scope', 'system', true);

CREATE TABLE owner_rules (
    id           bigserial PRIMARY KEY,
    workspace_id bigint NOT NULL DEFAULT stackurity_ws() REFERENCES workspaces(id) ON DELETE CASCADE,
    project_id   bigint REFERENCES projects(id) ON DELETE CASCADE,
    asset_id     bigint REFERENCES assets(id) ON DELETE CASCADE,
    layer        text NOT NULL DEFAULT '' CHECK (layer IN ('', 'web_server', 'cms', 'os', 'runtime', 'data_store',
                     'libraries', 'declared', 'managed_service', 'platform', 'other')),
    component    text NOT NULL DEFAULT '' CHECK (length(component) <= 200),
    user_id      bigint REFERENCES users(id) ON DELETE CASCADE,
    team_id      bigint REFERENCES teams(id) ON DELETE CASCADE,
    note         text NOT NULL DEFAULT '' CHECK (length(note) <= 500),
    created_at   timestamptz NOT NULL DEFAULT now(),
    created_by   bigint REFERENCES users(id) ON DELETE SET NULL,
    -- clock_timestamp() when written: issues checked before it are checked again.
    updated_at   timestamptz NOT NULL DEFAULT clock_timestamp(),
    CHECK (num_nonnulls(project_id, asset_id) <= 1),
    CHECK (num_nonnulls(user_id, team_id) >= 1)
);
CREATE INDEX owner_rules_workspace ON owner_rules (workspace_id);
CREATE INDEX owner_rules_project ON owner_rules (project_id) WHERE project_id IS NOT NULL;
CREATE INDEX owner_rules_asset ON owner_rules (asset_id) WHERE asset_id IS NOT NULL;
CREATE TRIGGER owner_rules_project_id_same_ws BEFORE INSERT OR UPDATE OF project_id ON owner_rules
    FOR EACH ROW EXECUTE FUNCTION stackurity_same_workspace('projects', 'project_id');
CREATE TRIGGER owner_rules_asset_id_same_ws BEFORE INSERT OR UPDATE OF asset_id ON owner_rules
    FOR EACH ROW EXECUTE FUNCTION stackurity_same_workspace('assets', 'asset_id');
CREATE TRIGGER owner_rules_user_id_same_ws BEFORE INSERT OR UPDATE OF user_id ON owner_rules
    FOR EACH ROW EXECUTE FUNCTION stackurity_same_workspace('users', 'user_id');
CREATE TRIGGER owner_rules_team_id_same_ws BEFORE INSERT OR UPDATE OF team_id ON owner_rules
    FOR EACH ROW EXECUTE FUNCTION stackurity_same_workspace('teams', 'team_id');
ALTER TABLE owner_rules ENABLE ROW LEVEL SECURITY, FORCE ROW LEVEL SECURITY;
CREATE POLICY ws ON owner_rules USING (workspace_id = stackurity_ws()) WITH CHECK (workspace_id = stackurity_ws());
CREATE POLICY sys ON owner_rules USING (stackurity_system()) WITH CHECK (stackurity_system());

ALTER TABLE findings
    ADD COLUMN owner_rule_id     bigint REFERENCES owner_rules(id) ON DELETE SET NULL,
    ADD COLUMN assignment_manual boolean NOT NULL DEFAULT false,
    ADD COLUMN owner_checked_at  timestamptz;

-- Everything assigned so far was assigned by a person.
UPDATE findings SET assignment_manual = true WHERE assignee_user_id IS NOT NULL OR assignee_team_id IS NOT NULL;

-- Open issues the rules may still assign, by when they were last checked.
CREATE INDEX findings_owner_pending ON findings (workspace_id, (COALESCE(owner_checked_at, '-infinity'::timestamptz)))
    WHERE status = 'open' AND NOT assignment_manual AND assignee_user_id IS NULL AND assignee_team_id IS NULL;
CREATE INDEX findings_owner_rule ON findings (owner_rule_id) WHERE owner_rule_id IS NOT NULL;
