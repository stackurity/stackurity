-- Notifications at three levels, like groups and projects in GitLab
-- (docs/design/projects.md, "Notifications of projects and assets"):
-- a route (rule) and a channel belong to the organisation (both owners
-- NULL), to a project or to an asset. The organisation's rules apply to
-- every project and asset; a project or asset can turn an inherited rule
-- off for itself (route_exclusions) or replace it with its own copy
-- (inherits_route_id), and add rules of its own.

SET LOCAL lock_timeout = '10s';
SELECT set_config('stackurity.scope', 'system', true);

ALTER TABLE routes
    ADD COLUMN owner_project_id  bigint REFERENCES projects(id) ON DELETE CASCADE,
    ADD COLUMN owner_asset_id    bigint REFERENCES assets(id) ON DELETE CASCADE,
    ADD COLUMN inherits_route_id bigint REFERENCES routes(id) ON DELETE SET NULL,
    ADD CONSTRAINT routes_one_owner CHECK (num_nonnulls(owner_project_id, owner_asset_id) <= 1),
    -- A project's rule hears about that project's assets only.
    ADD CONSTRAINT routes_project_owner_scope CHECK (owner_project_id IS NULL OR project_ids = ARRAY[owner_project_id]),
    ADD CONSTRAINT routes_asset_owner_scope CHECK (owner_asset_id IS NULL OR cardinality(project_ids) = 0);
CREATE INDEX routes_owner_project ON routes (owner_project_id) WHERE owner_project_id IS NOT NULL;
CREATE INDEX routes_owner_asset ON routes (owner_asset_id) WHERE owner_asset_id IS NOT NULL;
CREATE INDEX routes_inherits ON routes (inherits_route_id) WHERE inherits_route_id IS NOT NULL;

ALTER TABLE channels
    ADD COLUMN owner_project_id bigint REFERENCES projects(id) ON DELETE CASCADE,
    ADD COLUMN owner_asset_id   bigint REFERENCES assets(id) ON DELETE CASCADE,
    ADD CONSTRAINT channels_one_owner CHECK (num_nonnulls(owner_project_id, owner_asset_id) <= 1);
CREATE INDEX channels_owner_project ON channels (owner_project_id) WHERE owner_project_id IS NOT NULL;
CREATE INDEX channels_owner_asset ON channels (owner_asset_id) WHERE owner_asset_id IS NOT NULL;

-- Names are unique per owner: two projects may both have a rule "Urgent".
ALTER TABLE routes DROP CONSTRAINT routes_name_key;
CREATE UNIQUE INDEX routes_name_key ON routes (workspace_id, COALESCE(owner_project_id, 0), COALESCE(owner_asset_id, 0), name);
ALTER TABLE channels DROP CONSTRAINT channels_name_key;
CREATE UNIQUE INDEX channels_name_key ON channels (workspace_id, COALESCE(owner_project_id, 0), COALESCE(owner_asset_id, 0), name);

DO $$
DECLARE
    r record;
BEGIN
    FOR r IN SELECT * FROM (VALUES
        ('routes', 'owner_project_id', 'projects'),
        ('routes', 'owner_asset_id', 'assets'),
        ('routes', 'inherits_route_id', 'routes'),
        ('channels', 'owner_project_id', 'projects'),
        ('channels', 'owner_asset_id', 'assets')
    ) AS t(tbl, col, ref) LOOP
        EXECUTE format('CREATE TRIGGER %I BEFORE INSERT OR UPDATE OF %I ON %I FOR EACH ROW EXECUTE FUNCTION stackurity_same_workspace(%L, %L)',
            r.tbl || '_' || r.col || '_same_ws', r.col, r.tbl, r.ref, r.col);
    END LOOP;
END $$;

-- An inherited rule turned off for a project or an asset.
CREATE TABLE route_exclusions (
    id           bigserial PRIMARY KEY,
    workspace_id bigint NOT NULL DEFAULT stackurity_ws() REFERENCES workspaces(id) ON DELETE CASCADE,
    route_id     bigint NOT NULL REFERENCES routes(id) ON DELETE CASCADE,
    project_id   bigint REFERENCES projects(id) ON DELETE CASCADE,
    asset_id     bigint REFERENCES assets(id) ON DELETE CASCADE,
    created_by   bigint REFERENCES users(id) ON DELETE SET NULL,
    created_at   timestamptz NOT NULL DEFAULT now(),
    CHECK (num_nonnulls(project_id, asset_id) = 1)
);
CREATE UNIQUE INDEX route_exclusions_project ON route_exclusions (route_id, project_id) WHERE project_id IS NOT NULL;
CREATE UNIQUE INDEX route_exclusions_asset ON route_exclusions (route_id, asset_id) WHERE asset_id IS NOT NULL;
CREATE INDEX route_exclusions_workspace ON route_exclusions (workspace_id);
ALTER TABLE route_exclusions ENABLE ROW LEVEL SECURITY, FORCE ROW LEVEL SECURITY;
CREATE POLICY ws ON route_exclusions USING (workspace_id = stackurity_ws()) WITH CHECK (workspace_id = stackurity_ws());
CREATE POLICY sys ON route_exclusions USING (stackurity_system()) WITH CHECK (stackurity_system());
DO $$
DECLARE
    r record;
BEGIN
    FOR r IN SELECT * FROM (VALUES
        ('route_id', 'routes'), ('project_id', 'projects'), ('asset_id', 'assets'), ('created_by', 'users')
    ) AS t(col, ref) LOOP
        EXECUTE format('CREATE TRIGGER %I BEFORE INSERT OR UPDATE OF %I ON route_exclusions FOR EACH ROW EXECUTE FUNCTION stackurity_same_workspace(%L, %L)',
            'route_exclusions_' || r.col || '_same_ws', r.col, r.ref, r.col);
    END LOOP;
END $$;

-- Add to Slack and Add to Teams started from a project make that
-- project's channel.
ALTER TABLE slack_oauth_states ADD COLUMN owner_project_id bigint REFERENCES projects(id) ON DELETE CASCADE;
ALTER TABLE teams_install_codes ADD COLUMN owner_project_id bigint REFERENCES projects(id) ON DELETE CASCADE;
CREATE TRIGGER slack_oauth_states_owner_project_id_same_ws BEFORE INSERT OR UPDATE OF owner_project_id ON slack_oauth_states
    FOR EACH ROW EXECUTE FUNCTION stackurity_same_workspace('projects', 'owner_project_id');
CREATE TRIGGER teams_install_codes_owner_project_id_same_ws BEFORE INSERT OR UPDATE OF owner_project_id ON teams_install_codes
    FOR EACH ROW EXECUTE FUNCTION stackurity_same_workspace('projects', 'owner_project_id');

-- A rule limited to exactly one project becomes that project's rule: it
-- sends what it sent before, and the project's admins can now manage it.
UPDATE routes SET owner_project_id = project_ids[1] WHERE cardinality(project_ids) = 1;

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'stackurity_app') THEN
        GRANT SELECT, INSERT, UPDATE, DELETE ON route_exclusions TO stackurity_app;
    END IF;
END $$;
