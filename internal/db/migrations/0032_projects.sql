-- Projects and permissions (docs/design/projects.md).
--
-- An organisation (workspace) groups its assets into projects. One asset can
-- belong to several projects. People and teams get a role on chosen projects
-- (or, rarely, on one asset) instead of on the whole organisation.
--
-- Isolation works like workspace isolation: the application sets two more
-- connection settings per request, and row-level security narrows every
-- asset-bound table to what they allow.
--
--   stackurity.member   the user id of a caller with no organisation-wide
--                       role: they see only the assets of their projects
--                       and asset grants.
--   stackurity.project  the project an organisation-wide caller chose in
--                       the project switcher: they see only its assets.
--
-- Both unset (organisation-wide roles, agents, collectors, background work)
-- is the fast path: the policies compare one per-query flag and never look
-- at projects, so the findings list costs what it did before.

CREATE TABLE projects (
    id           bigserial PRIMARY KEY,
    workspace_id bigint NOT NULL DEFAULT stackurity_ws() REFERENCES workspaces(id) ON DELETE CASCADE,
    name         text NOT NULL CHECK (length(name) BETWEEN 1 AND 100),
    description  text NOT NULL DEFAULT '',
    created_at   timestamptz NOT NULL DEFAULT now(),
    archived_at  timestamptz,
    UNIQUE (workspace_id, name)
);

CREATE TABLE project_assets (
    workspace_id bigint NOT NULL DEFAULT stackurity_ws() REFERENCES workspaces(id) ON DELETE CASCADE,
    project_id   bigint NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    asset_id     bigint NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    added_at     timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (project_id, asset_id)
);
CREATE INDEX project_assets_asset ON project_assets (asset_id);
CREATE INDEX project_assets_workspace ON project_assets (workspace_id);

-- A role for a person or a team, on a project or on one asset.
CREATE TABLE access_grants (
    id           bigserial PRIMARY KEY,
    workspace_id bigint NOT NULL DEFAULT stackurity_ws() REFERENCES workspaces(id) ON DELETE CASCADE,
    project_id   bigint REFERENCES projects(id) ON DELETE CASCADE,
    asset_id     bigint REFERENCES assets(id) ON DELETE CASCADE,
    user_id      bigint REFERENCES users(id) ON DELETE CASCADE,
    team_id      bigint REFERENCES teams(id) ON DELETE CASCADE,
    role         text NOT NULL CHECK (role IN ('admin', 'security', 'engineer', 'viewer')),
    created_at   timestamptz NOT NULL DEFAULT now(),
    created_by   bigint REFERENCES users(id) ON DELETE SET NULL,
    CHECK (num_nonnulls(project_id, asset_id) = 1),
    CHECK (num_nonnulls(user_id, team_id) = 1)
);
CREATE UNIQUE INDEX access_grants_project_user ON access_grants (project_id, user_id) WHERE project_id IS NOT NULL AND user_id IS NOT NULL;
CREATE UNIQUE INDEX access_grants_project_team ON access_grants (project_id, team_id) WHERE project_id IS NOT NULL AND team_id IS NOT NULL;
CREATE UNIQUE INDEX access_grants_asset_user ON access_grants (asset_id, user_id) WHERE asset_id IS NOT NULL AND user_id IS NOT NULL;
CREATE UNIQUE INDEX access_grants_asset_team ON access_grants (asset_id, team_id) WHERE asset_id IS NOT NULL AND team_id IS NOT NULL;
CREATE INDEX access_grants_user ON access_grants (user_id) WHERE user_id IS NOT NULL;
CREATE INDEX access_grants_team ON access_grants (team_id) WHERE team_id IS NOT NULL;
CREATE INDEX access_grants_workspace ON access_grants (workspace_id);

-- Every reference names a row of the same workspace (see 0025).
DO $$
DECLARE
    r record;
BEGIN
    FOR r IN SELECT * FROM (VALUES
        ('project_assets', 'project_id', 'projects'),
        ('project_assets', 'asset_id', 'assets'),
        ('access_grants', 'project_id', 'projects'),
        ('access_grants', 'asset_id', 'assets'),
        ('access_grants', 'team_id', 'teams'),
        ('access_grants', 'user_id', 'users')
    ) AS t(tbl, col, ref) LOOP
        EXECUTE format('CREATE TRIGGER %I BEFORE INSERT OR UPDATE OF %I ON %I FOR EACH ROW EXECUTE FUNCTION stackurity_same_workspace(%L, %L)',
            r.tbl || '_' || r.col || '_same_ws', r.col, r.tbl, r.ref, r.col);
    END LOOP;
END $$;

-- A member with project access only has no organisation-wide role.
ALTER TABLE workspace_members ALTER COLUMN role DROP NOT NULL;
-- The project a person last chose in the switcher, opened by default.
ALTER TABLE workspace_members ADD COLUMN default_project_id bigint REFERENCES projects(id) ON DELETE SET NULL;

-- Notification routes can be limited to projects (empty: every asset).
ALTER TABLE routes ADD COLUMN project_ids bigint[] NOT NULL DEFAULT '{}';

-- --- scope functions

CREATE FUNCTION stackurity_member() RETURNS bigint LANGUAGE sql STABLE AS
$$ SELECT NULLIF(current_setting('stackurity.member', true), '')::bigint $$;
CREATE FUNCTION stackurity_project() RETURNS bigint LANGUAGE sql STABLE AS
$$ SELECT NULLIF(current_setting('stackurity.project', true), '')::bigint $$;
-- True when this connection sees only some of the workspace's assets.
CREATE FUNCTION stackurity_narrowed() RETURNS boolean LANGUAGE sql STABLE AS
$$ SELECT stackurity_member() IS NOT NULL OR stackurity_project() IS NOT NULL $$;

-- The projects the member was granted, directly or through a team.
-- Subqueries such as (SELECT stackurity_member()) below are evaluated once
-- per query rather than once per row.
CREATE FUNCTION stackurity_member_projects() RETURNS bigint[] LANGUAGE sql STABLE AS $$
    SELECT COALESCE(array_agg(DISTINCT g.project_id), '{}') FROM access_grants g
    WHERE g.project_id IS NOT NULL
      AND (g.user_id = (SELECT stackurity_member())
           OR g.team_id IN (SELECT tm.team_id FROM team_members tm WHERE tm.user_id = (SELECT stackurity_member())))
$$;

-- The assets a narrowed connection may see: those of the chosen project,
-- and for a member those of their active projects and asset grants. NULL
-- when the connection is not narrowed.
CREATE FUNCTION stackurity_visible_assets() RETURNS bigint[] LANGUAGE sql STABLE AS $$
    SELECT CASE WHEN NOT stackurity_narrowed() THEN NULL ELSE ARRAY(
        SELECT pa.asset_id FROM project_assets pa JOIN projects p ON p.id = pa.project_id
        WHERE ((SELECT stackurity_project()) IS NULL OR pa.project_id = (SELECT stackurity_project()))
          AND ((SELECT stackurity_member()) IS NULL
               OR (p.archived_at IS NULL AND pa.project_id IN (SELECT unnest(stackurity_member_projects()))))
        UNION
        SELECT g.asset_id FROM access_grants g
        WHERE (SELECT stackurity_member()) IS NOT NULL AND g.asset_id IS NOT NULL
          AND (g.user_id = (SELECT stackurity_member())
               OR g.team_id IN (SELECT tm.team_id FROM team_members tm WHERE tm.user_id = (SELECT stackurity_member())))
          AND ((SELECT stackurity_project()) IS NULL
               OR EXISTS (SELECT 1 FROM project_assets pa2 WHERE pa2.asset_id = g.asset_id AND pa2.project_id = (SELECT stackurity_project())))
    ) END
$$;

-- The highest role a user has on an asset through project and asset
-- grants (their own or their teams'), or NULL. Organisation-wide roles are
-- checked by the application before this.
CREATE FUNCTION stackurity_grant_role(p_user bigint, p_asset bigint) RETURNS text LANGUAGE sql STABLE AS $$
    SELECT g.role FROM access_grants g
    LEFT JOIN projects p ON p.id = g.project_id
    WHERE (g.user_id = p_user OR g.team_id IN (SELECT tm.team_id FROM team_members tm WHERE tm.user_id = p_user))
      AND (g.asset_id = p_asset
           OR (p.archived_at IS NULL AND EXISTS (SELECT 1 FROM project_assets pa WHERE pa.project_id = g.project_id AND pa.asset_id = p_asset)))
    ORDER BY CASE g.role WHEN 'admin' THEN 4 WHEN 'security' THEN 3 WHEN 'engineer' THEN 2 ELSE 1 END DESC
    LIMIT 1
$$;

-- --- row-level security on the new tables

ALTER TABLE projects ENABLE ROW LEVEL SECURITY, FORCE ROW LEVEL SECURITY;
-- A member sees the projects they were granted, by name; nothing else.
CREATE POLICY ws ON projects
    USING (workspace_id = stackurity_ws() AND ((SELECT stackurity_member()) IS NULL OR id IN (SELECT unnest(stackurity_member_projects()))))
    WITH CHECK (workspace_id = stackurity_ws());
CREATE POLICY sys ON projects USING (stackurity_system()) WITH CHECK (stackurity_system());

ALTER TABLE project_assets ENABLE ROW LEVEL SECURITY, FORCE ROW LEVEL SECURITY;
CREATE POLICY ws ON project_assets
    USING (workspace_id = stackurity_ws() AND ((SELECT stackurity_member()) IS NULL OR project_id IN (SELECT unnest(stackurity_member_projects()))))
    WITH CHECK (workspace_id = stackurity_ws());
CREATE POLICY sys ON project_assets USING (stackurity_system()) WITH CHECK (stackurity_system());

-- Grants are read by the scope functions above, so this policy must not
-- call them; the API shows grants to organisation admins only.
ALTER TABLE access_grants ENABLE ROW LEVEL SECURITY, FORCE ROW LEVEL SECURITY;
CREATE POLICY ws ON access_grants USING (workspace_id = stackurity_ws()) WITH CHECK (workspace_id = stackurity_ws());
CREATE POLICY sys ON access_grants USING (stackurity_system()) WITH CHECK (stackurity_system());

-- --- narrowing the asset-bound tables
--
-- (SELECT stackurity_narrowed()) and the IN (SELECT unnest(...)) list are
-- evaluated once per query (an InitPlan and a hashed SubPlan), not per row.
-- When the connection is not narrowed the OR is decided by the first term
-- and the asset list is never computed.
DO $$
DECLARE
    r record;
    pred text;
BEGIN
    FOR r IN SELECT * FROM (VALUES
        ('assets', 'id IN (SELECT unnest(stackurity_visible_assets()))'),
        ('asset_identifiers', 'asset_id IN (SELECT unnest(stackurity_visible_assets()))'),
        ('asset_relations', 'from_asset IN (SELECT unnest(stackurity_visible_assets())) AND to_asset IN (SELECT unnest(stackurity_visible_assets()))'),
        ('collections', 'asset_id IN (SELECT unnest(stackurity_visible_assets()))'),
        ('coverage', 'asset_id IN (SELECT unnest(stackurity_visible_assets()))'),
        ('coverage_history', 'EXISTS (SELECT 1 FROM collections c WHERE c.id = coverage_history.collection_id)'),
        ('inventory', 'asset_id IN (SELECT unnest(stackurity_visible_assets()))'),
        ('findings', 'asset_id IN (SELECT unnest(stackurity_visible_assets()))'),
        ('finding_events', 'EXISTS (SELECT 1 FROM findings f WHERE f.id = finding_events.finding_id)'),
        ('fix_groups', 'asset_id IN (SELECT unnest(stackurity_visible_assets()))'),
        ('remediation_actions', 'asset_id IN (SELECT unnest(stackurity_visible_assets()))'),
        ('identity_conflicts', 'asset_ids <@ (SELECT stackurity_visible_assets())'),
        -- A remediation plan is seen through its actions on visible assets.
        ('remediation_plans', 'EXISTS (SELECT 1 FROM remediation_actions ra WHERE ra.plan_id = remediation_plans.id)'),
        -- An incident is seen through its visible findings (its counts and
        -- names are recomputed from them by the store), and a collection or
        -- coverage problem through its asset. Feed problems hold no tenant data.
        ('incidents', 'EXISTS (SELECT 1 FROM findings f WHERE f.incident_id = incidents.id)'
            || ' OR (incidents.kind IN (''collection'', ''coverage'') AND incidents.key ~ ''^asset:[0-9]+''
                 AND substring(incidents.key FROM ''^asset:([0-9]+)'')::bigint IN (SELECT unnest(stackurity_visible_assets())))'
            || ' OR incidents.kind = ''feed''')
    ) AS t(tbl, cond) LOOP
        pred := format('workspace_id = stackurity_ws() AND ((SELECT stackurity_narrowed()) IS NOT TRUE OR (%s))', r.cond);
        EXECUTE format('DROP POLICY ws ON %I', r.tbl);
        EXECUTE format('CREATE POLICY ws ON %I USING (%s) WITH CHECK (%s)', r.tbl, pred, pred);
    END LOOP;
END $$;

-- Audit events: a narrowed connection sees events about the assets,
-- findings and incidents it can see. Events about anything else (people,
-- settings, other projects) are for organisation-wide roles. Anyone may
-- record an event in their workspace.
CREATE FUNCTION stackurity_audit_visible(p_type text, p_id text) RETURNS boolean LANGUAGE sql STABLE AS $$
    SELECT CASE
        WHEN p_type = 'asset' THEN p_id ~ '^[0-9]{1,18}$'
            AND EXISTS (SELECT 1 FROM assets a WHERE a.id = p_id::bigint)
        WHEN p_type = 'finding' THEN p_id ~ '^[0-9]{1,18}(,[0-9]{1,18})*$'
            AND NOT EXISTS (SELECT 1 FROM unnest(string_to_array(p_id, ',')) x(id)
                            WHERE NOT EXISTS (SELECT 1 FROM findings f WHERE f.id = x.id::bigint))
        WHEN p_type = 'incident' THEN p_id ~ '^[0-9]{1,18}$'
            AND EXISTS (SELECT 1 FROM incidents i WHERE i.id = p_id::bigint)
        WHEN p_type = 'project' THEN stackurity_member() IS NULL AND p_id ~ '^[0-9]{1,18}$'
            AND p_id::bigint = stackurity_project()
        ELSE false
    END
$$;
DROP POLICY ws ON audit_events;
CREATE POLICY ws ON audit_events FOR SELECT
    USING (workspace_id = stackurity_ws()
           AND ((SELECT stackurity_narrowed()) IS NOT TRUE OR stackurity_audit_visible(object_type, object_id)));
CREATE POLICY ws_insert ON audit_events FOR INSERT WITH CHECK (workspace_id = stackurity_ws());
CREATE POLICY ws_update ON audit_events FOR UPDATE USING (workspace_id = stackurity_ws() AND (SELECT stackurity_narrowed()) IS NOT TRUE)
    WITH CHECK (workspace_id = stackurity_ws());
CREATE POLICY ws_delete ON audit_events FOR DELETE USING (workspace_id = stackurity_ws() AND (SELECT stackurity_narrowed()) IS NOT TRUE);

-- Grants for the application role (0010 set default privileges; repeated
-- here for databases where the migrating user differs).
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'stackurity_app') THEN
        EXECUTE format('GRANT SELECT, INSERT, UPDATE, DELETE ON projects, project_assets, access_grants TO stackurity_app');
        EXECUTE format('GRANT USAGE, SELECT, UPDATE ON SEQUENCE projects_id_seq, access_grants_id_seq TO stackurity_app');
    END IF;
EXCEPTION WHEN insufficient_privilege THEN NULL;
END $$;
