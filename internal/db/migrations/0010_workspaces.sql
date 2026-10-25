-- Workspaces: one installation, many organisations (docs/design/workspaces.md).
-- Existing data becomes workspace 1. Isolation is enforced twice: the request
-- scope set on each connection, and row-level security on every tenant table.

CREATE TABLE workspaces (
    id           bigserial PRIMARY KEY,
    name         text NOT NULL,
    slug         text NOT NULL UNIQUE CHECK (slug ~ '^[a-z0-9][a-z0-9-]{0,62}$'),
    created_at   timestamptz NOT NULL DEFAULT now(),
    disabled_at  timestamptz
);
INSERT INTO workspaces (id, name, slug) VALUES (1, 'Default', 'default');
SELECT setval(pg_get_serial_sequence('workspaces', 'id'), 1);

CREATE TABLE workspace_members (
    workspace_id  bigint NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
    user_id       bigint NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role          text NOT NULL CHECK (role IN ('admin', 'security', 'engineer', 'viewer')),
    created_at    timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (workspace_id, user_id)
);
CREATE INDEX workspace_members_user ON workspace_members (user_id);
INSERT INTO workspace_members (workspace_id, user_id, role) SELECT 1, id, role FROM users;

ALTER TABLE users ADD COLUMN instance_admin boolean NOT NULL DEFAULT false;
UPDATE users SET instance_admin = true WHERE role = 'admin';
-- users.role is superseded by workspace_members.role and kept only so that a
-- rollback to the previous release still starts.
ALTER TABLE users ALTER COLUMN role SET DEFAULT 'viewer';

ALTER TABLE sessions ADD COLUMN workspace_id bigint REFERENCES workspaces(id) ON DELETE CASCADE;
UPDATE sessions SET workspace_id = 1;

ALTER TABLE jobs ADD COLUMN workspace_id bigint REFERENCES workspaces(id) ON DELETE CASCADE;
UPDATE jobs SET workspace_id = 1
    WHERE kind NOT IN ('feed.sync') AND done_at IS NULL AND failed_at IS NULL;
CREATE INDEX jobs_workspace ON jobs (workspace_id);
-- Jobs are deduplicated per workspace; platform jobs (feed sync) have none.
DROP INDEX jobs_dedupe;
CREATE UNIQUE INDEX jobs_dedupe ON jobs (COALESCE(workspace_id, 0), dedupe_key)
    WHERE dedupe_key IS NOT NULL AND done_at IS NULL AND failed_at IS NULL;

-- The scope of the current connection, set by the application per request.
-- Unset means no tenant rows: the default fails closed.
CREATE FUNCTION stackurity_ws() RETURNS bigint LANGUAGE sql STABLE AS
$$ SELECT NULLIF(current_setting('stackurity.workspace_id', true), '')::bigint $$;
CREATE FUNCTION stackurity_system() RETURNS boolean LANGUAGE sql STABLE AS
$$ SELECT coalesce(current_setting('stackurity.scope', true), '') = 'system' $$;

ALTER TABLE jobs ALTER COLUMN workspace_id SET DEFAULT stackurity_ws();

-- Tenant tables: add workspace_id, fill existing rows, default to the scope.
DO $$
DECLARE t text;
BEGIN
    FOREACH t IN ARRAY ARRAY[
        'teams', 'team_members', 'api_tokens', 'assets', 'asset_identifiers', 'identity_conflicts',
        'asset_relations', 'collections', 'inventory', 'coverage', 'coverage_history', 'integrations',
        'audit_events', 'settings', 'findings', 'finding_events', 'incidents', 'channels', 'routes',
        'deliveries', 'remediation_policies', 'remediation_plans', 'remediation_actions', 'fix_groups',
        'enrollments']
    LOOP
        EXECUTE format('ALTER TABLE %I ADD COLUMN workspace_id bigint REFERENCES workspaces(id) ON DELETE CASCADE', t);
        EXECUTE format('UPDATE %I SET workspace_id = 1', t);
        EXECUTE format('ALTER TABLE %I ALTER COLUMN workspace_id SET NOT NULL, ALTER COLUMN workspace_id SET DEFAULT stackurity_ws()', t);
        EXECUTE format('CREATE INDEX %I ON %I (workspace_id)', t || '_workspace', t);
        EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY, FORCE ROW LEVEL SECURITY', t);
        EXECUTE format('CREATE POLICY ws ON %I USING (workspace_id = stackurity_ws()) WITH CHECK (workspace_id = stackurity_ws())', t);
        EXECUTE format('CREATE POLICY sys ON %I USING (stackurity_system()) WITH CHECK (stackurity_system())', t);
    END LOOP;
END $$;

-- Workspaces see their own jobs; the worker claims every job in system scope.
ALTER TABLE jobs ENABLE ROW LEVEL SECURITY, FORCE ROW LEVEL SECURITY;
CREATE POLICY ws ON jobs USING (workspace_id = stackurity_ws()) WITH CHECK (workspace_id = stackurity_ws());
CREATE POLICY sys ON jobs USING (stackurity_system()) WITH CHECK (stackurity_system());

-- Audit events of the platform itself (logins, workspace changes) have no
-- workspace and are read in system scope only.
ALTER TABLE audit_events ALTER COLUMN workspace_id DROP NOT NULL;

-- Names and keys that were unique per installation are now unique per workspace.
ALTER TABLE teams DROP CONSTRAINT teams_name_key, ADD CONSTRAINT teams_name_key UNIQUE (workspace_id, name);
ALTER TABLE channels DROP CONSTRAINT channels_name_key, ADD CONSTRAINT channels_name_key UNIQUE (workspace_id, name);
ALTER TABLE routes DROP CONSTRAINT routes_name_key, ADD CONSTRAINT routes_name_key UNIQUE (workspace_id, name);
ALTER TABLE integrations DROP CONSTRAINT integrations_kind_name_key, ADD CONSTRAINT integrations_kind_name_key UNIQUE (workspace_id, kind, name);
ALTER TABLE remediation_policies DROP CONSTRAINT remediation_policies_name_key, ADD CONSTRAINT remediation_policies_name_key UNIQUE (workspace_id, name);
ALTER TABLE asset_identifiers DROP CONSTRAINT asset_identifiers_pkey, ADD PRIMARY KEY (workspace_id, scheme, value);
ALTER TABLE settings DROP CONSTRAINT settings_pkey, ADD PRIMARY KEY (workspace_id, key);
DROP INDEX incidents_open_key;
CREATE UNIQUE INDEX incidents_open_key ON incidents (workspace_id, kind, key, COALESCE(owner_team_id, 0)) WHERE status = 'open';
DROP INDEX remediation_plans_proposed;
CREATE UNIQUE INDEX remediation_plans_proposed ON remediation_plans
    (workspace_id, component_id, package, target_version, target, COALESCE(policy_id, 0), change_type)
    WHERE status = 'proposed';

-- The component catalogue is shared, but a package name can reveal private
-- code, so a workspace sees only components its own inventory references.
-- Writes happen in system scope (ingest upserts, feed matching).
DO $$
DECLARE t text; key text;
BEGIN
    FOREACH t IN ARRAY ARRAY['components', 'package_releases', 'evaluation_gaps'] LOOP
        key := CASE WHEN t = 'components' THEN 'id' ELSE 'component_id' END;
        EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY, FORCE ROW LEVEL SECURITY', t);
        EXECUTE format('CREATE POLICY ws ON %I FOR SELECT USING (EXISTS (SELECT 1 FROM inventory i WHERE i.component_id = %I.%I))', t, t, key);
        EXECUTE format('CREATE POLICY sys ON %I USING (stackurity_system()) WITH CHECK (stackurity_system())', t);
    END LOOP;
END $$;
CREATE INDEX IF NOT EXISTS inventory_component_all ON inventory (component_id);

-- Superusers and BYPASSRLS roles ignore row-level security, and Compose runs
-- the application as the database superuser. The application switches to this
-- role on every connection (SET ROLE), so policies always apply. Where the
-- migrating user may not create roles (managed databases), the application
-- runs as the table owner and FORCE ROW LEVEL SECURITY applies instead.
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'stackurity_app') THEN
        BEGIN
            CREATE ROLE stackurity_app NOLOGIN NOSUPERUSER NOBYPASSRLS;
        EXCEPTION
            WHEN duplicate_object OR unique_violation THEN NULL;  -- created concurrently
            WHEN insufficient_privilege THEN RETURN;
        END;
    END IF;
    BEGIN
        EXECUTE format('GRANT stackurity_app TO %I', current_user);
    EXCEPTION WHEN insufficient_privilege THEN RETURN;
    END;
    EXECUTE format('GRANT USAGE ON SCHEMA %I TO stackurity_app', current_schema());
    EXECUTE format('GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA %I TO stackurity_app', current_schema());
    EXECUTE format('GRANT USAGE, SELECT, UPDATE ON ALL SEQUENCES IN SCHEMA %I TO stackurity_app', current_schema());
    EXECUTE format('GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA %I TO stackurity_app', current_schema());
    EXECUTE format('ALTER DEFAULT PRIVILEGES IN SCHEMA %I GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO stackurity_app', current_schema());
    EXECUTE format('ALTER DEFAULT PRIVILEGES IN SCHEMA %I GRANT USAGE, SELECT, UPDATE ON SEQUENCES TO stackurity_app', current_schema());
END $$;
