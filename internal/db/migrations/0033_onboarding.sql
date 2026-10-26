-- Onboarding (0.9): the first-run flow, invitations by project, and a quiet
-- first scan. Every change is additive: new tables, nullable columns and
-- columns with constant defaults, so no table is rewritten.

-- Read and update rows of every workspace below (row-level security is
-- forced for the table owner where the application role cannot be created).
SELECT set_config('stackurity.scope', 'system', true);

-- --- the first-run flow

-- new: the flow shows (to admins, while the organisation has no assets);
-- skipped: Home shows a checklist card instead; done: nothing shows.
ALTER TABLE workspaces ADD COLUMN onboarding_state text NOT NULL DEFAULT 'new'
    CHECK (onboarding_state IN ('new', 'skipped', 'done'));
-- The project chosen in the flow, so it resumes where it was left.
ALTER TABLE workspaces ADD COLUMN onboarding_project_id bigint REFERENCES projects(id) ON DELETE SET NULL;

-- Existing installations that already have assets never see the flow.
UPDATE workspaces w SET onboarding_state = 'done'
WHERE EXISTS (SELECT 1 FROM assets a WHERE a.workspace_id = w.id);

-- --- new assets land in the project they were added for

-- An enrollment code and the collector token it is exchanged for (or a
-- collector token made for a repository) can name a project: assets they
-- create are added to it.
ALTER TABLE enrollments ADD COLUMN project_id bigint REFERENCES projects(id) ON DELETE SET NULL;
ALTER TABLE api_tokens ADD COLUMN project_id bigint REFERENCES projects(id) ON DELETE SET NULL;
CREATE TRIGGER enrollments_project_id_same_ws BEFORE INSERT OR UPDATE OF project_id ON enrollments
    FOR EACH ROW EXECUTE FUNCTION stackurity_same_workspace('projects', 'project_id');
CREATE TRIGGER api_tokens_project_id_same_ws BEFORE INSERT OR UPDATE OF project_id ON api_tokens
    FOR EACH ROW EXECUTE FUNCTION stackurity_same_workspace('projects', 'project_id');

-- --- a quiet first scan

-- An asset's first-scan backlog (findings first seen before the asset was
-- announced with its "connected" message) raises no urgent alert, Jira
-- issue, escalation or overdue reminder. Assets that existed before this
-- release keep their deadlines as they were: the column is false for them
-- and true for every asset created from now on.
ALTER TABLE assets ADD COLUMN quiet_backlog boolean NOT NULL DEFAULT false;
ALTER TABLE assets ALTER COLUMN quiet_backlog SET DEFAULT true;

-- --- invitations

-- A single-use link that lets someone join the organisation with a role on
-- one project (or an organisation-wide role, project_id NULL). Only the
-- SHA-256 of the token is stored; the link is shown or emailed once.
CREATE TABLE invitations (
    id           bigserial PRIMARY KEY,
    workspace_id bigint NOT NULL DEFAULT stackurity_ws() REFERENCES workspaces(id) ON DELETE CASCADE,
    email        text NOT NULL CHECK (email = lower(email) AND length(email) BETWEEN 3 AND 254),
    name         text NOT NULL DEFAULT '' CHECK (length(name) <= 200),
    project_id   bigint REFERENCES projects(id) ON DELETE CASCADE,
    role         text NOT NULL CHECK (role IN ('admin', 'security', 'engineer', 'viewer')),
    prefix       text NOT NULL,
    token_hash   bytea NOT NULL UNIQUE,
    created_by   bigint REFERENCES users(id) ON DELETE SET NULL,
    created_at   timestamptz NOT NULL DEFAULT now(),
    expires_at   timestamptz NOT NULL,
    emailed_at   timestamptz,
    accepted_at  timestamptz,
    accepted_by  bigint REFERENCES users(id) ON DELETE SET NULL,
    revoked_at   timestamptz,
    CHECK (accepted_at IS NULL OR revoked_at IS NULL)
);
-- One open invitation per person and project; inviting again replaces it.
CREATE UNIQUE INDEX invitations_open ON invitations (workspace_id, email, COALESCE(project_id, 0))
    WHERE accepted_at IS NULL AND revoked_at IS NULL;
CREATE INDEX invitations_workspace ON invitations (workspace_id, created_at DESC);
CREATE TRIGGER invitations_project_id_same_ws BEFORE INSERT OR UPDATE OF project_id ON invitations
    FOR EACH ROW EXECUTE FUNCTION stackurity_same_workspace('projects', 'project_id');

ALTER TABLE invitations ENABLE ROW LEVEL SECURITY, FORCE ROW LEVEL SECURITY;
-- Organisation routes only: members with project access never reach them,
-- so the policy is per workspace like access_grants.
CREATE POLICY ws ON invitations USING (workspace_id = stackurity_ws()) WITH CHECK (workspace_id = stackurity_ws());
-- Accepting runs in system scope: the person following the link is not a
-- member yet, and the token alone names the invitation.
CREATE POLICY sys ON invitations USING (stackurity_system()) WITH CHECK (stackurity_system());

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'stackurity_app') THEN
        GRANT SELECT, INSERT, UPDATE, DELETE ON invitations TO stackurity_app;
        GRANT USAGE, SELECT, UPDATE ON SEQUENCE invitations_id_seq TO stackurity_app;
    END IF;
END $$;
