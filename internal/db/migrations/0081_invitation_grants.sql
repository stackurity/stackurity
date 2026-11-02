-- Invitations carry the same "what can they see?" as Add user: an
-- organisation-wide role (invitations.role with project_id NULL and no
-- rows here), or a set of grants on chosen projects and assets, each with
-- its own role (rows here; invitations.role is then NULL).
--
-- Invitations issued before this migration keep working unchanged: one
-- project_id and one role (a project invitation), or project_id NULL and a
-- role (organisation-wide). Accepting reads whichever the row has.
--
-- A grant keeps the name of its project or asset as it was when invited
-- (label), so that if the project or asset is deleted before the link is
-- used (ON DELETE SET NULL), the person accepting is told what was dropped.
-- Additive: one new table, one constraint relaxed. No data is rewritten.

SET LOCAL lock_timeout = '10s';

ALTER TABLE invitations ALTER COLUMN role DROP NOT NULL;
-- An invitation names a role (organisation-wide, or the legacy single
-- project), or has grants and no role. Grants and project_id never mix.
ALTER TABLE invitations ADD CONSTRAINT invitations_role_or_grants CHECK (role IS NOT NULL OR project_id IS NULL);

CREATE TABLE invitation_grants (
    id            bigserial PRIMARY KEY,
    workspace_id  bigint NOT NULL DEFAULT stackurity_ws() REFERENCES workspaces(id) ON DELETE CASCADE,
    invitation_id bigint NOT NULL REFERENCES invitations(id) ON DELETE CASCADE,
    kind          text NOT NULL CHECK (kind IN ('project', 'asset')),
    project_id    bigint REFERENCES projects(id) ON DELETE SET NULL,
    asset_id      bigint REFERENCES assets(id) ON DELETE SET NULL,
    -- The same roles as access_grants (the dashboard offers no admin on a
    -- project or asset: it gives nothing beyond security there).
    role          text NOT NULL CHECK (role IN ('admin', 'security', 'engineer', 'viewer')),
    label         text NOT NULL DEFAULT '' CHECK (length(label) <= 300),
    CHECK (kind = 'project' AND asset_id IS NULL OR kind = 'asset' AND project_id IS NULL)
);
CREATE UNIQUE INDEX invitation_grants_project ON invitation_grants (invitation_id, project_id) WHERE project_id IS NOT NULL;
CREATE UNIQUE INDEX invitation_grants_asset ON invitation_grants (invitation_id, asset_id) WHERE asset_id IS NOT NULL;
CREATE INDEX invitation_grants_invitation ON invitation_grants (invitation_id);
CREATE INDEX invitation_grants_project_id ON invitation_grants (project_id) WHERE project_id IS NOT NULL;
CREATE INDEX invitation_grants_asset_id ON invitation_grants (asset_id) WHERE asset_id IS NOT NULL;

-- Every reference names a row of the same workspace (see 0025).
CREATE TRIGGER invitation_grants_invitation_id_same_ws BEFORE INSERT OR UPDATE OF invitation_id ON invitation_grants
    FOR EACH ROW EXECUTE FUNCTION stackurity_same_workspace('invitations', 'invitation_id');
CREATE TRIGGER invitation_grants_project_id_same_ws BEFORE INSERT OR UPDATE OF project_id ON invitation_grants
    FOR EACH ROW EXECUTE FUNCTION stackurity_same_workspace('projects', 'project_id');
CREATE TRIGGER invitation_grants_asset_id_same_ws BEFORE INSERT OR UPDATE OF asset_id ON invitation_grants
    FOR EACH ROW EXECUTE FUNCTION stackurity_same_workspace('assets', 'asset_id');

-- The same policies as invitations: organisation routes in the workspace,
-- and system scope for the person following the link.
ALTER TABLE invitation_grants ENABLE ROW LEVEL SECURITY, FORCE ROW LEVEL SECURITY;
CREATE POLICY ws ON invitation_grants USING (workspace_id = stackurity_ws()) WITH CHECK (workspace_id = stackurity_ws());
CREATE POLICY sys ON invitation_grants USING (stackurity_system()) WITH CHECK (stackurity_system());

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'stackurity_app') THEN
        GRANT SELECT, INSERT, UPDATE, DELETE ON invitation_grants TO stackurity_app;
        GRANT USAGE, SELECT, UPDATE ON SEQUENCE invitation_grants_id_seq TO stackurity_app;
    END IF;
END $$;
