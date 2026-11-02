-- Invitations can add the person to teams when they accept (Settings →
-- Users → Invite, "Add to teams"). Team membership gives the team's
-- access (its grants on projects and assets); the team an asset belongs
-- to (assets.owner_team_id) routes alerts and gives no access.
--
-- A team deleted before the link is used is dropped (ON DELETE SET NULL),
-- and the name kept in label says which, as for invitation_grants (0081).
-- Additive: one new table.

SET LOCAL lock_timeout = '10s';

CREATE TABLE invitation_teams (
    id            bigserial PRIMARY KEY,
    workspace_id  bigint NOT NULL DEFAULT stackurity_ws() REFERENCES workspaces(id) ON DELETE CASCADE,
    invitation_id bigint NOT NULL REFERENCES invitations(id) ON DELETE CASCADE,
    team_id       bigint REFERENCES teams(id) ON DELETE SET NULL,
    label         text NOT NULL DEFAULT '' CHECK (length(label) <= 300)
);
CREATE UNIQUE INDEX invitation_teams_team ON invitation_teams (invitation_id, team_id) WHERE team_id IS NOT NULL;
CREATE INDEX invitation_teams_invitation ON invitation_teams (invitation_id);
CREATE INDEX invitation_teams_team_id ON invitation_teams (team_id) WHERE team_id IS NOT NULL;

CREATE TRIGGER invitation_teams_invitation_id_same_ws BEFORE INSERT OR UPDATE OF invitation_id ON invitation_teams
    FOR EACH ROW EXECUTE FUNCTION stackurity_same_workspace('invitations', 'invitation_id');
CREATE TRIGGER invitation_teams_team_id_same_ws BEFORE INSERT OR UPDATE OF team_id ON invitation_teams
    FOR EACH ROW EXECUTE FUNCTION stackurity_same_workspace('teams', 'team_id');

ALTER TABLE invitation_teams ENABLE ROW LEVEL SECURITY, FORCE ROW LEVEL SECURITY;
CREATE POLICY ws ON invitation_teams USING (workspace_id = stackurity_ws()) WITH CHECK (workspace_id = stackurity_ws());
CREATE POLICY sys ON invitation_teams USING (stackurity_system()) WITH CHECK (stackurity_system());

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'stackurity_app') THEN
        GRANT SELECT, INSERT, UPDATE, DELETE ON invitation_teams TO stackurity_app;
        GRANT USAGE, SELECT, UPDATE ON SEQUENCE invitation_teams_id_seq TO stackurity_app;
    END IF;
END $$;
