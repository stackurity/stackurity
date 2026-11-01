-- The Stackurity Microsoft Teams app ("Add to Teams"). Additive: one table
-- and one index.
--
-- An admin who clicks Add to Teams gets a short code, shown only to them,
-- which they send to the bot in the Teams channel that should get the
-- notifications. The code binds that channel to the organisation: single
-- use, 15 minutes, made for one person in one organisation. Only the
-- SHA-256 of the code is stored. channel_id and tenant_id record what it
-- was used for, so the dashboard can show the result.
SELECT set_config('stackurity.scope', 'system', true);

CREATE TABLE teams_install_codes (
    id            bigserial PRIMARY KEY,
    workspace_id  bigint NOT NULL DEFAULT stackurity_ws() REFERENCES workspaces(id) ON DELETE CASCADE,
    code_hash     bytea NOT NULL UNIQUE,
    user_id       bigint NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at    timestamptz NOT NULL DEFAULT now(),
    expires_at    timestamptz NOT NULL,
    used_at       timestamptz,
    channel_id    bigint REFERENCES channels(id) ON DELETE SET NULL,
    tenant_id     text NOT NULL DEFAULT '' CHECK (length(tenant_id) <= 64)
);
CREATE INDEX teams_install_codes_expiry ON teams_install_codes (expires_at);
CREATE TRIGGER teams_install_codes_user_id_same_ws BEFORE INSERT OR UPDATE OF user_id ON teams_install_codes
    FOR EACH ROW EXECUTE FUNCTION stackurity_same_workspace('users', 'user_id');
CREATE TRIGGER teams_install_codes_channel_id_same_ws BEFORE INSERT OR UPDATE OF channel_id ON teams_install_codes
    FOR EACH ROW EXECUTE FUNCTION stackurity_same_workspace('channels', 'channel_id');
ALTER TABLE teams_install_codes ENABLE ROW LEVEL SECURITY, FORCE ROW LEVEL SECURITY;
CREATE POLICY ws ON teams_install_codes USING (workspace_id = stackurity_ws()) WITH CHECK (workspace_id = stackurity_ws());
CREATE POLICY sys ON teams_install_codes USING (stackurity_system()) WITH CHECK (stackurity_system());

-- Teams channels of the app by team, for removal events from Teams.
CREATE INDEX channels_teams_app ON channels ((config->>'tenant_id'), (config->>'teams_team_id'))
    WHERE kind = 'teams' AND config->>'teams_app' = 'true';
