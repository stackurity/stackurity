-- Connect Jira with Atlassian OAuth 2.0 (3LO). The operator registers one
-- Atlassian app (STACKURITY_JIRA_CLIENT_ID and _SECRET); an administrator
-- of an organisation connects it with one click. See docs/jira-app.md.
--
-- Additive: two new tables, nothing is rewritten. Jira channels keep their
-- API-token configuration; one that uses a connection has auth "oauth",
-- connection_id and cloud_id in its config.

SET LOCAL lock_timeout = '10s';

-- One Atlassian authorisation (grant) made from an organisation. A grant
-- covers every site the person picked on Atlassian's consent page (sites,
-- from accessible-resources); its tokens are sealed with
-- STACKURITY_SECRET_KEY like stored secrets, bound to the organisation and
-- the connection, and are never returned by the API. Atlassian rotates the
-- refresh token on every use: a refresh holds this row's lock, so two
-- workers never use the same refresh token and the new one is stored with
-- the access token in one update (token_version counts them).
-- status is reconnect_needed once Atlassian refused the refresh token
-- (revoked, expired, password changed); deliveries then fail with that
-- reason until an administrator reconnects.
CREATE TABLE jira_connections (
    id             bigserial PRIMARY KEY,
    workspace_id   bigint NOT NULL DEFAULT stackurity_ws() REFERENCES workspaces(id) ON DELETE CASCADE,
    sites          jsonb NOT NULL DEFAULT '[]' CHECK (jsonb_typeof(sites) = 'array'),
    scopes         text NOT NULL DEFAULT '' CHECK (length(scopes) <= 1000),
    access_token   bytea,
    refresh_token  bytea,
    expires_at     timestamptz NOT NULL DEFAULT now(),
    token_version  bigint NOT NULL DEFAULT 0,
    status         text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'reconnect_needed')),
    status_reason  text NOT NULL DEFAULT '' CHECK (length(status_reason) <= 500),
    connected_by   bigint REFERENCES users(id) ON DELETE SET NULL,
    connected_at   timestamptz NOT NULL DEFAULT now(),
    refreshed_at   timestamptz
);
CREATE INDEX jira_connections_ws ON jira_connections (workspace_id);
CREATE TRIGGER jira_connections_connected_by_same_ws BEFORE INSERT OR UPDATE OF connected_by ON jira_connections
    FOR EACH ROW EXECUTE FUNCTION stackurity_same_workspace('users', 'connected_by');
ALTER TABLE jira_connections ENABLE ROW LEVEL SECURITY, FORCE ROW LEVEL SECURITY;
CREATE POLICY ws ON jira_connections USING (workspace_id = stackurity_ws()) WITH CHECK (workspace_id = stackurity_ws());
CREATE POLICY sys ON jira_connections USING (stackurity_system()) WITH CHECK (stackurity_system());

-- The OAuth state of a Connect Jira in progress: single use, 10 minutes,
-- bound to the organisation and the person who started it, and to the
-- connection when it reconnects one. Only the SHA-256 of the state is kept.
CREATE TABLE jira_oauth_states (
    id             bigserial PRIMARY KEY,
    workspace_id   bigint NOT NULL DEFAULT stackurity_ws() REFERENCES workspaces(id) ON DELETE CASCADE,
    state_hash     bytea NOT NULL UNIQUE,
    user_id        bigint NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    connection_id  bigint REFERENCES jira_connections(id) ON DELETE CASCADE,
    return_to      text NOT NULL DEFAULT '' CHECK (length(return_to) <= 300),
    created_at     timestamptz NOT NULL DEFAULT now(),
    expires_at     timestamptz NOT NULL,
    used_at        timestamptz
);
CREATE INDEX jira_oauth_states_expiry ON jira_oauth_states (expires_at);
CREATE TRIGGER jira_oauth_states_user_id_same_ws BEFORE INSERT OR UPDATE OF user_id ON jira_oauth_states
    FOR EACH ROW EXECUTE FUNCTION stackurity_same_workspace('users', 'user_id');
CREATE TRIGGER jira_oauth_states_connection_same_ws BEFORE INSERT OR UPDATE OF connection_id ON jira_oauth_states
    FOR EACH ROW EXECUTE FUNCTION stackurity_same_workspace('jira_connections', 'connection_id');
ALTER TABLE jira_oauth_states ENABLE ROW LEVEL SECURITY, FORCE ROW LEVEL SECURITY;
CREATE POLICY ws ON jira_oauth_states USING (workspace_id = stackurity_ws()) WITH CHECK (workspace_id = stackurity_ws());
CREATE POLICY sys ON jira_oauth_states USING (stackurity_system()) WITH CHECK (stackurity_system());
