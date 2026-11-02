-- "Connect PagerDuty" (internal/api/pagerduty_app.go): one row per connect
-- in progress, bound to the organisation and the person who started it.
-- Only the SHA-256 of the OAuth state and of the session handle are kept.
-- The PKCE code verifier and, after the code exchange, PagerDuty's access
-- token are sealed with the server's secret key. The row is deleted when
-- the integration is made, when the person cancels, and at most 10 minutes
-- after the last step (expires_at, purged hourly and on every new
-- connect): the token is not kept once the routing key is stored.
CREATE TABLE pagerduty_connects (
    id            bigserial PRIMARY KEY,
    workspace_id  bigint NOT NULL DEFAULT stackurity_ws() REFERENCES workspaces(id) ON DELETE CASCADE,
    state_hash    bytea NOT NULL UNIQUE,
    user_id       bigint NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    verifier      bytea NOT NULL,
    return_to     text NOT NULL DEFAULT '' CHECK (length(return_to) <= 300),
    created_at    timestamptz NOT NULL DEFAULT now(),
    expires_at    timestamptz NOT NULL,
    used_at       timestamptz,
    session_hash  bytea UNIQUE,
    region        text NOT NULL DEFAULT '' CHECK (region IN ('', 'us', 'eu')),
    access_token  bytea
);
CREATE INDEX pagerduty_connects_expiry ON pagerduty_connects (expires_at);
CREATE TRIGGER pagerduty_connects_user_id_same_ws BEFORE INSERT OR UPDATE OF user_id ON pagerduty_connects
    FOR EACH ROW EXECUTE FUNCTION stackurity_same_workspace('users', 'user_id');
ALTER TABLE pagerduty_connects ENABLE ROW LEVEL SECURITY, FORCE ROW LEVEL SECURITY;
CREATE POLICY ws ON pagerduty_connects USING (workspace_id = stackurity_ws()) WITH CHECK (workspace_id = stackurity_ws());
CREATE POLICY sys ON pagerduty_connects USING (stackurity_system()) WITH CHECK (stackurity_system());
