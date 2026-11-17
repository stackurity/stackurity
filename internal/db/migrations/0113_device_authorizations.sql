-- Signing in a command-line tool from the browser: the OAuth 2.0 Device
-- Authorization Grant (RFC 8628, docs/device-login.md). The tool asks for a
-- code (POST /api/v1/device/code), the person approves it on /device in a
-- signed-in browser, and the tool collects an upload-only API token
-- (POST /api/v1/device/token).
--
-- A request has no organisation until someone approves it, and the tool
-- that polls for it has no credentials, so the table is read and written in
-- system scope only, always by the hash of a code. Only hashes of the device
-- code (what the tool polls with) and the user code (what the person types)
-- are kept.
--
-- status: 'pending' until the person decides; 'approved' (token_id is the
-- token made for it, with a secret nobody knows yet); 'denied'; 'issued'
-- once the tool collected the token (it gets the secret once). An approved
-- request that expires before the tool collects its token has that token
-- revoked.
SET LOCAL lock_timeout = '10s';

SELECT set_config('stackurity.scope', 'system', true);

CREATE TABLE device_authorizations (
    id               bigserial PRIMARY KEY,
    device_code_hash bytea NOT NULL UNIQUE,
    user_code_hash   bytea NOT NULL UNIQUE,
    client_id        text NOT NULL CHECK (client_id ~ '^[a-z][a-z0-9-]{0,62}$'),
    host_label       text NOT NULL DEFAULT '' CHECK (length(host_label) <= 64),
    request_ip       text NOT NULL DEFAULT '' CHECK (length(request_ip) <= 64),
    created_at       timestamptz NOT NULL DEFAULT now(),
    expires_at       timestamptz NOT NULL,
    interval_seconds int NOT NULL DEFAULT 5 CHECK (interval_seconds BETWEEN 1 AND 300),
    last_polled_at   timestamptz,
    status           text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'approved', 'denied', 'issued')),
    decided_at       timestamptz,
    issued_at        timestamptz,
    workspace_id     bigint REFERENCES workspaces(id) ON DELETE CASCADE,
    user_id          bigint REFERENCES users(id) ON DELETE CASCADE,
    project_id       bigint REFERENCES projects(id) ON DELETE SET NULL,
    token_id         bigint REFERENCES api_tokens(id) ON DELETE SET NULL,
    CHECK (status = 'pending' OR (decided_at IS NOT NULL AND workspace_id IS NOT NULL AND user_id IS NOT NULL))
);
CREATE INDEX device_authorizations_expiry ON device_authorizations (expires_at);
-- The approver, project and token belong to the organisation it was
-- approved for (migration 0025).
CREATE TRIGGER device_authorizations_user_id_same_ws BEFORE INSERT OR UPDATE OF user_id ON device_authorizations
    FOR EACH ROW EXECUTE FUNCTION stackurity_same_workspace('users', 'user_id');
CREATE TRIGGER device_authorizations_project_id_same_ws BEFORE INSERT OR UPDATE OF project_id ON device_authorizations
    FOR EACH ROW EXECUTE FUNCTION stackurity_same_workspace('projects', 'project_id');
CREATE TRIGGER device_authorizations_token_id_same_ws BEFORE INSERT OR UPDATE OF token_id ON device_authorizations
    FOR EACH ROW EXECUTE FUNCTION stackurity_same_workspace('api_tokens', 'token_id');

ALTER TABLE device_authorizations ENABLE ROW LEVEL SECURITY, FORCE ROW LEVEL SECURITY;
CREATE POLICY sys ON device_authorizations USING (stackurity_system()) WITH CHECK (stackurity_system());

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'stackurity_app') THEN
        GRANT SELECT, INSERT, UPDATE, DELETE ON device_authorizations TO stackurity_app;
        GRANT USAGE, SELECT, UPDATE ON SEQUENCE device_authorizations_id_seq TO stackurity_app;
    END IF;
END $$;
