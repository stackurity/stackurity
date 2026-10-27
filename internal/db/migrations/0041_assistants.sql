-- Connected AI assistants: OAuth 2.1 sign-in for the remote MCP endpoint
-- (docs/ai-assistants.md). Every change is additive: four new tables, each
-- with row-level security. Only the SHA-256 of each code and token is stored.

-- Read and update rows of every workspace below (row-level security is
-- forced for the table owner where the application role cannot be created).
SELECT set_config('stackurity.scope', 'system', true);

-- --- clients

-- An OAuth client (Claude, ChatGPT, an IDE...). Registered by the client
-- itself (dynamic client registration, id "stkc_..."), or read from the
-- client's metadata document (the id is that HTTPS URL). Not tied to a
-- workspace: one registration serves everyone who connects with it, so the
-- table is read and written in system scope only.
CREATE TABLE oauth_clients (
    id            text PRIMARY KEY CHECK (length(id) BETWEEN 1 AND 2048),
    name          text NOT NULL DEFAULT '' CHECK (length(name) <= 200),
    client_uri    text NOT NULL DEFAULT '' CHECK (length(client_uri) <= 2048),
    redirect_uris text[] NOT NULL CHECK (cardinality(redirect_uris) BETWEEN 1 AND 10),
    -- none (a public client, PKCE only), or a secret sent to the token
    -- endpoint in the body or with HTTP Basic.
    auth_method   text NOT NULL DEFAULT 'none' CHECK (auth_method IN ('none', 'client_secret_post', 'client_secret_basic')),
    secret_hash   bytea,
    metadata_url  boolean NOT NULL DEFAULT false,
    created_at    timestamptz NOT NULL DEFAULT now(),
    fetched_at    timestamptz,
    last_used_at  timestamptz,
    CHECK ((auth_method = 'none') = (secret_hash IS NULL))
);
CREATE INDEX oauth_clients_created ON oauth_clients (created_at) WHERE last_used_at IS NULL;

ALTER TABLE oauth_clients ENABLE ROW LEVEL SECURITY, FORCE ROW LEVEL SECURITY;
CREATE POLICY sys ON oauth_clients USING (stackurity_system()) WITH CHECK (stackurity_system());

-- --- connections

-- A connected assistant: what the person allowed on the consent screen.
-- It acts as user_id in one workspace, with at most role (and never more
-- than the person's own role, checked on every request), and, with
-- project_id, only on that project's assets. The current refresh token's
-- hash is kept; the one before it too, so a replayed refresh token revokes
-- the connection (OAuth 2.1 refresh token rotation).
CREATE TABLE oauth_grants (
    id                    bigserial PRIMARY KEY,
    workspace_id          bigint NOT NULL DEFAULT stackurity_ws() REFERENCES workspaces(id) ON DELETE CASCADE,
    client_id             text NOT NULL REFERENCES oauth_clients(id) ON DELETE CASCADE,
    user_id               bigint NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    project_id            bigint REFERENCES projects(id) ON DELETE CASCADE,
    role                  text NOT NULL CHECK (role IN ('viewer', 'engineer', 'security', 'admin')),
    client_name           text NOT NULL DEFAULT '' CHECK (length(client_name) <= 200),
    redirect_host         text NOT NULL DEFAULT '' CHECK (length(redirect_host) <= 300),
    refresh_hash          bytea UNIQUE,
    previous_refresh_hash bytea,
    refresh_expires_at    timestamptz,
    created_at            timestamptz NOT NULL DEFAULT now(),
    last_used_at          timestamptz,
    revoked_at            timestamptz,
    revoked_reason        text NOT NULL DEFAULT '' CHECK (length(revoked_reason) <= 200)
);
CREATE INDEX oauth_grants_user ON oauth_grants (user_id, created_at DESC);
CREATE INDEX oauth_grants_previous ON oauth_grants (previous_refresh_hash) WHERE previous_refresh_hash IS NOT NULL;
CREATE TRIGGER oauth_grants_user_id_same_ws BEFORE INSERT OR UPDATE OF user_id ON oauth_grants
    FOR EACH ROW EXECUTE FUNCTION stackurity_same_workspace('users', 'user_id');
CREATE TRIGGER oauth_grants_project_id_same_ws BEFORE INSERT OR UPDATE OF project_id ON oauth_grants
    FOR EACH ROW EXECUTE FUNCTION stackurity_same_workspace('projects', 'project_id');

ALTER TABLE oauth_grants ENABLE ROW LEVEL SECURITY, FORCE ROW LEVEL SECURITY;
-- Tokens are looked up and connections listed across workspaces (a person
-- sees all of theirs), in system scope by user; the workspace policy is
-- there for audit and support queries.
CREATE POLICY ws ON oauth_grants USING (workspace_id = stackurity_ws()) WITH CHECK (workspace_id = stackurity_ws());
CREATE POLICY sys ON oauth_grants USING (stackurity_system()) WITH CHECK (stackurity_system());

-- --- authorization codes

-- Issued when the person allows the connection; single use, 2 minutes,
-- bound to the client, redirect URI and PKCE challenge. A code used twice
-- revokes the connection made with it.
CREATE TABLE oauth_codes (
    id             bigserial PRIMARY KEY,
    workspace_id   bigint NOT NULL DEFAULT stackurity_ws() REFERENCES workspaces(id) ON DELETE CASCADE,
    code_hash      bytea NOT NULL UNIQUE,
    client_id      text NOT NULL REFERENCES oauth_clients(id) ON DELETE CASCADE,
    user_id        bigint NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    project_id     bigint REFERENCES projects(id) ON DELETE CASCADE,
    role           text NOT NULL CHECK (role IN ('viewer', 'engineer', 'security', 'admin')),
    redirect_uri   text NOT NULL CHECK (length(redirect_uri) <= 2048),
    code_challenge text NOT NULL CHECK (code_challenge ~ '^[A-Za-z0-9_-]{43}$'),
    resource       text NOT NULL DEFAULT '' CHECK (length(resource) <= 2048),
    created_at     timestamptz NOT NULL DEFAULT now(),
    expires_at     timestamptz NOT NULL,
    used_at        timestamptz,
    grant_id       bigint REFERENCES oauth_grants(id) ON DELETE SET NULL
);
CREATE INDEX oauth_codes_expiry ON oauth_codes (expires_at);
CREATE TRIGGER oauth_codes_user_id_same_ws BEFORE INSERT OR UPDATE OF user_id ON oauth_codes
    FOR EACH ROW EXECUTE FUNCTION stackurity_same_workspace('users', 'user_id');
CREATE TRIGGER oauth_codes_project_id_same_ws BEFORE INSERT OR UPDATE OF project_id ON oauth_codes
    FOR EACH ROW EXECUTE FUNCTION stackurity_same_workspace('projects', 'project_id');

ALTER TABLE oauth_codes ENABLE ROW LEVEL SECURITY, FORCE ROW LEVEL SECURITY;
CREATE POLICY ws ON oauth_codes USING (workspace_id = stackurity_ws()) WITH CHECK (workspace_id = stackurity_ws());
CREATE POLICY sys ON oauth_codes USING (stackurity_system()) WITH CHECK (stackurity_system());

-- --- access tokens

-- Short-lived (one hour) bearer tokens of a connection. They work only
-- through /mcp, never directly on the API.
CREATE TABLE oauth_access_tokens (
    token_hash   bytea PRIMARY KEY,
    workspace_id bigint NOT NULL DEFAULT stackurity_ws() REFERENCES workspaces(id) ON DELETE CASCADE,
    grant_id     bigint NOT NULL REFERENCES oauth_grants(id) ON DELETE CASCADE,
    created_at   timestamptz NOT NULL DEFAULT now(),
    expires_at   timestamptz NOT NULL
);
CREATE INDEX oauth_access_tokens_grant ON oauth_access_tokens (grant_id, expires_at);

ALTER TABLE oauth_access_tokens ENABLE ROW LEVEL SECURITY, FORCE ROW LEVEL SECURITY;
CREATE POLICY ws ON oauth_access_tokens USING (workspace_id = stackurity_ws()) WITH CHECK (workspace_id = stackurity_ws());
CREATE POLICY sys ON oauth_access_tokens USING (stackurity_system()) WITH CHECK (stackurity_system());

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'stackurity_app') THEN
        GRANT SELECT, INSERT, UPDATE, DELETE ON oauth_clients, oauth_grants, oauth_codes, oauth_access_tokens TO stackurity_app;
        GRANT USAGE, SELECT, UPDATE ON SEQUENCE oauth_grants_id_seq, oauth_codes_id_seq TO stackurity_app;
    END IF;
END $$;
