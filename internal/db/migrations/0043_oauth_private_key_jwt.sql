-- Assistants that authenticate at the token endpoint with a signed JWT
-- (private_key_jwt, RFC 7523), such as ChatGPT, whose client ID metadata
-- document (https://chatgpt.com/oauth/client.json) declares it. Additive:
-- the auth_method check gains a value, two nullable or defaulted columns,
-- and one new table.

SELECT set_config('stackurity.scope', 'system', true);

ALTER TABLE oauth_clients DROP CONSTRAINT oauth_clients_auth_method_check;
ALTER TABLE oauth_clients ADD CONSTRAINT oauth_clients_auth_method_check
    CHECK (auth_method IN ('none', 'client_secret_post', 'client_secret_basic', 'private_key_jwt'));
-- A secret is stored exactly for the two secret methods.
ALTER TABLE oauth_clients DROP CONSTRAINT oauth_clients_check;
ALTER TABLE oauth_clients ADD CONSTRAINT oauth_clients_secret_check
    CHECK ((auth_method IN ('client_secret_post', 'client_secret_basic')) = (secret_hash IS NOT NULL));

-- private_key_jwt: where the client's public keys are (an HTTPS URL), or the
-- keys themselves when its metadata document lists them inline.
ALTER TABLE oauth_clients ADD COLUMN jwks_uri text NOT NULL DEFAULT '' CHECK (length(jwks_uri) <= 2048);
ALTER TABLE oauth_clients ADD COLUMN jwks jsonb;
ALTER TABLE oauth_clients ADD CONSTRAINT oauth_clients_jwt_keys_check
    CHECK (auth_method <> 'private_key_jwt' OR jwks_uri <> '' OR jwks IS NOT NULL);

-- Client assertions already used (the SHA-256 of client_id and jti), kept
-- until the assertion expires, so one cannot be replayed. Read and written
-- in system scope only, like oauth_clients.
CREATE TABLE oauth_client_assertions (
    jti_hash   bytea PRIMARY KEY,
    client_id  text NOT NULL REFERENCES oauth_clients(id) ON DELETE CASCADE,
    expires_at timestamptz NOT NULL
);
CREATE INDEX oauth_client_assertions_expiry ON oauth_client_assertions (expires_at);

ALTER TABLE oauth_client_assertions ENABLE ROW LEVEL SECURITY, FORCE ROW LEVEL SECURITY;
CREATE POLICY sys ON oauth_client_assertions USING (stackurity_system()) WITH CHECK (stackurity_system());

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'stackurity_app') THEN
        GRANT SELECT, INSERT, UPDATE, DELETE ON oauth_client_assertions TO stackurity_app;
    END IF;
END $$;
