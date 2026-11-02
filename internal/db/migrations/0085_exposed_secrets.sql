-- Exposed secrets (docs/design/exposed-secrets.md): API keys, tokens,
-- private keys and passwords a scan found in a repository's files or in
-- the files a deployed web application serves. Additive: one table.
--
-- The value is never stored: a row keeps the rule, the file and line, a
-- masked preview and a fingerprint (the SHA-256 of a random-looking value,
-- or of the place for a guessable one), so the same key in several places
-- is one secret. A scan that no longer finds a row resolves it; a person
-- can mark one ignored (a test key, a revoked key) with a reason.
SELECT set_config('stackurity.scope', 'system', true);

CREATE TABLE exposed_secrets (
    id                 bigserial PRIMARY KEY,
    workspace_id       bigint NOT NULL DEFAULT stackurity_ws() REFERENCES workspaces(id) ON DELETE CASCADE,
    asset_id           bigint NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    collector_id       text NOT NULL CHECK (length(collector_id) <= 100),
    rule               text NOT NULL CHECK (length(rule) <= 64),
    title              text NOT NULL CHECK (length(title) <= 100),
    location           text NOT NULL CHECK (length(location) <= 1024),
    line               integer NOT NULL DEFAULT 0 CHECK (line >= 0),
    fingerprint        text NOT NULL CHECK (fingerprint ~ '^[0-9a-f]{64}$'),
    preview            text NOT NULL CHECK (length(preview) <= 64),
    severity           text NOT NULL CHECK (severity IN ('critical', 'high', 'medium', 'low')),
    exposure           text NOT NULL CHECK (exposure IN ('public', 'repository')),
    note               text NOT NULL DEFAULT '' CHECK (length(note) <= 300),
    status             text NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'resolved', 'ignored')),
    first_seen         timestamptz NOT NULL,
    last_seen          timestamptz NOT NULL,
    resolved_at        timestamptz,
    last_collection_id bigint,
    ignored_by         bigint REFERENCES users(id) ON DELETE SET NULL,
    ignored_at         timestamptz,
    ignore_reason      text NOT NULL DEFAULT '' CHECK (length(ignore_reason) <= 500),
    UNIQUE (asset_id, collector_id, fingerprint, location)
);
CREATE INDEX exposed_secrets_workspace ON exposed_secrets (workspace_id, status);
CREATE INDEX exposed_secrets_fingerprint ON exposed_secrets (workspace_id, fingerprint);
CREATE TRIGGER exposed_secrets_asset_id_same_ws BEFORE INSERT OR UPDATE OF asset_id ON exposed_secrets
    FOR EACH ROW EXECUTE FUNCTION stackurity_same_workspace('assets', 'asset_id');
ALTER TABLE exposed_secrets ENABLE ROW LEVEL SECURITY, FORCE ROW LEVEL SECURITY;
-- Follows its asset, like findings under projects (0032).
CREATE POLICY ws ON exposed_secrets
    USING (workspace_id = stackurity_ws() AND ((SELECT stackurity_narrowed()) IS NOT TRUE
        OR asset_id IN (SELECT unnest(stackurity_visible_assets()))))
    WITH CHECK (workspace_id = stackurity_ws() AND ((SELECT stackurity_narrowed()) IS NOT TRUE
        OR asset_id IN (SELECT unnest(stackurity_visible_assets()))));
CREATE POLICY sys ON exposed_secrets USING (stackurity_system()) WITH CHECK (stackurity_system());

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'stackurity_app') THEN
        GRANT SELECT, INSERT, UPDATE, DELETE ON exposed_secrets TO stackurity_app;
        GRANT USAGE, SELECT, UPDATE ON SEQUENCE exposed_secrets_id_seq TO stackurity_app;
    END IF;
END $$;
