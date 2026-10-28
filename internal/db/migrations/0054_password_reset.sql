-- Password reset by email (docs/install.md, "Forgotten passwords"). Only a
-- SHA-256 of each link's token is stored; a token works once, for 15
-- minutes, and a new request replaces the account's earlier ones.
CREATE TABLE password_resets (
    token_hash  bytea PRIMARY KEY,
    user_id     bigint NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at  timestamptz NOT NULL DEFAULT now(),
    expires_at  timestamptz NOT NULL,
    used_at     timestamptz
);
CREATE INDEX password_resets_user ON password_resets (user_id);
CREATE INDEX password_resets_expires ON password_resets (expires_at);

-- An administrator set a temporary password: the person must choose their
-- own at their next sign-in before doing anything else.
ALTER TABLE users ADD COLUMN password_change_required boolean NOT NULL DEFAULT false;

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'stackurity_app') THEN
        GRANT SELECT, INSERT, UPDATE, DELETE ON password_resets TO stackurity_app;
    END IF;
END $$;
