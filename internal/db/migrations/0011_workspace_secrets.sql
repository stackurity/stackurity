-- Credentials a workspace stores itself (secret:NAME references), encrypted
-- by the application with STACKURITY_SECRET_KEY. The database never sees a
-- plaintext value, and the API never returns one.
CREATE TABLE workspace_secrets (
    workspace_id  bigint NOT NULL DEFAULT stackurity_ws() REFERENCES workspaces(id) ON DELETE CASCADE,
    name          text NOT NULL CHECK (name ~ '^[A-Za-z0-9_.-]{1,64}$'),
    sealed        bytea NOT NULL,
    created_by    bigint REFERENCES users(id) ON DELETE SET NULL,
    created_at    timestamptz NOT NULL DEFAULT now(),
    updated_at    timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (workspace_id, name)
);
ALTER TABLE workspace_secrets ENABLE ROW LEVEL SECURITY, FORCE ROW LEVEL SECURITY;
CREATE POLICY ws ON workspace_secrets USING (workspace_id = stackurity_ws()) WITH CHECK (workspace_id = stackurity_ws());
CREATE POLICY sys ON workspace_secrets USING (stackurity_system()) WITH CHECK (stackurity_system());
