-- One-time codes that let a new host install the agent without anyone
-- pasting a long-lived token into a shell. A code is exchanged once (or a set
-- number of times) for a collector token, and carries the agent settings the
-- administrator chose.
CREATE TABLE enrollments (
    id             bigserial PRIMARY KEY,
    prefix         text NOT NULL,
    code_hash      bytea NOT NULL UNIQUE,
    label          text NOT NULL DEFAULT '',
    environment    text NOT NULL DEFAULT '',
    app_dirs       text[] NOT NULL DEFAULT '{}',
    discover_apps  boolean NOT NULL DEFAULT false,
    uses_left      int NOT NULL CHECK (uses_left >= 0),
    created_by     bigint REFERENCES users(id) ON DELETE SET NULL,
    created_at     timestamptz NOT NULL DEFAULT now(),
    expires_at     timestamptz NOT NULL,
    last_used_at   timestamptz,
    revoked_at     timestamptz
);
