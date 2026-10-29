-- Multi-factor authentication with time-based one-time passwords (RFC 6238)
-- and one-time recovery codes (docs/install.md, "Two-factor sign-in").
-- Accounts are global, so these tables are too (like users and sessions).

-- One row per account that started or finished enrolment. The secret is
-- sealed with STACKURITY_SECRET_KEY (AES-256-GCM, internal/secrets);
-- enabled_at is null until the person confirmed a code. last_step is the
-- RFC 6238 time step of the last code accepted: a code at or before it is
-- refused, so a code seen over someone's shoulder cannot be used again.
CREATE TABLE user_mfa (
    user_id      bigint PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    totp_sealed  bytea NOT NULL,
    enabled_at   timestamptz,
    last_step    bigint NOT NULL DEFAULT 0,
    created_at   timestamptz NOT NULL DEFAULT now()
);

-- Recovery codes: only a SHA-256 of each (80 random bits) is stored.
CREATE TABLE mfa_recovery_codes (
    user_id    bigint NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    code_hash  bytea NOT NULL,
    used_at    timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, code_hash)
);

-- The second step of a password sign-in: a short-lived challenge held in a
-- cookie between the password and the code. Too many wrong codes end it,
-- and the password must be entered again.
CREATE TABLE mfa_challenges (
    token_hash  bytea PRIMARY KEY,
    user_id     bigint NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    failures    int NOT NULL DEFAULT 0,
    created_at  timestamptz NOT NULL DEFAULT now(),
    expires_at  timestamptz NOT NULL
);
CREATE INDEX mfa_challenges_expires ON mfa_challenges (expires_at);

-- How a session was signed in. password_login: with a local password (not
-- single sign-on, an invitation or a sign-up link); mfa_at: when a second
-- factor was checked. Sessions created by older releases or other paths
-- keep the defaults and are never sent to enrolment.
ALTER TABLE sessions ADD COLUMN password_login boolean NOT NULL DEFAULT false,
                     ADD COLUMN mfa_at timestamptz;

-- "Require two-factor sign-in for all members": members who sign in with a
-- password and have no second factor are sent to enrolment.
ALTER TABLE workspaces ADD COLUMN require_mfa boolean NOT NULL DEFAULT false;

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'stackurity_app') THEN
        GRANT SELECT, INSERT, UPDATE, DELETE ON user_mfa, mfa_recovery_codes, mfa_challenges TO stackurity_app;
    END IF;
END $$;
