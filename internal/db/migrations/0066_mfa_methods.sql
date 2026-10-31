-- Two-factor methods (docs/install.md, "Two-factor sign-in"): passkeys and
-- security keys (WebAuthn), email codes as a fallback, and a workspace
-- policy that replaces the single "Require two-factor sign-in" checkbox.
-- Accounts are global, so the new account tables are too (like user_mfa).

-- Passkeys and security keys. record is the credential record as
-- go-webauthn keeps it (public key, sign counter, flags, AAGUID,
-- transports); the columns beside it are what the dashboard lists and what
-- lookups need. The relying party ID is the host of STACKURITY_BASE_URL:
-- a credential works only there.
CREATE TABLE webauthn_credentials (
    id                bigserial PRIMARY KEY,
    user_id           bigint NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    credential_id     bytea NOT NULL UNIQUE,
    name              text NOT NULL CHECK (length(name) BETWEEN 1 AND 64),
    record            jsonb NOT NULL,
    -- backed_up: a synced passkey (backup state), not a single device.
    backed_up         boolean NOT NULL DEFAULT false,
    -- discoverable: usable for sign-in without an email (credProps; null
    -- when the browser did not say).
    discoverable      boolean,
    created_at        timestamptz NOT NULL DEFAULT now(),
    last_used_at      timestamptz,
    -- clone_warning_at: an assertion came with a signature counter at or
    -- below the stored one; that sign-in was refused.
    clone_warning_at  timestamptz
);
CREATE INDEX webauthn_credentials_user ON webauthn_credentials (user_id);

-- The WebAuthn user handle: 64 random bytes made at the first
-- registration, never the account id or email.
ALTER TABLE users ADD COLUMN webauthn_handle bytea UNIQUE;

-- A WebAuthn ceremony in progress: the challenge and options, held by the
-- server and bound to the browser by a cookie holding the secret whose
-- hash is token_hash. Each is used once.
CREATE TABLE webauthn_ceremonies (
    token_hash    bytea PRIMARY KEY,
    user_id       bigint REFERENCES users(id) ON DELETE CASCADE,
    purpose       text NOT NULL CHECK (purpose IN ('register', 'second_factor', 'passwordless', 'step_up')),
    session_data  jsonb NOT NULL,
    created_at    timestamptz NOT NULL DEFAULT now(),
    expires_at    timestamptz NOT NULL
);
CREATE INDEX webauthn_ceremonies_expires ON webauthn_ceremonies (expires_at);

-- Email codes, the fallback second factor, turned on by each person
-- (confirmed with a code sent to their address) where a workspace of
-- theirs allows it. enabled_at is null while the confirmation is pending.
CREATE TABLE user_email_mfa (
    user_id          bigint PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    enabled_at       timestamptz,
    code_hash        bytea,
    code_expires_at  timestamptz,
    failures         int NOT NULL DEFAULT 0,
    created_at       timestamptz NOT NULL DEFAULT now()
);

-- An email code sent during a sign-in belongs to that sign-in's challenge:
-- only a hash of the challenge secret with the code is stored.
ALTER TABLE mfa_challenges ADD COLUMN email_code_hash bytea,
                           ADD COLUMN email_code_expires_at timestamptz,
                           ADD COLUMN email_sends int NOT NULL DEFAULT 0,
                           ADD COLUMN email_sent_at timestamptz;

-- How each session was signed in. login_method: password, passkey,
-- invite, signup, or sso (single sign-on, the only one the two-factor
-- policy leaves alone; a session pinned by an organisation's single sign-on
-- is exempt too). A session with none is held to the policy.
-- mfa_method: the second factor checked (totp, recovery_code, passkey,
-- email), and mfa_credential_id the passkey it was checked with. Sessions
-- from before this migration with mfa_at set used TOTP; pinned ones are
-- single sign-on.
ALTER TABLE sessions ADD COLUMN login_method text,
                     ADD COLUMN mfa_method text,
                     ADD COLUMN mfa_credential_id bigint;
UPDATE sessions SET login_method = 'password' WHERE password_login;
UPDATE sessions SET login_method = 'sso' WHERE sso_workspace_id IS NOT NULL;
UPDATE sessions SET mfa_method = 'totp' WHERE mfa_at IS NOT NULL;

-- The workspace's two-factor policy (Settings → Users):
--   mfa_policy: optional, everyone, or admins (admins and security);
--   mfa_methods: the methods that count here;
--   mfa_phishing_resistant_admins: admins must sign in with a passkey
--   (Enterprise plan).
-- require_mfa stays and is kept true whenever a policy requires anything.
ALTER TABLE workspaces ADD COLUMN mfa_policy text NOT NULL DEFAULT 'optional'
                           CHECK (mfa_policy IN ('optional', 'everyone', 'admins')),
                       ADD COLUMN mfa_methods text[] NOT NULL DEFAULT '{passkey,totp}'
                           CHECK (mfa_methods <@ ARRAY['passkey', 'totp', 'email']::text[]
                                  AND (mfa_methods && ARRAY['passkey', 'totp']::text[])),
                       ADD COLUMN mfa_phishing_resistant_admins boolean NOT NULL DEFAULT false;
UPDATE workspaces SET mfa_policy = 'everyone' WHERE require_mfa;

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'stackurity_app') THEN
        GRANT SELECT, INSERT, UPDATE, DELETE ON webauthn_credentials, webauthn_ceremonies, user_email_mfa TO stackurity_app;
    END IF;
END $$;
