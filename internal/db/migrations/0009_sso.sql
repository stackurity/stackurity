-- Accounts that sign in through an OpenID Connect provider are linked by the
-- provider's issuer and subject, which never change, rather than by email.
ALTER TABLE users ADD COLUMN oidc_issuer text, ADD COLUMN oidc_subject text;
CREATE UNIQUE INDEX users_oidc ON users (oidc_issuer, oidc_subject) WHERE oidc_subject IS NOT NULL;

-- Sign-ins in progress: the state parameter, bound to the browser that
-- started it, with the nonce and PKCE verifier to check on the callback.
CREATE TABLE oidc_logins (
    state_hash    bytea PRIMARY KEY,
    browser_hash  bytea NOT NULL,
    nonce         text NOT NULL,
    verifier      text NOT NULL,
    expires_at    timestamptz NOT NULL
);
