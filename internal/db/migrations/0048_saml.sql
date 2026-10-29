-- SAML single sign-on (licensed build). Accounts are linked like OpenID
-- Connect ones, by users.oidc_issuer (the identity provider's entity ID) and
-- users.oidc_subject (its name ID).

-- Sign-ins in progress: the ID of the authentication request sent to the
-- identity provider, bound to the browser that started it and to the
-- workspace it signs into, with where to go afterwards.
CREATE TABLE saml_requests (
    request_id    text PRIMARY KEY,
    browser_hash  bytea NOT NULL,
    workspace_id  bigint NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
    return_to     text NOT NULL DEFAULT '/',
    expires_at    timestamptz NOT NULL
);
CREATE INDEX saml_requests_browser ON saml_requests (browser_hash);

-- Assertions already used, so each is accepted once. Kept until the
-- assertion could no longer be accepted anyway.
CREATE TABLE saml_assertions (
    idp_entity_id  text NOT NULL,
    assertion_id   text NOT NULL,
    expires_at     timestamptz NOT NULL,
    PRIMARY KEY (idp_entity_id, assertion_id)
);
CREATE INDEX saml_assertions_expiry ON saml_assertions (expires_at);
