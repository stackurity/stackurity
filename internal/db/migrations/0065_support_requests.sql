-- Support requests (the Coverage page's "Request support" button): a
-- workspace asks for an ecosystem or operating system Stackurity does not
-- check yet. One row per workspace and ecosystem, so asking again changes
-- nothing. Instance administrators see them counted per ecosystem on the
-- coverage-gap report, as a roadmap signal; workspaces are never named
-- there.
--
-- ecosystem is the key the Coverage page uses (store.EcosystemCoverage):
-- a package type ("cocoapods"), a distribution release
-- ("deb:ubuntu-24.04"), "windows" or "wordpress". label is how it was named
-- when it was asked for.

SET LOCAL lock_timeout = '10s';

CREATE TABLE support_requests (
    workspace_id  bigint NOT NULL DEFAULT stackurity_ws() REFERENCES workspaces(id) ON DELETE CASCADE,
    ecosystem     text NOT NULL CHECK (length(ecosystem) BETWEEN 1 AND 100),
    label         text NOT NULL DEFAULT '' CHECK (length(label) <= 200),
    requested_by  bigint REFERENCES users(id) ON DELETE SET NULL,
    created_at    timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (workspace_id, ecosystem)
);
CREATE INDEX support_requests_ecosystem ON support_requests (ecosystem);

-- Any member of the workspace may ask, including members with project
-- access only: the request names an ecosystem, never an asset.
ALTER TABLE support_requests ENABLE ROW LEVEL SECURITY, FORCE ROW LEVEL SECURITY;
CREATE POLICY ws ON support_requests USING (workspace_id = stackurity_ws()) WITH CHECK (workspace_id = stackurity_ws());
-- The coverage-gap report counts them across workspaces in system scope.
CREATE POLICY sys ON support_requests USING (stackurity_system()) WITH CHECK (stackurity_system());

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'stackurity_app') THEN
        GRANT SELECT, INSERT, UPDATE, DELETE ON support_requests TO stackurity_app;
    END IF;
END $$;
