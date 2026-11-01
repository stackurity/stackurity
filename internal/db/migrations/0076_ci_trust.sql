-- Keyless CI scans (docs/install.md, "Scans in CI without a stored
-- secret"). An administrator trusts a CI provider's OpenID Connect tokens
-- for one repository (or, chosen explicitly, every repository of one owner
-- or group); POST /ci/token exchanges such a token for a collector token
-- that lives 15 minutes, is filed in the trust's project, and may report
-- only the repository the CI job ran for.
--
-- Every change to existing tables is additive (nullable columns or
-- constant defaults): nothing is rewritten.

SET LOCAL lock_timeout = '10s';

CREATE TABLE ci_trusts (
    id               bigserial PRIMARY KEY,
    workspace_id     bigint NOT NULL DEFAULT stackurity_ws() REFERENCES workspaces(id) ON DELETE CASCADE,
    name             text NOT NULL DEFAULT '' CHECK (length(name) <= 200),
    -- github: GitHub Actions; gitlab: GitLab CI (gitlab.com or self-managed).
    provider         text NOT NULL CHECK (provider IN ('github', 'gitlab')),
    -- The token's iss, matched exactly. HTTPS only.
    issuer           text NOT NULL CHECK (issuer LIKE 'https://%' AND length(issuer) <= 500),
    -- owner/repo (GitHub repository, GitLab project_path), or owner/* for
    -- every repository below one owner or group, which the administrator
    -- chose explicitly (owner_wildcard).
    repository       text NOT NULL CHECK (length(repository) BETWEEN 3 AND 300),
    owner_wildcard   boolean NOT NULL DEFAULT false,
    CHECK (owner_wildcard = (repository LIKE '%/*')),
    -- Optional constraints; empty means any. ref is a full ref
    -- (refs/heads/main); workflow_ref is GitHub's job_workflow_ref or
    -- GitLab's ci_config_ref_uri.
    ref              text NOT NULL DEFAULT '' CHECK (length(ref) <= 300),
    environment      text NOT NULL DEFAULT '' CHECK (length(environment) <= 200),
    workflow_ref     text NOT NULL DEFAULT '' CHECK (length(workflow_ref) <= 500),
    -- Scans exchanged under this trust create their asset in this project.
    project_id       bigint REFERENCES projects(id) ON DELETE CASCADE,
    -- The owner's numeric id (GitHub repository_owner_id, GitLab
    -- namespace_id) from the first token accepted, after which a token
    -- from an owner of the same name but another id (a deleted and
    -- re-registered organisation) is refused.
    owner_id         text NOT NULL DEFAULT '',
    created_by       bigint REFERENCES users(id) ON DELETE SET NULL,
    created_by_name  text NOT NULL DEFAULT '',
    created_at       timestamptz NOT NULL DEFAULT now(),
    last_used_at     timestamptz
);
CREATE INDEX ci_trusts_issuer ON ci_trusts (issuer);
CREATE TRIGGER ci_trusts_project_id_same_ws BEFORE INSERT OR UPDATE OF project_id ON ci_trusts
    FOR EACH ROW EXECUTE FUNCTION stackurity_same_workspace('projects', 'project_id');

-- A collector token issued under a trust: deleting the trust revokes its
-- tokens. repository_url is the only asset identity (git-url) the token
-- may report.
ALTER TABLE api_tokens
    ADD COLUMN ci_trust_id    bigint REFERENCES ci_trusts(id) ON DELETE CASCADE,
    ADD COLUMN repository_url text NOT NULL DEFAULT '';
CREATE INDEX api_tokens_ci_expired ON api_tokens (expires_at) WHERE ci_trust_id IS NOT NULL;

-- Trusts are organisation-wide: a connection narrowed to some projects
-- sees none.
ALTER TABLE ci_trusts ENABLE ROW LEVEL SECURITY, FORCE ROW LEVEL SECURITY;
CREATE POLICY ws ON ci_trusts
    USING (workspace_id = stackurity_ws() AND (SELECT stackurity_narrowed()) IS NOT TRUE)
    WITH CHECK (workspace_id = stackurity_ws() AND (SELECT stackurity_narrowed()) IS NOT TRUE);
CREATE POLICY sys ON ci_trusts USING (stackurity_system()) WITH CHECK (stackurity_system());
