-- Website checks (docs/website-check.md): what a public website shows from
-- the outside (server and framework versions in its headers, the JavaScript
-- libraries its home page loads, its TLS), matched against the stored
-- vulnerability, known-exploited and end-of-life data. A check is one
-- browser-like visit; nothing is probed.
--
-- site_checks keeps each check an organisation asked for, so the report can
-- be opened again. plan_allowances gains the kind 'site_checks' for the
-- plan's monthly allowance (site_checks_per_month). Additive only.

SET LOCAL lock_timeout = '10s';
SELECT set_config('stackurity.scope', 'system', true);

ALTER TABLE plan_allowances DROP CONSTRAINT plan_allowances_kind_check;
ALTER TABLE plan_allowances ADD CONSTRAINT plan_allowances_kind_check CHECK (kind IN ('sbom_imports', 'site_checks'));

CREATE TABLE site_checks (
    id              bigserial PRIMARY KEY,
    workspace_id    bigint NOT NULL DEFAULT stackurity_ws() REFERENCES workspaces(id) ON DELETE CASCADE,
    -- The address asked for and the one the check ended on (after
    -- redirects).
    url             text NOT NULL CHECK (length(url) BETWEEN 1 AND 2048),
    final_url       text NOT NULL DEFAULT '' CHECK (length(final_url) <= 2048),
    host            text NOT NULL CHECK (length(host) BETWEEN 1 AND 253),
    -- The whole report (sitecheck.Report), as the API returns it.
    report          jsonb NOT NULL CHECK (jsonb_typeof(report) = 'object'),
    -- Counts for the list, from the report.
    issues          integer NOT NULL DEFAULT 0 CHECK (issues >= 0),
    known_exploited integer NOT NULL DEFAULT 0 CHECK (known_exploited >= 0),
    end_of_life     integer NOT NULL DEFAULT 0 CHECK (end_of_life >= 0),
    -- Who asked: a person, or an API token (with the person it acts for).
    created_by      bigint REFERENCES users(id) ON DELETE SET NULL,
    created_by_name text NOT NULL DEFAULT '',
    token_id        bigint REFERENCES api_tokens(id) ON DELETE SET NULL,
    created_at      timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX site_checks_workspace_created ON site_checks (workspace_id, created_at DESC, id DESC);
ALTER TABLE site_checks ENABLE ROW LEVEL SECURITY, FORCE ROW LEVEL SECURITY;
CREATE POLICY ws ON site_checks USING (workspace_id = stackurity_ws()) WITH CHECK (workspace_id = stackurity_ws());
CREATE POLICY sys ON site_checks USING (stackurity_system()) WITH CHECK (stackurity_system());

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'stackurity_app') THEN
        GRANT SELECT, INSERT, DELETE ON site_checks TO stackurity_app;
        GRANT USAGE ON SEQUENCE site_checks_id_seq TO stackurity_app;
    END IF;
END $$;
