-- Error reports: errors people hit in the dashboard and 5xx answers from
-- the API (docs/install.md#error-reports). Counted, not logged: one row per
-- fingerprint, day and workspace (NULL: a page before sign-in, or a server
-- error outside any workspace), with the first and last time it was seen,
-- how often, one scrubbed sample, and the versions and browser families
-- that hit it. Nothing here leaves the installation.
--
-- client_errors is workspace data, under row-level security like every
-- tenant table; rows without a workspace are seen only in system scope.
-- client_error_fingerprints is platform data (system scope only): when each
-- fingerprint was first seen, and since when it counts as new, for the
-- Platform health section and its alert. The view client_errors_by_fingerprint
-- adds up the days and workspaces for instance administrators; it runs with
-- the caller's rights, so outside system scope it sees only the caller's
-- own workspace.
--
-- Rows older than 90 days are deleted by the hourly housekeeping.
-- Additive: two new tables and a view.

SET LOCAL lock_timeout = '10s';
SELECT set_config('stackurity.scope', 'system', true);

CREATE TABLE client_errors (
    id           bigserial PRIMARY KEY,
    workspace_id bigint DEFAULT stackurity_ws() REFERENCES workspaces(id) ON DELETE CASCADE,
    day          date NOT NULL DEFAULT current_date,
    -- SHA-256 (hex) of kind, route, API route, status, code, error name and
    -- top frame (internal/clienterrors).
    fingerprint  text NOT NULL CHECK (fingerprint ~ '^[0-9a-f]{64}$'),
    kind         text NOT NULL CHECK (kind IN ('client', 'server')),
    -- What the fingerprint is made of, kept for listing.
    route        text NOT NULL DEFAULT '' CHECK (length(route) <= 200),
    method       text NOT NULL DEFAULT '' CHECK (method IN ('', 'GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS')),
    api_route    text NOT NULL DEFAULT '' CHECK (length(api_route) <= 200),
    status       integer NOT NULL DEFAULT 0 CHECK (status BETWEEN 0 AND 599),
    code         text NOT NULL DEFAULT '' CHECK (length(code) <= 64),
    name         text NOT NULL DEFAULT '' CHECK (length(name) <= 64),
    top_frame    text NOT NULL DEFAULT '' CHECK (length(top_frame) <= 200),
    first_seen   timestamptz NOT NULL DEFAULT now(),
    last_seen    timestamptz NOT NULL DEFAULT now(),
    count        bigint NOT NULL DEFAULT 1 CHECK (count > 0),
    -- The latest report, scrubbed (no ids, emails, tokens, query strings).
    sample       jsonb NOT NULL DEFAULT '{}' CHECK (length(sample::text) <= 8192),
    -- At most 10 of each, in the order first seen.
    versions     text[] NOT NULL DEFAULT '{}' CHECK (cardinality(versions) <= 10),
    browsers     text[] NOT NULL DEFAULT '{}' CHECK (cardinality(browsers) <= 10)
);
CREATE UNIQUE INDEX client_errors_key ON client_errors (COALESCE(workspace_id, 0), fingerprint, day);
CREATE INDEX client_errors_day ON client_errors (day);
CREATE INDEX client_errors_fingerprint ON client_errors (fingerprint, day);
ALTER TABLE client_errors ENABLE ROW LEVEL SECURITY, FORCE ROW LEVEL SECURITY;
CREATE POLICY ws ON client_errors
    USING (workspace_id = stackurity_ws()) WITH CHECK (workspace_id = stackurity_ws());
CREATE POLICY sys ON client_errors USING (stackurity_system()) WITH CHECK (stackurity_system());

CREATE TABLE client_error_fingerprints (
    fingerprint text PRIMARY KEY CHECK (fingerprint ~ '^[0-9a-f]{64}$'),
    first_seen  timestamptz NOT NULL DEFAULT now(),
    last_seen   timestamptz NOT NULL DEFAULT now(),
    -- When it last became new: first seen, or seen again after 7 days or
    -- more without it. The alert goes out once for each value.
    new_since   timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX client_error_fingerprints_new ON client_error_fingerprints (new_since);
ALTER TABLE client_error_fingerprints ENABLE ROW LEVEL SECURITY, FORCE ROW LEVEL SECURITY;
CREATE POLICY sys ON client_error_fingerprints USING (stackurity_system()) WITH CHECK (stackurity_system());

CREATE VIEW client_errors_by_fingerprint WITH (security_invoker = true) AS
    SELECT e.fingerprint, min(e.kind) AS kind, min(e.route) AS route, min(e.method) AS method,
           min(e.api_route) AS api_route, min(e.status) AS status, min(e.code) AS code, min(e.name) AS name,
           min(e.top_frame) AS top_frame, min(e.first_seen) AS first_seen, max(e.last_seen) AS last_seen,
           sum(e.count)::bigint AS count, count(DISTINCT COALESCE(e.workspace_id, 0)) AS workspaces,
           min(e.day) AS first_day, max(e.day) AS last_day
    FROM client_errors e
    GROUP BY e.fingerprint;

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'stackurity_app') THEN
        EXECUTE 'GRANT SELECT, INSERT, UPDATE, DELETE ON client_errors, client_error_fingerprints TO stackurity_app';
        EXECUTE 'GRANT SELECT ON client_errors_by_fingerprint TO stackurity_app';
        EXECUTE 'GRANT USAGE, SELECT, UPDATE ON SEQUENCE client_errors_id_seq TO stackurity_app';
    END IF;
EXCEPTION WHEN insufficient_privilege THEN NULL;
END $$;
