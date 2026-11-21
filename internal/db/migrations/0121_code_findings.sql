-- Code findings: what code-review security scanners found in a
-- repository's source, imported from their reports (internal/codefindings):
-- deepsec's JSON export and SARIF 2.1.0. A row names the source (deepsec,
-- or sarif:<tool>), the scanner's rule, the file and lines, the finding's
-- text and fix, and the source's own verdict (deepsec's revalidation:
-- true-positive, false-positive, fixed, uncertain, accepted-risk,
-- duplicate; SARIF: suppressed). Text is stored and shown as plain text.
-- No person named in a report (owners, committers) is stored.
--
-- A finding is identified per asset and source by its fingerprint (rule,
-- file and title or the scanner's own fingerprint; not the lines, which
-- move). A complete import that no longer has an open one resolves it as
-- gone; one whose verdict says there is nothing to do (false positive,
-- fixed, accepted risk, duplicate, suppressed) is resolved as 'verdict'
-- and never alerts. A person can dismiss one; it stays dismissed.
--
-- Open critical and high security findings raise one incident per asset
-- (kind 'code', key 'asset:<id>'), seen by a narrowed connection through
-- its asset like leaked keys and risky settings. Additive: two new tables
-- and the incidents policy.
--
-- Release owner: renumber this file if another migration takes 0121 first.

SET LOCAL lock_timeout = '10s';
SELECT set_config('stackurity.scope', 'system', true);

-- The last import per asset and source: when, from which tool, version,
-- model and run, whether it was complete, and how many it held.
CREATE TABLE code_imports (
    workspace_id bigint NOT NULL DEFAULT stackurity_ws() REFERENCES workspaces(id) ON DELETE CASCADE,
    asset_id     bigint NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    source       text NOT NULL CHECK (source ~ '^[a-z0-9][a-z0-9:._-]{0,79}$'),
    format       text NOT NULL CHECK (format IN ('deepsec', 'sarif')),
    tool         text NOT NULL DEFAULT '' CHECK (length(tool) <= 128),
    tool_version text NOT NULL DEFAULT '' CHECK (length(tool_version) <= 64),
    model        text NOT NULL DEFAULT '' CHECK (length(model) <= 128),
    run_id       text NOT NULL DEFAULT '' CHECK (length(run_id) <= 128),
    complete     boolean NOT NULL,
    found        integer NOT NULL DEFAULT 0,
    imported_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (asset_id, source)
);
CREATE INDEX code_imports_workspace ON code_imports (workspace_id);
CREATE TRIGGER code_imports_asset_id_same_ws BEFORE INSERT OR UPDATE OF asset_id ON code_imports
    FOR EACH ROW EXECUTE FUNCTION stackurity_same_workspace('assets', 'asset_id');
ALTER TABLE code_imports ENABLE ROW LEVEL SECURITY, FORCE ROW LEVEL SECURITY;
CREATE POLICY ws ON code_imports
    USING (workspace_id = stackurity_ws() AND ((SELECT stackurity_narrowed()) IS NOT TRUE
        OR asset_id IN (SELECT unnest(stackurity_visible_assets()))))
    WITH CHECK (workspace_id = stackurity_ws() AND ((SELECT stackurity_narrowed()) IS NOT TRUE
        OR asset_id IN (SELECT unnest(stackurity_visible_assets()))));
CREATE POLICY sys ON code_imports USING (stackurity_system()) WITH CHECK (stackurity_system());

CREATE TABLE code_findings (
    id              bigserial PRIMARY KEY,
    workspace_id    bigint NOT NULL DEFAULT stackurity_ws() REFERENCES workspaces(id) ON DELETE CASCADE,
    asset_id        bigint NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    source          text NOT NULL CHECK (source ~ '^[a-z0-9][a-z0-9:._-]{0,79}$'),
    fingerprint     text NOT NULL CHECK (fingerprint ~ '^[0-9a-f]{32}$'),
    rule            text NOT NULL CHECK (length(rule) BETWEEN 1 AND 256),
    category        text NOT NULL CHECK (category IN ('security', 'bug', 'other')),
    title           text NOT NULL CHECK (length(title) <= 300),
    severity        text NOT NULL CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info')),
    path            text NOT NULL DEFAULT '' CHECK (length(path) <= 1024),
    start_line      integer NOT NULL DEFAULT 0 CHECK (start_line >= 0),
    end_line        integer NOT NULL DEFAULT 0 CHECK (end_line >= 0),
    description     text NOT NULL DEFAULT '' CHECK (length(description) <= 8000),
    recommendation  text NOT NULL DEFAULT '' CHECK (length(recommendation) <= 4000),
    confidence      text NOT NULL DEFAULT '' CHECK (confidence IN ('', 'high', 'medium', 'low')),
    verdict         text NOT NULL DEFAULT '' CHECK (verdict IN ('', 'true-positive', 'false-positive', 'fixed', 'uncertain',
                                                               'accepted-risk', 'duplicate', 'suppressed')),
    verdict_note    text NOT NULL DEFAULT '' CHECK (length(verdict_note) <= 4000),
    tool            text NOT NULL DEFAULT '' CHECK (length(tool) <= 128),
    tool_version    text NOT NULL DEFAULT '' CHECK (length(tool_version) <= 64),
    model           text NOT NULL DEFAULT '' CHECK (length(model) <= 128),
    run_id          text NOT NULL DEFAULT '' CHECK (length(run_id) <= 128),
    status          text NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'resolved')),
    resolution      text NOT NULL DEFAULT '' CHECK (resolution IN ('', 'gone', 'verdict', 'dismissed')),
    resolution_note text NOT NULL DEFAULT '' CHECK (length(resolution_note) <= 1000),
    resolved_by     bigint REFERENCES users(id) ON DELETE SET NULL,
    first_seen      timestamptz NOT NULL DEFAULT now(),
    last_seen       timestamptz NOT NULL DEFAULT now(),
    resolved_at     timestamptz,
    UNIQUE (asset_id, source, fingerprint),
    CHECK ((status = 'open') = (resolution = ''))
);
CREATE INDEX code_findings_workspace_open ON code_findings (workspace_id, severity) WHERE status = 'open';
CREATE INDEX code_findings_asset ON code_findings (asset_id);
CREATE TRIGGER code_findings_asset_id_same_ws BEFORE INSERT OR UPDATE OF asset_id ON code_findings
    FOR EACH ROW EXECUTE FUNCTION stackurity_same_workspace('assets', 'asset_id');
CREATE TRIGGER code_findings_resolved_by_same_ws BEFORE INSERT OR UPDATE OF resolved_by ON code_findings
    FOR EACH ROW EXECUTE FUNCTION stackurity_same_workspace('users', 'resolved_by');
ALTER TABLE code_findings ENABLE ROW LEVEL SECURITY, FORCE ROW LEVEL SECURITY;
CREATE POLICY ws ON code_findings
    USING (workspace_id = stackurity_ws() AND ((SELECT stackurity_narrowed()) IS NOT TRUE
        OR asset_id IN (SELECT unnest(stackurity_visible_assets()))))
    WITH CHECK (workspace_id = stackurity_ws() AND ((SELECT stackurity_narrowed()) IS NOT TRUE
        OR asset_id IN (SELECT unnest(stackurity_visible_assets()))));
CREATE POLICY sys ON code_findings USING (stackurity_system()) WITH CHECK (stackurity_system());

-- Last, as changing a policy locks its table until the commit.
DROP POLICY ws ON incidents;
CREATE POLICY ws ON incidents
    USING (workspace_id = stackurity_ws() AND ((SELECT stackurity_narrowed()) IS NOT TRUE
        OR incidents.id IN (SELECT f.incident_id FROM findings f
                            WHERE f.asset_id = ANY ((SELECT stackurity_visible_assets())::bigint[]) AND f.incident_id IS NOT NULL)
        OR (incidents.kind IN ('collection', 'coverage', 'leak', 'config', 'code') AND incidents.key ~ '^asset:[0-9]+'
            AND substring(incidents.key FROM '^asset:([0-9]+)')::bigint IN (SELECT unnest(stackurity_visible_assets())))
        OR incidents.kind = 'feed'))
    WITH CHECK (workspace_id = stackurity_ws() AND ((SELECT stackurity_narrowed()) IS NOT TRUE
        OR incidents.id IN (SELECT f.incident_id FROM findings f
                            WHERE f.asset_id = ANY ((SELECT stackurity_visible_assets())::bigint[]) AND f.incident_id IS NOT NULL)
        OR (incidents.kind IN ('collection', 'coverage', 'leak', 'config', 'code') AND incidents.key ~ '^asset:[0-9]+'
            AND substring(incidents.key FROM '^asset:([0-9]+)')::bigint IN (SELECT unnest(stackurity_visible_assets())))
        OR incidents.kind = 'feed'));
