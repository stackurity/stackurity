-- AI assistant configuration: risky settings a collector found in the
-- configuration files AI coding assistants read from a project
-- (model.AssistantScan, internal/collect/assistantcfg): a hook or task that
-- downloads and runs code, an MCP server installed from a Git repository, a
-- setting that sends the assistant's requests to another host.
--
-- A finding is identified per asset and collector by its fingerprint (rule,
-- setting and command) and file. A complete scan that no longer sees an
-- open finding resolves it as gone; seen again, it opens again. A person can
-- dismiss one (a setting the team means to keep); a dismissed finding stays
-- dismissed whatever later scans see.
--
-- Open critical and high findings raise one incident per asset (kind
-- 'assistant', key 'asset:<id>'), seen by a narrowed connection through its
-- asset like leaked keys. Additive: two new tables and the incidents policy.

SET LOCAL lock_timeout = '10s';
SELECT set_config('stackurity.scope', 'system', true);

CREATE TABLE assistant_findings (
    id                 bigserial PRIMARY KEY,
    workspace_id       bigint NOT NULL DEFAULT stackurity_ws() REFERENCES workspaces(id) ON DELETE CASCADE,
    asset_id           bigint NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    collector_id       text NOT NULL CHECK (length(collector_id) <= 2048),
    fingerprint        text NOT NULL CHECK (fingerprint ~ '^[0-9a-f]{32}$'),
    path               text NOT NULL CHECK (length(path) <= 2048),
    line               integer NOT NULL DEFAULT 0,
    rule               text NOT NULL CHECK (length(rule) <= 256),
    title              text NOT NULL DEFAULT '' CHECK (length(title) <= 256),
    tool               text NOT NULL DEFAULT '' CHECK (length(tool) <= 256),
    setting            text NOT NULL DEFAULT '' CHECK (length(setting) <= 256),
    command            text NOT NULL DEFAULT '' CHECK (length(command) <= 512),
    severity           text NOT NULL CHECK (severity IN ('critical', 'high', 'medium', 'low')),
    status             text NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'resolved')),
    resolution         text NOT NULL DEFAULT '' CHECK (resolution IN ('', 'gone', 'dismissed')),
    resolution_note    text NOT NULL DEFAULT '' CHECK (length(resolution_note) <= 1000),
    resolved_by        bigint REFERENCES users(id) ON DELETE SET NULL,
    first_seen         timestamptz NOT NULL DEFAULT now(),
    last_seen          timestamptz NOT NULL DEFAULT now(),
    resolved_at        timestamptz,
    last_collection_id bigint REFERENCES collections(id) ON DELETE SET NULL,
    UNIQUE (asset_id, collector_id, fingerprint, path),
    CHECK ((status = 'open') = (resolution = ''))
);
CREATE INDEX assistant_findings_workspace_open ON assistant_findings (workspace_id, severity) WHERE status = 'open';
CREATE INDEX assistant_findings_asset ON assistant_findings (asset_id);
CREATE INDEX assistant_findings_collection ON assistant_findings (last_collection_id) WHERE last_collection_id IS NOT NULL;
CREATE TRIGGER assistant_findings_asset_id_same_ws BEFORE INSERT OR UPDATE OF asset_id ON assistant_findings
    FOR EACH ROW EXECUTE FUNCTION stackurity_same_workspace('assets', 'asset_id');
CREATE TRIGGER assistant_findings_resolved_by_same_ws BEFORE INSERT OR UPDATE OF resolved_by ON assistant_findings
    FOR EACH ROW EXECUTE FUNCTION stackurity_same_workspace('users', 'resolved_by');
ALTER TABLE assistant_findings ENABLE ROW LEVEL SECURITY, FORCE ROW LEVEL SECURITY;
CREATE POLICY ws ON assistant_findings
    USING (workspace_id = stackurity_ws() AND ((SELECT stackurity_narrowed()) IS NOT TRUE
        OR asset_id IN (SELECT unnest(stackurity_visible_assets()))))
    WITH CHECK (workspace_id = stackurity_ws() AND ((SELECT stackurity_narrowed()) IS NOT TRUE
        OR asset_id IN (SELECT unnest(stackurity_visible_assets()))));
CREATE POLICY sys ON assistant_findings USING (stackurity_system()) WITH CHECK (stackurity_system());

-- The last scan per asset and collector: a scan that did not check
-- everything (limits, unreadable or invalid files) says so, and an asset
-- never scanned is not shown as clean.
CREATE TABLE assistant_scans (
    workspace_id bigint NOT NULL DEFAULT stackurity_ws() REFERENCES workspaces(id) ON DELETE CASCADE,
    asset_id     bigint NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    collector_id text NOT NULL CHECK (length(collector_id) <= 2048),
    complete     boolean NOT NULL,
    reason       text NOT NULL DEFAULT '' CHECK (length(reason) <= 2048),
    files        integer NOT NULL DEFAULT 0,
    found        integer NOT NULL DEFAULT 0,
    scanned_at   timestamptz NOT NULL,
    PRIMARY KEY (asset_id, collector_id)
);
CREATE INDEX assistant_scans_workspace ON assistant_scans (workspace_id);
CREATE TRIGGER assistant_scans_asset_id_same_ws BEFORE INSERT OR UPDATE OF asset_id ON assistant_scans
    FOR EACH ROW EXECUTE FUNCTION stackurity_same_workspace('assets', 'asset_id');
ALTER TABLE assistant_scans ENABLE ROW LEVEL SECURITY, FORCE ROW LEVEL SECURITY;
CREATE POLICY ws ON assistant_scans
    USING (workspace_id = stackurity_ws() AND ((SELECT stackurity_narrowed()) IS NOT TRUE
        OR asset_id IN (SELECT unnest(stackurity_visible_assets()))))
    WITH CHECK (workspace_id = stackurity_ws() AND ((SELECT stackurity_narrowed()) IS NOT TRUE
        OR asset_id IN (SELECT unnest(stackurity_visible_assets()))));
CREATE POLICY sys ON assistant_scans USING (stackurity_system()) WITH CHECK (stackurity_system());

-- Last, as changing a policy locks its table until the commit.
DROP POLICY ws ON incidents;
CREATE POLICY ws ON incidents
    USING (workspace_id = stackurity_ws() AND ((SELECT stackurity_narrowed()) IS NOT TRUE
        OR incidents.id IN (SELECT f.incident_id FROM findings f
                            WHERE f.asset_id = ANY ((SELECT stackurity_visible_assets())::bigint[]) AND f.incident_id IS NOT NULL)
        OR (incidents.kind IN ('collection', 'coverage', 'leak', 'assistant') AND incidents.key ~ '^asset:[0-9]+'
            AND substring(incidents.key FROM '^asset:([0-9]+)')::bigint IN (SELECT unnest(stackurity_visible_assets())))
        OR incidents.kind = 'feed'))
    WITH CHECK (workspace_id = stackurity_ws() AND ((SELECT stackurity_narrowed()) IS NOT TRUE
        OR incidents.id IN (SELECT f.incident_id FROM findings f
                            WHERE f.asset_id = ANY ((SELECT stackurity_visible_assets())::bigint[]) AND f.incident_id IS NOT NULL)
        OR (incidents.kind IN ('collection', 'coverage', 'leak', 'assistant') AND incidents.key ~ '^asset:[0-9]+'
            AND substring(incidents.key FROM '^asset:([0-9]+)')::bigint IN (SELECT unnest(stackurity_visible_assets())))
        OR incidents.kind = 'feed'));
