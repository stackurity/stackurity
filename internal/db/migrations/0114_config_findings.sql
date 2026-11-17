-- Config findings: risky settings a collector found in an asset's files
-- (model.ConfigScan, internal/collect/confcheck): AI coding-agent hooks and
-- MCP start commands that download and run code, SSH access that gives
-- root an unrestricted shell, GitHub Actions workflows that run third-party
-- actions by a movable tag. A row names the file, the rule, what in the
-- file it is about (a hook event, a key's fingerprint and comment, an
-- action reference), why it is a risk and what to change. No secret is
-- stored: SSH keys are named by fingerprint, credentials in commands are
-- masked by the collector.
--
-- A finding is identified per asset and collector by its fingerprint (rule,
-- file and subject). A complete scan that no longer sees an open one
-- resolves it as gone; seen again, it opens again. A person can dismiss one
-- (a key that is meant to be there); it stays dismissed.
--
-- Open high findings raise one incident per asset (kind 'config', key
-- 'asset:<id>'), seen by a narrowed connection through its asset like
-- leaked keys. Additive: two new tables and the incidents policy.
--
-- Release owner: renumber this file if another migration takes 0114 first.

SET LOCAL lock_timeout = '10s';
SELECT set_config('stackurity.scope', 'system', true);

CREATE TABLE config_findings (
    id                 bigserial PRIMARY KEY,
    workspace_id       bigint NOT NULL DEFAULT stackurity_ws() REFERENCES workspaces(id) ON DELETE CASCADE,
    asset_id           bigint NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    collector_id       text NOT NULL CHECK (length(collector_id) <= 2048),
    fingerprint        text NOT NULL CHECK (fingerprint ~ '^[0-9a-f]{32}$'),
    rule               text NOT NULL CHECK (length(rule) <= 256),
    category           text NOT NULL CHECK (category IN ('agent_hook', 'ssh', 'ci')),
    title              text NOT NULL DEFAULT '' CHECK (length(title) <= 256),
    severity           text NOT NULL CHECK (severity IN ('high', 'medium', 'low', 'info')),
    path               text NOT NULL CHECK (length(path) <= 2048),
    line               integer NOT NULL DEFAULT 0,
    subject            text NOT NULL DEFAULT '' CHECK (length(subject) <= 256),
    why                text NOT NULL DEFAULT '' CHECK (length(why) <= 2048),
    fix                text NOT NULL DEFAULT '' CHECK (length(fix) <= 2048),
    status             text NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'resolved')),
    resolution         text NOT NULL DEFAULT '' CHECK (resolution IN ('', 'gone', 'dismissed')),
    resolution_note    text NOT NULL DEFAULT '' CHECK (length(resolution_note) <= 1000),
    resolved_by        bigint REFERENCES users(id) ON DELETE SET NULL,
    first_seen         timestamptz NOT NULL DEFAULT now(),
    last_seen          timestamptz NOT NULL DEFAULT now(),
    resolved_at        timestamptz,
    last_collection_id bigint REFERENCES collections(id) ON DELETE SET NULL,
    UNIQUE (asset_id, collector_id, fingerprint),
    CHECK ((status = 'open') = (resolution = ''))
);
CREATE INDEX config_findings_workspace_open ON config_findings (workspace_id, severity) WHERE status = 'open';
CREATE INDEX config_findings_asset ON config_findings (asset_id);
CREATE INDEX config_findings_collection ON config_findings (last_collection_id) WHERE last_collection_id IS NOT NULL;
CREATE TRIGGER config_findings_asset_id_same_ws BEFORE INSERT OR UPDATE OF asset_id ON config_findings
    FOR EACH ROW EXECUTE FUNCTION stackurity_same_workspace('assets', 'asset_id');
CREATE TRIGGER config_findings_resolved_by_same_ws BEFORE INSERT OR UPDATE OF resolved_by ON config_findings
    FOR EACH ROW EXECUTE FUNCTION stackurity_same_workspace('users', 'resolved_by');
ALTER TABLE config_findings ENABLE ROW LEVEL SECURITY, FORCE ROW LEVEL SECURITY;
CREATE POLICY ws ON config_findings
    USING (workspace_id = stackurity_ws() AND ((SELECT stackurity_narrowed()) IS NOT TRUE
        OR asset_id IN (SELECT unnest(stackurity_visible_assets()))))
    WITH CHECK (workspace_id = stackurity_ws() AND ((SELECT stackurity_narrowed()) IS NOT TRUE
        OR asset_id IN (SELECT unnest(stackurity_visible_assets()))));
CREATE POLICY sys ON config_findings USING (stackurity_system()) WITH CHECK (stackurity_system());

-- The last config check per asset and collector: one that did not read
-- everything says so, so an asset with no findings is not shown as clean
-- when part of it was not read.
CREATE TABLE config_scans (
    workspace_id bigint NOT NULL DEFAULT stackurity_ws() REFERENCES workspaces(id) ON DELETE CASCADE,
    asset_id     bigint NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    collector_id text NOT NULL CHECK (length(collector_id) <= 2048),
    complete     boolean NOT NULL,
    reason       text NOT NULL DEFAULT '' CHECK (length(reason) <= 2048),
    found        integer NOT NULL DEFAULT 0,
    scanned_at   timestamptz NOT NULL,
    PRIMARY KEY (asset_id, collector_id)
);
CREATE INDEX config_scans_workspace ON config_scans (workspace_id);
CREATE TRIGGER config_scans_asset_id_same_ws BEFORE INSERT OR UPDATE OF asset_id ON config_scans
    FOR EACH ROW EXECUTE FUNCTION stackurity_same_workspace('assets', 'asset_id');
ALTER TABLE config_scans ENABLE ROW LEVEL SECURITY, FORCE ROW LEVEL SECURITY;
CREATE POLICY ws ON config_scans
    USING (workspace_id = stackurity_ws() AND ((SELECT stackurity_narrowed()) IS NOT TRUE
        OR asset_id IN (SELECT unnest(stackurity_visible_assets()))))
    WITH CHECK (workspace_id = stackurity_ws() AND ((SELECT stackurity_narrowed()) IS NOT TRUE
        OR asset_id IN (SELECT unnest(stackurity_visible_assets()))));
CREATE POLICY sys ON config_scans USING (stackurity_system()) WITH CHECK (stackurity_system());

-- Last, as changing a policy locks its table until the commit.
DROP POLICY ws ON incidents;
CREATE POLICY ws ON incidents
    USING (workspace_id = stackurity_ws() AND ((SELECT stackurity_narrowed()) IS NOT TRUE
        OR incidents.id IN (SELECT f.incident_id FROM findings f
                            WHERE f.asset_id = ANY ((SELECT stackurity_visible_assets())::bigint[]) AND f.incident_id IS NOT NULL)
        OR (incidents.kind IN ('collection', 'coverage', 'leak', 'config') AND incidents.key ~ '^asset:[0-9]+'
            AND substring(incidents.key FROM '^asset:([0-9]+)')::bigint IN (SELECT unnest(stackurity_visible_assets())))
        OR incidents.kind = 'feed'))
    WITH CHECK (workspace_id = stackurity_ws() AND ((SELECT stackurity_narrowed()) IS NOT TRUE
        OR incidents.id IN (SELECT f.incident_id FROM findings f
                            WHERE f.asset_id = ANY ((SELECT stackurity_visible_assets())::bigint[]) AND f.incident_id IS NOT NULL)
        OR (incidents.kind IN ('collection', 'coverage', 'leak', 'config') AND incidents.key ~ '^asset:[0-9]+'
            AND substring(incidents.key FROM '^asset:([0-9]+)')::bigint IN (SELECT unnest(stackurity_visible_assets())))
        OR incidents.kind = 'feed'));
