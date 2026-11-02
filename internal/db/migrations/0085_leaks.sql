-- Leaked keys: keys, tokens and passwords a collector found written in an
-- asset's files (model.LeakScan, internal/collect/leaks). A row names where
-- the value is, a fingerprint and a masked preview; there is no column for
-- the value, which never reaches the server.
--
-- A leak is identified per asset and collector by its fingerprint and file.
-- A complete scan that no longer sees an open leak resolves it as gone;
-- seen again, it opens again. A person can dismiss one (a test key kept on
-- purpose); a dismissed leak stays dismissed whatever later scans see.
--
-- Open critical and high leaks raise one incident per asset (kind 'leak',
-- key 'asset:<id>'), seen by a narrowed connection through its asset like
-- collection and coverage problems. Additive: two new tables (leaks, and
-- leak_scans for whether each asset's last scan was complete) and the
-- incidents policy.

SET LOCAL lock_timeout = '10s';
SELECT set_config('stackurity.scope', 'system', true);

CREATE TABLE leaks (
    id                 bigserial PRIMARY KEY,
    workspace_id       bigint NOT NULL DEFAULT stackurity_ws() REFERENCES workspaces(id) ON DELETE CASCADE,
    asset_id           bigint NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    collector_id       text NOT NULL CHECK (length(collector_id) <= 2048),
    fingerprint        text NOT NULL CHECK (fingerprint ~ '^[0-9a-f]{32}$'),
    path               text NOT NULL CHECK (length(path) <= 2048),
    line               integer NOT NULL DEFAULT 0,
    rule               text NOT NULL CHECK (length(rule) <= 256),
    title              text NOT NULL DEFAULT '' CHECK (length(title) <= 256),
    name               text NOT NULL DEFAULT '' CHECK (length(name) <= 256),
    preview            text NOT NULL DEFAULT '' CHECK (length(preview) <= 256),
    severity           text NOT NULL CHECK (severity IN ('critical', 'high', 'medium', 'low')),
    exposure           text NOT NULL DEFAULT '' CHECK (exposure IN ('', 'served', 'world_readable')),
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
CREATE INDEX leaks_workspace_open ON leaks (workspace_id, severity) WHERE status = 'open';
CREATE INDEX leaks_asset ON leaks (asset_id);
CREATE INDEX leaks_collection ON leaks (last_collection_id) WHERE last_collection_id IS NOT NULL;
CREATE TRIGGER leaks_asset_id_same_ws BEFORE INSERT OR UPDATE OF asset_id ON leaks
    FOR EACH ROW EXECUTE FUNCTION stackurity_same_workspace('assets', 'asset_id');
CREATE TRIGGER leaks_resolved_by_same_ws BEFORE INSERT OR UPDATE OF resolved_by ON leaks
    FOR EACH ROW EXECUTE FUNCTION stackurity_same_workspace('users', 'resolved_by');
ALTER TABLE leaks ENABLE ROW LEVEL SECURITY, FORCE ROW LEVEL SECURITY;
CREATE POLICY ws ON leaks
    USING (workspace_id = stackurity_ws() AND ((SELECT stackurity_narrowed()) IS NOT TRUE
        OR asset_id IN (SELECT unnest(stackurity_visible_assets()))))
    WITH CHECK (workspace_id = stackurity_ws() AND ((SELECT stackurity_narrowed()) IS NOT TRUE
        OR asset_id IN (SELECT unnest(stackurity_visible_assets()))));
CREATE POLICY sys ON leaks USING (stackurity_system()) WITH CHECK (stackurity_system());

-- The last key scan per asset and collector: a scan that did not check
-- everything (limits, unreadable files) says so, so an asset with no open
-- leaks is not shown as clean when part of it was not read.
CREATE TABLE leak_scans (
    workspace_id bigint NOT NULL DEFAULT stackurity_ws() REFERENCES workspaces(id) ON DELETE CASCADE,
    asset_id     bigint NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    collector_id text NOT NULL CHECK (length(collector_id) <= 2048),
    complete     boolean NOT NULL,
    reason       text NOT NULL DEFAULT '' CHECK (length(reason) <= 2048),
    found        integer NOT NULL DEFAULT 0,
    scanned_at   timestamptz NOT NULL,
    PRIMARY KEY (asset_id, collector_id)
);
CREATE INDEX leak_scans_workspace ON leak_scans (workspace_id);
CREATE TRIGGER leak_scans_asset_id_same_ws BEFORE INSERT OR UPDATE OF asset_id ON leak_scans
    FOR EACH ROW EXECUTE FUNCTION stackurity_same_workspace('assets', 'asset_id');
ALTER TABLE leak_scans ENABLE ROW LEVEL SECURITY, FORCE ROW LEVEL SECURITY;
CREATE POLICY ws ON leak_scans
    USING (workspace_id = stackurity_ws() AND ((SELECT stackurity_narrowed()) IS NOT TRUE
        OR asset_id IN (SELECT unnest(stackurity_visible_assets()))))
    WITH CHECK (workspace_id = stackurity_ws() AND ((SELECT stackurity_narrowed()) IS NOT TRUE
        OR asset_id IN (SELECT unnest(stackurity_visible_assets()))));
CREATE POLICY sys ON leak_scans USING (stackurity_system()) WITH CHECK (stackurity_system());

-- Last, as changing a policy locks its table until the commit.
DROP POLICY ws ON incidents;
CREATE POLICY ws ON incidents
    USING (workspace_id = stackurity_ws() AND ((SELECT stackurity_narrowed()) IS NOT TRUE
        OR incidents.id IN (SELECT f.incident_id FROM findings f
                            WHERE f.asset_id = ANY ((SELECT stackurity_visible_assets())::bigint[]) AND f.incident_id IS NOT NULL)
        OR (incidents.kind IN ('collection', 'coverage', 'leak') AND incidents.key ~ '^asset:[0-9]+'
            AND substring(incidents.key FROM '^asset:([0-9]+)')::bigint IN (SELECT unnest(stackurity_visible_assets())))
        OR incidents.kind = 'feed'))
    WITH CHECK (workspace_id = stackurity_ws() AND ((SELECT stackurity_narrowed()) IS NOT TRUE
        OR incidents.id IN (SELECT f.incident_id FROM findings f
                            WHERE f.asset_id = ANY ((SELECT stackurity_visible_assets())::bigint[]) AND f.incident_id IS NOT NULL)
        OR (incidents.kind IN ('collection', 'coverage', 'leak') AND incidents.key ~ '^asset:[0-9]+'
            AND substring(incidents.key FROM '^asset:([0-9]+)')::bigint IN (SELECT unnest(stackurity_visible_assets())))
        OR incidents.kind = 'feed'));
