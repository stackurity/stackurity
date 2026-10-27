-- Monitored-asset limits per organisation (docs/asset-limits.md). Additive:
-- a nullable column and a new table, so no table is rewritten.

SELECT set_config('stackurity.scope', 'system', true);

-- The most monitored assets the organisation may have; NULL means no limit
-- (every self-hosted install unless an instance admin sets one). At the
-- limit new assets are refused; existing ones keep being collected,
-- evaluated and alerted on.
ALTER TABLE workspaces ADD COLUMN asset_limit integer CHECK (asset_limit IS NULL OR asset_limit >= 0);

-- New assets refused because the organisation was at its limit, one row per
-- asset kind and name with a count of attempts, so admins can see what is
-- waiting. The store keeps the most recent 200 per organisation.
CREATE TABLE refused_assets (
    id               bigserial PRIMARY KEY,
    workspace_id     bigint NOT NULL DEFAULT stackurity_ws() REFERENCES workspaces(id) ON DELETE CASCADE,
    kind             text NOT NULL CHECK (length(kind) <= 40),
    name             text NOT NULL CHECK (length(name) <= 500),
    source           text NOT NULL DEFAULT '' CHECK (length(source) <= 200),
    attempts         integer NOT NULL DEFAULT 1,
    first_refused_at timestamptz NOT NULL DEFAULT now(),
    last_refused_at  timestamptz NOT NULL DEFAULT now(),
    UNIQUE (workspace_id, kind, name)
);
CREATE INDEX refused_assets_recent ON refused_assets (workspace_id, last_refused_at DESC);

ALTER TABLE refused_assets ENABLE ROW LEVEL SECURITY, FORCE ROW LEVEL SECURITY;
-- Read on an organisation route only, like invitations.
CREATE POLICY ws ON refused_assets USING (workspace_id = stackurity_ws()) WITH CHECK (workspace_id = stackurity_ws());
CREATE POLICY sys ON refused_assets USING (stackurity_system()) WITH CHECK (stackurity_system());

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'stackurity_app') THEN
        GRANT SELECT, INSERT, UPDATE, DELETE ON refused_assets TO stackurity_app;
        GRANT USAGE, SELECT, UPDATE ON SEQUENCE refused_assets_id_seq TO stackurity_app;
    END IF;
END $$;
