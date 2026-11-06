-- Monthly allowances of an organisation's plan (docs/asset-limits.md,
-- "Plan limits"): SBOM imports a calendar month (UTC). One row per kind
-- and month, taken a place at a time (store.takePlanAllowance), so two
-- imports cannot both take the last one. Unset plan limits never write
-- here.

SET LOCAL lock_timeout = '10s';

CREATE TABLE plan_allowances (
    workspace_id bigint NOT NULL DEFAULT stackurity_ws() REFERENCES workspaces(id) ON DELETE CASCADE,
    kind         text NOT NULL CHECK (kind IN ('sbom_imports')),
    period_start date NOT NULL,
    used         bigint NOT NULL DEFAULT 0 CHECK (used >= 0),
    PRIMARY KEY (workspace_id, kind, period_start)
);
ALTER TABLE plan_allowances ENABLE ROW LEVEL SECURITY, FORCE ROW LEVEL SECURITY;
CREATE POLICY ws ON plan_allowances USING (workspace_id = stackurity_ws()) WITH CHECK (workspace_id = stackurity_ws());
CREATE POLICY sys ON plan_allowances USING (stackurity_system()) WITH CHECK (stackurity_system());

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'stackurity_app') THEN
        GRANT SELECT, INSERT, UPDATE, DELETE ON plan_allowances TO stackurity_app;
    END IF;
END $$;
