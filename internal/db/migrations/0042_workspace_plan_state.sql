-- Per-organisation project limit, read-only state and report mode
-- (docs/asset-limits.md). Additive: nullable or defaulted columns, so no
-- table is rewritten. Each is unset on every self-hosted install: nothing
-- in the core sets them; an instance administrator or a hosted edition's
-- billing may.

SELECT set_config('stackurity.scope', 'system', true);

-- The most active (not archived) projects the organisation may have; NULL
-- means no limit. At the limit new projects are refused; existing ones are
-- never archived or deleted.
ALTER TABLE workspaces ADD COLUMN project_limit integer CHECK (project_limit IS NULL OR project_limit >= 0);

-- Read-only since this time; NULL means the organisation works normally.
-- A read-only organisation can sign in and look at everything, but nothing
-- new is collected and no notifications are sent. The reason is shown to
-- its members.
ALTER TABLE workspaces ADD COLUMN read_only_at timestamptz;
ALTER TABLE workspaces ADD COLUMN read_only_reason text NOT NULL DEFAULT '' CHECK (length(read_only_reason) <= 500);

-- full: reports and exports are complete. trial: they hold the first rows
-- of each list, say how many more there are, and carry a watermark.
ALTER TABLE workspaces ADD COLUMN report_mode text NOT NULL DEFAULT 'full' CHECK (report_mode IN ('full', 'trial'));
