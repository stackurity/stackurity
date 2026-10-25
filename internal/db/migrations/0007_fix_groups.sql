-- Action plan: findings grouped by the action that resolves them.
ALTER TABLE findings ADD COLUMN fix_group text NOT NULL DEFAULT '';
CREATE INDEX findings_fix_group ON findings (fix_group) WHERE status = 'open';

CREATE TABLE fix_groups (
    id          text PRIMARY KEY,
    asset_id    bigint NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    kind        text NOT NULL,
    data        jsonb NOT NULL,      -- the full group as served by the API
    sort_order  int NOT NULL,        -- urgency order from the planner
    updated_at  timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX fix_groups_asset ON fix_groups (asset_id);
