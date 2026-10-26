-- Foreign keys are checked without row-level security, so on their own they
-- let a workspace point its rows at another workspace's: a route at another
-- workspace's channel, an asset or a finding at its team, a team or a
-- finding at a user who is not a member. Such a write also told the caller
-- whether the other workspace's id exists.
--
-- These triggers require every reference a person can set, and those the
-- notification and remediation code derive from them, to name a row of the
-- same workspace, and every user reference to name a member of it. A
-- violation raises foreign_key_violation, as a missing row does, so the
-- answer is the same whether the id exists elsewhere or not. They fire only
-- when the referencing column is written, and the hot ingest paths
-- (inventory, findings by asset) are left to the code that derives them.

CREATE FUNCTION stackurity_same_workspace() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    ref bigint;
    ok boolean;
BEGIN
    EXECUTE format('SELECT ($1).%I::bigint', TG_ARGV[1]) USING NEW INTO ref;
    IF ref IS NULL THEN
        RETURN NEW;
    END IF;
    IF TG_ARGV[0] = 'users' THEN
        SELECT EXISTS (SELECT 1 FROM workspace_members m WHERE m.user_id = ref AND m.workspace_id = NEW.workspace_id) INTO ok;
    ELSE
        EXECUTE format('SELECT EXISTS (SELECT 1 FROM %I r WHERE r.id = $1 AND r.workspace_id = $2)', TG_ARGV[0])
            USING ref, NEW.workspace_id INTO ok;
    END IF;
    IF NOT ok THEN
        RAISE EXCEPTION '%.% does not name a row of the same workspace', TG_TABLE_NAME, TG_ARGV[1]
            USING ERRCODE = 'foreign_key_violation';
    END IF;
    RETURN NEW;
END $$;

DO $$
DECLARE
    r record;
BEGIN
    FOR r IN SELECT * FROM (VALUES
        ('routes', 'channel_id', 'channels'),
        ('assets', 'owner_team_id', 'teams'),
        ('incidents', 'owner_team_id', 'teams'),
        ('findings', 'assignee_team_id', 'teams'),
        ('findings', 'assignee_user_id', 'users'),
        ('team_members', 'team_id', 'teams'),
        ('team_members', 'user_id', 'users'),
        ('asset_relations', 'from_asset', 'assets'),
        ('asset_relations', 'to_asset', 'assets'),
        ('deliveries', 'channel_id', 'channels'),
        ('deliveries', 'route_id', 'routes'),
        ('deliveries', 'incident_id', 'incidents'),
        ('incident_issues', 'channel_id', 'channels'),
        ('incident_issues', 'incident_id', 'incidents'),
        ('api_tokens', 'asset_id', 'assets'),
        ('api_tokens', 'user_id', 'users'),
        ('integrations', 'asset_id', 'assets'),
        ('remediation_plans', 'policy_id', 'remediation_policies'),
        ('remediation_actions', 'plan_id', 'remediation_plans'),
        ('remediation_actions', 'asset_id', 'assets')
    ) AS t(tbl, col, ref) LOOP
        EXECUTE format('CREATE TRIGGER %I BEFORE INSERT OR UPDATE OF %I ON %I FOR EACH ROW EXECUTE FUNCTION stackurity_same_workspace(%L, %L)',
            r.tbl || '_' || r.col || '_same_ws', r.col, r.tbl, r.ref, r.col);
    END LOOP;
END $$;
