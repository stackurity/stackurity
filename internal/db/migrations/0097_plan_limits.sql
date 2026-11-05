-- Plan limits of an organisation (docs/asset-limits.md, "Plan limits"):
-- how many alert rules, channels, owner rules, CI trusts, VEX sources,
-- API tokens and teams it may have, how many members, which kinds of
-- channel, and whether projects over its project limit are read-only.
-- Empty (the default, and always on a self-hosted install unless an
-- instance administrator sets it) means no limit. A hosted edition sets
-- it from each organisation's plan.
--
-- The limits are enforced by a trigger on each table, so every path that
-- adds a row (the API, the Slack and Teams installs, accepting an
-- invitation, a project's copy of an inherited rule) is held to them. A
-- row that exists is never removed or refused an update: only new ones
-- are refused.

SET LOCAL lock_timeout = '10s';

ALTER TABLE workspaces ADD COLUMN plan_limits jsonb NOT NULL DEFAULT '{}'
    CHECK (jsonb_typeof(plan_limits) = 'object');

-- stackurity_plan_limit(kind) refuses a new row of kind when the
-- organisation already has as many as its plan allows. The count is taken
-- in system scope (a member who works in one project counts the whole
-- organisation) under a per-organisation lock held until the transaction
-- ends, so two requests cannot both take the last place. The refusal is
-- SQLSTATE SK402 with the details as JSON (store.PlanLimitError).
CREATE FUNCTION stackurity_plan_limit() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    kind   text := TG_ARGV[0];
    ws     bigint := NEW.workspace_id;
    prev   text := current_setting('stackurity.scope', true);
    limits jsonb;
    lim    bigint;
    n      bigint;
    ck     text;
    adding text;
BEGIN
    PERFORM set_config('stackurity.scope', 'system', true);
    SELECT plan_limits INTO limits FROM workspaces WHERE id = ws;
    IF limits IS NULL OR limits = '{}'::jsonb THEN
        PERFORM set_config('stackurity.scope', coalesce(prev, ''), true);
        RETURN NEW;
    END IF;

    IF kind = 'channels' AND jsonb_typeof(limits->'allowed_channel_kinds') = 'array' THEN
        ck := CASE
            WHEN NEW.kind = 'slack' AND NEW.config->>'slack_app' = 'true' THEN 'slack_app'
            WHEN NEW.kind = 'teams' AND NEW.config->>'teams_app' = 'true' THEN 'teams_app'
            ELSE NEW.kind END;
        IF NOT (limits->'allowed_channel_kinds') ? ck THEN
            PERFORM set_config('stackurity.scope', coalesce(prev, ''), true);
            RAISE EXCEPTION 'plan_limit' USING ERRCODE = 'SK402',
                DETAIL = jsonb_build_object('kind', 'channel_kind', 'channel_kind', ck,
                    'next_plan', coalesce(limits->>'next_plan', ''))::text;
        END IF;
    END IF;

    -- Only API tokens people make count: agents', enrollment and CI
    -- tokens belong to no user.
    IF kind = 'api_tokens' THEN
        IF NEW.user_id IS NULL THEN
            PERFORM set_config('stackurity.scope', coalesce(prev, ''), true);
            RETURN NEW;
        END IF;
    END IF;

    IF kind = 'members' THEN
        lim := (limits->>'max_members')::bigint;
    ELSE
        lim := (limits->'rule_limits'->>kind)::bigint;
    END IF;
    IF lim IS NULL THEN
        PERFORM set_config('stackurity.scope', coalesce(prev, ''), true);
        RETURN NEW;
    END IF;

    PERFORM pg_advisory_xact_lock(726354142, ws::int);
    CASE kind
    WHEN 'alert_rules' THEN
        SELECT count(*) INTO n FROM routes WHERE workspace_id = ws;
    WHEN 'channels' THEN
        SELECT count(*) INTO n FROM channels WHERE workspace_id = ws;
    WHEN 'owner_rules' THEN
        SELECT count(*) INTO n FROM owner_rules WHERE workspace_id = ws;
    WHEN 'ci_trusts' THEN
        SELECT count(*) INTO n FROM ci_trusts WHERE workspace_id = ws;
    WHEN 'vex_sources' THEN
        SELECT count(*) INTO n FROM vex_sources WHERE workspace_id = ws;
    WHEN 'teams' THEN
        SELECT count(*) INTO n FROM teams WHERE workspace_id = ws;
    WHEN 'api_tokens' THEN
        SELECT count(*) INTO n FROM api_tokens WHERE workspace_id = ws AND user_id IS NOT NULL
            AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at > now());
    WHEN 'members' THEN
        -- Members and pending invitations, the person being added (or
        -- invited again) left out: accepting an invitation turns one into
        -- the other.
        IF TG_TABLE_NAME = 'workspace_members' THEN
            SELECT lower(u.email) INTO adding FROM users u WHERE u.id = NEW.user_id;
        ELSE
            adding := NEW.email;
        END IF;
        SELECT (SELECT count(*) FROM workspace_members m JOIN users u ON u.id = m.user_id
                 WHERE m.workspace_id = ws AND lower(u.email) IS DISTINCT FROM adding)
             + (SELECT count(DISTINCT i.email) FROM invitations i
                 WHERE i.workspace_id = ws AND i.accepted_at IS NULL AND i.revoked_at IS NULL
                   AND i.expires_at > now() AND i.email IS DISTINCT FROM adding)
          INTO n;
    END CASE;
    PERFORM set_config('stackurity.scope', coalesce(prev, ''), true);
    IF n >= lim THEN
        RAISE EXCEPTION 'plan_limit' USING ERRCODE = 'SK402',
            DETAIL = jsonb_build_object('kind', kind, 'limit', lim, 'used', n,
                'next_plan', coalesce(limits->>'next_plan', ''))::text;
    END IF;
    RETURN NEW;
END $$;

CREATE TRIGGER routes_plan_limit BEFORE INSERT ON routes
    FOR EACH ROW EXECUTE FUNCTION stackurity_plan_limit('alert_rules');
CREATE TRIGGER channels_plan_limit BEFORE INSERT ON channels
    FOR EACH ROW EXECUTE FUNCTION stackurity_plan_limit('channels');
CREATE TRIGGER owner_rules_plan_limit BEFORE INSERT ON owner_rules
    FOR EACH ROW EXECUTE FUNCTION stackurity_plan_limit('owner_rules');
CREATE TRIGGER ci_trusts_plan_limit BEFORE INSERT ON ci_trusts
    FOR EACH ROW EXECUTE FUNCTION stackurity_plan_limit('ci_trusts');
CREATE TRIGGER vex_sources_plan_limit BEFORE INSERT ON vex_sources
    FOR EACH ROW EXECUTE FUNCTION stackurity_plan_limit('vex_sources');
CREATE TRIGGER teams_plan_limit BEFORE INSERT ON teams
    FOR EACH ROW EXECUTE FUNCTION stackurity_plan_limit('teams');
CREATE TRIGGER api_tokens_plan_limit BEFORE INSERT ON api_tokens
    FOR EACH ROW EXECUTE FUNCTION stackurity_plan_limit('api_tokens');
CREATE TRIGGER workspace_members_plan_limit BEFORE INSERT ON workspace_members
    FOR EACH ROW EXECUTE FUNCTION stackurity_plan_limit('members');
CREATE TRIGGER invitations_plan_limit BEFORE INSERT ON invitations
    FOR EACH ROW EXECUTE FUNCTION stackurity_plan_limit('members');
