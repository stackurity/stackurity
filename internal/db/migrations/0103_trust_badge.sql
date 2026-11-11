-- Trust badge, part 1 (docs/trust-badge.md): what the badge's rule reads
-- and the history of its decisions. Nothing here is public, and nothing is
-- written unless STACKURITY_TRUST_BADGE=on.
--
--   inventory_evaluations  when each inventory row was last evaluated against
--                          each vulnerability source, and which refresh of
--                          that source (its cursor and last successful sync)
--                          the evaluation used. inventory.coverage_feed and
--                          evaluated_at stay as they are.
--   trust_badges           a workspace's badges: slug, scope (projects or
--                          assets, never the whole organisation), the badge
--                          terms accepted, and one switch per public item.
--   trust_badge_status     every decision (active or not active) with its
--                          evidence. Append-only: the application role may
--                          not update or delete it, and a trigger rejects
--                          both for anyone outside the retention purge.
--   trust_badge_purges     one row for each retention purge.
--
-- The retention purge is trust_badge_status_purge(older_than, policy), a
-- SECURITY DEFINER function that only the stackurity_purge role may run. It
-- deletes only decisions older than the period (at least 30 days) and
-- records the purge. History has no foreign keys to badges or workspaces on
-- purpose: deleting a badge or an organisation must not delete its history
-- outside the retention policy, which counsel sets.
--
-- Limit, documented in docs/trust-badge.md: where the migrating user may not
-- create roles (some managed databases), the application runs as the table
-- owner, the grants below do not apply, and only the trigger stands between
-- the application and the history.

SET LOCAL lock_timeout = '10s';
SELECT set_config('stackurity.scope', 'system', true);

CREATE TABLE inventory_evaluations (
    inventory_id      bigint NOT NULL REFERENCES inventory(id) ON DELETE CASCADE,
    feed              text NOT NULL CHECK (feed <> ''),
    workspace_id      bigint NOT NULL DEFAULT stackurity_ws() REFERENCES workspaces(id) ON DELETE CASCADE,
    evaluated_at      timestamptz NOT NULL,
    -- The source as the evaluation read it: its cursor and last successful
    -- sync at the start of the run (NULL: it had never synced).
    feed_cursor       text NOT NULL DEFAULT '',
    feed_last_success timestamptz,
    PRIMARY KEY (inventory_id, feed)
);
CREATE INDEX inventory_evaluations_workspace ON inventory_evaluations (workspace_id);
ALTER TABLE inventory_evaluations ENABLE ROW LEVEL SECURITY, FORCE ROW LEVEL SECURITY;
CREATE POLICY ws ON inventory_evaluations USING (workspace_id = stackurity_ws()) WITH CHECK (workspace_id = stackurity_ws());
CREATE POLICY sys ON inventory_evaluations USING (stackurity_system()) WITH CHECK (stackurity_system());

CREATE TABLE trust_badges (
    id                bigserial PRIMARY KEY,
    workspace_id      bigint NOT NULL DEFAULT stackurity_ws() REFERENCES workspaces(id) ON DELETE CASCADE,
    -- The public address (stackurity.ai/trust/<slug>): unique across every
    -- workspace, lower case.
    slug              text NOT NULL CHECK (slug ~ '^[a-z0-9][a-z0-9-]{1,48}[a-z0-9]$'),
    enabled           boolean NOT NULL DEFAULT false,
    -- What the badge covers, like a notification rule: some projects or
    -- some assets. There is no organisation-wide scope.
    scope_kind        text NOT NULL CHECK (scope_kind IN ('projects', 'assets')),
    project_ids       bigint[] NOT NULL DEFAULT '{}',
    asset_ids         bigint[] NOT NULL DEFAULT '{}',
    terms_version     text NOT NULL DEFAULT '',
    terms_accepted_by bigint REFERENCES users(id) ON DELETE SET NULL,
    terms_accepted_at timestamptz,
    -- One switch per public item (spec section 5).
    show_marketing    boolean NOT NULL DEFAULT true,
    show_checked_time boolean NOT NULL DEFAULT true,
    show_kinds        boolean NOT NULL DEFAULT false,
    show_logo         boolean NOT NULL DEFAULT true,
    listed            boolean NOT NULL DEFAULT true,
    created_by        bigint REFERENCES users(id) ON DELETE SET NULL,
    created_at        timestamptz NOT NULL DEFAULT now(),
    updated_at        timestamptz NOT NULL DEFAULT now(),
    CHECK ((scope_kind = 'projects' AND cardinality(asset_ids) = 0)
        OR (scope_kind = 'assets' AND cardinality(project_ids) = 0)),
    -- A badge goes live only after someone accepted the badge terms.
    CHECK (NOT enabled OR (terms_version <> '' AND terms_accepted_at IS NOT NULL))
);
CREATE UNIQUE INDEX trust_badges_slug ON trust_badges (slug);
CREATE INDEX trust_badges_workspace ON trust_badges (workspace_id);
ALTER TABLE trust_badges ENABLE ROW LEVEL SECURITY, FORCE ROW LEVEL SECURITY;
CREATE POLICY ws ON trust_badges USING (workspace_id = stackurity_ws()) WITH CHECK (workspace_id = stackurity_ws());
CREATE POLICY sys ON trust_badges USING (stackurity_system()) WITH CHECK (stackurity_system());
CREATE TRIGGER trust_badges_terms_accepted_by_same_ws BEFORE INSERT OR UPDATE OF terms_accepted_by ON trust_badges
    FOR EACH ROW EXECUTE FUNCTION stackurity_same_workspace('users', 'terms_accepted_by');
CREATE TRIGGER trust_badges_created_by_same_ws BEFORE INSERT OR UPDATE OF created_by ON trust_badges
    FOR EACH ROW EXECUTE FUNCTION stackurity_same_workspace('users', 'created_by');

CREATE TABLE trust_badge_status (
    id              bigserial PRIMARY KEY,
    workspace_id    bigint NOT NULL DEFAULT stackurity_ws(),
    badge_id        bigint NOT NULL,
    decided_at      timestamptz NOT NULL,
    result          text NOT NULL CHECK (result IN ('active', 'not_active')),
    reason          text NOT NULL,
    rule_version    text NOT NULL CHECK (rule_version <> ''),
    previous_result text CHECK (previous_result IN ('active', 'not_active')),
    -- The rule's inputs and the decision (internal/trustbadge.Evidence):
    -- enough to rebuild the decision.
    evidence        jsonb NOT NULL
);
CREATE INDEX trust_badge_status_badge ON trust_badge_status (badge_id, decided_at DESC);
CREATE INDEX trust_badge_status_decided ON trust_badge_status (decided_at);
ALTER TABLE trust_badge_status ENABLE ROW LEVEL SECURITY, FORCE ROW LEVEL SECURITY;
CREATE POLICY ws_select ON trust_badge_status FOR SELECT USING (workspace_id = stackurity_ws());
CREATE POLICY ws_insert ON trust_badge_status FOR INSERT WITH CHECK (workspace_id = stackurity_ws());
CREATE POLICY sys ON trust_badge_status USING (stackurity_system()) WITH CHECK (stackurity_system());

CREATE TABLE trust_badge_purges (
    id             bigserial PRIMARY KEY,
    purged_at      timestamptz NOT NULL DEFAULT now(),
    older_than     interval NOT NULL,
    policy_version text NOT NULL,
    rows_deleted   bigint NOT NULL,
    scope          text NOT NULL
);
ALTER TABLE trust_badge_purges ENABLE ROW LEVEL SECURITY, FORCE ROW LEVEL SECURITY;
CREATE POLICY sys ON trust_badge_purges USING (stackurity_system()) WITH CHECK (stackurity_system());

-- Rejects every update, delete and truncate of the history, except deletes
-- made by the purge function: it sets stackurity.trust_badge_purge and runs
-- as the table's owner, never as the application role.
CREATE FUNCTION trust_badge_status_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'DELETE' AND TG_TABLE_NAME = 'trust_badge_status'
       AND current_setting('stackurity.trust_badge_purge', true) = 'on'
       AND (SELECT oid FROM pg_roles WHERE rolname = current_user) = (SELECT relowner FROM pg_class WHERE oid = TG_RELID) THEN
        RETURN OLD;
    END IF;
    RAISE EXCEPTION '% is append-only: entries are never changed, and are deleted only by the retention purge', TG_TABLE_NAME
        USING ERRCODE = 'insufficient_privilege';
END $$;
CREATE TRIGGER trust_badge_status_append_only BEFORE UPDATE OR DELETE ON trust_badge_status
    FOR EACH ROW EXECUTE FUNCTION trust_badge_status_guard();
CREATE TRIGGER trust_badge_status_no_truncate BEFORE TRUNCATE ON trust_badge_status
    FOR EACH STATEMENT EXECUTE FUNCTION trust_badge_status_guard();
CREATE TRIGGER trust_badge_purges_append_only BEFORE UPDATE OR DELETE ON trust_badge_purges
    FOR EACH ROW EXECUTE FUNCTION trust_badge_status_guard();
CREATE TRIGGER trust_badge_purges_no_truncate BEFORE TRUNCATE ON trust_badge_purges
    FOR EACH STATEMENT EXECUTE FUNCTION trust_badge_status_guard();

DO $do$
BEGIN
    EXECUTE format($f$
CREATE FUNCTION trust_badge_status_purge(older_than interval, policy_version text) RETURNS bigint
LANGUAGE plpgsql SECURITY DEFINER SET search_path = %I, pg_temp AS $body$
DECLARE
    n bigint;
    prev_scope text := current_setting('stackurity.scope', true);
BEGIN
    IF older_than IS NULL OR older_than < interval '30 days' THEN
        RAISE EXCEPTION 'the retention period must be at least 30 days';
    END IF;
    IF coalesce(btrim(policy_version), '') = '' THEN
        RAISE EXCEPTION 'a retention policy version is required';
    END IF;
    PERFORM set_config('stackurity.scope', 'system', true);
    PERFORM set_config('stackurity.trust_badge_purge', 'on', true);
    DELETE FROM trust_badge_status WHERE decided_at < now() - older_than;
    GET DIAGNOSTICS n = ROW_COUNT;
    PERFORM set_config('stackurity.trust_badge_purge', '', true);
    INSERT INTO trust_badge_purges (older_than, policy_version, rows_deleted, scope)
        VALUES (older_than, btrim(policy_version), n, 'every workspace');
    PERFORM set_config('stackurity.scope', coalesce(prev_scope, ''), true);
    RETURN n;
END $body$ $f$, current_schema());
END $do$;
REVOKE EXECUTE ON FUNCTION trust_badge_status_purge(interval, text) FROM PUBLIC;

-- The purge role: NOLOGIN, used only for the scheduled purge (SET LOCAL ROLE
-- in its own transaction). Created like stackurity_app (migration 0010).
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'stackurity_purge') THEN
        BEGIN
            CREATE ROLE stackurity_purge NOLOGIN NOSUPERUSER NOBYPASSRLS;
        EXCEPTION
            WHEN duplicate_object OR unique_violation THEN NULL;
            WHEN insufficient_privilege THEN RETURN;
        END;
    END IF;
    BEGIN
        EXECUTE format('GRANT stackurity_purge TO %I', current_user);
    EXCEPTION WHEN insufficient_privilege THEN RETURN;
    END;
    EXECUTE format('GRANT USAGE ON SCHEMA %I TO stackurity_purge', current_schema());
    EXECUTE format('GRANT EXECUTE ON FUNCTION %I.trust_badge_status_purge(interval, text) TO stackurity_purge', current_schema());
END $$;

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'stackurity_app') THEN
        GRANT SELECT, INSERT, UPDATE, DELETE ON inventory_evaluations, trust_badges TO stackurity_app;
        GRANT USAGE, SELECT, UPDATE ON SEQUENCE trust_badges_id_seq TO stackurity_app;
        -- Default privileges grant every table's UPDATE and DELETE: take
        -- them back from the history and the purge log.
        REVOKE ALL ON trust_badge_status, trust_badge_purges FROM stackurity_app;
        GRANT SELECT, INSERT ON trust_badge_status TO stackurity_app;
        GRANT USAGE ON SEQUENCE trust_badge_status_id_seq TO stackurity_app;
        GRANT SELECT ON trust_badge_purges TO stackurity_app;
        REVOKE EXECUTE ON FUNCTION trust_badge_status_purge(interval, text) FROM stackurity_app;
    END IF;
END $$;
