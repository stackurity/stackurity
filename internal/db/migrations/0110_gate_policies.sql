-- Policy gates (docs/design/policy-gates.md, docs/policy-gates.md): an
-- organisation writes rules once ("no known exploited vulnerability on an
-- internet-facing asset"), scoped like notifications (migration 0096), and
-- CI jobs, deploy pipelines, the Dashboard and the weekly summary read the
-- same answer.
--
-- A policy belongs to the organisation (both owners NULL), to a project or
-- to an asset. The organisation's policies reach every asset; a project or
-- asset can turn an inherited policy off for itself
-- (gate_policy_exclusions) or replace it with its own copy
-- (inherits_policy_id), and add policies of its own.
--
-- Violations are computed on read from findings and leaks; there is no
-- violations table to drift. gate_policy_open keeps the violations seen by
-- the last rollup, so gate_policy_daily can count those opened and closed
-- each day. gate_policy_checks records every check a pipeline asks for
-- (written from the check endpoint, delivery step 2). Additive only: new
-- tables, nothing existing changes.

SET LOCAL lock_timeout = '10s';
SELECT set_config('stackurity.scope', 'system', true);

CREATE TABLE gate_policies (
    id                 bigserial PRIMARY KEY,
    workspace_id       bigint NOT NULL DEFAULT stackurity_ws() REFERENCES workspaces(id) ON DELETE CASCADE,
    name               text NOT NULL CHECK (length(name) BETWEEN 1 AND 200),
    description        text NOT NULL DEFAULT '' CHECK (length(description) <= 2000),
    kind               text NOT NULL CHECK (kind IN ('known_exploited', 'end_of_life', 'finding_age', 'leaked_key')),
    -- The rule's parameters, checked per kind by the store
    -- (store.NormalizeGateParams).
    params             jsonb NOT NULL DEFAULT '{}' CHECK (jsonb_typeof(params) = 'object'),
    -- Asset filters: asset_kinds[], environments[] ("production" means the
    -- risk policy's production environments), exposure any|exposed, tags[].
    filters            jsonb NOT NULL DEFAULT '{}' CHECK (jsonb_typeof(filters) = 'object'),
    mode               text NOT NULL DEFAULT 'warn' CHECK (mode IN ('off', 'warn', 'enforce')),
    owner_project_id   bigint REFERENCES projects(id) ON DELETE CASCADE,
    owner_asset_id     bigint REFERENCES assets(id) ON DELETE CASCADE,
    inherits_policy_id bigint REFERENCES gate_policies(id) ON DELETE SET NULL,
    -- Goes up by one with every change of kind, params or filters (not of
    -- name, description or mode), so a check or an exception can say which
    -- version of the rule it saw.
    rule_version       integer NOT NULL DEFAULT 1 CHECK (rule_version >= 1),
    created_by         bigint REFERENCES users(id) ON DELETE SET NULL,
    created_by_name    text NOT NULL DEFAULT '',
    created_at         timestamptz NOT NULL DEFAULT now(),
    updated_by         bigint REFERENCES users(id) ON DELETE SET NULL,
    updated_by_name    text NOT NULL DEFAULT '',
    updated_at         timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT gate_policies_one_owner CHECK (num_nonnulls(owner_project_id, owner_asset_id) <= 1)
);
-- Names are unique per owner, as for notification rules.
CREATE UNIQUE INDEX gate_policies_name_key ON gate_policies (workspace_id, COALESCE(owner_project_id, 0), COALESCE(owner_asset_id, 0), name);
CREATE INDEX gate_policies_owner_project ON gate_policies (owner_project_id) WHERE owner_project_id IS NOT NULL;
CREATE INDEX gate_policies_owner_asset ON gate_policies (owner_asset_id) WHERE owner_asset_id IS NOT NULL;
CREATE INDEX gate_policies_inherits ON gate_policies (inherits_policy_id) WHERE inherits_policy_id IS NOT NULL;
ALTER TABLE gate_policies ENABLE ROW LEVEL SECURITY, FORCE ROW LEVEL SECURITY;
CREATE POLICY ws ON gate_policies USING (workspace_id = stackurity_ws()) WITH CHECK (workspace_id = stackurity_ws());
CREATE POLICY sys ON gate_policies USING (stackurity_system()) WITH CHECK (stackurity_system());

-- An inherited policy turned off for a project or an asset.
CREATE TABLE gate_policy_exclusions (
    id           bigserial PRIMARY KEY,
    workspace_id bigint NOT NULL DEFAULT stackurity_ws() REFERENCES workspaces(id) ON DELETE CASCADE,
    policy_id    bigint NOT NULL REFERENCES gate_policies(id) ON DELETE CASCADE,
    project_id   bigint REFERENCES projects(id) ON DELETE CASCADE,
    asset_id     bigint REFERENCES assets(id) ON DELETE CASCADE,
    created_by   bigint REFERENCES users(id) ON DELETE SET NULL,
    created_at   timestamptz NOT NULL DEFAULT now(),
    CHECK (num_nonnulls(project_id, asset_id) = 1)
);
CREATE UNIQUE INDEX gate_policy_exclusions_project ON gate_policy_exclusions (policy_id, project_id) WHERE project_id IS NOT NULL;
CREATE UNIQUE INDEX gate_policy_exclusions_asset ON gate_policy_exclusions (policy_id, asset_id) WHERE asset_id IS NOT NULL;
CREATE INDEX gate_policy_exclusions_workspace ON gate_policy_exclusions (workspace_id);
ALTER TABLE gate_policy_exclusions ENABLE ROW LEVEL SECURITY, FORCE ROW LEVEL SECURITY;
CREATE POLICY ws ON gate_policy_exclusions USING (workspace_id = stackurity_ws()) WITH CHECK (workspace_id = stackurity_ws());
CREATE POLICY sys ON gate_policy_exclusions USING (stackurity_system()) WITH CHECK (stackurity_system());

-- Exceptions: a policy does not count against one asset, one component on
-- it, or one finding or leaked key on it, until expires_at. Requested,
-- then approved or declined, as ignore requests (migration 0031). An
-- approved exception always has an expiry (capped by the risk policy's
-- exception_max_days); past it, it counts as ended with end_reason
-- 'expired'. The API comes in a later step; the table is complete now.
--
-- finding_id and leak_id name rows that may be rewritten by evaluations,
-- so they carry no foreign key: an exception whose finding is gone simply
-- matches nothing, and the record stays for evidence.
CREATE TABLE gate_policy_exceptions (
    id                bigserial PRIMARY KEY,
    workspace_id      bigint NOT NULL DEFAULT stackurity_ws() REFERENCES workspaces(id) ON DELETE CASCADE,
    policy_id         bigint NOT NULL REFERENCES gate_policies(id) ON DELETE CASCADE,
    rule_version      integer NOT NULL DEFAULT 1,
    target_kind       text NOT NULL CHECK (target_kind IN ('finding', 'asset', 'component')),
    asset_id          bigint NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    finding_id        bigint,
    leak_id           bigint,
    -- component: the component's purl key (components.purl_key).
    component_key     text NOT NULL DEFAULT '' CHECK (length(component_key) <= 2048),
    -- The finding's advisory key or the leak's rule, for people to read.
    target_label      text NOT NULL DEFAULT '' CHECK (length(target_label) <= 500),
    reason            text NOT NULL CHECK (reason IN ('accepted_risk', 'false_positive', 'mitigated', 'no_fix')),
    note              text NOT NULL DEFAULT '' CHECK (length(note) <= 4000),
    status            text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'approved', 'declined', 'ended')),
    requested_by      bigint REFERENCES users(id) ON DELETE SET NULL,
    requested_by_name text NOT NULL DEFAULT '',
    requested_at      timestamptz NOT NULL DEFAULT now(),
    decided_by        bigint REFERENCES users(id) ON DELETE SET NULL,
    decided_by_name   text NOT NULL DEFAULT '',
    decided_at        timestamptz,
    decision_note     text NOT NULL DEFAULT '' CHECK (length(decision_note) <= 4000),
    expires_at        timestamptz,
    ended_at          timestamptz,
    ended_by          bigint REFERENCES users(id) ON DELETE SET NULL,
    ended_by_name     text NOT NULL DEFAULT '',
    end_reason        text NOT NULL DEFAULT '' CHECK (end_reason IN ('', 'expired', 'revoked', 'fixed')),
    CHECK (target_kind <> 'finding' OR num_nonnulls(finding_id, leak_id) = 1),
    CHECK (target_kind <> 'component' OR (component_key <> '' AND finding_id IS NULL AND leak_id IS NULL)),
    CHECK (target_kind <> 'asset' OR (component_key = '' AND finding_id IS NULL AND leak_id IS NULL)),
    CHECK (status <> 'approved' OR expires_at IS NOT NULL),
    CHECK ((status = 'ended') = (ended_at IS NOT NULL)),
    CHECK ((end_reason <> '') = (ended_at IS NOT NULL))
);
CREATE INDEX gate_policy_exceptions_workspace ON gate_policy_exceptions (workspace_id);
CREATE INDEX gate_policy_exceptions_active ON gate_policy_exceptions (policy_id, asset_id) WHERE status = 'approved';
CREATE INDEX gate_policy_exceptions_pending ON gate_policy_exceptions (requested_at) WHERE status = 'pending';
ALTER TABLE gate_policy_exceptions ENABLE ROW LEVEL SECURITY, FORCE ROW LEVEL SECURITY;
CREATE POLICY ws ON gate_policy_exceptions USING (workspace_id = stackurity_ws()) WITH CHECK (workspace_id = stackurity_ws());
CREATE POLICY sys ON gate_policy_exceptions USING (stackurity_system()) WITH CHECK (stackurity_system());

-- One check a pipeline (or the API) asked for: who, which asset and
-- commit or image, the answer and the violations it listed. Written by
-- the check endpoint (delivery step 2). Kept when the asset is deleted
-- (asset_name says what it was), for evidence.
CREATE TABLE gate_policy_checks (
    id           bigserial PRIMARY KEY,
    workspace_id bigint NOT NULL DEFAULT stackurity_ws() REFERENCES workspaces(id) ON DELETE CASCADE,
    asset_id     bigint REFERENCES assets(id) ON DELETE SET NULL,
    asset_name   text NOT NULL DEFAULT '' CHECK (length(asset_name) <= 500),
    source       text NOT NULL CHECK (source IN ('ci', 'deploy', 'api')),
    actor_type   text NOT NULL DEFAULT '' CHECK (length(actor_type) <= 50),
    actor_id     bigint,
    actor_name   text NOT NULL DEFAULT '' CHECK (length(actor_name) <= 500),
    commit_sha   text NOT NULL DEFAULT '' CHECK (length(commit_sha) <= 100),
    ref          text NOT NULL DEFAULT '' CHECK (length(ref) <= 500),
    image_digest text NOT NULL DEFAULT '' CHECK (length(image_digest) <= 200),
    repository   text NOT NULL DEFAULT '' CHECK (length(repository) <= 2048),
    result       text NOT NULL CHECK (result IN ('pass', 'warn', 'fail')),
    violations   jsonb NOT NULL DEFAULT '[]' CHECK (jsonb_typeof(violations) = 'array'),
    created_at   timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX gate_policy_checks_workspace ON gate_policy_checks (workspace_id, created_at DESC);
CREATE INDEX gate_policy_checks_asset ON gate_policy_checks (asset_id, created_at DESC) WHERE asset_id IS NOT NULL;
ALTER TABLE gate_policy_checks ENABLE ROW LEVEL SECURITY, FORCE ROW LEVEL SECURITY;
CREATE POLICY ws ON gate_policy_checks
    USING (workspace_id = stackurity_ws() AND ((SELECT stackurity_narrowed()) IS NOT TRUE
        OR asset_id IN (SELECT unnest(stackurity_visible_assets()))))
    WITH CHECK (workspace_id = stackurity_ws() AND ((SELECT stackurity_narrowed()) IS NOT TRUE
        OR asset_id IN (SELECT unnest(stackurity_visible_assets()))));
CREATE POLICY sys ON gate_policy_checks USING (stackurity_system()) WITH CHECK (stackurity_system());

-- The violations the last rollup saw, per policy: the next rollup compares
-- against them to count violations opened and closed.
CREATE TABLE gate_policy_open (
    workspace_id  bigint NOT NULL DEFAULT stackurity_ws() REFERENCES workspaces(id) ON DELETE CASCADE,
    policy_id     bigint NOT NULL REFERENCES gate_policies(id) ON DELETE CASCADE,
    violation_key text NOT NULL CHECK (length(violation_key) <= 200),
    asset_id      bigint NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    first_seen    timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (policy_id, violation_key)
);
CREATE INDEX gate_policy_open_workspace ON gate_policy_open (workspace_id);
CREATE INDEX gate_policy_open_asset ON gate_policy_open (asset_id);
ALTER TABLE gate_policy_open ENABLE ROW LEVEL SECURITY, FORCE ROW LEVEL SECURITY;
CREATE POLICY ws ON gate_policy_open USING (workspace_id = stackurity_ws()) WITH CHECK (workspace_id = stackurity_ws());
CREATE POLICY sys ON gate_policy_open USING (stackurity_system()) WITH CHECK (stackurity_system());

-- Daily counts per policy, for trends and evidence: violations and assets
-- as at the day's last rollup, and the violations opened and closed that
-- day. policy_id has no foreign key, so a deleted policy keeps its history
-- (policy_name says what it was).
CREATE TABLE gate_policy_daily (
    workspace_id bigint NOT NULL DEFAULT stackurity_ws() REFERENCES workspaces(id) ON DELETE CASCADE,
    day          date NOT NULL,
    policy_id    bigint NOT NULL,
    policy_name  text NOT NULL DEFAULT '',
    mode         text NOT NULL DEFAULT '',
    violations   integer NOT NULL DEFAULT 0,
    assets       integer NOT NULL DEFAULT 0,
    opened       integer NOT NULL DEFAULT 0,
    closed       integer NOT NULL DEFAULT 0,
    updated_at   timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (workspace_id, policy_id, day)
);
CREATE INDEX gate_policy_daily_day ON gate_policy_daily (workspace_id, day);
ALTER TABLE gate_policy_daily ENABLE ROW LEVEL SECURITY, FORCE ROW LEVEL SECURITY;
CREATE POLICY ws ON gate_policy_daily USING (workspace_id = stackurity_ws()) WITH CHECK (workspace_id = stackurity_ws());
CREATE POLICY sys ON gate_policy_daily USING (stackurity_system()) WITH CHECK (stackurity_system());

DO $$
DECLARE
    r record;
BEGIN
    FOR r IN SELECT * FROM (VALUES
        ('gate_policies', 'owner_project_id', 'projects'),
        ('gate_policies', 'owner_asset_id', 'assets'),
        ('gate_policies', 'inherits_policy_id', 'gate_policies'),
        ('gate_policies', 'created_by', 'users'),
        ('gate_policies', 'updated_by', 'users'),
        ('gate_policy_exclusions', 'policy_id', 'gate_policies'),
        ('gate_policy_exclusions', 'project_id', 'projects'),
        ('gate_policy_exclusions', 'asset_id', 'assets'),
        ('gate_policy_exclusions', 'created_by', 'users'),
        ('gate_policy_exceptions', 'policy_id', 'gate_policies'),
        ('gate_policy_exceptions', 'asset_id', 'assets'),
        ('gate_policy_exceptions', 'requested_by', 'users'),
        ('gate_policy_exceptions', 'decided_by', 'users'),
        ('gate_policy_exceptions', 'ended_by', 'users'),
        ('gate_policy_checks', 'asset_id', 'assets'),
        ('gate_policy_open', 'policy_id', 'gate_policies'),
        ('gate_policy_open', 'asset_id', 'assets')
    ) AS t(tbl, col, ref) LOOP
        EXECUTE format('CREATE TRIGGER %I BEFORE INSERT OR UPDATE OF %I ON %I FOR EACH ROW EXECUTE FUNCTION stackurity_same_workspace(%L, %L)',
            r.tbl || '_' || r.col || '_same_ws', r.col, r.tbl, r.ref, r.col);
    END LOOP;
END $$;

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'stackurity_app') THEN
        GRANT SELECT, INSERT, UPDATE, DELETE ON gate_policies, gate_policy_exclusions, gate_policy_exceptions,
            gate_policy_checks, gate_policy_open, gate_policy_daily TO stackurity_app;
        GRANT USAGE, SELECT, UPDATE ON SEQUENCE gate_policies_id_seq, gate_policy_exclusions_id_seq,
            gate_policy_exceptions_id_seq, gate_policy_checks_id_seq TO stackurity_app;
    END IF;
EXCEPTION WHEN insufficient_privilege THEN NULL;
END $$;
