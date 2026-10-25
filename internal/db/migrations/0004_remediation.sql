-- Stage 4: policy-controlled remediation (FR-10, FR-11, FR-17).
-- Nothing is ever changed without an enabled policy that matches it and an
-- approved plan; detection never depends on any of this.

CREATE TABLE remediation_policies (
    id                bigserial PRIMARY KEY,
    name              text NOT NULL UNIQUE,
    description       text NOT NULL DEFAULT '',
    enabled           boolean NOT NULL DEFAULT false,
    -- what: target kind and scope
    target            text NOT NULL CHECK (target IN ('host_package', 'repository')),
    ecosystems        text[] NOT NULL DEFAULT '{}',   -- purl types: deb, rpm, apk, npm, composer
    components        text[] NOT NULL DEFAULT '{}',   -- versionless purls or globs; empty = any in ecosystems
    environments      text[] NOT NULL DEFAULT '{}',
    team_ids          bigint[] NOT NULL DEFAULT '{}',
    asset_tags        text[] NOT NULL DEFAULT '{}',
    change_types      text[] NOT NULL DEFAULT '{patch}', -- patch, minor, major, distro (security update within a release)
    allow_major       boolean NOT NULL DEFAULT false,    -- a separate, explicit authorisation
    min_priority      text NOT NULL DEFAULT 'P4',
    only_with_findings boolean NOT NULL DEFAULT true,    -- fix findings, not routine updates
    approval          text NOT NULL DEFAULT 'required' CHECK (approval IN ('required', 'automatic')),
    -- how: rollout
    window_days       int[] NOT NULL DEFAULT '{1,2,3,4,5}', -- ISO weekdays
    window_start      text NOT NULL DEFAULT '',             -- "02:00"; empty = any time
    window_end        text NOT NULL DEFAULT '',
    timezone          text NOT NULL DEFAULT 'UTC',
    canary_count      int NOT NULL DEFAULT 1,
    soak_minutes      int NOT NULL DEFAULT 60,
    max_concurrent    int NOT NULL DEFAULT 5,
    health_units      text[] NOT NULL DEFAULT '{}',  -- systemd units that must be active after the change
    auto_rollback     boolean NOT NULL DEFAULT false,
    created_by        bigint REFERENCES users(id) ON DELETE SET NULL,
    created_at        timestamptz NOT NULL DEFAULT now(),
    updated_at        timestamptz NOT NULL DEFAULT now()
);

-- A plan is one approved change: a component to a target version across
-- the assets that need it.
CREATE TABLE remediation_plans (
    id             bigserial PRIMARY KEY,
    policy_id      bigint REFERENCES remediation_policies(id) ON DELETE SET NULL,
    policy_name    text NOT NULL,
    target         text NOT NULL,
    component_id   bigint NOT NULL REFERENCES components(id) ON DELETE CASCADE,
    package        text NOT NULL,         -- package manager name (binary package / npm name)
    target_version text NOT NULL,
    change_type    text NOT NULL,
    finding_keys   text[] NOT NULL DEFAULT '{}',
    status         text NOT NULL DEFAULT 'proposed' CHECK (status IN
                     ('proposed', 'approved', 'rejected', 'in_progress', 'succeeded', 'failed', 'cancelled', 'partially_failed')),
    stage          text NOT NULL DEFAULT 'canary' CHECK (stage IN ('canary', 'main', 'done')),
    rollback       text NOT NULL DEFAULT 'manual',  -- automatic, best_effort, manual, not_applicable
    created_by     text NOT NULL DEFAULT 'system',
    approved_by    bigint REFERENCES users(id) ON DELETE SET NULL,
    approved_at    timestamptz,
    decision_note  text NOT NULL DEFAULT '',
    created_at     timestamptz NOT NULL DEFAULT now(),
    updated_at     timestamptz NOT NULL DEFAULT now(),
    canary_done_at timestamptz
);
CREATE UNIQUE INDEX remediation_plans_active ON remediation_plans (component_id, package, target_version, target)
    WHERE status IN ('proposed', 'approved', 'in_progress');

CREATE TABLE remediation_actions (
    id             bigserial PRIMARY KEY,
    plan_id        bigint NOT NULL REFERENCES remediation_plans(id) ON DELETE CASCADE,
    asset_id       bigint NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    inventory_id   bigint REFERENCES inventory(id) ON DELETE SET NULL,
    kind           text NOT NULL CHECK (kind IN ('package_upgrade', 'package_rollback', 'pull_request')),
    package        text NOT NULL,
    manager        text NOT NULL DEFAULT '',   -- apt, dnf, apk, renovate
    from_version   text NOT NULL,
    to_version     text NOT NULL,
    stage          text NOT NULL DEFAULT 'main',
    status         text NOT NULL DEFAULT 'pending' CHECK (status IN
                     ('pending', 'dispatched', 'applied', 'verified', 'failed', 'rolled_back', 'cancelled', 'skipped')),
    dry_run        jsonb NOT NULL DEFAULT '{}',
    result         jsonb NOT NULL DEFAULT '{}',
    error          text NOT NULL DEFAULT '',
    health         jsonb NOT NULL DEFAULT '{}',
    attempts       int NOT NULL DEFAULT 0,
    created_at     timestamptz NOT NULL DEFAULT now(),
    released_at    timestamptz,   -- set when the rollout lets an agent pick it up
    dispatched_at  timestamptz,
    applied_at     timestamptz,
    verified_at    timestamptz,
    deadline       timestamptz
);
CREATE INDEX remediation_actions_asset ON remediation_actions (asset_id, status);
CREATE INDEX remediation_actions_plan ON remediation_actions (plan_id);
-- One live action per asset and package.
CREATE UNIQUE INDEX remediation_actions_live ON remediation_actions (asset_id, package)
    WHERE status IN ('pending', 'dispatched', 'applied');

-- A collector token can be bound to one asset: an agent may only fetch
-- actions for the host it reports as.
ALTER TABLE api_tokens ADD COLUMN asset_id bigint REFERENCES assets(id) ON DELETE CASCADE;
