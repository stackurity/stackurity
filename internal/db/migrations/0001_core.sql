-- Stage 1: identity, inventory, coverage, audit, jobs.

CREATE TABLE teams (
    id          bigserial PRIMARY KEY,
    name        text NOT NULL UNIQUE,
    email       text NOT NULL DEFAULT '',
    created_at  timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE users (
    id             bigserial PRIMARY KEY,
    email          text NOT NULL UNIQUE,
    name           text NOT NULL DEFAULT '',
    role           text NOT NULL CHECK (role IN ('admin', 'security', 'engineer', 'viewer')),
    password_hash  text NOT NULL,
    disabled       boolean NOT NULL DEFAULT false,
    created_at     timestamptz NOT NULL DEFAULT now(),
    last_login_at  timestamptz
);

CREATE TABLE team_members (
    team_id  bigint NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
    user_id  bigint NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    PRIMARY KEY (team_id, user_id)
);

CREATE TABLE sessions (
    token_hash  bytea PRIMARY KEY,
    user_id     bigint NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at  timestamptz NOT NULL DEFAULT now(),
    expires_at  timestamptz NOT NULL
);
CREATE INDEX sessions_expires ON sessions (expires_at);

-- API tokens: for users (CLI) or for collectors (agents). Only a hash is stored.
CREATE TABLE api_tokens (
    id            bigserial PRIMARY KEY,
    name          text NOT NULL,
    prefix        text NOT NULL,
    token_hash    bytea NOT NULL UNIQUE,
    user_id       bigint REFERENCES users(id) ON DELETE CASCADE,
    role          text NOT NULL CHECK (role IN ('admin', 'security', 'engineer', 'viewer', 'collector')),
    created_by    bigint REFERENCES users(id) ON DELETE SET NULL,
    created_at    timestamptz NOT NULL DEFAULT now(),
    expires_at    timestamptz,
    last_used_at  timestamptz,
    revoked_at    timestamptz
);

CREATE TABLE assets (
    id                 bigserial PRIMARY KEY,
    kind               text NOT NULL,
    name               text NOT NULL,
    environment        text NOT NULL DEFAULT '',
    owner_team_id      bigint REFERENCES teams(id) ON DELETE SET NULL,
    provider           text NOT NULL DEFAULT '',
    region             text NOT NULL DEFAULT '',
    criticality        text NOT NULL DEFAULT 'unknown' CHECK (criticality IN ('low', 'medium', 'high', 'critical', 'unknown')),
    internet_exposed   boolean,
    tags               text[] NOT NULL DEFAULT '{}',
    attributes         jsonb NOT NULL DEFAULT '{}',
    first_seen         timestamptz NOT NULL DEFAULT now(),
    last_seen          timestamptz NOT NULL DEFAULT now(),
    collection_status  text NOT NULL DEFAULT 'ok',
    merged_into        bigint REFERENCES assets(id),
    created_at         timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX assets_kind ON assets (kind) WHERE merged_into IS NULL;

CREATE TABLE asset_identifiers (
    scheme    text NOT NULL,
    value     text NOT NULL,
    asset_id  bigint NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    first_seen timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (scheme, value)
);
CREATE INDEX asset_identifiers_asset ON asset_identifiers (asset_id);

-- Batches whose identifiers point at more than one asset are recorded here
-- for an administrator to resolve (FR-02).
CREATE TABLE identity_conflicts (
    id           bigserial PRIMARY KEY,
    asset_ids    bigint[] NOT NULL,
    identifiers  jsonb NOT NULL,
    detected_at  timestamptz NOT NULL DEFAULT now(),
    resolved_at  timestamptz,
    resolved_by  bigint REFERENCES users(id)
);

CREATE TABLE asset_relations (
    from_asset  bigint NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    to_asset    bigint NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    kind        text NOT NULL,
    source      text NOT NULL DEFAULT '',
    created_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (from_asset, to_asset, kind)
);

CREATE TABLE components (
    id          bigserial PRIMARY KEY,
    purl_key    text NOT NULL UNIQUE,
    type        text NOT NULL,
    namespace   text NOT NULL DEFAULT '',
    name        text NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX components_name ON components (lower(name));

-- One row per ingested batch: provenance for everything it produced.
CREATE TABLE collections (
    id                bigserial PRIMARY KEY,
    asset_id          bigint NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    collector_id      text NOT NULL,
    collector_version text NOT NULL DEFAULT '',
    method            text NOT NULL,
    observed_at       timestamptz NOT NULL,
    received_at       timestamptz NOT NULL DEFAULT now(),
    complete          boolean NOT NULL,
    observation_count int NOT NULL,
    submitted_by      bigint REFERENCES api_tokens(id) ON DELETE SET NULL
);
CREATE INDEX collections_asset ON collections (asset_id, received_at DESC);

-- Current inventory. Rows absent from a complete collection by the same
-- collector are marked removed rather than deleted, to keep history.
CREATE TABLE inventory (
    id                 bigserial PRIMARY KEY,
    asset_id           bigint NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    component_id       bigint NOT NULL REFERENCES components(id),
    purl               text NOT NULL,
    version            text NOT NULL,
    location           text NOT NULL DEFAULT '',
    collector_id       text NOT NULL,
    direct             boolean,
    scope              text NOT NULL DEFAULT '',
    confidence         text NOT NULL,
    evidence           jsonb NOT NULL DEFAULT '{}',
    first_seen         timestamptz NOT NULL,
    last_seen          timestamptz NOT NULL,
    last_collection_id bigint NOT NULL REFERENCES collections(id),
    removed_at         timestamptz,
    UNIQUE (asset_id, component_id, version, location, collector_id)
);
CREATE INDEX inventory_component ON inventory (component_id) WHERE removed_at IS NULL;
CREATE INDEX inventory_asset ON inventory (asset_id) WHERE removed_at IS NULL;

-- Coverage ledger (FR-16): latest state per target scope, plus history.
CREATE TABLE coverage (
    asset_id      bigint NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    collector_id  text NOT NULL,
    scope         text NOT NULL,
    status        text NOT NULL,
    reason        text NOT NULL DEFAULT '',
    tool_version  text NOT NULL DEFAULT '',
    last_attempt  timestamptz NOT NULL,
    last_success  timestamptz,
    PRIMARY KEY (asset_id, collector_id, scope)
);

CREATE TABLE coverage_history (
    id             bigserial PRIMARY KEY,
    collection_id  bigint NOT NULL REFERENCES collections(id) ON DELETE CASCADE,
    scope          text NOT NULL,
    status         text NOT NULL,
    reason         text NOT NULL DEFAULT ''
);
CREATE INDEX coverage_history_collection ON coverage_history (collection_id);

-- Configured integrations, e.g. Git repositories to scan on a schedule.
CREATE TABLE integrations (
    id            bigserial PRIMARY KEY,
    kind          text NOT NULL,
    name          text NOT NULL,
    config        jsonb NOT NULL DEFAULT '{}',
    secret_ref    text NOT NULL DEFAULT '',
    schedule      interval NOT NULL DEFAULT '6 hours',
    enabled       boolean NOT NULL DEFAULT true,
    asset_id      bigint REFERENCES assets(id) ON DELETE SET NULL,
    last_attempt  timestamptz,
    last_success  timestamptz,
    last_error    text NOT NULL DEFAULT '',
    created_at    timestamptz NOT NULL DEFAULT now(),
    UNIQUE (kind, name)
);

CREATE TABLE audit_events (
    id           bigserial PRIMARY KEY,
    at           timestamptz NOT NULL DEFAULT now(),
    actor_type   text NOT NULL,           -- user, token, system
    actor_id     bigint,
    actor_name   text NOT NULL DEFAULT '',
    action       text NOT NULL,
    object_type  text NOT NULL DEFAULT '',
    object_id    text NOT NULL DEFAULT '',
    detail       jsonb NOT NULL DEFAULT '{}',
    remote_addr  text NOT NULL DEFAULT ''
);
CREATE INDEX audit_events_at ON audit_events (at DESC);
CREATE INDEX audit_events_object ON audit_events (object_type, object_id);

CREATE TABLE jobs (
    id          bigserial PRIMARY KEY,
    kind        text NOT NULL,
    payload     jsonb NOT NULL DEFAULT '{}',
    dedupe_key  text,
    run_at      timestamptz NOT NULL DEFAULT now(),
    attempts    int NOT NULL DEFAULT 0,
    max_attempts int NOT NULL DEFAULT 5,
    locked_by   text,
    locked_at   timestamptz,
    last_error  text NOT NULL DEFAULT '',
    done_at     timestamptz,
    failed_at   timestamptz,
    created_at  timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX jobs_ready ON jobs (run_at) WHERE done_at IS NULL AND failed_at IS NULL;
CREATE UNIQUE INDEX jobs_dedupe ON jobs (dedupe_key) WHERE dedupe_key IS NOT NULL AND done_at IS NULL AND failed_at IS NULL;

CREATE TABLE settings (
    key    text PRIMARY KEY,
    value  jsonb NOT NULL
);
