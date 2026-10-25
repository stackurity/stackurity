-- Stage 3: risk priority, finding workflow, incidents, notifications.

-- Workflow state is separate from detection status: status (open/resolved)
-- is set by the matcher, state by people.
ALTER TABLE findings
    ADD COLUMN state             text NOT NULL DEFAULT 'new'
        CHECK (state IN ('new', 'acknowledged', 'in_progress', 'suppressed', 'risk_accepted')),
    ADD COLUMN priority          text NOT NULL DEFAULT 'P4' CHECK (priority IN ('P1', 'P2', 'P3', 'P4')),
    ADD COLUMN priority_score    real NOT NULL DEFAULT 0,
    ADD COLUMN priority_factors  jsonb NOT NULL DEFAULT '[]',
    ADD COLUMN sos               boolean NOT NULL DEFAULT false,
    ADD COLUMN sos_rule          text NOT NULL DEFAULT '',
    ADD COLUMN assignee_user_id  bigint REFERENCES users(id) ON DELETE SET NULL,
    ADD COLUMN assignee_team_id  bigint REFERENCES teams(id) ON DELETE SET NULL,
    ADD COLUMN ack_due           timestamptz,
    ADD COLUMN fix_due           timestamptz,
    ADD COLUMN acknowledged_at   timestamptz,
    ADD COLUMN acknowledged_by   bigint REFERENCES users(id) ON DELETE SET NULL,
    ADD COLUMN suppressed_until  timestamptz,
    ADD COLUMN state_reason      text NOT NULL DEFAULT '',
    ADD COLUMN escalation_level  int NOT NULL DEFAULT 0,
    ADD COLUMN escalated_at      timestamptz,
    ADD COLUMN incident_id       bigint;

CREATE INDEX findings_state ON findings (state) WHERE status = 'open';
CREATE INDEX findings_priority ON findings (priority) WHERE status = 'open';
CREATE INDEX findings_incident ON findings (incident_id);

CREATE TABLE finding_events (
    id          bigserial PRIMARY KEY,
    finding_id  bigint NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    at          timestamptz NOT NULL DEFAULT now(),
    actor_type  text NOT NULL,
    actor_id    bigint,
    actor_name  text NOT NULL DEFAULT '',
    action      text NOT NULL,
    from_state  text NOT NULL DEFAULT '',
    to_state    text NOT NULL DEFAULT '',
    note        text NOT NULL DEFAULT '',
    detail      jsonb NOT NULL DEFAULT '{}'
);
CREATE INDEX finding_events_finding ON finding_events (finding_id, at);

-- An incident groups findings with the same issue for the same owner, so
-- one CVE across fifty hosts is one alert, not fifty.
CREATE TABLE incidents (
    id                 bigserial PRIMARY KEY,
    kind               text NOT NULL,     -- vulnerability, end_of_life, collection, feed, coverage
    key                text NOT NULL,     -- CVE / advisory / product:cycle / feed name / asset id
    owner_team_id      bigint REFERENCES teams(id) ON DELETE SET NULL,
    title              text NOT NULL,
    priority           text NOT NULL DEFAULT 'P4',
    sos                boolean NOT NULL DEFAULT false,
    status             text NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'resolved')),
    state              text NOT NULL DEFAULT 'new',   -- rolled up from findings
    finding_count      int NOT NULL DEFAULT 0,
    asset_count        int NOT NULL DEFAULT 0,
    detail             jsonb NOT NULL DEFAULT '{}',
    created_at         timestamptz NOT NULL DEFAULT now(),
    updated_at         timestamptz NOT NULL DEFAULT now(),
    resolved_at        timestamptz,
    notified_priority  text NOT NULL DEFAULT '',   -- highest priority already announced
    notified_at        timestamptz,
    escalation_level   int NOT NULL DEFAULT 0,
    resolved_notified  boolean NOT NULL DEFAULT false
);
-- One open incident per (kind, key, owner); NULL owner is its own group.
CREATE UNIQUE INDEX incidents_open_key ON incidents (kind, key, COALESCE(owner_team_id, 0)) WHERE status = 'open';
CREATE INDEX incidents_status ON incidents (status, priority);

ALTER TABLE findings ADD CONSTRAINT findings_incident_fk FOREIGN KEY (incident_id) REFERENCES incidents(id) ON DELETE SET NULL;

CREATE TABLE channels (
    id          bigserial PRIMARY KEY,
    kind        text NOT NULL CHECK (kind IN ('email', 'slack', 'teams', 'webhook')),
    name        text NOT NULL UNIQUE,
    config      jsonb NOT NULL DEFAULT '{}',
    secret_ref  text NOT NULL DEFAULT '',
    enabled     boolean NOT NULL DEFAULT true,
    created_at  timestamptz NOT NULL DEFAULT now(),
    last_ok_at  timestamptz,
    last_error  text NOT NULL DEFAULT ''
);

-- Routes decide which incidents go to which channel.
CREATE TABLE routes (
    id                   bigserial PRIMARY KEY,
    name                 text NOT NULL UNIQUE,
    channel_id           bigint NOT NULL REFERENCES channels(id) ON DELETE CASCADE,
    enabled              boolean NOT NULL DEFAULT true,
    min_priority         text NOT NULL DEFAULT 'P2' CHECK (min_priority IN ('P1', 'P2', 'P3', 'P4')),
    sos_only             boolean NOT NULL DEFAULT false,
    kinds                text[] NOT NULL DEFAULT '{}',   -- empty = all
    environments         text[] NOT NULL DEFAULT '{}',   -- empty = all
    team_ids             bigint[] NOT NULL DEFAULT '{}', -- empty = all
    escalation           boolean NOT NULL DEFAULT false, -- receives escalations only
    send_resolved        boolean NOT NULL DEFAULT true,
    quiet_start          text NOT NULL DEFAULT '',       -- "22:00"; SOS bypasses quiet hours
    quiet_end            text NOT NULL DEFAULT '',
    timezone             text NOT NULL DEFAULT 'UTC',
    max_per_hour         int NOT NULL DEFAULT 20,
    created_at           timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE deliveries (
    id           bigserial PRIMARY KEY,
    channel_id   bigint NOT NULL REFERENCES channels(id) ON DELETE CASCADE,
    route_id     bigint REFERENCES routes(id) ON DELETE SET NULL,
    incident_id  bigint REFERENCES incidents(id) ON DELETE CASCADE,
    event        text NOT NULL,   -- opened, escalated, priority_raised, resolved, digest, test
    dedupe_key   text NOT NULL,
    payload      jsonb NOT NULL,
    status       text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'sent', 'failed', 'held')),
    attempts     int NOT NULL DEFAULT 0,
    next_attempt timestamptz NOT NULL DEFAULT now(),
    last_error   text NOT NULL DEFAULT '',
    created_at   timestamptz NOT NULL DEFAULT now(),
    sent_at      timestamptz,
    UNIQUE (channel_id, dedupe_key)
);
CREATE INDEX deliveries_pending ON deliveries (next_attempt) WHERE status = 'pending';
CREATE INDEX deliveries_incident ON deliveries (incident_id);
