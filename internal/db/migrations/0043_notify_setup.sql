-- Simpler notification setup. Additive: one CHECK constraint is widened,
-- columns are added with defaults, and four tables are created, each with
-- row-level security per workspace. Routes get the events their mode sent,
-- so every existing route keeps its behaviour.

SELECT set_config('stackurity.scope', 'system', true);

-- 1. Routes send an explicit set of events instead of a fixed mode:
--    urgent          new issues at min_priority or above, SOS or known exploited
--    new_issues      new issues at new_min_priority or above
--    regressed       issues that came back after a fix
--    overdue         urgent issues past their fix deadline (with escalation)
--    connected       a new asset's first scan
--    problems        collection, feed, coverage and platform problems
--    daily_summary   a summary every day at summary_time
--    weekly_summary  a summary on summary_day at summary_time
-- event_channels sends some events to another channel of the same kind
-- (Slack only), as {"daily_summary": 12}. mode stays, derived from the
-- events (custom when no old mode matches), for older readers of the API.
-- Each existing route gets the events its mode sent, so nothing changes.
ALTER TABLE routes DROP CONSTRAINT routes_mode_check;
ALTER TABLE routes ADD CONSTRAINT routes_mode_check
    CHECK (mode IN ('urgent_summary', 'urgent_weekly', 'urgent_only', 'daily', 'weekly', 'custom'));
ALTER TABLE routes
    ADD COLUMN events text[] NOT NULL DEFAULT '{urgent,regressed,overdue,connected,problems,daily_summary}'
        CHECK (events <@ ARRAY['urgent', 'new_issues', 'regressed', 'overdue', 'connected', 'problems', 'daily_summary', 'weekly_summary']),
    ADD COLUMN event_channels jsonb NOT NULL DEFAULT '{}' CHECK (jsonb_typeof(event_channels) = 'object'),
    ADD COLUMN new_min_priority text NOT NULL DEFAULT 'P4' CHECK (new_min_priority IN ('P1', 'P2', 'P3', 'P4')),
    -- The end of the period the last weekly summary covered; last_summary_at
    -- is the daily summary's (and, until now, the weekly mode's).
    ADD COLUMN last_weekly_summary_at timestamptz NOT NULL DEFAULT now();
UPDATE routes SET events = CASE mode
        WHEN 'urgent_summary' THEN '{urgent,regressed,overdue,connected,problems,daily_summary}'::text[]
        WHEN 'urgent_only' THEN '{urgent,regressed,overdue,connected,problems}'::text[]
        WHEN 'daily' THEN '{daily_summary}'::text[]
        WHEN 'weekly' THEN '{weekly_summary}'::text[]
    END,
    last_weekly_summary_at = last_summary_at;

-- 2. Why a delivery was held: '' (not held), hourly_limit (the route's
-- max_per_hour) or email_quota (the organisation's email limits on email
-- sent by Stackurity). Kept after the held message is rolled into a summary
-- or digest, so the delivery log and Platform health can say so.
ALTER TABLE deliveries ADD COLUMN held_by text NOT NULL DEFAULT ''
    CHECK (held_by IN ('', 'hourly_limit', 'email_quota'));
CREATE INDEX deliveries_held_by ON deliveries (created_at) WHERE held_by <> '';

-- 3. Email sent by Stackurity (channel kind stackurity_email), delivered
-- through the platform's own mail server on hosted installations.
ALTER TABLE channels DROP CONSTRAINT channels_kind_check;
ALTER TABLE channels ADD CONSTRAINT channels_kind_check
    CHECK (kind IN ('email', 'stackurity_email', 'slack', 'teams', 'webhook', 'jira'));

-- Addresses that are not members of the organisation must confirm once, by a link
-- emailed to them, before anything is sent to them. One row per address per
-- organisation; only the SHA-256 of the link's token is stored.
CREATE TABLE email_recipients (
    id            bigserial PRIMARY KEY,
    workspace_id  bigint NOT NULL DEFAULT stackurity_ws() REFERENCES workspaces(id) ON DELETE CASCADE,
    email         text NOT NULL CHECK (email = lower(email) AND length(email) <= 254),
    token_hash    bytea UNIQUE,
    requested_by  bigint REFERENCES users(id) ON DELETE SET NULL,
    requested_at  timestamptz NOT NULL DEFAULT now(),
    expires_at    timestamptz,
    confirmed_at  timestamptz,
    UNIQUE (workspace_id, email)
);
CREATE TRIGGER email_recipients_requested_by_same_ws BEFORE INSERT OR UPDATE OF requested_by ON email_recipients
    FOR EACH ROW EXECUTE FUNCTION stackurity_same_workspace('users', 'requested_by');
ALTER TABLE email_recipients ENABLE ROW LEVEL SECURITY, FORCE ROW LEVEL SECURITY;
CREATE POLICY ws ON email_recipients USING (workspace_id = stackurity_ws()) WITH CHECK (workspace_id = stackurity_ws());
CREATE POLICY sys ON email_recipients USING (stackurity_system()) WITH CHECK (stackurity_system());

-- Emails sent by Stackurity per organisation, for its per-minute, per-hour
-- and per-day limits. A row is reserved before sending (emails = number of
-- recipients) and removed if the send fails; rows older than a day are
-- removed as new ones are added.
CREATE TABLE email_sends (
    id            bigserial PRIMARY KEY,
    workspace_id  bigint NOT NULL DEFAULT stackurity_ws() REFERENCES workspaces(id) ON DELETE CASCADE,
    sent_at       timestamptz NOT NULL DEFAULT now(),
    emails        int NOT NULL CHECK (emails > 0)
);
CREATE INDEX email_sends_window ON email_sends (workspace_id, sent_at);
ALTER TABLE email_sends ENABLE ROW LEVEL SECURITY, FORCE ROW LEVEL SECURITY;
CREATE POLICY ws ON email_sends USING (workspace_id = stackurity_ws()) WITH CHECK (workspace_id = stackurity_ws());
CREATE POLICY sys ON email_sends USING (stackurity_system()) WITH CHECK (stackurity_system());

-- 4. The Stackurity Slack app ("Add to Slack"). One row per organisation
-- and Slack workspace (team) the app was installed into from it. The bot
-- token is sealed with STACKURITY_SECRET_KEY like stored secrets; each
-- channel's incoming webhook URL is a stored secret. The team id maps
-- uninstall events from Slack to every organisation that installed it.
CREATE TABLE slack_installations (
    id            bigserial PRIMARY KEY,
    workspace_id  bigint NOT NULL DEFAULT stackurity_ws() REFERENCES workspaces(id) ON DELETE CASCADE,
    team_id       text NOT NULL CHECK (team_id ~ '^[A-Z0-9]{1,32}$'),
    team_name     text NOT NULL DEFAULT '' CHECK (length(team_name) <= 200),
    app_id        text NOT NULL DEFAULT '' CHECK (length(app_id) <= 32),
    bot_user_id   text NOT NULL DEFAULT '' CHECK (length(bot_user_id) <= 32),
    scopes        text NOT NULL DEFAULT '' CHECK (length(scopes) <= 1000),
    bot_token     bytea,
    installed_by  bigint REFERENCES users(id) ON DELETE SET NULL,
    installed_at  timestamptz NOT NULL DEFAULT now(),
    UNIQUE (workspace_id, team_id)
);
CREATE INDEX slack_installations_team ON slack_installations (team_id);
CREATE TRIGGER slack_installations_installed_by_same_ws BEFORE INSERT OR UPDATE OF installed_by ON slack_installations
    FOR EACH ROW EXECUTE FUNCTION stackurity_same_workspace('users', 'installed_by');
ALTER TABLE slack_installations ENABLE ROW LEVEL SECURITY, FORCE ROW LEVEL SECURITY;
CREATE POLICY ws ON slack_installations USING (workspace_id = stackurity_ws()) WITH CHECK (workspace_id = stackurity_ws());
CREATE POLICY sys ON slack_installations USING (stackurity_system()) WITH CHECK (stackurity_system());

-- The OAuth state of an "Add to Slack" in progress: single use, 10
-- minutes, bound to the organisation and the person who started it. Only
-- the SHA-256 of the state is stored.
CREATE TABLE slack_oauth_states (
    id            bigserial PRIMARY KEY,
    workspace_id  bigint NOT NULL DEFAULT stackurity_ws() REFERENCES workspaces(id) ON DELETE CASCADE,
    state_hash    bytea NOT NULL UNIQUE,
    user_id       bigint NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    return_to     text NOT NULL DEFAULT '' CHECK (length(return_to) <= 300),
    created_at    timestamptz NOT NULL DEFAULT now(),
    expires_at    timestamptz NOT NULL,
    used_at       timestamptz
);
CREATE INDEX slack_oauth_states_expiry ON slack_oauth_states (expires_at);
CREATE TRIGGER slack_oauth_states_user_id_same_ws BEFORE INSERT OR UPDATE OF user_id ON slack_oauth_states
    FOR EACH ROW EXECUTE FUNCTION stackurity_same_workspace('users', 'user_id');
ALTER TABLE slack_oauth_states ENABLE ROW LEVEL SECURITY, FORCE ROW LEVEL SECURITY;
CREATE POLICY ws ON slack_oauth_states USING (workspace_id = stackurity_ws()) WITH CHECK (workspace_id = stackurity_ws());
CREATE POLICY sys ON slack_oauth_states USING (stackurity_system()) WITH CHECK (stackurity_system());
