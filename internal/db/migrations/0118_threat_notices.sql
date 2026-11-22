-- Threat notices (docs/threat-notices.md): when a new attack, attacker tool
-- or actively exploited vulnerability appears, each organisation is told
-- once whether it was found on its assets, whether its connected assets are
-- checked and clean, which connection the check still needs, or (an older
-- self-hosted server) that it must upgrade to get the check.
--
--   threats_seen              the threat catalogue entries this server has
--                             known (embedded in the release, or from the
--                             signed feed), and on Stackurity Cloud when the
--                             owner's summary copy was sent. Public
--                             intelligence: no workspace data; the copy's
--                             counts are totals per verdict, never names.
--   threat_notices            one per organisation and threat: the verdict,
--                             what it rests on (counts only), the verdict
--                             people were last told and when each channel
--                             (banner, email, notification routes) had it.
--   threat_notice_dismissals  who hid the banner and when: it stays hidden
--                             until people are told something new
--                             (banner_at moves past dismissed_at).
--
-- Routes get a new event, threat_notices, which every route that sends
-- messages as they happen (urgent, new issues or problems) is given, so
-- existing Slack, Teams and email routes receive notices without a change.
-- Webhook routes are left out: a receiver may not expect the new event
-- (threat_notice), so they opt in.
--
-- Additive: three new tables, a widened CHECK and an UPDATE of routes.
--
-- Release owner: renumber this file only if another migration takes the
-- same file name (duplicate numbers are fine).

SET LOCAL lock_timeout = '10s';
SELECT set_config('stackurity.scope', 'system', true);

CREATE TABLE threats_seen (
    id            text PRIMARY KEY CHECK (id ~ '^[a-z0-9][a-z0-9-]{0,63}$'),
    name          text NOT NULL CHECK (name <> '' AND length(name) <= 200),
    revision      integer NOT NULL CHECK (revision >= 1),
    source        text NOT NULL CHECK (source IN ('embedded', 'feed')),
    first_seen_at timestamptz NOT NULL DEFAULT now(),
    updated_at    timestamptz NOT NULL DEFAULT now(),
    -- Stackurity Cloud only (STACKURITY_THREAT_NOTICE_COPY_TO): the one
    -- summary email per threat to the operator, and the totals it gave.
    copy_sent_at  timestamptz,
    copy_counts   jsonb NOT NULL DEFAULT '{}' CHECK (jsonb_typeof(copy_counts) = 'object')
);

CREATE TABLE threat_notices (
    id               bigserial PRIMARY KEY,
    workspace_id     bigint NOT NULL DEFAULT stackurity_ws() REFERENCES workspaces(id) ON DELETE CASCADE,
    threat_id        text NOT NULL REFERENCES threats_seen(id) ON DELETE CASCADE,
    -- The verdict now, and the one people were last told (they differ when
    -- it improved, or changed in a way that is not news: see
    -- threats.Worsened).
    verdict          text NOT NULL CHECK (verdict IN ('found', 'covered', 'needs_connection', 'upgrade')),
    notified_verdict text NOT NULL CHECK (notified_verdict IN ('found', 'covered', 'needs_connection', 'upgrade')),
    -- Evidence, as counts: open findings of the threat's rules and
    -- vulnerabilities and on how many assets; assets per connection the
    -- threat needs ({"host_agent": 3}); the connections still missing.
    findings         integer NOT NULL DEFAULT 0 CHECK (findings >= 0),
    assets           integer NOT NULL DEFAULT 0 CHECK (assets >= 0),
    connected        jsonb NOT NULL DEFAULT '{}' CHECK (jsonb_typeof(connected) = 'object'),
    -- Assets per connection whose collector is older than the check (not
    -- checked yet), and open findings of the threat's signal rules
    -- (something only named like it).
    outdated         jsonb NOT NULL DEFAULT '{}' CHECK (jsonb_typeof(outdated) = 'object'),
    signals          integer NOT NULL DEFAULT 0 CHECK (signals >= 0),
    -- What people were told with notified_verdict (the same counts, the
    -- missing connections, and the assets with findings for scoping
    -- routes): an email retried, or a delivery a restart cut short, says
    -- that, not a later quiet change.
    told             jsonb NOT NULL DEFAULT '{}' CHECK (jsonb_typeof(told) = 'object'),
    missing          text[] NOT NULL DEFAULT '{}',
    created_at       timestamptz NOT NULL DEFAULT now(),
    updated_at       timestamptz NOT NULL DEFAULT now(),
    -- Delivery per channel for notified_verdict. The banner shows from
    -- banner_at (moved only when people are told). email_result says what
    -- happened to the email to the administrators and security team; a
    -- failed send is tried again (email_at stays empty) up to 5 attempts;
    -- channels_queued is how many notification routes were given it.
    banner_at        timestamptz NOT NULL DEFAULT now(),
    email_at         timestamptz,
    email_result     text NOT NULL DEFAULT '' CHECK (email_result IN ('', 'sent', 'no_mailer', 'no_recipients', 'failed')),
    email_recipients integer NOT NULL DEFAULT 0,
    email_attempts   integer NOT NULL DEFAULT 0,
    channels_at      timestamptz,
    channels_queued  integer NOT NULL DEFAULT 0,
    UNIQUE (workspace_id, threat_id)
);
CREATE INDEX threat_notices_threat ON threat_notices (threat_id, verdict);
-- Organisation-wide: a member with access to some projects only does not
-- see them (they speak about every asset).
ALTER TABLE threat_notices ENABLE ROW LEVEL SECURITY, FORCE ROW LEVEL SECURITY;
CREATE POLICY ws ON threat_notices
    USING (workspace_id = stackurity_ws() AND (SELECT stackurity_narrowed()) IS NOT TRUE)
    WITH CHECK (workspace_id = stackurity_ws() AND (SELECT stackurity_narrowed()) IS NOT TRUE);
CREATE POLICY sys ON threat_notices USING (stackurity_system()) WITH CHECK (stackurity_system());

CREATE TABLE threat_notice_dismissals (
    workspace_id bigint NOT NULL DEFAULT stackurity_ws() REFERENCES workspaces(id) ON DELETE CASCADE,
    notice_id    bigint NOT NULL REFERENCES threat_notices(id) ON DELETE CASCADE,
    user_id      bigint NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    -- The verdict the banner showed when it was hidden (a record only).
    verdict      text NOT NULL CHECK (verdict IN ('found', 'covered', 'needs_connection', 'upgrade')),
    dismissed_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (notice_id, user_id)
);
CREATE INDEX threat_notice_dismissals_user ON threat_notice_dismissals (user_id);
CREATE TRIGGER threat_notice_dismissals_notice_same_ws BEFORE INSERT OR UPDATE OF notice_id ON threat_notice_dismissals
    FOR EACH ROW EXECUTE FUNCTION stackurity_same_workspace('threat_notices', 'notice_id');
CREATE TRIGGER threat_notice_dismissals_user_same_ws BEFORE INSERT OR UPDATE OF user_id ON threat_notice_dismissals
    FOR EACH ROW EXECUTE FUNCTION stackurity_same_workspace('users', 'user_id');
ALTER TABLE threat_notice_dismissals ENABLE ROW LEVEL SECURITY, FORCE ROW LEVEL SECURITY;
CREATE POLICY ws ON threat_notice_dismissals
    USING (workspace_id = stackurity_ws() AND (SELECT stackurity_narrowed()) IS NOT TRUE)
    WITH CHECK (workspace_id = stackurity_ws() AND (SELECT stackurity_narrowed()) IS NOT TRUE);
CREATE POLICY sys ON threat_notice_dismissals USING (stackurity_system()) WITH CHECK (stackurity_system());

-- Routes: the threat_notices event. Routes that send messages as they
-- happen get it, so nothing needs changing for notices to arrive.
ALTER TABLE routes DROP CONSTRAINT routes_events_check;
ALTER TABLE routes ADD CONSTRAINT routes_events_check
    CHECK (events <@ ARRAY['urgent', 'new_issues', 'regressed', 'overdue', 'connected', 'problems', 'daily_summary',
                           'weekly_summary', 'threat_notices']);
UPDATE routes SET events = events || '{threat_notices}'::text[]
    WHERE NOT ('threat_notices' = ANY (events)) AND (events && '{urgent,new_issues,problems}'::text[])
      AND NOT EXISTS (SELECT 1 FROM channels c WHERE c.id = routes.channel_id AND c.kind = 'webhook');
