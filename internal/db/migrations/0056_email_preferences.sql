-- Email preferences for bulk email (internal/notify/bulk.go). Additive: four
-- new tables, each for platform work only (row-level security lets only the
-- system scope in; the API reaches them for the signed-in person or a signed
-- link, never across people).
--
-- Bulk email has categories a person can unsubscribe from: marketing
-- (product updates, release announcements) and vulnerability_news.
-- Transactional email (sign-up, password reset, invitations, billing) and
-- notifications about the person's own organisation (alerts, summaries,
-- incidents) are not bulk email and are not affected by anything here.

SELECT set_config('stackurity.scope', 'system', true);

-- A person's choice per category. No row means subscribed (the default);
-- a row records the latest choice, when it was made and how: link (the
-- preference page opened from an email), header (a mail client's one-click
-- unsubscribe, RFC 8058), settings (signed in, Your account) or support (an
-- operator acting on a request, stackurity admin email-suppress).
CREATE TABLE email_preferences (
    user_id     bigint NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    category    text NOT NULL CHECK (category IN ('marketing', 'vulnerability_news')),
    subscribed  boolean NOT NULL,
    source      text NOT NULL CHECK (source IN ('link', 'header', 'settings', 'support')),
    changed_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, category)
);
ALTER TABLE email_preferences ENABLE ROW LEVEL SECURITY, FORCE ROW LEVEL SECURITY;
CREATE POLICY sys ON email_preferences USING (stackurity_system()) WITH CHECK (stackurity_system());

-- Unsubscribed addresses per category, kept by the SHA-256 of the
-- lower-cased address (as email_blocks), so an unsubscribe still holds
-- after the account is deleted or its address changes, without keeping the
-- address. Every bulk send checks this, the person's preference and
-- email_blocks just before it goes. Subscribing again in settings or on
-- the preference page removes the row.
CREATE TABLE email_suppressions (
    email_hash  bytea NOT NULL,
    category    text NOT NULL CHECK (category IN ('marketing', 'vulnerability_news')),
    source      text NOT NULL CHECK (source IN ('link', 'header', 'settings', 'support')),
    created_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (email_hash, category)
);
ALTER TABLE email_suppressions ENABLE ROW LEVEL SECURITY, FORCE ROW LEVEL SECURITY;
CREATE POLICY sys ON email_suppressions USING (stackurity_system()) WITH CHECK (stackurity_system());

-- One bulk email (a release announcement, a vulnerability digest), keyed so
-- that running it again continues it instead of starting another. The
-- message is stored, so a retry sends exactly what the first run sent.
CREATE TABLE email_campaigns (
    id          bigserial PRIMARY KEY,
    key         text NOT NULL UNIQUE CHECK (key ~ '^[a-z0-9][a-z0-9._-]{0,99}$'),
    category    text NOT NULL CHECK (category IN ('marketing', 'vulnerability_news')),
    subject     text NOT NULL CHECK (length(subject) BETWEEN 1 AND 200),
    message     jsonb NOT NULL,
    created_by  text NOT NULL DEFAULT '' CHECK (length(created_by) <= 200),
    created_at  timestamptz NOT NULL DEFAULT now()
);
ALTER TABLE email_campaigns ENABLE ROW LEVEL SECURITY, FORCE ROW LEVEL SECURITY;
CREATE POLICY sys ON email_campaigns USING (stackurity_system()) WITH CHECK (stackurity_system());

-- Each recipient of a campaign, claimed before the email is handed to the
-- mail server: sending (claimed; never claimed again, so a crash mid-send
-- cannot send twice), sent, skipped (unsubscribed, suppressed, blocked or
-- disabled when its turn came; reason says which) or failed (the mail
-- server refused it; a later run tries again).
CREATE TABLE email_campaign_sends (
    campaign_id  bigint NOT NULL REFERENCES email_campaigns(id) ON DELETE CASCADE,
    user_id      bigint NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    status       text NOT NULL CHECK (status IN ('sending', 'sent', 'skipped', 'failed')),
    reason       text NOT NULL DEFAULT '' CHECK (length(reason) <= 500),
    updated_at   timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (campaign_id, user_id)
);
CREATE INDEX email_campaign_sends_user ON email_campaign_sends (user_id);
ALTER TABLE email_campaign_sends ENABLE ROW LEVEL SECURITY, FORCE ROW LEVEL SECURITY;
CREATE POLICY sys ON email_campaign_sends USING (stackurity_system()) WITH CHECK (stackurity_system());
