-- Feedback: the queue the Stackurity team triages, and each installation's
-- record of what its users sent.
--
-- The queue (feedback_items, feedback_attachments, feedback_events,
-- feedback_agent_tokens) is used only on the server that runs it
-- (STACKURITY_FEEDBACK_QUEUE_DIR; the Stackurity team's production). It is
-- platform data: no workspace column, and only system scope sees it, so no
-- workspace principal can read it through any query. Every installation
-- creates the tables; they stay empty unless the queue is on.
--
-- feedback_sent is per workspace and per user: the reference (FB-123) and
-- the status token the queue returned, so "My feedback" can show the status.
-- Additive: five new tables.

SET LOCAL lock_timeout = '10s';
SELECT set_config('stackurity.scope', 'system', true);

CREATE TABLE feedback_items (
    id            bigserial PRIMARY KEY,
    kind          text NOT NULL CHECK (kind IN ('issue', 'feature', 'question')),
    description   text NOT NULL CHECK (length(description) BETWEEN 1 AND 5000),
    contact_email text NOT NULL DEFAULT '' CHECK (length(contact_email) <= 200),
    -- Where it came from: Stackurity Cloud, a self-hosted installation, or
    -- the form on the website.
    source        text NOT NULL CHECK (source IN ('cloud', 'self_hosted', 'website')),
    version       text NOT NULL DEFAULT '' CHECK (length(version) <= 40),
    edition       text NOT NULL DEFAULT '' CHECK (edition IN ('', 'community', 'pro', 'enterprise')),
    page          text NOT NULL DEFAULT '' CHECK (length(page) <= 300),
    browser       text NOT NULL DEFAULT '' CHECK (length(browser) <= 80),
    viewport      text NOT NULL DEFAULT '' CHECK (viewport ~ '^([0-9]{2,5}x[0-9]{2,5})?$'),
    status        text NOT NULL DEFAULT 'new' CHECK (status IN ('new', 'triaged', 'in_progress', 'needs_owner',
                      'fixed', 'released', 'wont_fix', 'duplicate')),
    -- Shown to the person who sent it (the reason for won't fix, what
    -- changed); triage_notes are for the team only.
    resolution    text NOT NULL DEFAULT '' CHECK (length(resolution) <= 2000),
    triage_notes  text NOT NULL DEFAULT '' CHECK (length(triage_notes) <= 20000),
    -- The pull request or issue with the change.
    link          text NOT NULL DEFAULT '' CHECK (length(link) <= 300),
    duplicate_of  bigint REFERENCES feedback_items(id) ON DELETE SET NULL,
    fixed_in      text NOT NULL DEFAULT '' CHECK (length(fixed_in) <= 40),
    -- SHA-256 of the status token the sender's installation keeps.
    token_hash    bytea NOT NULL UNIQUE CHECK (length(token_hash) = 32),
    created_at    timestamptz NOT NULL DEFAULT now(),
    updated_at    timestamptz NOT NULL DEFAULT now(),
    triaged_at    timestamptz,
    closed_at     timestamptz,
    notified_at   timestamptz,
    CHECK ((status IN ('released', 'wont_fix', 'duplicate')) = (closed_at IS NOT NULL)),
    CHECK (status <> 'wont_fix' OR resolution <> '')
);
CREATE INDEX feedback_items_status ON feedback_items (status, id);
CREATE INDEX feedback_items_closed ON feedback_items (closed_at) WHERE closed_at IS NOT NULL;
ALTER TABLE feedback_items ENABLE ROW LEVEL SECURITY, FORCE ROW LEVEL SECURITY;
CREATE POLICY sys ON feedback_items USING (stackurity_system()) WITH CHECK (stackurity_system());

CREATE TABLE feedback_attachments (
    id           bigserial PRIMARY KEY,
    item_id      bigint NOT NULL REFERENCES feedback_items(id) ON DELETE CASCADE,
    name         text NOT NULL CHECK (length(name) BETWEEN 1 AND 100),
    content_type text NOT NULL CHECK (content_type IN ('image/png', 'image/jpeg', 'image/gif', 'image/webp',
                     'video/mp4', 'video/webm', 'application/pdf')),
    size         bigint NOT NULL CHECK (size > 0),
    sha256       bytea NOT NULL CHECK (length(sha256) = 32),
    -- The random file name under the queue's directory.
    storage_key  text NOT NULL UNIQUE CHECK (storage_key ~ '^[0-9a-f]{32}$'),
    -- What was checked: type, size and structure, and the virus scanner
    -- when one is configured.
    scan         text NOT NULL CHECK (scan IN ('checked', 'checked_clamav')),
    created_at   timestamptz NOT NULL DEFAULT now(),
    -- Set when the retention job deleted the file (the row stays with the
    -- item, so the history says what was attached).
    purged_at    timestamptz
);
CREATE INDEX feedback_attachments_item ON feedback_attachments (item_id);
ALTER TABLE feedback_attachments ENABLE ROW LEVEL SECURITY, FORCE ROW LEVEL SECURITY;
CREATE POLICY sys ON feedback_attachments USING (stackurity_system()) WITH CHECK (stackurity_system());

-- Who changed what and when.
CREATE TABLE feedback_events (
    id          bigserial PRIMARY KEY,
    item_id     bigint NOT NULL REFERENCES feedback_items(id) ON DELETE CASCADE,
    at          timestamptz NOT NULL DEFAULT now(),
    actor       text NOT NULL CHECK (length(actor) <= 200),
    action      text NOT NULL CHECK (action IN ('created', 'updated', 'emailed', 'attachments_purged')),
    from_status text NOT NULL DEFAULT '',
    to_status   text NOT NULL DEFAULT '',
    detail      text NOT NULL DEFAULT '' CHECK (length(detail) <= 2000)
);
CREATE INDEX feedback_events_item ON feedback_events (item_id, id);
ALTER TABLE feedback_events ENABLE ROW LEVEL SECURITY, FORCE ROW LEVEL SECURITY;
CREATE POLICY sys ON feedback_events USING (stackurity_system()) WITH CHECK (stackurity_system());

-- Tokens for the automated triage agent: read items and attachments, write
-- status and notes, nothing else (the API refuses them on every other route).
CREATE TABLE feedback_agent_tokens (
    id           bigserial PRIMARY KEY,
    name         text NOT NULL CHECK (length(name) BETWEEN 1 AND 100),
    prefix       text NOT NULL,
    token_hash   bytea NOT NULL UNIQUE CHECK (length(token_hash) = 32),
    created_by   bigint REFERENCES users(id) ON DELETE SET NULL,
    created_at   timestamptz NOT NULL DEFAULT now(),
    expires_at   timestamptz NOT NULL,
    last_used_at timestamptz,
    revoked_at   timestamptz
);
ALTER TABLE feedback_agent_tokens ENABLE ROW LEVEL SECURITY, FORCE ROW LEVEL SECURITY;
CREATE POLICY sys ON feedback_agent_tokens USING (stackurity_system()) WITH CHECK (stackurity_system());

-- What this installation's users sent, for "My feedback".
CREATE TABLE feedback_sent (
    id           bigserial PRIMARY KEY,
    workspace_id bigint NOT NULL DEFAULT stackurity_ws() REFERENCES workspaces(id) ON DELETE CASCADE,
    user_id      bigint NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    ref          text NOT NULL CHECK (ref ~ '^FB-[0-9]{1,18}$'),
    -- The status token: it reads this item's status at the queue and
    -- nothing else.
    token        text NOT NULL CHECK (token ~ '^fbs_[a-z2-7]{52}$'),
    kind         text NOT NULL CHECK (kind IN ('issue', 'feature', 'question')),
    summary      text NOT NULL CHECK (length(summary) <= 200),
    attachments  integer NOT NULL DEFAULT 0 CHECK (attachments BETWEEN 0 AND 3),
    status       text NOT NULL DEFAULT 'received' CHECK (status IN ('received', 'reviewing', 'in_progress', 'fixed',
                     'released', 'wont_fix', 'duplicate', 'unknown')),
    status_note  text NOT NULL DEFAULT '' CHECK (length(status_note) <= 2000),
    fixed_in     text NOT NULL DEFAULT '' CHECK (length(fixed_in) <= 40),
    status_at    timestamptz,
    checked_at   timestamptz,
    created_at   timestamptz NOT NULL DEFAULT now(),
    UNIQUE (workspace_id, ref)
);
CREATE INDEX feedback_sent_user ON feedback_sent (workspace_id, user_id, id DESC);
CREATE TRIGGER feedback_sent_user_id_same_ws BEFORE INSERT OR UPDATE OF user_id ON feedback_sent
    FOR EACH ROW EXECUTE FUNCTION stackurity_same_workspace('users', 'user_id');
ALTER TABLE feedback_sent ENABLE ROW LEVEL SECURITY, FORCE ROW LEVEL SECURITY;
CREATE POLICY ws ON feedback_sent
    USING (workspace_id = stackurity_ws()) WITH CHECK (workspace_id = stackurity_ws());
CREATE POLICY sys ON feedback_sent USING (stackurity_system()) WITH CHECK (stackurity_system());
