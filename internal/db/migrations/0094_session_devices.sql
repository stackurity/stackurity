-- Your account → Active sessions: each person sees their own browser
-- sessions and can sign them out. public_id names a session in the API (the
-- token hash never leaves the server) and stays the same when the session
-- gets a new ID (a factor added, a new password: the row takes the new
-- token). user_agent and ip are what the browser and the client address
-- (behind a trusted proxy, its forwarded address) were at sign-in;
-- signed_in_at is when the person signed in. Sessions from before this
-- migration have none of these: they read as signed in at created_at, with
-- no device. The table holds at most 12 hours of sessions.
SET LOCAL lock_timeout = '10s';

ALTER TABLE sessions ADD COLUMN public_id uuid NOT NULL DEFAULT gen_random_uuid(),
                     ADD COLUMN user_agent text,
                     ADD COLUMN ip text,
                     ADD COLUMN signed_in_at timestamptz;
CREATE UNIQUE INDEX sessions_public_id ON sessions (public_id);
CREATE INDEX sessions_user ON sessions (user_id);
