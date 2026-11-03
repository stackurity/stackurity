-- Your account → Active sessions: each person sees their own browser
-- sessions and can sign them out. public_id names a session in the API (the
-- token hash never leaves the server); user_agent and ip are what the
-- browser and the client address (behind a trusted proxy, its forwarded
-- address) were at sign-in; signed_in_at is when the person signed in, kept
-- when the session gets a new ID (a factor added, a new password), where
-- created_at is the current ID's. Sessions from before this migration show
-- no device and signed in when their current ID was made.
ALTER TABLE sessions ADD COLUMN public_id uuid NOT NULL DEFAULT gen_random_uuid(),
                     ADD COLUMN user_agent text,
                     ADD COLUMN ip text,
                     ADD COLUMN signed_in_at timestamptz;
UPDATE sessions SET signed_in_at = created_at;
ALTER TABLE sessions ALTER COLUMN signed_in_at SET DEFAULT now(),
                     ALTER COLUMN signed_in_at SET NOT NULL;
CREATE UNIQUE INDEX sessions_public_id ON sessions (public_id);
CREATE INDEX sessions_user ON sessions (user_id);
