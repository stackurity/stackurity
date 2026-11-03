-- Indexes for reading each workspace's latest activity in one pass over all
-- workspaces (the Stackurity Cloud trial report: the first and last
-- collection, and the last sign-in, of every organisation). Additive; each
-- index is built while writes to its table wait, which takes seconds at
-- today's sizes.
--
-- The first and last collection of every workspace: an index-only scan
-- instead of reading every collection from the heap (about 600,000 rows:
-- 280 ms to 110 ms for the whole report).
SET LOCAL lock_timeout = '30s';

CREATE INDEX collections_workspace_received ON collections (workspace_id, received_at);

-- The last sign-in of every workspace: only the auth.login events, instead
-- of every audit event. The action leads, so one range of the index holds
-- every workspace's sign-ins.
CREATE INDEX audit_events_action_workspace ON audit_events (action, workspace_id, at);
