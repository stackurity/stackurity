-- Migration 0030 counted assets that existed at the upgrade as announced by
-- setting announced_at to the time of the upgrade. Summaries list assets
-- announced in their period as newly connected, so the first daily or
-- weekly summary after the upgrade said every existing asset had just
-- connected. Those assets were announced when they were first seen.
--
-- The rows 0030 set are exactly those whose announced_at equals the time
-- 0030 was recorded: both were written in one transaction, so now() is the
-- same. Assets announced since then have their own time, and a database
-- created at 0030 or later had no assets to change.
UPDATE assets a SET announced_at = LEAST(a.first_seen, a.announced_at)
FROM schema_migrations m
WHERE m.name = '0030_grouped_notifications' AND a.announced_at = m.applied_at;
