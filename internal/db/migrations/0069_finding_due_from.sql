-- Deadlines run from when the asset first had the vulnerability, not from
-- when the package version that has it now appeared. A new version of an
-- affected package (a kernel update installing a new kernel, an upgrade that
-- leaves the component affected) is a new inventory row and so a new
-- finding, whose first_seen is the day of the update; deadlines computed
-- from it restarted on every update. due_from carries the earlier start
-- over to the new finding; NULL means first_seen.
--
-- Additive: one nullable column, nothing is rewritten. Findings opened before
-- the upgrade keep their deadlines.

SET LOCAL lock_timeout = '10s';

ALTER TABLE findings ADD COLUMN due_from timestamptz;
