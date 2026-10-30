-- Routes may add an "Updates available" section to their daily or weekly
-- summaries: installs older than their package's latest stable release
-- (no advisory involved), counted by update type, with the packages most
-- behind. Off by default, so no existing summary changes.
--
-- Additive: one column with a constant default, nothing is rewritten.

SET LOCAL lock_timeout = '10s';

ALTER TABLE routes ADD COLUMN summary_updates boolean NOT NULL DEFAULT false;
