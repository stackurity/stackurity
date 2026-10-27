-- Feed syncs write only the advisories that changed (internal/store,
-- UpsertAdvisories). Each advisory keeps a hash of what is stored for it; a
-- record whose hash is unchanged is skipped, and for a changed one only the
-- package rows that differ are deleted or inserted. Before this, every sync
-- deleted and re-inserted all package rows of every record it read.
--
-- Adding a nullable column and a new table rewrites nothing. If a lock is
-- held (a long report or backup), this gives up after 10 seconds per lock;
-- run it again in a quieter moment (a migration is one transaction).
SET LOCAL lock_timeout = '10s';

ALTER TABLE advisories ADD COLUMN content_hash text;

-- Affected entries (ranges and listed versions) are stored once each and
-- referenced by hash: most repeat across releases, channels and advisories.
-- Rows written before this keep their entry in advisory_packages.affected,
-- which is read when affected_hash is NULL, until their advisory is stored
-- again. Values no row references are pruned daily. affected_hash has no
-- foreign key: checking one on every delete would need an index on 3.5
-- million rows; the writers and the pruning share a lock instead.
CREATE TABLE affected_values (
    hash      bytea PRIMARY KEY,   -- first 16 bytes of the SHA-256 of affected
    affected  jsonb NOT NULL
);
ALTER TABLE advisory_packages ADD COLUMN affected_hash bytea,
    ALTER COLUMN affected DROP NOT NULL;

-- Packages whose advisory data a sync changed and whose components have not
-- been queued for re-evaluation yet. Written in the same transaction as the
-- advisories and cleared by the sync of the package's own ecosystem once it
-- has queued their re-evaluation, so a sync that is interrupted after
-- storing records still has them re-evaluated by the next one (which finds
-- those records unchanged). Keyed by ecosystem, not by the feed that wrote
-- them: an advisory covering npm and PyPI packages is in both archives and
-- is stored by whichever sync reads it first. Public intelligence, like
-- advisories: no workspace data.
CREATE TABLE pending_packages (
    base_ecosystem  text NOT NULL,
    name            text NOT NULL,
    added_at        timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (base_ecosystem, name)
);

-- The next sync of each OSV feed reads the full archive once instead of the
-- changes since its cursor. It stores every advisory's hash and rewrites the
-- package rows in the new form, which is what the incremental syncs then
-- compare against. Amazon Linux always reads
-- everything.
UPDATE feeds SET cursor = '' WHERE name LIKE 'osv:%' AND cursor <> '';
