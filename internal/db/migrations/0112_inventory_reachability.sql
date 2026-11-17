-- Reachability of each inventory row: whether first-party code imports the
-- package (applications, repositories) or a running process executes or
-- has loaded it (hosts). One of unknown, reachable, not_imported,
-- not_running; the ingest validates the value (model.ValidReachStatus),
-- and the CHECK holds it for rows written after this migration.
-- Every row starts unknown, and a collector that does not assess it
-- writes unknown again: nothing is shown as unreachable without evidence.
-- reachability_evidence holds the collector's evidence lines (a JSON
-- array of strings), NULL when it sent none.
--
-- Adding a column with a constant default does not rewrite the table, and
-- a NOT VALID check does not scan it; lock_timeout makes the migration
-- fail rather than queue behind a long-running query and block ingest.
SET LOCAL lock_timeout = '10s';

ALTER TABLE inventory
    ADD COLUMN reachability text NOT NULL DEFAULT 'unknown',
    ADD COLUMN reachability_evidence jsonb,
    ADD CONSTRAINT inventory_reachability_valid
        CHECK (reachability IN ('unknown', 'reachable', 'not_imported', 'not_running')) NOT VALID;
