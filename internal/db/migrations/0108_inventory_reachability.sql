-- Reachability of each inventory row: whether first-party code imports the
-- package (applications, repositories) or a running process executes or
-- has loaded it (hosts). One of unknown, reachable, not_imported,
-- not_running; the ingest validates the value (model.ValidReachStatus).
-- Every row starts unknown, and a collector that does not assess it
-- writes unknown again: nothing is shown as unreachable without evidence.
-- reachability_evidence holds the collector's evidence lines (a JSON
-- array of strings), NULL when it sent none.
--
-- Adding a column with a constant default does not rewrite the table.
ALTER TABLE inventory
    ADD COLUMN reachability text NOT NULL DEFAULT 'unknown',
    ADD COLUMN reachability_evidence jsonb;
