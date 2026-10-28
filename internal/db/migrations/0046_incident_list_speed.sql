-- Incidents seen with a project chosen in the switcher (or by a member who
-- sees only some assets) took 8 to 27 seconds on a database with 240,000
-- findings.
--
-- The incidents policy from migration 0032 asked "does this incident have a
-- visible finding?" with EXISTS (... WHERE f.incident_id = incidents.id).
-- PostgreSQL answers that for many incidents as one hashed SubPlan, and
-- nothing in it limited which findings to read: it read every finding of
-- every workspace, open and resolved, from the heap (hundreds of megabytes)
-- and applied the findings policy to each, on every request, twice (the
-- count and the page).
--
-- The policy now starts from the visible assets: the findings on them that
-- belong to an incident, read from findings_asset_incident alone (an
-- index-only scan). What it allows is unchanged: an incident is visible when
-- a finding it holds is on a visible asset (the findings policy still
-- applies inside the subquery), and collection, coverage and feed problems
-- as before. The other columns in the index let store.ListIncidents work out
-- each incident's visible priority, SOS and escalation from the index in one
-- pass, instead of looking up each incident's findings in turn; status is in
-- the key so that the default list (open incidents) reads only open findings.
CREATE INDEX findings_asset_incident ON findings (asset_id, status, incident_id)
    INCLUDE (workspace_id, state, priority, sos, escalation_level)
    WHERE incident_id IS NOT NULL;

-- The findings summary counts what was resolved in the last week. After a
-- large rescan that is most findings, and each was read from the heap:
-- three seconds for 125,000. With the asset and workspace in the index (for
-- the join and the row-level security check) the count reads the index only.
CREATE INDEX findings_resolved_at_cover ON findings (resolved_at) INCLUDE (asset_id, workspace_id) WHERE status = 'resolved';

-- Last, as dropping an index and changing a policy lock their tables
-- against reading until the commit, which follows at once.
DROP INDEX findings_resolved_at;
ALTER INDEX findings_resolved_at_cover RENAME TO findings_resolved_at;
DROP POLICY ws ON incidents;
CREATE POLICY ws ON incidents
    USING (workspace_id = stackurity_ws() AND ((SELECT stackurity_narrowed()) IS NOT TRUE
        OR incidents.id IN (SELECT f.incident_id FROM findings f
                            WHERE f.asset_id = ANY ((SELECT stackurity_visible_assets())::bigint[]) AND f.incident_id IS NOT NULL)
        OR (incidents.kind IN ('collection', 'coverage') AND incidents.key ~ '^asset:[0-9]+'
            AND substring(incidents.key FROM '^asset:([0-9]+)')::bigint IN (SELECT unnest(stackurity_visible_assets())))
        OR incidents.kind = 'feed'))
    WITH CHECK (workspace_id = stackurity_ws() AND ((SELECT stackurity_narrowed()) IS NOT TRUE
        OR incidents.id IN (SELECT f.incident_id FROM findings f
                            WHERE f.asset_id = ANY ((SELECT stackurity_visible_assets())::bigint[]) AND f.incident_id IS NOT NULL)
        OR (incidents.kind IN ('collection', 'coverage') AND incidents.key ~ '^asset:[0-9]+'
            AND substring(incidents.key FROM '^asset:([0-9]+)')::bigint IN (SELECT unnest(stackurity_visible_assets())))
        OR incidents.kind = 'feed'));
