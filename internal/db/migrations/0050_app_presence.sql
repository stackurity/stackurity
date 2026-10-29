-- Applications that are gone, reports that prove part of an inventory, and
-- distinct names for copies of one application on a host. Additive: a
-- defaulted column, a widened CHECK constraint, and a one-off rename.

SET LOCAL lock_timeout = '10s';
SELECT set_config('stackurity.scope', 'system', true);

-- 1. A collection that was not complete can still prove that something is
--    gone outside the paths it could not read (an unreadable cache
--    directory). proves_absence records that it did; complete still means
--    the collector read everything.
ALTER TABLE collections ADD COLUMN proves_absence boolean NOT NULL DEFAULT false;

-- 2. A check whose report could not read everything ends as "incomplete"
--    instead of waiting (and asking the agent again) for a week.
ALTER TABLE checks DROP CONSTRAINT IF EXISTS checks_outcome_check;
ALTER TABLE checks ADD CONSTRAINT checks_outcome_check
    CHECK (outcome IN ('', 'passed', 'partly_fixed', 'still_open', 'incomplete', 'expired'));

-- 3. assets.collection_status gains 'removed': an application whose
--    directory its host's agent no longer reports (deleted, or an old
--    release next to the current one). It is a text column; nothing to
--    change here.

-- 4. Copies of one application on a host got the same generated name when
--    both existed before 0.13 ("ghost on commmerceblog" for
--    /var/www/ghost/versions/6.22.0 and .../6.52.0). Name each by its path
--    below the directory the copies share, as new ones are named
--    (internal/store/appnames.go): "ghost (/6.22.0) on commmerceblog". A
--    name a person set is never changed.
WITH apps AS (
    SELECT a.id, a.workspace_id, a.name, a.attributes->>'host' AS host,
           split_part(ai.value, ':', 2) AS host_id,
           string_to_array(rtrim(substr(ai.value, length(split_part(ai.value, ':', 1) || ':' || split_part(ai.value, ':', 2) || ':') + 1), '/'), '/') AS parts
    FROM assets a JOIN asset_identifiers ai ON ai.asset_id = a.id AND ai.scheme = 'app-path'
    WHERE a.kind = 'application' AND a.merged_into IS NULL
      AND ai.value LIKE 'host:%:/%' AND COALESCE(a.attributes->>'host', '') <> ''
      AND right(a.name, length(' on ' || (a.attributes->>'host'))) = ' on ' || (a.attributes->>'host')
),
clash AS (
    SELECT workspace_id, host_id, name FROM apps GROUP BY 1, 2, 3 HAVING count(*) > 1
),
members AS (
    SELECT p.* FROM apps p JOIN clash c USING (workspace_id, host_id, name)
),
-- How many leading path elements the copies' parent directories share.
shared AS (
    SELECT m.workspace_id, m.host_id, m.name,
           COALESCE((SELECT max(k) FROM generate_series(1, min(cardinality(m.parts)) - 1) k
             WHERE (SELECT count(DISTINCT x.parts[1:k]) FROM members x
                    WHERE x.workspace_id = m.workspace_id AND x.host_id = m.host_id AND x.name = m.name) = 1
               AND k <= (SELECT min(cardinality(x.parts)) - 1 FROM members x
                    WHERE x.workspace_id = m.workspace_id AND x.host_id = m.host_id AND x.name = m.name)), 1) AS k
    FROM members m GROUP BY 1, 2, 3
)
UPDATE assets a SET name = left(m.name, length(m.name) - length(' on ' || m.host))
    || ' (' || CASE WHEN s.k <= 1 THEN array_to_string(m.parts, '/')
                    ELSE '/' || array_to_string(m.parts[s.k + 1:], '/') END
    || ') on ' || m.host
FROM members m JOIN shared s USING (workspace_id, host_id, name)
WHERE a.id = m.id AND NOT a.name_by_person;
