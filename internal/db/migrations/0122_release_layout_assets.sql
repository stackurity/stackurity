-- Agents from 0.20.24 on report an application deployed in a release layout
-- (releases/ or versions/ plus a current link: Capistrano, Deployer,
-- Envoyer, Ghost-CLI) by the layout's own directory (attribute app_home)
-- instead of its current release. The server now gives such a report to
-- the asset of a release in that layout (internal/store/appadopt.go), but
-- agents upgraded before it made a new asset: the old one was removed, its
-- issues resolved as removed and reappeared on the new one, and its
-- projects stayed behind.
--
-- For each such new asset, the older asset it should have kept takes its
-- identifiers, name (unless a person named either), attributes and
-- projects, and the new asset is deleted. Its inventory and findings are
-- hours old copies of the old asset's: the agent's next report revives the
-- old asset's rows (same component, version, location), which reopens its
-- own issues. Idempotent: a repaired asset no longer has a newer twin.

SET LOCAL lock_timeout = '10s';
SELECT set_config('stackurity.scope', 'system', true);

DO $$
DECLARE
    r record;
BEGIN
    FOR r IN
        SELECT n.id AS new_id, n.name AS new_name, n.name_by_person AS new_by_person, n.attributes AS new_attrs, o.id AS old_id
        FROM assets n
        JOIN asset_identifiers ni ON ni.asset_id = n.id AND ni.scheme = 'app-path'
        CROSS JOIN LATERAL (
            SELECT a.id
            FROM asset_identifiers oi JOIN assets a ON a.id = oi.asset_id
            WHERE oi.scheme = 'app-path' AND a.kind = 'application' AND a.merged_into IS NULL
              AND a.id <> n.id AND a.workspace_id = n.workspace_id AND a.first_seen < n.first_seen
              AND (left(oi.value, length(ni.value) + 10) = ni.value || '/releases/'
                OR left(oi.value, length(ni.value) + 10) = ni.value || '/versions/')
            ORDER BY oi.value = split_part(ni.value, ':', 1) || ':' || split_part(ni.value, ':', 2) || ':' || (n.attributes->>'app_dir') DESC,
                     a.last_seen DESC, a.id
            LIMIT 1
        ) o
        WHERE n.kind = 'application' AND n.merged_into IS NULL AND n.attributes ? 'app_home'
          AND ni.value = split_part(ni.value, ':', 1) || ':' || split_part(ni.value, ':', 2) || ':' || (n.attributes->>'app_home')
        ORDER BY n.id
    LOOP
        UPDATE asset_identifiers SET asset_id = r.old_id WHERE asset_id = r.new_id;
        INSERT INTO project_assets (workspace_id, project_id, asset_id, added_at)
            SELECT workspace_id, project_id, r.old_id, added_at FROM project_assets WHERE asset_id = r.new_id
            ON CONFLICT DO NOTHING;
        UPDATE assets SET
            attributes = attributes || r.new_attrs,
            name = CASE WHEN name_by_person THEN name ELSE r.new_name END,
            name_by_person = name_by_person OR r.new_by_person
        WHERE id = r.old_id;
        DELETE FROM assets WHERE merged_into = r.new_id;
        DELETE FROM assets WHERE id = r.new_id;
    END LOOP;
END $$;
