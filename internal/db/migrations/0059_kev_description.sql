-- CISA's short description of each known exploited vulnerability (the KEV
-- catalogue's shortDescription), shown with the CVE where a list of new
-- additions is given, such as a weekly vulnerability digest. Additive: the
-- column starts empty and the next kev:cisa sync, which replaces the
-- catalogue whole, fills it.

SET LOCAL lock_timeout = '10s';
SELECT set_config('stackurity.scope', 'system', true);

ALTER TABLE known_exploited ADD COLUMN short_description text NOT NULL DEFAULT '';
