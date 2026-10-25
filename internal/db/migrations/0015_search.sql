-- Global search (GET /api/v1/search) looks advisories up by alias as well as
-- by id and group, which needs an index on the alias array.
CREATE INDEX IF NOT EXISTS advisories_aliases ON advisories USING gin (aliases);
