-- Connected container registries (integration kind container_registry,
-- docs/install.md "Container registries"): the images (digests) each one
-- tracks. A row is an image the integration chose to scan: one of the
-- most recently pushed tags of its repository, or a tag matching a
-- pattern. tracked turns false when it no longer is (a newer tag took its
-- place, or its repository was left out); removed_at is set when the
-- registry no longer has any of its tags, and its asset is then marked
-- removed (its issues resolve as removed, its history stays).
--
-- Additive: a new table. Deleting the integration deletes its rows; the
-- image assets stay, as for every integration.

SET LOCAL lock_timeout = '10s';

CREATE TABLE registry_images (
    id              bigserial PRIMARY KEY,
    workspace_id    bigint NOT NULL DEFAULT stackurity_ws() REFERENCES workspaces(id) ON DELETE CASCADE,
    integration_id  bigint NOT NULL REFERENCES integrations(id) ON DELETE CASCADE,
    repository      text NOT NULL CHECK (length(repository) BETWEEN 1 AND 255),
    digest          text NOT NULL CHECK (digest ~ '^sha256:[a-f0-9]{64}$'),
    image_ref       text NOT NULL,
    tags            text[] NOT NULL DEFAULT '{}',
    pushed_at       timestamptz,
    asset_id        bigint REFERENCES assets(id) ON DELETE SET NULL,
    tracked         boolean NOT NULL DEFAULT true,
    first_seen      timestamptz NOT NULL DEFAULT now(),
    last_seen       timestamptz NOT NULL DEFAULT now(),
    removed_at      timestamptz,
    UNIQUE (integration_id, repository, digest)
);
CREATE INDEX registry_images_workspace ON registry_images (workspace_id);
CREATE INDEX registry_images_asset ON registry_images (asset_id) WHERE asset_id IS NOT NULL;

-- Integrations are organisation-wide, and so are their images: a
-- connection narrowed to some projects sees none.
ALTER TABLE registry_images ENABLE ROW LEVEL SECURITY, FORCE ROW LEVEL SECURITY;
CREATE POLICY ws ON registry_images
    USING (workspace_id = stackurity_ws() AND (SELECT stackurity_narrowed()) IS NOT TRUE)
    WITH CHECK (workspace_id = stackurity_ws() AND (SELECT stackurity_narrowed()) IS NOT TRUE);
CREATE POLICY sys ON registry_images USING (stackurity_system()) WITH CHECK (stackurity_system());
