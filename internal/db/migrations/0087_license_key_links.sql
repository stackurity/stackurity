-- "Get a free key" on a self-hosted server (internal/api/keylink.go): the
-- browser goes to Stackurity Cloud, which sends it back with the key in the
-- address's fragment. The server itself never calls out. Each trip carries a
-- one-time state, bound to the instance administrator's browser session and
-- valid for 15 minutes; only its SHA-256 is stored, and using it deletes it.
--
-- server_id is a random id of this installation. The trip sends a hash of
-- it (never the id), so the Cloud can count servers without learning more.
SELECT set_config('stackurity.scope', 'system', true);

CREATE TABLE license_key_links (
    state_hash    bytea PRIMARY KEY,
    user_id       bigint NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    session_hash  bytea NOT NULL,
    expires_at    timestamptz NOT NULL,
    created_at    timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX license_key_links_expires ON license_key_links (expires_at);

ALTER TABLE license_requirement ADD COLUMN server_id uuid NOT NULL DEFAULT gen_random_uuid();
