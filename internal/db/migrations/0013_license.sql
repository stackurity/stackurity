-- The installation's licence key (verified by the application; Community
-- without one) and each workspace's plan. 'inherit' gives a workspace the
-- licence's edition (a self-hosted install); a hosted platform sets plans per
-- organisation, never above the licence.
CREATE TABLE license_key (
    id           int PRIMARY KEY CHECK (id = 1),
    key          text NOT NULL,
    uploaded_by  bigint REFERENCES users(id) ON DELETE SET NULL,
    uploaded_at  timestamptz NOT NULL DEFAULT now()
);
ALTER TABLE workspaces ADD COLUMN plan text NOT NULL DEFAULT 'inherit'
    CHECK (plan IN ('inherit', 'community', 'pro', 'enterprise'));
