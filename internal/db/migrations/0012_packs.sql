-- Installed stack packs. Packs are installed for the whole installation by an
-- instance administrator; the archive is kept so every server process and
-- client (stackurity scan, agents) runs exactly the module that was approved,
-- and the previous version is kept for a one-step rollback.
CREATE TABLE packs (
    id                text PRIMARY KEY,
    version           text NOT NULL,
    manifest          jsonb NOT NULL,
    archive           bytea NOT NULL,
    sha256            text NOT NULL,
    trust             text NOT NULL CHECK (trust IN ('official', 'verified', 'unsigned')),
    enabled           boolean NOT NULL DEFAULT true,
    installed_by      bigint REFERENCES users(id) ON DELETE SET NULL,
    installed_at      timestamptz NOT NULL DEFAULT now(),
    previous_version  text,
    previous_archive  bytea,
    previous_trust    text
);
