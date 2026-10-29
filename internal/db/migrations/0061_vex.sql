-- VEX import and export (docs/risk.md, "VEX"). An imported VEX document is
-- kept with its statements and what each statement matched here; an
-- imported not_affected statement asks for approval in the approval inbox
-- (ignore_requests.vex_statement_id) unless the document's source is
-- trusted to apply on its own, and an approved one becomes ignore rules
-- pinned to the version (and image digest) it was matched on.
--
-- Every change to existing tables is additive (new nullable columns or
-- constant defaults): nothing is rewritten.

SET LOCAL lock_timeout = '10s';

-- Who VEX comes from, and whether its not_affected statements may apply
-- without a person approving them. auto_apply only takes effect when the
-- source is pinned to something a document cannot claim by itself: a
-- public key its signed attestations must verify with, or the API token
-- its uploads must come from (checked by the application on each import).
CREATE TABLE vex_sources (
    id               bigserial PRIMARY KEY,
    workspace_id     bigint NOT NULL DEFAULT stackurity_ws() REFERENCES workspaces(id) ON DELETE CASCADE,
    name             text NOT NULL CHECK (length(name) BETWEEN 1 AND 100),
    auto_apply       boolean NOT NULL DEFAULT false,
    token_id         bigint REFERENCES api_tokens(id) ON DELETE SET NULL,
    public_key       text NOT NULL DEFAULT '',
    key_fingerprint  text NOT NULL DEFAULT '',
    created_by_name  text NOT NULL DEFAULT '',
    created_at       timestamptz NOT NULL DEFAULT now(),
    updated_at       timestamptz NOT NULL DEFAULT now(),
    UNIQUE (workspace_id, name)
);

-- One imported document: where it came from, the file, its signature, and
-- the scope the import was limited to.
CREATE TABLE vex_documents (
    id                bigserial PRIMARY KEY,
    workspace_id      bigint NOT NULL DEFAULT stackurity_ws() REFERENCES workspaces(id) ON DELETE CASCADE,
    source_id         bigint REFERENCES vex_sources(id) ON DELETE SET NULL,
    source_name       text NOT NULL DEFAULT '',
    format            text NOT NULL CHECK (format IN ('openvex', 'cyclonedx')),
    doc_id            text NOT NULL DEFAULT '',
    author            text NOT NULL DEFAULT '',
    doc_version       text NOT NULL DEFAULT '',
    doc_timestamp     timestamptz,
    filename          text NOT NULL DEFAULT '',
    sha256            text NOT NULL,
    size              int NOT NULL,
    -- none: not signed; verified: signed and verified with the source's
    -- key; unverified: signed, but no key to check it with.
    signature         text NOT NULL CHECK (signature IN ('none', 'verified', 'unverified')),
    key_fingerprint   text NOT NULL DEFAULT '',
    scope_asset_id    bigint REFERENCES assets(id) ON DELETE SET NULL,
    scope_project_id  bigint REFERENCES projects(id) ON DELETE SET NULL,
    auto_applied      boolean NOT NULL DEFAULT false,
    via               text NOT NULL DEFAULT 'vex' CHECK (via IN ('vex', 'sbom')),
    statements        int NOT NULL DEFAULT 0,
    matched           int NOT NULL DEFAULT 0,
    imported_by       bigint REFERENCES users(id) ON DELETE SET NULL,
    imported_by_name  text NOT NULL DEFAULT '',
    imported_at       timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX vex_documents_workspace ON vex_documents (workspace_id, imported_at DESC);

-- A statement of a document. products is what the document named,
-- problems the products (or the whole statement) that could not be
-- matched, and why. effective_at decides which statement about the same
-- component and vulnerability is the latest.
CREATE TABLE vex_statements (
    id                     bigserial PRIMARY KEY,
    workspace_id           bigint NOT NULL DEFAULT stackurity_ws() REFERENCES workspaces(id) ON DELETE CASCADE,
    document_id            bigint NOT NULL REFERENCES vex_documents(id) ON DELETE CASCADE,
    source_name            text NOT NULL DEFAULT '',
    vulnerability          text NOT NULL,
    aliases                text[] NOT NULL DEFAULT '{}',
    status                 text NOT NULL CHECK (status IN ('not_affected', 'affected', 'fixed', 'under_investigation', 'invalid')),
    justification          text NOT NULL DEFAULT '',
    original_state         text NOT NULL DEFAULT '',
    original_justification text NOT NULL DEFAULT '',
    impact_statement       text NOT NULL DEFAULT '',
    action_statement       text NOT NULL DEFAULT '',
    status_notes           text NOT NULL DEFAULT '',
    products               jsonb NOT NULL DEFAULT '[]',
    problems               jsonb NOT NULL DEFAULT '[]',
    effective_at           timestamptz NOT NULL,
    request_id             bigint,
    created_at             timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX vex_statements_document ON vex_statements (document_id);

-- What a statement matched: a component at a version on an asset (and the
-- image digest when the statement named the image by digest), for one
-- finding key. A statement stops applying to a finding when the
-- inventory row's version, or the image's digest, is no longer this one.
CREATE TABLE vex_matches (
    statement_id  bigint NOT NULL REFERENCES vex_statements(id) ON DELETE CASCADE,
    workspace_id  bigint NOT NULL DEFAULT stackurity_ws() REFERENCES workspaces(id) ON DELETE CASCADE,
    asset_id      bigint NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    component_id  bigint NOT NULL REFERENCES components(id) ON DELETE CASCADE,
    version       text NOT NULL,
    digest        text NOT NULL DEFAULT '',
    key           text NOT NULL,
    PRIMARY KEY (statement_id, asset_id, component_id, version, key)
);
CREATE INDEX vex_matches_issue ON vex_matches (asset_id, component_id, key);

-- An ignore rule made from an approved VEX statement applies only while
-- the finding's component is at this version (and the asset's image has
-- this digest); '' for rules made by people, which are not pinned.
ALTER TABLE finding_exceptions
    ADD COLUMN vex_statement_id bigint REFERENCES vex_statements(id) ON DELETE SET NULL,
    ADD COLUMN version          text NOT NULL DEFAULT '',
    ADD COLUMN digest           text NOT NULL DEFAULT '';
-- The active pinned rules, which every upkeep checks still match.
CREATE INDEX finding_exceptions_pinned ON finding_exceptions (id) WHERE ended_at IS NULL AND (version <> '' OR digest <> '');

-- A request in the approval inbox made by a VEX import.
ALTER TABLE ignore_requests ADD COLUMN vex_statement_id bigint REFERENCES vex_statements(id) ON DELETE CASCADE;

-- --- row-level security
--
-- Sources and documents are organisation-wide: a connection narrowed to
-- some projects sees none. A statement is seen through a match on a
-- visible asset (so a finding can say which statement covers it), and a
-- match through its asset.
ALTER TABLE vex_sources ENABLE ROW LEVEL SECURITY, FORCE ROW LEVEL SECURITY;
CREATE POLICY ws ON vex_sources
    USING (workspace_id = stackurity_ws() AND (SELECT stackurity_narrowed()) IS NOT TRUE)
    WITH CHECK (workspace_id = stackurity_ws() AND (SELECT stackurity_narrowed()) IS NOT TRUE);
CREATE POLICY sys ON vex_sources USING (stackurity_system()) WITH CHECK (stackurity_system());

ALTER TABLE vex_documents ENABLE ROW LEVEL SECURITY, FORCE ROW LEVEL SECURITY;
CREATE POLICY ws ON vex_documents
    USING (workspace_id = stackurity_ws() AND (SELECT stackurity_narrowed()) IS NOT TRUE)
    WITH CHECK (workspace_id = stackurity_ws() AND (SELECT stackurity_narrowed()) IS NOT TRUE);
CREATE POLICY sys ON vex_documents USING (stackurity_system()) WITH CHECK (stackurity_system());

ALTER TABLE vex_matches ENABLE ROW LEVEL SECURITY, FORCE ROW LEVEL SECURITY;
CREATE POLICY ws ON vex_matches
    USING (workspace_id = stackurity_ws() AND ((SELECT stackurity_narrowed()) IS NOT TRUE OR asset_id IN (SELECT unnest(stackurity_visible_assets()))))
    WITH CHECK (workspace_id = stackurity_ws() AND (SELECT stackurity_narrowed()) IS NOT TRUE);
CREATE POLICY sys ON vex_matches USING (stackurity_system()) WITH CHECK (stackurity_system());

ALTER TABLE vex_statements ENABLE ROW LEVEL SECURITY, FORCE ROW LEVEL SECURITY;
CREATE POLICY ws ON vex_statements
    USING (workspace_id = stackurity_ws() AND ((SELECT stackurity_narrowed()) IS NOT TRUE
           OR EXISTS (SELECT 1 FROM vex_matches m WHERE m.statement_id = vex_statements.id)))
    WITH CHECK (workspace_id = stackurity_ws() AND (SELECT stackurity_narrowed()) IS NOT TRUE);
CREATE POLICY sys ON vex_statements USING (stackurity_system()) WITH CHECK (stackurity_system());

-- Requests made by a VEX import are decided by organisation-wide security
-- and admin users only: a narrowed connection does not see them.
DROP POLICY ws ON ignore_requests;
CREATE POLICY ws ON ignore_requests
    USING (workspace_id = stackurity_ws() AND ((SELECT stackurity_narrowed()) IS NOT TRUE OR (
        ignore_requests.vex_statement_id IS NULL
        AND (ignore_requests.asset_id IS NULL OR ignore_requests.asset_id IN (SELECT unnest(stackurity_visible_assets())))
        AND NOT EXISTS (SELECT 1 FROM unnest(ignore_requests.finding_ids) x(id) WHERE NOT EXISTS (SELECT 1 FROM findings f WHERE f.id = x.id)))))
    WITH CHECK (workspace_id = stackurity_ws() AND ((SELECT stackurity_narrowed()) IS NOT TRUE OR (
        ignore_requests.vex_statement_id IS NULL
        AND (ignore_requests.asset_id IS NULL OR ignore_requests.asset_id IN (SELECT unnest(stackurity_visible_assets())))
        AND NOT EXISTS (SELECT 1 FROM unnest(ignore_requests.finding_ids) x(id) WHERE NOT EXISTS (SELECT 1 FROM findings f WHERE f.id = x.id)))));

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'stackurity_app') THEN
        EXECUTE format('GRANT SELECT, INSERT, UPDATE, DELETE ON vex_sources, vex_documents, vex_statements, vex_matches TO stackurity_app');
        EXECUTE format('GRANT USAGE, SELECT, UPDATE ON SEQUENCE vex_sources_id_seq, vex_documents_id_seq, vex_statements_id_seq TO stackurity_app');
    END IF;
EXCEPTION WHEN insufficient_privilege THEN NULL;
END $$;
