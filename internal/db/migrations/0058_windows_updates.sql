-- Windows cumulative updates read from Microsoft's Security Update Guide (the
-- msrc:Windows feed, internal/intel/msrc.go). The CVEs each update fixes are
-- stored as advisories like any other feed's (ecosystem "Windows:<line>",
-- package "windows", fixed version the build). This table names the update
-- that brings each build, for the finding and the action plan ("install
-- KB5066782"), and tells hotpatch builds apart. Public intelligence, like
-- advisories: no workspace data.
CREATE TABLE windows_updates (
    line      text NOT NULL,                  -- update line: "Server 2022", "11 24H2"
    build     text NOT NULL,                  -- "10.0.20348.4294"
    kb        text NOT NULL,                  -- "5066782"
    kind      text NOT NULL,                  -- Microsoft's subtype: "Security Update", "Standalone Security Update", "Security Hotpatch Update"
    hotpatch  boolean NOT NULL DEFAULT false,
    -- The document's own Patch Tuesday update for the line: the build most
    -- of its CVEs name. A revised CVE can name a later update in an older
    -- document (2024-Oct lists December's builds), so other builds are dated
    -- from the monthly builds around them, not from their document.
    monthly   boolean NOT NULL DEFAULT false,
    released  date NOT NULL,                  -- initial release of the monthly document that lists it
    document  text NOT NULL,                  -- the monthly document: "2025-Oct"
    PRIMARY KEY (line, build, kb, document)
);
CREATE INDEX windows_updates_document ON windows_updates (document);

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'stackurity_app') THEN
        GRANT SELECT, INSERT, UPDATE, DELETE ON windows_updates TO stackurity_app;
    END IF;
END $$;
