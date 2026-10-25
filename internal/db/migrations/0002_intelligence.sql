-- Stage 2: vulnerability, release and lifecycle intelligence, and findings.

-- One row per upstream source. Freshness is tracked per feed so stale or
-- failing sources are visible (FR-05, FR-06).
CREATE TABLE feeds (
    name          text PRIMARY KEY,         -- osv:npm, osv:Debian, releases:npm, lifecycle:endoflife
    kind          text NOT NULL CHECK (kind IN ('vulnerability', 'release', 'lifecycle')),
    enabled       boolean NOT NULL DEFAULT true,
    auto          boolean NOT NULL DEFAULT true,  -- created automatically from inventory ecosystems
    refresh       interval NOT NULL DEFAULT '1 hour',
    stale_after   interval NOT NULL DEFAULT '6 hours',
    cursor        text NOT NULL DEFAULT '',
    records       bigint NOT NULL DEFAULT 0,
    last_attempt  timestamptz,
    last_success  timestamptz,
    last_error    text NOT NULL DEFAULT '',
    last_changed  int NOT NULL DEFAULT 0,       -- records changed in the last successful run
    created_at    timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE advisories (
    id               text PRIMARY KEY,
    feed             text NOT NULL REFERENCES feeds(name) ON DELETE CASCADE,
    group_key        text NOT NULL,
    aliases          text[] NOT NULL DEFAULT '{}',
    summary          text NOT NULL DEFAULT '',
    details          text NOT NULL DEFAULT '',
    severity_level   text NOT NULL DEFAULT 'unknown',
    severity_score   real,
    severity_vector  text NOT NULL DEFAULT '',
    severity_source  text NOT NULL DEFAULT '',
    published        timestamptz,
    modified         timestamptz NOT NULL,
    withdrawn        timestamptz,
    refs             jsonb NOT NULL DEFAULT '[]',
    known_exploited  boolean NOT NULL DEFAULT false,
    fetched_at       timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX advisories_group ON advisories (group_key);
CREATE INDEX advisories_feed ON advisories (feed);

CREATE TABLE advisory_packages (
    advisory_id     text NOT NULL REFERENCES advisories(id) ON DELETE CASCADE,
    base_ecosystem  text NOT NULL,   -- "Debian"
    ecosystem       text NOT NULL,   -- "Debian:12"
    name            text NOT NULL,
    affected        jsonb NOT NULL
);
CREATE INDEX advisory_packages_lookup ON advisory_packages (base_ecosystem, name);
CREATE INDEX advisory_packages_advisory ON advisory_packages (advisory_id);

-- Release data per component from package registries.
CREATE TABLE package_releases (
    component_id      bigint PRIMARY KEY REFERENCES components(id) ON DELETE CASCADE,
    latest            text NOT NULL DEFAULT '',
    latest_stable     text NOT NULL DEFAULT '',
    latest_published  timestamptz,
    version_dates     jsonb NOT NULL DEFAULT '{}',  -- version -> release date, where the registry provides it
    deprecated        text NOT NULL DEFAULT '',
    source            text NOT NULL,
    source_url        text NOT NULL DEFAULT '',
    checked_at        timestamptz NOT NULL,
    last_error        text NOT NULL DEFAULT ''
);

CREATE TABLE lifecycle_products (
    product     text PRIMARY KEY,
    label       text NOT NULL,
    purls       text[] NOT NULL DEFAULT '{}',
    link        text NOT NULL DEFAULT '',
    fetched_at  timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX lifecycle_products_purls ON lifecycle_products USING gin (purls);

CREATE TABLE lifecycle_cycles (
    product        text NOT NULL REFERENCES lifecycle_products(product) ON DELETE CASCADE,
    cycle          text NOT NULL,
    label          text NOT NULL DEFAULT '',
    release_date   date,
    lts            boolean NOT NULL DEFAULT false,
    support_until  date,      -- end of active support
    eol_until      date,      -- end of security support
    is_eol         boolean NOT NULL DEFAULT false,
    latest         text NOT NULL DEFAULT '',
    latest_date    date,
    PRIMARY KEY (product, cycle)
);

-- Findings: one per (inventory row, kind, key). Vulnerability findings are
-- keyed by the advisory group (CVE when known) so GHSA/OSV/distro records for
-- the same issue collapse into one finding with several sources.
CREATE TABLE findings (
    id             bigserial PRIMARY KEY,
    kind           text NOT NULL CHECK (kind IN ('vulnerability', 'end_of_life')),
    key            text NOT NULL,
    inventory_id   bigint NOT NULL REFERENCES inventory(id) ON DELETE CASCADE,
    asset_id       bigint NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    component_id   bigint NOT NULL REFERENCES components(id) ON DELETE CASCADE,
    status         text NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'resolved')),
    verification   text NOT NULL CHECK (verification IN ('confirmed', 'needs_validation', 'rejected', 'unknown', 'stale')),
    severity       text NOT NULL DEFAULT 'unknown',
    score          real,
    title          text NOT NULL DEFAULT '',
    fixed_version  text NOT NULL DEFAULT '',
    sources        text[] NOT NULL DEFAULT '{}',
    evidence       jsonb NOT NULL DEFAULT '{}',
    first_seen     timestamptz NOT NULL DEFAULT now(),
    last_seen      timestamptz NOT NULL DEFAULT now(),
    resolved_at    timestamptz,
    resolution     text NOT NULL DEFAULT '',
    UNIQUE (inventory_id, kind, key)
);
CREATE INDEX findings_open ON findings (severity, asset_id) WHERE status = 'open';
CREATE INDEX findings_component ON findings (component_id);
CREATE INDEX findings_key ON findings (key);

-- Components whose ecosystem has no vulnerability source are recorded so
-- "no findings" is never mistaken for "checked and clean" (FR-16).
CREATE TABLE evaluation_gaps (
    component_id  bigint NOT NULL REFERENCES components(id) ON DELETE CASCADE,
    reason        text NOT NULL,
    updated_at    timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (component_id)
);

-- CISA Known Exploited Vulnerabilities: evidence of active exploitation for
-- risk prioritisation.
CREATE TABLE known_exploited (
    cve         text PRIMARY KEY,
    vendor      text NOT NULL DEFAULT '',
    product     text NOT NULL DEFAULT '',
    name        text NOT NULL DEFAULT '',
    added       date,
    due_date    date,
    ransomware  boolean NOT NULL DEFAULT false
);
