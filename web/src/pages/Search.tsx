import { useEffect, useState } from "react";
import { Link, useSearchParams } from "react-router";
import { api, qs, SEARCH_MAX_LENGTH, SEARCH_MIN_LENGTH, type SearchResults } from "../api";
import { useLoad } from "../hooks";
import { searchPath, searchSections, type SearchGroup, type SearchSection } from "../components/Search";
import { EmptyState, ErrorBox, Loading, PageHeader, StatTile } from "../components/ui";
import { searchOverview, searchSuggestions } from "../searchOverview";

const LIMIT = 50;

/** Where the full list for a group lives, filtered by the same text; null when there is none for everyone who can search. */
function listFor(group: SearchGroup, r: SearchResults): string | null {
  const q = r.query;
  switch (group) {
    case "vulnerabilities":
      return `/fixes/issues${qs({ q, status: "all" })}`;
    case "assets":
      return `/assets${qs({ q })}`;
    case "components":
      return `/components${qs({ q: r.summary?.component_query || q })}`;
    case "teams":
      return "/people/teams";
    case "advisories": // No list of advisories by text; a narrower id finds the rest.
    case "members": // The member list is for admins only.
      return null;
  }
}

/** What each group holds, in the words of someone investigating. */
const DESCRIPTIONS: Record<SearchGroup, string> = {
  assets: "Servers, images, repositories and other assets whose name or an identifier matches.",
  components: "Installed packages that match, with their versions and where they are installed. Open one to see every version and asset.",
  vulnerabilities: "CVEs and other issues found on your assets, with their severity, and open issues whose title matches.",
  advisories: "Public advisories from the intelligence feeds that match but affect nothing in this workspace.",
  teams: "Teams whose name or email matches, with the assets they own.",
  members: "People in this workspace whose name or email matches.",
};

function SeeAll({ to, title }: { to: string | null; title: string }) {
  if (!to) return <span className="muted small">Refine the search to see the rest</span>;
  return (
    <Link to={to} className="small">
      See all in {title.toLowerCase()}
    </Link>
  );
}

function Count({ s }: { s: SearchSection }) {
  return <span className="muted small">{s.more ? `first ${s.items.length}` : s.items.length}</span>;
}

function Hits({ s }: { s: SearchSection }) {
  return (
    <ul className="search-hits">
      {s.items.map((it) => (
        <li key={it.key} className="search-hit">
          <Link to={it.href} className="search-hit-title">
            {it.title}
          </Link>
          <span className="search-hit-meta">{it.meta}</span>
          {it.detail && <span className="search-hit-detail">{it.detail}</span>}
        </li>
      ))}
    </ul>
  );
}

function Group({ s, r }: { s: SearchSection; r: SearchResults }) {
  return (
    <section className="card" aria-labelledby={`search-${s.id}`}>
      <header className="card-head card-head-desc">
        <div className="card-head-text">
          <h2 id={`search-${s.id}`}>
            {s.title} <Count s={s} />
          </h2>
          <p className="card-desc">{DESCRIPTIONS[s.id]}</p>
        </div>
        {s.more && <SeeAll to={listFor(s.id, r)} title={s.title} />}
      </header>
      <Hits s={s} />
    </section>
  );
}

/** The figures for the whole query, then the assets that match by name: what someone checks first. */
function Overview({ r, assets }: { r: SearchResults; assets?: SearchSection }) {
  const figures = searchOverview(r);
  return (
    <section className="card" aria-labelledby="search-overview">
      <header className="card-head card-head-desc">
        <div className="card-head-text">
          <h2 id="search-overview">Overview</h2>
          <p className="card-desc">
            {figures.length > 0
              ? `What in this workspace matches “${r.query}”: the components installed, the assets they are on and the open issues that need attention. Select a figure to open the list behind it.`
              : `Assets in this workspace that match “${r.query}”. No installed component or open issue matches.`}
          </p>
        </div>
      </header>
      {figures.length > 0 && (
        <>
          <div className="tiles tiles-tight" role="group" aria-label={`Summary for “${r.query}”`}>
            {figures.map((f) => (
              <StatTile
                key={f.key}
                label={f.label}
                value={
                  f.href ? (
                    <Link to={f.href} className="tile-link">
                      {f.value}
                    </Link>
                  ) : (
                    f.value
                  )
                }
                tone={f.urgent ? "crit" : undefined}
                sub={f.sub}
              />
            ))}
          </div>
          <p className="hint">
            Issue counts use the Issues list's search: open issues whose package, id, title or asset name contains “{r.summary?.findings_query}”.
          </p>
        </>
      )}
      {assets && (
        <>
          <header className="card-head">
            <h3 id="search-assets">
              Matching assets <Count s={assets} />
            </h3>
            {assets.more && <SeeAll to={listFor("assets", r)} title="Assets" />}
          </header>
          <p className="hint">{DESCRIPTIONS.assets}</p>
          <Hits s={assets} />
        </>
      )}
    </section>
  );
}

const EXAMPLES = ["CVE-2021-44228", "GHSA-35jh-r3h4-6jhm", "lodash@4.17.20", "openssl 3.0.2", "pkg:npm/express", "web-1", "sha256:…"];

export function SearchPage() {
  const [params, setParams] = useSearchParams();
  const qParam = (params.get("q") ?? "").trim();
  const [q, setQ] = useState(qParam);
  useEffect(() => setQ(qParam), [qParam]);
  const ready = qParam.length >= SEARCH_MIN_LENGTH;
  const res = useLoad(
    () => (ready ? api.get<SearchResults>("/search", { q: qParam, limit: LIMIT, summary: 1 }) : Promise.resolve(null)),
    [qParam],
  );
  const data = res.data;
  const sections = data ? searchSections(data, { order: "investigate" }) : [];
  const assets = sections.find((s) => s.id === "assets");
  const rest = sections.filter((s) => s.id !== "assets");
  const hasOverview = Boolean(assets) || (data ? searchOverview(data).length > 0 : false);
  const suggestions = searchSuggestions(qParam);

  return (
    <>
      <PageHeader
        title="Search"
        sub="Look up a vulnerability or advisory id, a package (optionally with a version), an asset name or identifier, a team or a workspace member. Results start with an overview, then components, vulnerabilities and advisories."
      />
      <form
        className="filters"
        role="search"
        onSubmit={(e) => {
          e.preventDefault();
          const t = q.trim();
          setParams(t ? { q: t } : {}, { replace: false });
        }}
      >
        <div className="field">
          <label htmlFor="search-page-q">Search</label>
          <input
            id="search-page-q"
            type="search"
            value={q}
            maxLength={SEARCH_MAX_LENGTH}
            placeholder="CVE-2024-3094, lodash@4.17.20, web-1, sha256:…"
            autoComplete="off"
            spellCheck={false}
            onChange={(e) => setQ(e.target.value)}
          />
        </div>
        <button type="submit" className="btn btn-primary">
          Search
        </button>
      </form>

      {!qParam ? (
        <EmptyState title="Search everything in this workspace">
          <p>
            Try{" "}
            {EXAMPLES.map((x, i) => (
              <span key={x}>
                {i > 0 && ", "}
                <code>{x}</code>
              </span>
            ))}
            . A package name such as <code>openssl</code> shows how many versions are installed, on which assets, and how many critical or urgent
            issues are open. Press <kbd>/</kbd> anywhere to jump to the search box.
          </p>
        </EmptyState>
      ) : !ready ? (
        <EmptyState title={`Type at least ${SEARCH_MIN_LENGTH} characters`}>
          <p>Short searches match too much. Add a character or two, or search for an id such as a CVE.</p>
        </EmptyState>
      ) : res.error ? (
        <ErrorBox error={res.error} title="Search failed" />
      ) : !res.data || (res.loading && res.data.query !== qParam) ? (
        <Loading label="Searching…" />
      ) : sections.length === 0 && !hasOverview ? (
        <EmptyState title={`Nothing matches “${qParam}”`}>
          <p>
            Search looks at advisory ids and aliases, the titles of open findings, installed packages, asset names and identifiers, team names and
            (for engineers and above) members' names and emails in this workspace.
          </p>
          <p>
            Try next:{" "}
            {suggestions.length > 0 && (
              <>
                search for{" "}
                {suggestions.map((x, i) => (
                  <span key={x}>
                    {i > 0 && " or "}
                    <Link to={searchPath(x)}>
                      <code>{x}</code>
                    </Link>
                  </span>
                ))}
                ;{" "}
              </>
            )}
            check the spelling, drop the version, or search for part of the name. A package that no collector has reported yet is not in the
            inventory: see <Link to="/components">Components</Link> for what is.
          </p>
        </EmptyState>
      ) : (
        <>
          {hasOverview && <Overview r={res.data} assets={assets} />}
          {rest.map((s) => (
            <Group key={s.id} s={s} r={res.data as SearchResults} />
          ))}
        </>
      )}
    </>
  );
}
