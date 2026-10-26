import { useEffect, useState } from "react";
import { Link, useSearchParams } from "react-router";
import { api, qs, SEARCH_MAX_LENGTH, SEARCH_MIN_LENGTH, type SearchResults } from "../api";
import { useLoad } from "../hooks";
import { searchSections, type SearchGroup } from "../components/Search";
import { EmptyState, ErrorBox, Loading, PageHeader } from "../components/ui";

const LIMIT = 50;

/** Where the full list for a group lives, filtered by the same text; null when there is none for everyone who can search. */
function listFor(group: SearchGroup, q: string): string | null {
  switch (group) {
    case "vulnerabilities":
      return `/fixes/issues${qs({ q, status: "all" })}`;
    case "findings":
      return `/fixes/issues${qs({ q })}`;
    case "assets":
      return `/assets${qs({ q })}`;
    case "components":
      return `/components${qs({ q })}`;
    case "teams":
      return "/settings/teams";
    case "members":
      // The member list is for admins only; a narrower search finds the rest.
      return null;
  }
}

function SeeAll({ to, title }: { to: string | null; title: string }) {
  if (!to) return <span className="muted small">Refine the search to see the rest</span>;
  return (
    <Link to={to} className="small">
      See all in {title.toLowerCase()}
    </Link>
  );
}

const EXAMPLES = ["CVE-2021-44228", "GHSA-35jh-r3h4-6jhm", "lodash@4.17.20", "openssl 3.0.2", "pkg:npm/express", "web-1", "sha256:…"];

export function SearchPage() {
  const [params, setParams] = useSearchParams();
  const qParam = (params.get("q") ?? "").trim();
  const [q, setQ] = useState(qParam);
  useEffect(() => setQ(qParam), [qParam]);
  const ready = qParam.length >= SEARCH_MIN_LENGTH;
  const res = useLoad(() => (ready ? api.get<SearchResults>("/search", { q: qParam, limit: LIMIT }) : Promise.resolve(null)), [qParam]);
  const sections = res.data ? searchSections(res.data) : [];

  return (
    <>
      <PageHeader title="Search" sub="Vulnerability and advisory ids, finding titles, packages (optionally with a version), asset names and identifiers, teams and workspace members." />
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
            . Press <kbd>/</kbd> anywhere to jump to the search box.
          </p>
        </EmptyState>
      ) : !ready ? (
        <EmptyState title={`Type at least ${SEARCH_MIN_LENGTH} characters`} />
      ) : res.error ? (
        <ErrorBox error={res.error} title="Search failed" />
      ) : !res.data || (res.loading && res.data.query !== qParam) ? (
        <Loading label="Searching…" />
      ) : sections.length === 0 ? (
        <EmptyState title={`Nothing matches “${qParam}”`}>
          <p>
            Search looks at advisory ids and aliases, the titles of open findings, installed packages, asset names and identifiers, team names and
            (for engineers and above) members' names and emails in this workspace. Check the
            spelling, drop the version, or search for part of the name.
          </p>
        </EmptyState>
      ) : (
        sections.map((s) => (
          <section className="card" key={s.id} aria-labelledby={`search-${s.id}`}>
            <header className="card-head">
              <h2 id={`search-${s.id}`}>
                {s.title} <span className="muted small">{s.more ? `first ${s.items.length}` : s.items.length}</span>
              </h2>
              {s.more && <SeeAll to={listFor(s.id, qParam)} title={s.title} />}
            </header>
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
          </section>
        ))
      )}
    </>
  );
}
