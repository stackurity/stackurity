import { useEffect, useId, useRef, useState, type KeyboardEvent as ReactKeyboardEvent, type ReactNode } from "react";
import { Link, useLocation, useNavigate } from "react-router";
import { api, qs, SEARCH_MAX_LENGTH, SEARCH_MIN_LENGTH, type SearchResults } from "../api";
import { useDebounced, useLoad } from "../hooks";
import { componentName, plural } from "../format";
import { AssetKindBadge, KevBadge, SeverityBadge } from "./Badge";
import { IconSearch } from "./Icons";

export type SearchGroup = "vulnerabilities" | "findings" | "assets" | "components" | "teams" | "members";

export interface SearchItem {
  key: string;
  href: string;
  title: ReactNode;
  meta: ReactNode;
  /** Extra lines on the results page (samples of affected assets, advisory text). */
  detail?: ReactNode;
}

export interface SearchSection {
  id: SearchGroup;
  title: string;
  items: SearchItem[];
  more: boolean;
  /** Best match rank in the section; sections with exact matches come first. */
  rank: number;
}

const GROUP_ORDER: SearchGroup[] = ["vulnerabilities", "findings", "assets", "components", "teams", "members"];

export function searchPath(q: string): string {
  return `/search${qs({ q })}`;
}

function samples(refs: { id: number; name: string; version?: string }[], total: number) {
  if (refs.length === 0) return null;
  return (
    <span className="search-samples">
      {refs.map((r, i) => (
        <span key={r.id}>
          {i > 0 && ", "}
          <Link to={`/assets/${r.id}`}>{r.name}</Link>
          {r.version && <span className="muted"> {r.version}</span>}
        </span>
      ))}
      {total > refs.length && <span className="muted"> and {(total - refs.length).toLocaleString()} more</span>}
    </span>
  );
}

/** Turns API results into ordered sections, shared by the dropdown and the results page. */
export function searchSections(r: SearchResults): SearchSection[] {
  const sections: SearchSection[] = [
    {
      id: "vulnerabilities",
      title: "Vulnerabilities",
      more: Boolean(r.more.vulnerabilities),
      rank: Math.min(3, ...r.vulnerabilities.map((v) => v.rank)),
      items: r.vulnerabilities.map((v) => {
        const affected = v.kind !== "";
        return {
          key: `v:${v.key}`,
          href: affected ? `/findings${qs({ key: v.key, status: "all" })}` : searchPath(v.key),
          title: (
            <>
              <span className="mono">{v.key}</span> <SeverityBadge severity={v.severity} score={v.score} />
              {v.known_exploited && <> <KevBadge /></>}
            </>
          ),
          meta: affected ? (
            <>
              {v.open_findings > 0
                ? `${plural(v.open_findings, "open finding")} on ${plural(v.affected_assets, "asset")}`
                : "No open findings"}
              {v.resolved_findings > 0 && `, ${v.resolved_findings.toLocaleString()} resolved`}
              {v.components.length > 0 && ` · ${v.components.join(", ")}`}
            </>
          ) : (
            "No affected assets in this workspace"
          ),
          detail: (
            <>
              {(v.title || v.advisory?.summary) && <span>{v.title || v.advisory?.summary}</span>}
              {affected && v.assets.length > 0 && <span>Assets: {samples(v.assets, v.affected_assets)}</span>}
              {v.advisory && (
                <span className="muted">
                  Advisories: {[...v.advisory.ids, ...v.advisory.aliases.filter((a) => !v.advisory?.ids.includes(a))].join(", ")}
                  {v.advisory.withdrawn && " (withdrawn)"}
                </span>
              )}
            </>
          ),
        };
      }),
    },
    {
      id: "findings",
      title: "Findings",
      more: Boolean(r.more.findings),
      rank: Math.min(3, ...(r.findings ?? []).map((f) => f.rank)),
      items: (r.findings ?? []).map((f) => ({
        key: `f:${f.key}:${f.title}`,
        href: `/findings${qs({ key: f.key })}`,
        title: (
          <>
            <span>{f.title}</span> <SeverityBadge severity={f.severity} score={f.score} />
          </>
        ),
        meta: (
          <>
            <span className="mono">{f.key}</span>
            {` · ${plural(f.open_findings, "open finding")} on ${plural(f.affected_assets, "asset")}`}
          </>
        ),
        detail: f.assets.length > 0 ? <span>Assets: {samples(f.assets, f.affected_assets)}</span> : undefined,
      })),
    },
    {
      id: "assets",
      title: "Assets",
      more: Boolean(r.more.assets),
      rank: Math.min(3, ...r.assets.map((a) => a.rank)),
      items: r.assets.map((a) => ({
        key: `a:${a.id}`,
        href: `/assets/${a.id}`,
        title: (
          <>
            <span>{a.name}</span> <AssetKindBadge kind={a.kind} />
          </>
        ),
        meta: (
          <>
            {[a.environment, a.owner_team && `owned by ${a.owner_team}`].filter(Boolean).join(" · ")}
            {(a.environment || a.owner_team) && " · "}
            {a.open_findings > 0 ? plural(a.open_findings, "open finding") : "no open findings"}
            {a.match_value && a.match_value !== a.name && (
              <>
                {" · "}
                {a.match_scheme}: <span className="mono">{a.match_value}</span>
              </>
            )}
          </>
        ),
      })),
    },
    {
      id: "components",
      title: "Components",
      more: Boolean(r.more.components),
      rank: Math.min(3, ...r.components.map((c) => c.rank)),
      items: r.components.map((c) => ({
        key: `c:${c.id}`,
        href: `/components/${c.id}`,
        title: (
          <>
            <span>{componentName(c.namespace, c.name)}</span> <span className="chip">{c.type}</span>
          </>
        ),
        meta: (
          <>
            {c.version
              ? c.version_assets > 0
                ? c.version_assets === c.asset_count
                  ? `${plural(c.version_assets, "asset")} at ${c.version}`
                  : `${c.version_assets.toLocaleString()} of ${plural(c.asset_count, "asset")} at ${c.version}`
                : `No asset has ${c.version}; ${plural(c.asset_count, "asset")} ${c.asset_count === 1 ? "has" : "have"} other versions`
              : `On ${plural(c.asset_count, "asset")}`}
            {c.open_findings > 0 && ` · ${plural(c.open_findings, "open finding")}`}
          </>
        ),
        detail: (
          <>
            {c.assets.length > 0 && <span>Assets: {samples(c.assets, c.version ? c.version_assets : c.asset_count)}</span>}
            {c.versions.length > 0 && (
              <span className="muted">
                Installed versions: {c.versions.slice(0, 10).join(", ")}
                {c.versions.length > 10 && ", …"}
              </span>
            )}
          </>
        ),
      })),
    },
    {
      id: "teams",
      title: "Teams",
      more: Boolean(r.more.teams),
      rank: Math.min(3, ...r.teams.map((t) => t.rank)),
      items: r.teams.map((t) => ({
        key: `t:${t.id}`,
        href: `/assets${qs({ owner_team_id: t.id })}`,
        title: <span>{t.name}</span>,
        meta: (
          <>
            {t.email && `${t.email} · `}
            {`owns ${plural(t.asset_count, "asset")}`}
            {t.open_findings > 0 && ` with ${plural(t.open_findings, "open finding")}`}
          </>
        ),
      })),
    },
    {
      id: "members",
      title: "Members",
      more: Boolean(r.more.members),
      rank: Math.min(3, ...(r.members ?? []).map((m) => m.rank)),
      items: (r.members ?? []).map((m) => ({
        key: `m:${m.id}`,
        href: `/findings${qs({ assignee_user: m.id })}`,
        title: <span>{m.name || m.email}</span>,
        meta: (
          <>
            {m.name && `${m.email} · `}
            {m.role}
            {m.disabled && " · disabled"}
            {` · ${m.open_assigned > 0 ? `${plural(m.open_assigned, "open finding")} assigned` : "no open findings assigned"}`}
          </>
        ),
      })),
    },
  ];
  return sections
    .filter((s) => s.items.length > 0)
    .sort((a, b) => a.rank - b.rank || GROUP_ORDER.indexOf(a.id) - GROUP_ORDER.indexOf(b.id));
}

function isEditable(t: EventTarget | null): boolean {
  if (!(t instanceof HTMLElement)) return false;
  return t.isContentEditable || ["INPUT", "TEXTAREA", "SELECT"].includes(t.tagName);
}

/**
 * The search box in the top bar. Typing shows the best matches of each type;
 * Enter opens the highlighted match, or the full results page. "/" focuses it.
 */
export function GlobalSearch() {
  const navigate = useNavigate();
  const { pathname, search } = useLocation();
  const [q, setQ] = useState("");
  const [open, setOpen] = useState(false);
  const [active, setActive] = useState(-1);
  const input = useRef<HTMLInputElement>(null);
  const box = useRef<HTMLDivElement>(null);
  const listId = useId();
  const term = useDebounced(q.trim(), 200);
  const ready = term.length >= SEARCH_MIN_LENGTH;
  const res = useLoad(() => (ready ? api.get<SearchResults>("/search", { q: term, limit: 5 }) : Promise.resolve(null)), [term]);
  const sections = res.data && res.data.query === term ? searchSections(res.data) : [];
  const items = sections.flatMap((s) => s.items);

  // "/" focuses the box from anywhere that is not a text field.
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "/" && !e.ctrlKey && !e.metaKey && !e.altKey && !isEditable(e.target)) {
        e.preventDefault();
        input.current?.focus();
        input.current?.select();
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  // Close on navigation and on clicks elsewhere.
  useEffect(() => setOpen(false), [pathname, search]);
  useEffect(() => {
    const onDown = (e: MouseEvent) => {
      if (box.current && !box.current.contains(e.target as Node)) setOpen(false);
    };
    document.addEventListener("mousedown", onDown);
    return () => document.removeEventListener("mousedown", onDown);
  }, []);
  useEffect(() => setActive(-1), [term]);

  const submit = () => {
    const t = q.trim();
    if (open && active >= 0 && items[active]) {
      navigate(items[active].href);
    } else if (t.length >= SEARCH_MIN_LENGTH) {
      navigate(searchPath(t));
    }
    setOpen(false);
  };

  const onKeyDown = (e: ReactKeyboardEvent<HTMLInputElement>) => {
    if (e.key === "ArrowDown" && items.length > 0) {
      e.preventDefault();
      setOpen(true);
      setActive((i) => (i + 1) % items.length);
    } else if (e.key === "ArrowUp" && items.length > 0) {
      e.preventDefault();
      setActive((i) => (i <= 0 ? items.length - 1 : i - 1));
    } else if (e.key === "Escape") {
      if (open) setOpen(false);
      else input.current?.blur();
    }
  };

  const optionId = (i: number) => `${listId}-${i}`;
  const showPop = open && q.trim().length > 0;
  let n = -1;

  return (
    <div className="global-search" ref={box}>
      <form
        role="search"
        onSubmit={(e) => {
          e.preventDefault();
          submit();
        }}
      >
        <label htmlFor={`${listId}-input`} className="sr-only">
          Search vulnerabilities, findings, packages, assets, teams and members
        </label>
        <span className="global-search-icon" aria-hidden="true">
          <IconSearch size={16} />
        </span>
        <input
          id={`${listId}-input`}
          ref={input}
          type="search"
          value={q}
          maxLength={SEARCH_MAX_LENGTH}
          placeholder="Search CVE, package, host, team"
          autoComplete="off"
          spellCheck={false}
          role="combobox"
          aria-expanded={showPop}
          aria-controls={listId}
          aria-autocomplete="list"
          aria-activedescendant={active >= 0 ? optionId(active) : undefined}
          onChange={(e) => {
            setQ(e.target.value);
            setOpen(true);
          }}
          onFocus={() => setOpen(true)}
          onKeyDown={onKeyDown}
        />
        <kbd className="global-search-key" aria-hidden="true">
          /
        </kbd>
      </form>
      {showPop && (
        <div className="search-pop" id={listId} role="listbox" aria-label="Search results">
          {q.trim().length < SEARCH_MIN_LENGTH ? (
            <p className="search-pop-note">Type at least {SEARCH_MIN_LENGTH} characters.</p>
          ) : res.error ? (
            <p className="search-pop-note">{res.error.message}</p>
          ) : sections.length === 0 ? (
            <p className="search-pop-note">{res.loading || term !== q.trim() ? "Searching…" : `Nothing matches “${q.trim()}”.`}</p>
          ) : (
            sections.map((s) => (
              <div key={s.id} role="group" aria-label={s.title} className="search-pop-group">
                <div className="search-pop-head">{s.title}</div>
                {s.items.map((it) => {
                  n++;
                  const i = n;
                  return (
                    <Link
                      key={it.key}
                      id={optionId(i)}
                      to={it.href}
                      role="option"
                      aria-selected={i === active}
                      className={`search-pop-item${i === active ? " active" : ""}`}
                      onMouseEnter={() => setActive(i)}
                      onClick={() => setOpen(false)}
                    >
                      <span className="search-hit-title">{it.title}</span>
                      <span className="search-hit-meta">{it.meta}</span>
                    </Link>
                  );
                })}
              </div>
            ))
          )}
          {q.trim().length >= SEARCH_MIN_LENGTH && (
            <Link to={searchPath(q.trim())} className="search-pop-all" onClick={() => setOpen(false)}>
              See all results for “{q.trim()}”
            </Link>
          )}
        </div>
      )}
    </div>
  );
}
