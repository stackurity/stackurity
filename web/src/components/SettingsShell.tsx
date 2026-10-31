import { useEffect, useRef, useState, useSyncExternalStore, type KeyboardEvent, type ReactNode } from "react";
import { Link, useLocation } from "react-router";
import { useAuth } from "../auth";
import {
  activeSection,
  groupSections,
  listKeyMove,
  searchSettings,
  settingsPane,
  SETTINGS_GROUPS,
  visibleSections,
  type GroupId,
  type ShownSection,
} from "../settingsNav";
import { ProBadge } from "./ProNotice";
import { IconCard, IconInventory, IconMessage, IconSearch, IconServer, IconShield, IconUser, IconUsers, IconWrench } from "./Icons";

const GROUP_ICON: Record<GroupId, ReactNode> = {
  workspace: <IconInventory size={16} />,
  detection: <IconShield size={16} />,
  response: <IconMessage size={16} />,
  people: <IconUsers size={16} />,
  billing: <IconCard size={16} />,
  account: <IconUser size={16} />,
  maintenance: <IconWrench size={16} />,
  installation: <IconServer size={16} />,
};
const GROUP_TITLE = Object.fromEntries(SETTINGS_GROUPS.map((g) => [g.id, g.title])) as Record<GroupId, string>;

/** The setting sections the signed-in person can see. */
export function useVisibleSections(): ShownSection[] {
  const { can, has, me, meta } = useAuth();
  return visibleSections({ can, has, instanceAdmin: Boolean(me?.user?.instance_admin), billing: Boolean(meta?.billing) });
}

/** Whether a media query matches now, following changes (a window resized). */
export function useMediaQuery(query: string): boolean {
  return useSyncExternalStore(
    (cb) => {
      const m = window.matchMedia(query);
      m.addEventListener("change", cb);
      return () => m.removeEventListener("change", cb);
    },
    () => window.matchMedia(query).matches,
    () => false,
  );
}

function SectionLink({ s, active, matched, showGroup }: { s: ShownSection; active: boolean; matched?: string; showGroup?: boolean }) {
  return (
    <Link to={s.to} className={`settings-nav-item${active ? " active" : ""}`} aria-current={active ? "page" : undefined} title={s.about}>
      <span className="settings-nav-label">
        {s.label}
        {s.pro && <ProBadge />}
        {s.elsewhere && <span className="settings-nav-elsewhere"> in {s.elsewhere} ↗</span>}
      </span>
      {(showGroup || matched) && (
        <span className="settings-nav-meta small muted">
          {showGroup && GROUP_TITLE[s.group]}
          {showGroup && matched && " · "}
          {matched && <>matches “{matched}”</>}
        </span>
      )}
      <span className="settings-nav-about small muted">{s.about}</span>
    </Link>
  );
}

/**
 * Settings in two panes: every section on the left, grouped, with a search
 * box; the open section on the right. On a phone the list fills the screen
 * at /settings, and a section opens full screen with a back button.
 */
export function SettingsShell({ children }: { children: ReactNode }) {
  const { pathname, search } = useLocation();
  const sections = useVisibleSections();
  const [query, setQuery] = useState("");
  const listRef = useRef<HTMLDivElement>(null);
  const searchRef = useRef<HTMLInputElement>(null);
  const active = activeSection(pathname, search, sections);
  const pane = settingsPane(pathname);
  const hits = query.trim() ? searchSettings(query, sections) : null;

  // The open section stays in view in a long list.
  useEffect(() => {
    listRef.current?.querySelector<HTMLElement>(".settings-nav-item.active")?.scrollIntoView({ block: "nearest" });
  }, [active]);

  const items = () => Array.from(listRef.current?.querySelectorAll<HTMLAnchorElement>("a.settings-nav-item") ?? []);
  const onListKey = (e: KeyboardEvent) => {
    const all = items();
    const cur = all.indexOf(document.activeElement as HTMLAnchorElement);
    if (e.key === "ArrowUp" && cur === 0) {
      e.preventDefault();
      searchRef.current?.focus();
      return;
    }
    const next = listKeyMove(cur, all.length, e.key);
    if (next === null) return;
    e.preventDefault();
    all[next]?.focus();
  };
  const onSearchKey = (e: KeyboardEvent<HTMLInputElement>) => {
    if (e.key === "ArrowDown") {
      e.preventDefault();
      items()[0]?.focus();
    } else if (e.key === "Enter" && hits && hits.length > 0) {
      e.preventDefault();
      // Through a click, so the unsaved-changes guard can ask first.
      items()[0]?.click();
    } else if (e.key === "Escape" && query) {
      e.preventDefault();
      setQuery("");
    }
  };

  const Heading = pane === "list" ? "h1" : "p";
  return (
    <div className={`settings-shell settings-pane-${pane}`}>
      <nav className="settings-nav" aria-label="Settings sections">
        <Heading className="settings-nav-title">Settings</Heading>
        <div className="settings-search">
          <IconSearch size={16} />
          <input
            ref={searchRef}
            type="search"
            placeholder="Find a setting"
            aria-label="Find a setting"
            aria-describedby="settings-search-hint"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            onKeyDown={onSearchKey}
          />
          <span id="settings-search-hint" className="sr-only">
            Try Slack, two-factor or billing. Arrow keys move through the list, Enter opens.
          </span>
        </div>
        <div ref={listRef} className="settings-nav-list" onKeyDown={onListKey}>
          {hits === null ? (
            groupSections(sections).map(({ group, sections: ss }) => (
              <section key={group.id} className="settings-nav-group" aria-labelledby={`sg-${group.id}`}>
                <h2 id={`sg-${group.id}`} className="settings-nav-group-title">
                  {GROUP_ICON[group.id]}
                  {group.title}
                </h2>
                <ul>
                  {ss.map((s) => (
                    <li key={s.id}>
                      <SectionLink s={s} active={s.id === active} />
                    </li>
                  ))}
                </ul>
              </section>
            ))
          ) : hits.length > 0 ? (
            <>
              <p className="sr-only" role="status">
                {hits.length} {hits.length === 1 ? "setting matches" : "settings match"}
              </p>
              <ul>
                {hits.map((h) => (
                  <li key={h.section.id}>
                    <SectionLink s={h.section} active={h.section.id === active} matched={h.matched} showGroup />
                  </li>
                ))}
              </ul>
            </>
          ) : (
            <div className="settings-nav-empty" role="status">
              <p>
                <strong>No setting matches “{query.trim()}”.</strong>
              </p>
              <p className="small muted">
                Every section is still listed when you clear the search. Try “Slack”, “two-factor” or “billing”.
              </p>
              <button type="button" className="btn btn-sm" onClick={() => setQuery("")}>
                Clear search
              </button>
            </div>
          )}
        </div>
      </nav>
      <div className="settings-detail">
        {/* A link, so the unsaved-changes guard asks before leaving a form. */}
        <Link to="/settings" className="settings-back">
          ← All settings
        </Link>
        {children}
      </div>
    </div>
  );
}
