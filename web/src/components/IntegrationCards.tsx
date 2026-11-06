import type { ReactNode } from "react";
import { Link } from "react-router";
import { RelativeTime } from "./ui";
import { credentialNote, GROUP_TITLE, LAST_OK_LABEL, STATUS_TONE, STATUS_WORD, statusOf, type HubItem, type HubStatus, type HubSummary, type StatusFilter } from "../integrationHub";
import "../styles/integrations.css";

/*
 * The parts of the Integrations page (pages/settings/Integrations.tsx): the
 * health summary, a card per connected integration and the "Add an
 * integration" catalogue. The words and numbers come from integrationHub.ts.
 */

/** Neutral line marks for integration kinds (no vendor logos). */
export function IntegrationIcon({ kind }: { kind: string }) {
  const paths: Record<string, ReactNode> = {
    email: (
      <>
        <rect x="3" y="5" width="18" height="14" rx="2" />
        <path d="m3 7 9 6 9-6" />
      </>
    ),
    slack: <path d="M9 3 7 21M17 3l-2 18M4 9h17M3 15h17" />,
    teams: (
      <>
        <circle cx="9" cy="8" r="3" />
        <circle cx="17" cy="9" r="2" />
        <path d="M3 20c0-3.3 2.7-6 6-6s6 2.7 6 6M15 14.5c.6-.3 1.3-.5 2-.5 2.2 0 4 1.8 4 4" />
      </>
    ),
    webhook: <path d="M10 14a4 4 0 0 0 5.7 0l3-3a4 4 0 0 0-5.7-5.7l-1 1M14 10a4 4 0 0 0-5.7 0l-3 3a4 4 0 0 0 5.7 5.7l1-1" />,
    jira: <path d="M12 3 21 12l-9 9-9-9zM12 8l4 4-4 4-4-4z" />,
    pagerduty: <path d="M6 21V3h7a5 5 0 0 1 0 10H6" />,
    servicenow: (
      <>
        <circle cx="12" cy="12" r="9" />
        <circle cx="12" cy="13" r="3.5" />
      </>
    ),
    git: (
      <>
        <circle cx="6" cy="5" r="2" />
        <circle cx="6" cy="19" r="2" />
        <circle cx="18" cy="8" r="2" />
        <path d="M6 7v10M18 10c0 4-6 3-11.5 7.5" />
      </>
    ),
    container: <path d="M12 3 20 7.5v9L12 21l-8-4.5v-9zM4 7.5l8 4.5 8-4.5M12 12v9" />,
    cloud: <path d="M7 18h10a4 4 0 0 0 .5-8A6 6 0 0 0 6 9a4.5 4.5 0 0 0 1 9z" />,
    kubernetes: (
      <>
        <path d="M12 2.5 20.5 7v10L12 21.5 3.5 17V7z" />
        <circle cx="12" cy="12" r="3" />
        <path d="M12 5.5V9M12 15v3.5M6.3 8.7 9.4 10.5M14.6 13.5l3.1 1.8M6.3 15.3l3.1-1.8M14.6 10.5l3.1-1.8" />
      </>
    ),
    plugin: <path d="M9 3v4M15 3v4M6 7h12v4a6 6 0 0 1-12 0zM12 17v4" />,
    server: (
      <>
        <rect x="3" y="4" width="18" height="7" rx="1.5" />
        <rect x="3" y="13" width="18" height="7" rx="1.5" />
        <path d="M7 7.5h.01M7 16.5h.01" />
      </>
    ),
    windows: <path d="M3 5.5 10.5 4.5v7H3zM12.5 4.2 21 3v8.5h-8.5zM3 12.5h7.5v7L3 18.5zM12.5 12.5H21V21l-8.5-1.2z" />,
    ci: <path d="M4 12a8 8 0 0 1 13.7-5.6L20 9M20 4v5h-5M20 12a8 8 0 0 1-13.7 5.6L4 15M4 20v-5h5" />,
    sbom: <path d="M7 3h7l5 5v13H7zM14 3v5h5M10 12h6M10 15.5h6M10 19h3" />,
    ai: <path d="M12 3l1.8 5.2L19 10l-5.2 1.8L12 17l-1.8-5.2L5 10l5.2-1.8zM19 16l.8 2.2L22 19l-2.2.8L19 22l-.8-2.2L16 19l2.2-.8z" />,
  };
  const key = kind === "stackurity_email" ? "email" : kind === "git_repository" || kind === "github_app" || kind === "gitlab" ? "git" : kind === "container_image" || kind === "container_registry" ? "container" : kind;
  return (
    <span className="int-icon ix-mark" aria-hidden="true">
      <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round">
        {paths[key] ?? paths.plugin}
      </svg>
    </span>
  );
}

/** A coloured dot and the status in words. */
export function StatusDot({ status }: { status: HubStatus }) {
  return (
    <span className={`ix-status ix-status-${STATUS_TONE[status]}`}>
      <span className="ix-dot" aria-hidden="true" />
      {STATUS_WORD[status]}
    </span>
  );
}

const plural = (n: number, one: string, many = `${one}s`) => `${n} ${n === 1 ? one : many}`;

/** Connected, healthy, failing (a link to the failing ones) and the newest delivery. */
export function HealthSummary({ summary, failingTo }: { summary: HubSummary; failingTo: string }) {
  const s = summary;
  const parts = [s.alerts && plural(s.alerts, "alert channel"), s.sources && plural(s.sources, "data source"), s.servers && plural(s.servers, "server group")].filter(Boolean);
  return (
    <section className="ix-summary" aria-label="Integration health">
      <div className="ix-stat">
        <div className="ix-stat-label">Connected</div>
        <div className="ix-stat-value">{s.connected}</div>
        <div className="ix-stat-sub">{parts.length ? parts.join(", ") : "Nothing yet"}</div>
      </div>
      <div className="ix-stat">
        <div className="ix-stat-label">Healthy</div>
        <div className="ix-stat-value">{s.healthy}</div>
        <div className="ix-stat-sub">
          {s.paused || s.never ? [s.paused && `${s.paused} paused`, s.never && `${s.never} never used`].filter(Boolean).join(", ") : "Worked the last time they ran"}
        </div>
      </div>
      <div className={`ix-stat${s.failing ? " ix-stat-bad" : ""}`}>
        <div className="ix-stat-label">Failing</div>
        <div className="ix-stat-value">{s.failing ? <Link to={failingTo}>{s.failing}</Link> : 0}</div>
        <div className="ix-stat-sub">{s.failing ? <Link to={failingTo}>Show the failing ones</Link> : "No errors on the last try"}</div>
      </div>
      <div className="ix-stat">
        <div className="ix-stat-label">Last delivery</div>
        <div className="ix-stat-value ix-stat-time">
          <RelativeTime iso={s.lastDelivery} />
        </div>
        <div className="ix-stat-sub">{s.lastDelivery ? `By ${s.lastDeliveryBy}` : s.alerts ? "No message delivered yet" : "No alert channel yet"}</div>
      </div>
    </section>
  );
}

/** All / Failing / Never used / Healthy / Paused, with their counts. */
export function StatusFilterBar({ summary, value, hrefFor }: { summary: HubSummary; value: StatusFilter; hrefFor: (f: StatusFilter) => string }) {
  const opts: { f: StatusFilter; label: string; n: number }[] = [
    { f: "all", label: "All", n: summary.connected },
    { f: "failing", label: STATUS_WORD.failing, n: summary.failing },
    { f: "never", label: STATUS_WORD.never, n: summary.never },
    { f: "healthy", label: STATUS_WORD.healthy, n: summary.healthy },
    { f: "paused", label: STATUS_WORD.paused, n: summary.paused },
  ];
  return (
    <nav className="ix-filter" aria-label="Show integrations by status">
      {opts
        .filter((o) => o.f === "all" || o.n > 0 || o.f === value)
        .map((o) => (
          <Link key={o.f} to={hrefFor(o.f)} className={`ix-filter-opt${o.f === value ? " is-active" : ""}`} aria-current={o.f === value ? "true" : undefined}>
            {o.label} <span className="ix-count">{o.n}</span>
          </Link>
        ))}
    </nav>
  );
}

export interface CardActions {
  admin: boolean;
  busy: boolean;
  onTest?: (i: HubItem) => void;
  onToggle?: (i: HubItem) => void;
  onRun?: (i: HubItem) => void;
  /** The result of this card's last Send test. */
  test?: { ok: boolean; error?: string } | null;
}

/** One connected integration: what it is, whether it works, where it applies and what it receives. */
export function IntegrationCard({ item, actions }: { item: HubItem; actions: CardActions }) {
  const status = statusOf(item);
  const { admin, busy } = actions;
  const canTest = item.group === "alerts" && admin && actions.onTest;
  const canToggle = (item.group === "alerts" || item.group === "sources") && admin && actions.onToggle;
  const canRun = item.group === "sources" && actions.onRun;
  const cred = item.group === "alerts" ? credentialNote(item.secretSource) : null;
  return (
    <li className={`ix-card ix-card-${status}`}>
      <div className="ix-card-head">
        <IntegrationIcon kind={item.kind} />
        <div className="ix-card-title">
          <Link to={item.to} className="ix-card-name">
            {item.name}
          </Link>
          <div className="ix-card-kind">{item.kindLabel}</div>
        </div>
        <StatusDot status={status} />
      </div>
      {item.target && (
        <div className={`ix-card-target${item.targetMono ? " mono" : ""}`} title={item.target}>
          {item.target}
        </div>
      )}
      <dl className="ix-meta">
        <div>
          <dt>{LAST_OK_LABEL[item.group]}</dt>
          <dd>
            <RelativeTime iso={item.ok} />
          </dd>
        </div>
        {item.group === "alerts" && item.delivered !== undefined && (
          <div>
            <dt>Last message delivered</dt>
            <dd>
              <RelativeTime iso={item.delivered} />
            </dd>
          </div>
        )}
        {item.group === "alerts" && (
          <div>
            <dt>Scope</dt>
            <dd>{item.scope.to ? <Link to={item.scope.to}>{item.scope.label}</Link> : item.scope.label}</dd>
          </div>
        )}
        {item.receives && (
          <div>
            <dt>Receives</dt>
            <dd className={item.receives.none ? "ix-muted" : undefined} title={item.receives.rules.length > 1 ? item.receives.rules.join("\n") : item.receives.text}>
              {item.receives.text}
            </dd>
          </div>
        )}
      </dl>
      {cred && (
        <p className={`ix-cred ix-cred-${cred.tone}`} role={cred.tone === "warn" ? "alert" : undefined}>
          {cred.text}
        </p>
      )}
      {item.error && status === "failing" && (
        <details className="ix-error">
          <summary title={item.error}>
            <span className="ix-error-label">Last error</span> <span className="ix-error-text">{item.error}</span>
          </summary>
          <p className="break">{item.error}</p>
        </details>
      )}
      {actions.test && (
        <p className={`ix-test ${actions.test.ok ? "ix-test-ok" : "ix-test-bad"}`} role="status">
          {actions.test.ok ? "Test message sent. Check that it arrived." : `Test failed: ${actions.test.error ?? "unknown error"}`}
        </p>
      )}
      <div className="ix-card-actions">
        {canTest && (
          <button type="button" className="btn btn-sm" onClick={() => actions.onTest!(item)} disabled={busy || !item.enabled} title={item.enabled ? undefined : "Resume it to send a test"}>
            Send test
          </button>
        )}
        {canRun && (
          <button type="button" className="btn btn-sm" onClick={() => actions.onRun!(item)} disabled={busy || !item.enabled} title={item.enabled ? undefined : "Resume it to run it"}>
            Run now
          </button>
        )}
        {canToggle && (
          <button type="button" className="btn btn-sm" onClick={() => actions.onToggle!(item)} disabled={busy}>
            {item.enabled ? "Pause" : "Resume"}
          </button>
        )}
        <Link className="btn btn-sm ix-open" to={item.to} aria-label={`Open ${item.name}`}>
          Open
        </Link>
      </div>
    </li>
  );
}

/** The connected integrations, a grid per group. */
export function IntegrationGrid({ items, actions, testOf }: { items: HubItem[]; actions: Omit<CardActions, "test">; testOf?: (i: HubItem) => CardActions["test"] }) {
  const groups = (["alerts", "sources", "servers"] as const).map((g) => ({ g, items: items.filter((i) => i.group === g) })).filter((x) => x.items.length > 0);
  return (
    <>
      {groups.map(({ g, items: xs }) => (
        <section key={g} aria-label={GROUP_TITLE[g]} className="ix-group">
          <h3 className="ix-group-title">
            {GROUP_TITLE[g]} <span className="ix-count">{xs.length}</span>
          </h3>
          <ul className="ix-grid">
            {xs.map((i) => (
              <IntegrationCard key={i.key} item={i} actions={{ ...actions, test: testOf?.(i) }} />
            ))}
          </ul>
        </section>
      ))}
    </>
  );
}

export interface CatalogueEntry {
  kind: string;
  title: string;
  text: string;
  to: string;
  admin?: boolean;
  /** Shown instead of the card's link (admins). */
  button?: ReactNode;
  /** connectedCounts key: "Connected (2)". */
  countKey?: string;
}

/** The catalogue card's button word: Add for something new, Connect for an account elsewhere, Show steps for instructions. */
export function actionLabel(c: Pick<CatalogueEntry, "to">): string {
  if (c.to === "/integrations/setup/ci" || c.to === "/integrations/setup/sbom") return "Show steps";
  if (c.to === "/integrations/plugins") return "Open";
  return c.to.startsWith("/integrations/new/") || c.to === "/assets/add" || c.to === "/integrations/kubernetes/add" ? "Add" : "Connect";
}

/** "Add an integration": a group per purpose, a card per kind. */
export function Catalogue({ groups, counts, admin }: { groups: { title: string; description: string; cards: CatalogueEntry[] }[]; counts: Record<string, number>; admin: boolean }) {
  return (
    <>
      {groups.map((g) => (
        <section key={g.title} aria-label={g.title} className="ix-group">
          <h3 className="ix-group-title">{g.title}</h3>
          <p className="ix-group-desc">{g.description}</p>
          <ul className="ix-grid ix-grid-catalogue">
            {g.cards.map((c) => {
              const n = c.countKey ? counts[c.countKey] ?? 0 : 0;
              return (
                <li key={c.title} className="ix-card ix-cat">
                  <div className="ix-card-head">
                    <IntegrationIcon kind={c.kind} />
                    <div className="ix-card-title">
                      <strong className="ix-card-name">{c.title}</strong>
                      {n > 0 && <div className="ix-connected">Connected ({n})</div>}
                    </div>
                  </div>
                  <p className="ix-cat-text">{c.text}</p>
                  {(!c.admin || admin) && (
                    <div className="ix-card-actions">
                      {c.button ?? (
                        <Link className="btn btn-sm" to={c.to}>
                          {actionLabel(c)}
                        </Link>
                      )}
                    </div>
                  )}
                </li>
              );
            })}
          </ul>
        </section>
      ))}
    </>
  );
}
