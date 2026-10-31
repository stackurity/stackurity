import { Fragment, useState, type ReactNode } from "react";
import { Link } from "react-router";
import type { AssetCoverageGroup, AssetCoverageList, AssetCoverageRow, CoverageRow, EcosystemCoverage, SecondCheckSummary } from "../api";
import {
  ASSET_GROUPS,
  CARDS_SHOWN,
  ECOSYSTEM_STATUS,
  assetPercent,
  ecosystemLink,
  groupLabel,
  notCheckedParts,
  reportingText,
  secondCheckNumbers,
  shortDay,
  type ActionCard,
  type Headline,
} from "../coverage";
import { IconActionPlan, IconCheckCircle, IconCopy, IconHelp, IconInventory, IconPackage, IconShield } from "./Icons";

// The Coverage page's sections (pages/Coverage.tsx loads the data). Each
// takes its data as props, so web tests render it as it is shown.

type P = { size?: number };

function Svg({ children, size = 18 }: { children: ReactNode; size?: number }) {
  return (
    <svg className="icon" width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.8}
      strokeLinecap="round" strokeLinejoin="round" aria-hidden="true" focusable="false">
      {children}
    </svg>
  );
}

const IconServer = (p: P) => (
  <Svg {...p}>
    <rect x="4" y="4" width="16" height="7" rx="1.5" />
    <rect x="4" y="13" width="16" height="7" rx="1.5" />
    <path d="M8 7.5h.01M8 16.5h.01" />
  </Svg>
);
const IconRepo = (p: P) => (
  <Svg {...p}>
    <path d="M6 3h11a1 1 0 0 1 1 1v14H7a2 2 0 0 0-2 2V5a2 2 0 0 1 1-2z" />
    <path d="M5 20a2 2 0 0 0 2 1h11v-3" />
  </Svg>
);
const IconImage = (p: P) => (
  <Svg {...p}>
    <path d="M12 3l8 4.5v9L12 21l-8-4.5v-9z" />
    <path d="M4 7.5l8 4.5 8-4.5M12 12v9" />
  </Svg>
);
const IconApp = (p: P) => (
  <Svg {...p}>
    <rect x="3" y="4" width="18" height="16" rx="2" />
    <path d="M3 9h18M7 6.5h.01M10 6.5h.01" />
  </Svg>
);
const IconLock = (p: P) => (
  <Svg {...p}>
    <rect x="5" y="11" width="14" height="10" rx="2" />
    <path d="M8 11V8a4 4 0 0 1 8 0v3" />
  </Svg>
);
const IconWarn = (p: P) => (
  <Svg {...p}>
    <path d="M12 4l9 16H3z" />
    <path d="M12 10v4M12 17h.01" />
  </Svg>
);
const IconMinus = (p: P) => (
  <Svg {...p}>
    <circle cx="12" cy="12" r="9" />
    <path d="M8 12h8" />
  </Svg>
);
const IconHalf = (p: P) => (
  <Svg {...p}>
    <circle cx="12" cy="12" r="9" />
    <path d="M12 3a9 9 0 0 1 0 18z" fill="currentColor" />
  </Svg>
);

export function KindIcon({ kind }: { kind: string }) {
  switch (kind) {
    case "host":
      return <IconServer />;
    case "repository":
      return <IconRepo />;
    case "image":
    case "workload":
      return <IconImage />;
    case "application":
      return <IconApp />;
    default:
      return <IconPackage />;
  }
}

/** A section with an icon, a heading and optional actions on the right. */
export function Section({ id, icon, title, aside, children, className }: {
  id: string;
  icon: ReactNode;
  title: string;
  aside?: ReactNode;
  children: ReactNode;
  className?: string;
}) {
  return (
    <section className={`cov-section ${className ?? ""}`} aria-labelledby={id}>
      <div className="cov-section-head">
        <span className="cov-section-icon" aria-hidden="true">
          {icon}
        </span>
        <h2 id={id}>{title}</h2>
        {aside && <div className="cov-section-aside">{aside}</div>}
      </div>
      {children}
    </section>
  );
}

// --- 1. Headline

/**
 * The one answer and one visual: the share checked, as a hero number, and
 * one segmented bar of every component; each segment and legend item is a
 * link to its components. Beside it, how many assets report.
 */
export function CoverageHeadline({ h, reporting, notReporting }: {
  h: Headline;
  reporting: { reporting: number; total: number; stale: number; text: string };
  notReporting: string | null;
}) {
  const fmt = (x: number) => x.toLocaleString("en");
  const drawn = h.segments.filter((s) => s.count > 0);
  return (
    <section className="cov-headline" aria-labelledby="cov-headline-title">
      <div className="cov-headline-main">
        <h2 id="cov-headline-title" className="cov-hero">
          {h.pct === null ? (
            <span className="cov-hero-text">{h.text}</span>
          ) : (
            <>
              <span className="cov-hero-num">{h.pct}%</span>
              <span className="cov-hero-text">of your components were checked</span>
            </>
          )}
        </h2>
        {h.total > 0 ? (
          <>
            <p className="cov-hero-sub">
              {fmt(h.checked)} of {fmt(h.total)} components
            </p>
            <div className="cov-bar" role="img" aria-label={drawn.map((s) => `${s.label}: ${fmt(s.count)}`).join(", ")}>
              {drawn.map((s) => (
                <Link
                  key={s.key}
                  to={s.to}
                  className={`cov-bar-seg cov-seg-${s.key}`}
                  style={{ flexGrow: s.count, flexBasis: 0 }}
                  title={`${s.label}: ${fmt(s.count)} (${Math.round(s.share)}%) · ${s.hint}`}
                  aria-label={`${s.label}: ${fmt(s.count)} components`}
                />
              ))}
            </div>
            <ul className="cov-legend">
              {h.segments.map((s) => (
                <li key={s.key} className={s.count === 0 ? "cov-legend-zero" : undefined}>
                  <Link to={s.to} title={s.hint}>
                    <span className={`cov-swatch cov-seg-${s.key}`} aria-hidden="true" />
                    <span className="cov-legend-label">{s.label}</span>
                    <span className="cov-legend-num">{fmt(s.count)}</span>
                  </Link>
                </li>
              ))}
            </ul>
          </>
        ) : (
          <p className="cov-hero-sub">
            Components appear after an asset's first report. <Link to="/assets/add">Add an asset</Link>
          </p>
        )}
      </div>
      <Link to={reporting.stale > 0 ? "/assets?status=stale" : "/assets"} className={`cov-reporting${reporting.stale > 0 ? " cov-reporting-warn" : ""}`}>
        <span className="cov-reporting-num">
          {fmt(reporting.reporting)}
          <span className="cov-reporting-of"> of {fmt(reporting.total)}</span>
        </span>
        <span className="cov-reporting-label">{reporting.total === 1 ? "asset reporting" : "assets reporting"}</span>
        {reporting.stale > 0 && <span className="cov-reporting-sub">{notReporting ?? `${fmt(reporting.stale)} not reporting`}</span>}
        {reporting.total > 0 && reporting.stale === 0 && <span className="cov-reporting-sub cov-ok-text">All reporting</span>}
      </Link>
    </section>
  );
}

// --- 2. Fix these

const CARD_ICONS = { version: <IconPackage />, files: <IconLock />, other: <IconHelp /> };

export function ActionCards({ cards }: { cards: ActionCard[] }) {
  const [all, setAll] = useState(false);
  if (cards.length === 0)
    return (
      <p className="cov-empty cov-empty-good">
        <IconCheckCircle size={22} /> <span>Nothing needs you; everything we can check, we checked.</span>
      </p>
    );
  const shown = all ? cards : cards.slice(0, CARDS_SHOWN);
  return (
    <>
      <ul className="cov-cards">
        {shown.map((c) => (
          <li key={c.key} className="cov-card">
            <div className="cov-card-head">
              <span className={`cov-card-icon cov-card-icon-${c.icon}`} aria-hidden="true">
                {CARD_ICONS[c.icon]}
              </span>
              <h3>{c.title}</h3>
            </div>
            {c.assets.length > 0 && (
              <ul className="cov-chips" aria-label="Affected assets">
                {c.assets.map((a) => (
                  <li key={a.id}>
                    <Link to={a.to} className="cov-chip">
                      {a.name}
                    </Link>
                  </li>
                ))}
                {c.moreAssets > 0 && <li className="cov-chip cov-chip-more">+{c.moreAssets}</li>}
              </ul>
            )}
            <p className="cov-card-fix">{c.fix}</p>
            {c.command && <code className="cov-card-cmd" title={c.command}>{c.command.split("\n")[0]}</code>}
            <div className="cov-card-action">{c.command ? <CopyButton text={c.command} /> : <HowToFix card={c} />}</div>
          </li>
        ))}
      </ul>
      {!all && cards.length > CARDS_SHOWN && (
        <button type="button" className="btn-link cov-see-all" onClick={() => setAll(true)}>
          See all {cards.length}
        </button>
      )}
    </>
  );
}

function HowToFix({ card }: { card: ActionCard }) {
  if (card.docs)
    return (
      <a className="btn btn-primary btn-sm" href={card.docs} target="_blank" rel="noopener noreferrer">
        How to fix
      </a>
    );
  return (
    <Link className="btn btn-primary btn-sm" to={card.to}>
      How to fix
    </Link>
  );
}

function CopyButton({ text }: { text: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <button
      type="button"
      className="btn btn-primary btn-sm"
      onClick={async () => {
        try {
          await navigator.clipboard.writeText(text);
          setCopied(true);
          setTimeout(() => setCopied(false), 2000);
        } catch {
          setCopied(false);
        }
      }}
    >
      <IconCopy size={15} /> {copied ? "Copied" : "Copy command"}
    </button>
  );
}

// --- 3. Ecosystems

const STATUS_ICONS = { checked: <IconCheckCircle size={16} />, partly: <IconHalf size={16} />, not_supported: <IconMinus size={16} /> };

export function EcosystemGrid({ ecosystems, onRequest, pending }: {
  ecosystems: EcosystemCoverage[];
  onRequest?: (e: EcosystemCoverage) => void;
  /** The ecosystem whose request is being sent. */
  pending?: string | null;
}) {
  if (ecosystems.length === 0) return <p className="cov-empty">No ecosystems found yet. They appear after an asset's first report.</p>;
  return (
    <ul className="cov-eco">
      {ecosystems.map((e) => {
        const st = ECOSYSTEM_STATUS[e.status];
        const to = ecosystemLink(e);
        const name = <span className="cov-eco-name">{e.label}</span>;
        return (
          <li key={e.key} className={`cov-eco-chip cov-eco-${e.status}`}>
            <span className={`cov-eco-status cov-tone-${st.tone}`} title={st.label}>
              {STATUS_ICONS[e.status]}
              <span className="sr-only">{st.label}:</span>
            </span>
            {to ? <Link to={to}>{name}</Link> : name}
            <span className="cov-eco-count" title={`${e.components.toLocaleString("en")} components`}>
              {e.components.toLocaleString("en")}
            </span>
            <span className="cov-eco-word">{st.label}</span>
            {e.status === "not_supported" &&
              (e.requested ? (
                <span className="cov-requested">
                  <IconCheckCircle size={14} /> Requested
                </span>
              ) : (
                onRequest && (
                  <button type="button" className="btn btn-sm cov-request" disabled={pending === e.key} onClick={() => onRequest(e)}>
                    {pending === e.key ? "Requesting…" : "Request support"}
                  </button>
                )
              ))}
          </li>
        );
      })}
    </ul>
  );
}

// --- 4. Coverage by asset

export function GroupChips({ groups, active, onChange }: {
  groups: Record<AssetCoverageGroup, number>;
  active: AssetCoverageGroup | "";
  onChange: (g: AssetCoverageGroup | "") => void;
}) {
  return (
    <div className="cov-filter" role="group" aria-label="Show assets">
      {ASSET_GROUPS.map((g) => (
        <button
          key={g.key}
          type="button"
          className={`cov-filter-chip cov-tone-${g.tone}${active === g.key ? " active" : ""}`}
          aria-pressed={active === g.key}
          onClick={() => onChange(active === g.key ? "" : g.key)}
        >
          {g.label} <span className="cov-filter-num">{(groups[g.key] ?? 0).toLocaleString("en")}</span>
        </button>
      ))}
    </div>
  );
}

export function MiniBar({ pct }: { pct: number | null }) {
  if (pct === null) return <span className="muted">no components</span>;
  return (
    <span className="cov-mini" title={`${pct}% checked`}>
      <span className="cov-mini-track" aria-hidden="true">
        <span className="cov-mini-fill" style={{ width: `${pct}%` }} />
      </span>
      <span className="cov-mini-num">{pct}%</span>
    </span>
  );
}

export function AssetCoverageTable({ list, renderProblems }: {
  list: AssetCoverageList;
  /** The asset's problem collector scopes, shown when its row is open. */
  renderProblems: (a: AssetCoverageRow) => ReactNode;
}) {
  const [open, setOpen] = useState<number | null>(null);
  if (list.items.length === 0) return <p className="cov-empty">No assets here.</p>;
  return (
    <div className="table-wrap cov-table-wrap">
      <table className="table cov-table">
        <caption className="sr-only">Coverage by asset, worst first</caption>
        <thead>
          <tr>
            <th scope="col">Asset</th>
            <th scope="col">Reporting</th>
            <th scope="col">Checked</th>
            <th scope="col">Not checked</th>
            <th scope="col">Last report</th>
            <th scope="col">
              <span className="sr-only">Problems</span>
            </th>
          </tr>
        </thead>
        <tbody>
          {list.items.map((a) => {
            const rep = reportingText(a);
            const parts = notCheckedParts(a);
            const isOpen = open === a.id;
            return (
              <Fragment key={a.id}>
                <tr className={isOpen ? "expanded" : undefined}>
                  <td data-label="Asset">
                    <span className="cov-asset">
                      <span className="cov-kind" aria-hidden="true">
                        <KindIcon kind={a.kind} />
                      </span>
                      <Link to={`/assets/${a.id}?tab=coverage`}>{a.name}</Link>
                      {a.group !== "healthy" && <span className={`cov-group cov-group-${a.group}`}>{groupLabel(a.group)}</span>}
                    </span>
                  </td>
                  <td data-label="Reporting">
                    <span className={`cov-rep cov-tone-${rep.tone}`}>{rep.text}</span>
                  </td>
                  <td data-label="Checked">
                    <MiniBar pct={assetPercent(a)} />
                  </td>
                  <td data-label="Not checked">
                    {parts.length === 0 ? (
                      <span className="muted">none</span>
                    ) : (
                      <span className="cov-nc">
                        {parts.map((p) => (
                          <span key={p.key} className={`cov-nc-part cov-tone-${p.tone}`}>
                            {p.text}
                          </span>
                        ))}
                      </span>
                    )}
                  </td>
                  <td data-label="Last report">{shortDay(a.last_report)}</td>
                  <td className="cov-expand-cell">
                    {a.problem_scopes > 0 && (
                      <button
                        type="button"
                        className="btn-link cov-expand"
                        aria-expanded={isOpen}
                        aria-controls={`cov-problems-${a.id}`}
                        onClick={() => setOpen(isOpen ? null : a.id)}
                      >
                        {isOpen ? "Hide" : `${a.problem_scopes.toLocaleString("en")} ${a.problem_scopes === 1 ? "problem" : "problems"}`}
                      </button>
                    )}
                  </td>
                </tr>
                {isOpen && (
                  <tr className="cov-problems-row">
                    <td colSpan={6} id={`cov-problems-${a.id}`}>
                      {renderProblems(a)}
                    </td>
                  </tr>
                )}
              </Fragment>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

const SCOPE_STATUS: Record<string, string> = {
  failed: "Failed",
  partial: "Partly read",
  unsupported: "Not read",
  skipped: "Skipped",
};

/** An asset's problem collector scopes, inline under its row. */
export function ProblemScopes({ rows }: { rows: CoverageRow[] }) {
  if (rows.length === 0) return <p className="small muted">Every part of the last report was read.</p>;
  return (
    <ul className="cov-scopes">
      {rows.map((r) => (
        <li key={`${r.collector_id}|${r.scope}`}>
          <span className={`cov-scope-status cov-scope-${r.status}`}>{SCOPE_STATUS[r.status] ?? r.status}</span>{" "}
          <span className="mono">{r.scope}</span>
          {r.reason && <span className="small muted"> · {r.reason}</span>}
        </li>
      ))}
    </ul>
  );
}

// --- 5. How we verify findings

export function SecondCheckPanel({ checks }: { checks: SecondCheckSummary | null | undefined }) {
  const s = secondCheckNumbers(checks);
  return (
    <details className="cov-verify">
      <summary>
        <span className="cov-section-icon" aria-hidden="true">
          <IconShield />
        </span>
        <span className="cov-verify-title">How we verify findings</span>
        {s.disagreed > 0 && (
          <span className="cov-warn-chip" role="status">
            <IconWarn size={14} /> {s.disagreed.toLocaleString("en")} disagreed
          </span>
        )}
      </summary>
      {s.empty ? (
        <p className="cov-empty">Nothing to verify yet. High-impact findings are checked a second time as they appear.</p>
      ) : (
        <ul className="cov-numbers">
          {s.items.map((i) => (
            <li key={i.key} className={i.key === "disagreed" && i.value > 0 ? "cov-number-warn" : undefined}>
              {i.to ? (
                <Link to={i.to}>
                  <span className="cov-number">{i.value.toLocaleString("en")}</span>
                  <span className="cov-number-label">{i.label}</span>
                </Link>
              ) : (
                <>
                  <span className="cov-number">{i.value.toLocaleString("en")}</span>
                  <span className="cov-number-label">{i.label}</span>
                </>
              )}
            </li>
          ))}
        </ul>
      )}
      <details className="cov-learn">
        <summary>Learn more</summary>
        <p className="small">Urgent findings are worked out again by a second, simpler check.</p>
        <p className="small">A disagreement flags the finding for a person; its priority stays. <Link to="/help/how-stackurity-knows">How Stackurity knows</Link></p>
        {checks && checks.logged_30d > 0 && <p className="small muted">{checks.logged_30d.toLocaleString("en")} disagreements logged in 30 days.</p>}
      </details>
    </details>
  );
}

export const SECTION_ICONS = { actions: <IconActionPlan />, ecosystems: <IconPackage />, assets: <IconInventory /> };
