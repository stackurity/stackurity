import { useRef, useState, type FormEvent, type ReactNode } from "react";
import { Link, useNavigate } from "react-router";
import { api, PRIORITIES, type FixGroup, type FixGroupSummary, type FixWork, type SavedView } from "../api";
import { absTime, plural, relTime } from "../format";
import { useAction } from "../hooks";
import { FIX_KIND_LABEL } from "./FixGroups";
import { fixPlaces, type CheckOptions } from "./FixVerify";
import { FindingActions, GROUP_ACTION_MAX } from "./Workflow";
import { ErrorBox, Notice } from "./ui";
import { SidewaysCue, useSideways } from "./Table";
import { impactNotes, shareText, urgentShare } from "../fixImpact";
import "../styles/action-centre.css";

/*
 * The Fixes page as an action centre: summary tiles that filter, a dense
 * sortable table of fixes (the Detailed view keeps the cards), saved views
 * and bulk actions on selected fixes. Pure pieces here; FixesPage
 * (pages/ActionPlan.tsx) loads the data and owns the address.
 */

/** Where the work on a fix stands, added up over its places. */
export interface Work {
  active: number;
  due: string | null;
  overdue: number;
  inProgress: number;
  regressed: number;
  owners: string[];
  unassigned: number;
  mine: number;
  /** Open issues in a pending request to ignore them. */
  awaitingApproval: number;
}

/** Adds up the work of a fix's places (one place: its own group). */
export function workOf(g: FixGroup, byGroup: Map<string, FixWork>): Work | null {
  const ws = fixPlaces(g)
    .map((p) => byGroup.get(p.group_id))
    .filter((w): w is FixWork => Boolean(w));
  if (ws.length === 0) return null;
  const owners: string[] = [];
  for (const w of ws) for (const o of w.owners ?? []) if (!owners.includes(o)) owners.push(o);
  const dues = ws.map((w) => w.due).filter((d): d is string => Boolean(d));
  return {
    active: ws.reduce((a, w) => a + w.active, 0),
    due: dues.length ? dues.reduce((a, b) => (new Date(a) <= new Date(b) ? a : b)) : null,
    overdue: ws.reduce((a, w) => a + w.overdue, 0),
    inProgress: ws.reduce((a, w) => a + w.in_progress, 0),
    regressed: ws.reduce((a, w) => a + w.regressed, 0),
    owners,
    unassigned: ws.reduce((a, w) => a + w.unassigned, 0),
    mine: ws.reduce((a, w) => a + w.mine, 0),
    awaitingApproval: ws.reduce((a, w) => a + (w.awaiting_approval ?? 0), 0),
  };
}

export type FixStatus = "open" | "in_progress" | "approval" | "checking" | "regressed";

export const STATUS_LABEL: Record<FixStatus, string> = {
  open: "Not started",
  in_progress: "In progress",
  approval: "Waiting for approval",
  checking: "Waiting for check",
  regressed: "Regressed",
};

const STATUS_HELP: Record<FixStatus, string> = {
  open: "Nobody has started on it yet",
  in_progress: "Someone started work, or said they applied it",
  approval: "Someone asked to ignore some of its issues; a security user has yet to decide",
  checking: "A check was asked for and is waiting for a fresh report",
  regressed: "Some of its issues were fixed before and came back",
};

/**
 * One phrase for where a fix stands: a waiting check first, then a
 * regression, then a request waiting for approval, then work started.
 */
export function fixStatus(g: FixGroup, work: Work | null, options?: CheckOptions): FixStatus {
  const checking = fixPlaces(g).some((p) => {
    const c = options?.byGroup.get(p.group_id)?.last_check;
    return Boolean(c && c.status !== "done");
  });
  if (checking) return "checking";
  if (work && work.regressed > 0) return "regressed";
  if (work && work.awaitingApproval > 0) return "approval";
  if (work && work.inProgress > 0) return "in_progress";
  return "open";
}

/** "3 assets" for a fix in several places, otherwise the asset (and its app directory). */
export function whereText(g: FixGroup): string {
  if (g.places && g.places.length > 1) return plural(g.places.length, "asset");
  return g.app_dir ? `${g.asset_name} ${g.app_dir}` : g.asset_name;
}

const EFFORT_RANK: Record<string, number> = { low: 0, medium: 1, high: 2 };
const STATUS_RANK: Record<FixStatus, number> = { regressed: 0, open: 1, approval: 2, in_progress: 3, checking: 4 };

/** Sort keys; flags and effort have no column any more but still sort a saved address. */
export type SortKey = "priority" | "fix" | "where" | "issues" | "flags" | "effort" | "owner" | "due" | "status";
export const SORT_KEYS: SortKey[] = ["priority", "fix", "where", "issues", "flags", "effort", "owner", "due", "status"];

/** "-issues" → issues, descending. Anything unknown is the server's order (most urgent first). */
export function parseSort(v: string | null): { key: SortKey | null; desc: boolean } {
  const desc = Boolean(v?.startsWith("-"));
  const k = (desc ? v!.slice(1) : (v ?? "")) as SortKey;
  return SORT_KEYS.includes(k) ? { key: k, desc } : { key: null, desc: false };
}

export interface Row {
  g: FixGroup;
  work: Work | null;
  status: FixStatus;
  /** Position in the server's order (most urgent first): the tie-break. */
  rank: number;
}

/** Sorts rows; equal ones keep the server's order. */
export function sortRows(rows: Row[], key: SortKey | null, desc: boolean): Row[] {
  if (!key) return rows;
  const val = (r: Row): number | string => {
    switch (key) {
      case "priority":
        return r.rank;
      case "fix":
        return r.g.title.toLowerCase();
      case "where":
        return whereText(r.g).toLowerCase();
      case "issues":
        return r.g.finding_count;
      case "flags":
        return (r.g.sos ? 1_000_000 : 0) + r.g.known_exploited;
      case "effort":
        return EFFORT_RANK[r.g.effort] ?? 3;
      case "owner":
        return r.work?.owners[0]?.toLowerCase() ?? "￿";
      case "due":
        return r.work?.due ? new Date(r.work.due).getTime() : Number.MAX_SAFE_INTEGER;
      case "status":
        return STATUS_RANK[r.status];
    }
  };
  const out = [...rows].sort((a, b) => {
    const x = val(a);
    const y = val(b);
    const c = typeof x === "number" && typeof y === "number" ? x - y : String(x).localeCompare(String(y));
    return (desc ? -c : c) || a.rank - b.rank;
  });
  return out;
}

/** Columns whose first click sorts the biggest first. */
const DESC_FIRST: SortKey[] = ["issues", "flags", "effort"];

export function PriorityChip({ p }: { p: string }) {
  if (!p) return <span className="ac-muted">—</span>;
  return (
    <span className={`ac-prio ac-prio-${p}`} title={`Most urgent issue: ${p}`}>
      {p}
    </span>
  );
}

/** The fix deadline: red only when an issue is past it. */
function DueCell({ w }: { w: Work | null }) {
  if (!w?.due) return <span className="ac-muted">None set</span>;
  const over = w.overdue > 0;
  return (
    <time dateTime={w.due} title={`Fix by ${absTime(w.due)}${over ? `: ${plural(w.overdue, "issue")} overdue` : ""}`} className={over ? "ac-due-over" : undefined}>
      {over ? `Overdue ${relTime(w.due).replace(/ ago$/, "")}` : `Due ${relTime(w.due)}`}
    </time>
  );
}

function OwnerCell({ w }: { w: Work | null }) {
  if (!w || w.owners.length === 0) return <span className="ac-muted">Unassigned</span>;
  const first = w.mine > 0 ? "You" : w.owners[0];
  const more = w.owners.length - 1 + (w.unassigned > 0 ? 1 : 0);
  return (
    <span title={[...w.owners, ...(w.unassigned > 0 ? [`${plural(w.unassigned, "issue")} unassigned`] : [])].join("\n")}>
      {first}
      {more > 0 && <span className="ac-muted"> +{more}</span>}
    </span>
  );
}

/**
 * Under a recommended action: its kind, the environment, and what needs care
 * ("Package upgrade · production · major upgrade · restart needed").
 */
function subText(g: FixGroup): string {
  return [FIX_KIND_LABEL[g.kind] ?? g.kind, g.places && g.places.length > 1 ? "" : g.environment, ...impactNotes(g)].filter(Boolean).join(" · ");
}

function RiskCell({ g }: { g: FixGroup }) {
  return (
    <span className="ac-risk">
      <PriorityChip p={g.top_priority} />
      {g.sos && (
        <span className="ac-flag ac-flag-sos" title="Matches an SOS rule in the risk policy">
          SOS
        </span>
      )}
      {g.known_exploited > 0 && (
        <span className="ac-flag" title={`${plural(g.known_exploited, "issue")} in the CISA Known Exploited Vulnerabilities catalogue`}>
          KEV {g.known_exploited}
        </span>
      )}
    </span>
  );
}

/**
 * The fixes as a dense table. A row opens the fix; the checkbox selects it
 * for bulk actions (shown only to people who may act).
 */
export function FixTable({
  rows,
  sort,
  onSort,
  selected,
  onSelect,
  selectable,
  urgentTotal,
}: {
  rows: Row[];
  sort: { key: SortKey | null; desc: boolean };
  onSort: (key: SortKey | null, desc: boolean) => void;
  selected: Set<string>;
  onSelect: (ids: string[], on: boolean) => void;
  selectable: boolean;
  /** All open P1 and P2 issues (GET /fix-groups/summary), for each fix's share of them. */
  urgentTotal?: number;
}) {
  const navigate = useNavigate();
  const wrap = useRef<HTMLDivElement>(null);
  const hidden = useSideways(wrap);
  const head = (key: SortKey, label: string, className?: string, numeric?: boolean) => {
    const active = sort.key === key;
    const next = () => {
      if (!active) onSort(key, DESC_FIRST.includes(key));
      else if (sort.desc === DESC_FIRST.includes(key)) onSort(key, !sort.desc);
      else onSort(null, false); // third click: back to most urgent first
    };
    return (
      <th
        scope="col"
        className={[className, numeric ? "num" : ""].filter(Boolean).join(" ") || undefined}
        aria-sort={active ? (sort.desc ? "descending" : "ascending") : "none"}
      >
        <button type="button" className="ac-sort" data-active={active} onClick={next}>
          {label}
          {active && <span className="ac-sort-arrow" aria-hidden="true">{sort.desc ? "▼" : "▲"}</span>}
        </button>
      </th>
    );
  };
  const allOn = rows.length > 0 && rows.every((r) => selected.has(r.g.id));
  const open = (g: FixGroup) => navigate(`/fixes/${encodeURIComponent(g.id)}`);
  return (
    <>
    <SidewaysCue hidden={hidden} />
    <div ref={wrap} className="ac-table-wrap">
      <table className="ac-table">
        <caption className="sr-only">Fixes, {sort.key ? `sorted by ${sort.key}` : "most urgent first"}</caption>
        <thead>
          <tr>
            {selectable && (
              <th scope="col" className="ac-col-select">
                <input type="checkbox" aria-label="Select every fix on this page" checked={allOn} onChange={(e) => onSelect(rows.map((r) => r.g.id), e.target.checked)} />
              </th>
            )}
            {head("fix", "Recommended action", "ac-col-fix")}
            {head("where", "Affected assets", "ac-col-where")}
            {head("priority", "Risk", "ac-col-prio")}
            {head("issues", "Issues resolved", "ac-col-issues", true)}
            {head("owner", "Owner", "ac-col-owner")}
            {head("due", "Deadline", "ac-col-due")}
            {head("status", "Status", "ac-col-status")}
          </tr>
        </thead>
        <tbody>
          {rows.map(({ g, work, status }) => {
            const on = selected.has(g.id);
            const places = g.places && g.places.length > 1 ? g.places : null;
            const share = urgentShare(g, urgentTotal);
            return (
              <tr
                key={g.id}
                className={on ? "ac-selected" : undefined}
                tabIndex={0}
                onClick={() => open(g)}
                onKeyDown={(e) => {
                  if (e.target === e.currentTarget && e.key === "Enter") open(g);
                }}
              >
                {selectable && (
                  <td className="ac-col-select" onClick={(e) => e.stopPropagation()}>
                    <input type="checkbox" aria-label={`Select ${g.title}`} checked={on} onChange={(e) => onSelect([g.id], e.target.checked)} />
                  </td>
                )}
                <td className="ac-col-fix">
                  <Link className="ac-fix-title" to={`/fixes/${encodeURIComponent(g.id)}`} title={g.title} onClick={(e) => e.stopPropagation()}>
                    {g.title}
                  </Link>
                  <span className="ac-sub">{subText(g)}</span>
                </td>
                <td className="ac-col-where" title={places ? places.map((p) => p.asset_name).join("\n") : undefined}>
                  {whereText(g)}
                  <span className="ac-phone-meta">
                    {work?.overdue ? <span className="ac-due-over"> · overdue</span> : null}
                    {g.known_exploited > 0 ? " · known exploited" : ""}
                    {g.sos ? " · SOS" : ""}
                    {work ? ` · ${work.mine > 0 ? "you" : (work.owners[0] ?? "unassigned")}` : ""}
                  </span>
                </td>
                <td className="ac-col-prio">
                  <RiskCell g={g} />
                </td>
                <td className="ac-col-issues num">
                  {g.finding_count.toLocaleString()}
                  {share !== null && (
                    <span className="ac-sub" title={`Clears ${shareText(share)} of all open P1 and P2 issues`}>
                      {shareText(share)} of P1/P2
                    </span>
                  )}
                </td>
                <td className="ac-col-owner">
                  <OwnerCell w={work} />
                </td>
                <td className="ac-col-due">
                  <DueCell w={work} />
                </td>
                <td className="ac-col-status">
                  <span className={`ac-status ac-status-${status}`} title={STATUS_HELP[status]}>
                    {STATUS_LABEL[status]}
                  </span>
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
    </>
  );
}

function Tile({ to, active, label, value, sub, tone }: { to?: string; active?: boolean; label: ReactNode; value: ReactNode; sub?: ReactNode; tone?: "bad" | "good" }) {
  const body = (
    <>
      <span className="ac-tile-label">{label}</span>
      <span className="ac-tile-value">{value}</span>
      {sub && <span className="ac-tile-sub">{sub}</span>}
    </>
  );
  const cls = `ac-tile${tone ? ` ac-tile-${tone}` : ""}`;
  return to ? (
    <Link className={cls} to={to} aria-current={active ? "true" : undefined}>
      {body}
    </Link>
  ) : (
    <div className={cls}>{body}</div>
  );
}

const PRIORITY_SUB: Record<string, string> = { P1: "Fix first", P2: "Fix soon", P3: "Plan it", P4: "When you can" };

/**
 * The summary row: open fixes by priority and overdue (each opens that
 * filter, again to clear it), issues the fixes clear, and fixes proven by
 * a newer scan in the last 30 days. Something not measured says so.
 */
export function ActionSummary({
  s,
  verified,
  link,
  priority,
  overdue,
  issuesLink,
}: {
  s: FixGroupSummary;
  /** Issues a newer inventory showed fixed in the last 30 days; null: not measured. */
  verified: number | null;
  link: (patch: Record<string, string>) => string;
  priority: string;
  overdue: boolean;
  issuesLink: string;
}) {
  const byP = s.by_priority ?? {};
  return (
    <section className="ac-tiles" aria-label="Open fixes at a glance">
      {PRIORITIES.map((p) => (
        <Tile
          key={p}
          to={link({ priority: priority === p ? "" : p })}
          active={priority === p}
          label={
            <>
              <span className={`ac-dot ac-dot-${p}`} aria-hidden="true" />
              {p} fixes
            </>
          }
          value={(byP[p] ?? 0).toLocaleString()}
          sub={PRIORITY_SUB[p]}
        />
      ))}
      <Tile
        to={link({ overdue: overdue ? "" : "true" })}
        active={overdue}
        label="Overdue"
        value={s.overdue === undefined ? <span className="ac-muted">—</span> : s.overdue.toLocaleString()}
        sub={s.overdue === undefined ? "not measured" : "past the fix deadline"}
        tone={s.overdue ? "bad" : undefined}
      />
      <Tile to={issuesLink} label="Issues these clear" value={s.findings.toLocaleString()} sub={s.unique_issues !== undefined ? plural(s.unique_issues, "distinct vulnerability", "distinct vulnerabilities") : undefined} />
      <Tile
        to="/outcomes?days=30"
        label="Verified fixed, 30 days"
        value={verified === null ? <span className="ac-muted">—</span> : verified.toLocaleString()}
        sub={verified === null ? "not measured" : "issues proven by a newer scan"}
        tone={verified ? "good" : undefined}
      />
    </section>
  );
}

/** Built-in views: query strings of the Fixes page. */
export const BUILTIN_VIEWS: { name: string; query: string; hint: string }[] = [
  { name: "My fixes", query: "assignee=me", hint: "Fixes with an issue assigned to you" },
  { name: "P1 & P2", query: "priority=P1,P2", hint: "The two most urgent priorities" },
  { name: "Overdue", query: "overdue=true", hint: "Past the risk policy's fix deadline" },
  { name: "Exploited", query: "exploited=true", hint: "Known to be exploited by attackers" },
];

/** The filter part of a query string, in a stable order, for comparing views. */
export function viewKey(query: string): string {
  const p = new URLSearchParams(query);
  p.delete("view");
  p.sort();
  return p.toString();
}

/**
 * The Views menu: built-in views, the person's saved ones, and saving the
 * current filters under a name.
 */
export function ViewsMenu({
  current,
  saved,
  error,
  onChanged,
}: {
  /** The page's query string now. */
  current: string;
  saved: SavedView[] | null;
  error?: unknown;
  onChanged: () => void;
}) {
  const [name, setName] = useState("");
  const act = useAction();
  const here = viewKey(current);
  const to = (q: string) => {
    const keep = new URLSearchParams(current).get("view");
    const n = new URLSearchParams(q);
    if (keep && !n.has("view")) n.set("view", keep);
    const str = n.toString();
    return `/fixes${str ? `?${str}` : ""}`;
  };
  const save = async (e: FormEvent) => {
    e.preventDefault();
    if (!name.trim()) return;
    if (await act.run(() => api.post<SavedView>("/saved-views", { page: "fixes", name: name.trim(), query: here }))) {
      setName("");
      onChanged();
    }
  };
  const remove = async (v: SavedView) => {
    const ok = await act.run(async () => {
      await api.del(`/saved-views/${v.id}`);
      return true;
    });
    if (ok) onChanged();
  };
  const active = [...BUILTIN_VIEWS, ...(saved ?? [])].find((v) => viewKey(v.query) === here && here !== "");
  return (
    <details className="ac-views">
      <summary className="btn">
        Views{active ? `: ${active.name}` : ""} <span aria-hidden="true">▾</span>
      </summary>
      <div className="ac-views-menu">
        <h3>Built in</h3>
        <ul>
          <li>
            <Link to={to("")} onClick={(e) => e.currentTarget.closest("details")?.removeAttribute("open")} aria-current={here === "" ? "true" : undefined}>
              All open fixes<span className="ac-view-hint">Most urgent first</span>
            </Link>
          </li>
          <li>
            <Link to="/fixes/mine" onClick={(e) => e.currentTarget.closest("details")?.removeAttribute("open")}>
              My work<span className="ac-view-hint">Your issues, approvals and what failed, on one page</span>
            </Link>
          </li>
          {BUILTIN_VIEWS.map((v) => (
            <li key={v.name}>
              <Link to={to(v.query)} onClick={(e) => e.currentTarget.closest("details")?.removeAttribute("open")} aria-current={viewKey(v.query) === here ? "true" : undefined}>
                {v.name}
                <span className="ac-view-hint">{v.hint}</span>
              </Link>
            </li>
          ))}
        </ul>
        <h3>Saved by you</h3>
        <ErrorBox error={act.error} />
        {error ? <p className="small ac-muted" style={{ padding: "0 12px" }}>Could not load your saved views.</p> : null}
        {saved && saved.length === 0 && (
          <p className="small ac-muted" style={{ padding: "0 12px", margin: 0 }}>
            None yet. Set the filters you want, then save them here.
          </p>
        )}
        {saved && saved.length > 0 && (
          <ul>
            {saved.map((v) => (
              <li key={v.id}>
                <Link to={to(v.query)} onClick={(e) => e.currentTarget.closest("details")?.removeAttribute("open")} aria-current={viewKey(v.query) === here ? "true" : undefined}>
                  {v.name}
                </Link>
                <button type="button" className="ac-view-delete" disabled={act.pending} onClick={() => remove(v)} aria-label={`Delete the view ${v.name}`}>
                  Delete
                </button>
              </li>
            ))}
          </ul>
        )}
        <form onSubmit={save} aria-label="Save the current filters as a view">
          <input type="text" aria-label="Name of the view" placeholder="Name these filters" maxLength={60} value={name} onChange={(e) => setName(e.target.value)} />
          <button type="submit" className="btn btn-sm" disabled={act.pending || !name.trim()}>
            Save
          </button>
        </form>
      </div>
    </details>
  );
}

/**
 * Actions on the selected fixes: assign (and the other workflow actions)
 * with the same requests as a fix's own page, and Check again for every
 * place that can report on demand.
 */
export function BulkBar({
  rows,
  options,
  onClear,
  onDone,
}: {
  rows: FixGroup[];
  options: CheckOptions;
  onClear: () => void;
  onDone: () => void;
}) {
  const [acting, setActing] = useState(false);
  const [note, setNote] = useState<string | null>(null);
  const act = useAction();
  const ids = rows.flatMap(fixPlaces).map((p) => p.group_id);
  const count = rows.reduce((a, g) => a + g.finding_count, 0);
  const checkable = ids.filter((id) => options.byGroup.get(id)?.on_demand);
  const check = async () => {
    setNote(null);
    const r = await act.run(() => Promise.allSettled(checkable.map((id) => api.post(`/fix-groups/${encodeURIComponent(id)}/check`))));
    if (!r) return;
    const asked = r.filter((x) => x.status === "fulfilled").length;
    const failed = r.length - asked;
    const cannot = ids.length - checkable.length;
    setNote(
      [
        asked > 0 ? `Asked ${plural(asked, "place")} for a fresh report.` : "",
        failed > 0 ? `${plural(failed, "place")} could not be asked.` : "",
        cannot > 0 ? `${plural(cannot, "place")} can't report on demand; open the fix for what to do instead.` : "",
      ]
        .filter(Boolean)
        .join(" "),
    );
    options.reload();
    onDone();
  };
  return (
    <div className="ac-bulk" role="region" aria-label="Actions on the selected fixes">
      <strong>{plural(rows.length, "fix", "fixes")} selected</strong>
      <span className="ac-muted">{plural(count, "issue")}</span>
      <button type="button" className="btn btn-sm" aria-expanded={acting} onClick={() => setActing(!acting)}>
        Assign owner…
      </button>
      <button
        type="button"
        className="btn btn-sm"
        disabled={act.pending || checkable.length === 0}
        onClick={check}
        title={checkable.length === 0 ? "None of these places can report on demand" : undefined}
      >
        {act.pending ? "Asking…" : "Check again"}
      </button>
      <button type="button" className="btn btn-sm btn-link" onClick={onClear}>
        Clear selection
      </button>
      <ErrorBox error={act.error} title="Could not ask for a check" />
      {note && <span className="small">{note}</span>}
      {acting &&
        (count > GROUP_ACTION_MAX ? (
          <Notice kind="info">
            These fixes have {count.toLocaleString()} issues, more than can be changed at once ({GROUP_ACTION_MAX.toLocaleString()}). Select fewer.
          </Notice>
        ) : (
          <FindingActions key={ids.join(",")} target={{ type: "groups", ids, count }} initialPanel="assign" compact onDone={onDone} />
        ))}
    </div>
  );
}
