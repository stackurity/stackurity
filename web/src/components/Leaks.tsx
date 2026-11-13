import { useState, type FormEvent } from "react";
import { useMenu } from "./useFocus";
import { Link } from "react-router";
import { api, type Check, type Leak, type LeakList, type LeakState, type LeakSummary } from "../api";
import { useAuth } from "../auth";
import { useAction, useLoad } from "../hooks";
import { LEAK_STATE, leakWorkLine, rotationGuide } from "../leaks";
import { Badge, SeverityBadge } from "./Badge";
import { promptText } from "./ConfirmDialog";
import { Table, type Column } from "./Table";
import { leaksEmpty } from "../emptyCopy";
import { Card, EmptyState, ErrorBox, Loading, Notice, Pager, RelativeTime, StatTile, Tabs } from "./ui";
import { Assignee, AssignPanel, DueDate } from "./Workflow";

/**
 * Leaked keys: keys, tokens and passwords found written in files. The value
 * is never on the server; a row names the kind of key, the file and the
 * line, and says in one line (why) what its place means and what to do.
 *
 * Each one is tracked work: an owner, a deadline, "I've rotated it", and a
 * scan that confirms the key is gone from the file (or still finds it).
 */

export const EXPOSURE_LABEL: Record<string, string> = {
  served: "Web server may send it",
  world_readable: "Every account can read it",
};

/** Which leaks a view lists: what needs action, or where keys are kept. */
export type LeakView = "action" | "kept" | "resolved";

export const LEAK_VIEW_QUERY: Record<LeakView, { status: string; severity?: string }> = {
  action: { status: "open", severity: "critical,high" },
  kept: { status: "open", severity: "medium,low" },
  resolved: { status: "resolved" },
};

const LIMIT = 50;

export function leakWhere(l: Leak): string {
  return l.line > 0 ? `${l.path}:${l.line}` : l.path;
}

/** The state people see, as one chip with its meaning on hover. */
export function LeakStateBadge({ state }: { state: LeakState }) {
  const s = LEAK_STATE[state] ?? { label: state, tone: "muted" as const, hint: "" };
  return <Badge status={`leak-${state}`} tone={s.tone} label={s.label} title={s.hint} />;
}

/** A small menu of row actions (Assign, Mark as rotated, Check again, Dismiss). */
function RowMenu({ label, items }: { label: string; items: { label: string; onSelect: () => void }[] }) {
  const m = useMenu();
  if (items.length === 0) return null;
  return (
    <div ref={m.box} style={{ position: "relative", display: "inline-block" }}>
      <button type="button" ref={m.button} className="btn btn-sm" {...m.buttonProps} aria-label={label}>
        Actions ▾
      </button>
      {m.open && (
        <div className="menu menu-right" role="menu" aria-label={label} ref={m.menu} onKeyDown={m.onMenuKeyDown}>
          {items.map((it) => (
            <button
              key={it.label}
              type="button"
              role="menuitem"
              className="menu-item"
              onClick={() => {
                m.close(true);
                it.onSelect();
              }}
            >
              {it.label}
            </button>
          ))}
        </div>
      )}
    </div>
  );
}

type Panel = { id: number; kind: "assign" | "rotate" | "checked"; check?: Check };

/** What a check asked for from a leak's row will do next. */
function checkNext(c: Check): string {
  if (c.method === "agent") return "The asset's agent scans it again and reports within a minute or two.";
  if (c.method === "integration") return "The server is scanning the repository again. This takes a minute or two.";
  return "It is checked at the asset's next report: run the scan again in CI or on the server.";
}

/** How to rotate this kind of key, and what "rotated" means here. */
export function RotationSteps({ leak }: { leak: Leak }) {
  const g = rotationGuide(leak.rule);
  return (
    <div className="small">
      <p>
        <strong>{g.provider}:</strong> {g.steps}
        {g.link && (
          <>
            {" "}
            <a href={g.link} target="_blank" rel="noreferrer">
              {g.provider}'s guide
            </a>
          </>
        )}
      </p>
      <p>
        Then remove the old key from {leakWhere(leak)}
        {leak.asset_kind === "repository" ? " and from the repository's history (git filter-repo); every clone still has it, so rotating comes first" : ""}
        .
      </p>
    </div>
  );
}

function RotatePanel({ leak, onDone, onCancel }: { leak: Leak; onDone: (c?: Check) => void; onCancel: () => void }) {
  const act = useAction();
  const [note, setNote] = useState("");
  const [check, setCheck] = useState(true);
  const go = async (e: FormEvent) => {
    e.preventDefault();
    const res = await act.run(() =>
      api.post<{ leak: Leak; check?: Check; check_error?: string }>(`/leaks/${leak.id}/rotated`, { note, check }),
    );
    if (res) onDone(res.check);
  };
  return (
    <form className="action-panel form form-compact" onSubmit={go} aria-label="Mark as rotated">
      <strong>Mark {leak.title} as rotated</strong>
      <p className="small">
        Rotating means three things: revoke the old key at the service that issued it, issue a new one and put it where the old one
        was used, and remove the old key from the file (and from the repository's history, if it was committed). Deleting it from
        the file alone does not help: copies of the file still have it.
      </p>
      <RotationSteps leak={leak} />
      <div className="field">
        <label htmlFor={`rot-${leak.id}`}>Note (what you did; never paste the key)</label>
        <textarea id={`rot-${leak.id}`} rows={2} maxLength={1000} value={note} onChange={(e) => setNote(e.target.value)} />
      </div>
      <label className="check">
        <input type="checkbox" checked={check} onChange={(e) => setCheck(e.target.checked)} /> Check again now, so a scan confirms the key
        is gone from the file
      </label>
      <ErrorBox error={act.error} />
      <div className="form-actions">
        <button type="submit" className="btn btn-primary btn-sm" disabled={act.pending}>
          I've revoked it and issued a new one
        </button>
        <button type="button" className="btn btn-sm" onClick={onCancel}>
          Cancel
        </button>
      </div>
    </form>
  );
}

export function LeaksTable({ leaks, showAsset, onChanged }: { leaks: Leak[]; showAsset: boolean; onChanged: () => void }) {
  const { canAct, me } = useAuth();
  const act = useAction();
  const [panel, setPanel] = useState<Panel | null>(null);
  const engineer = canAct("engineer");
  const security = canAct("security");

  const dismiss = async (leak: Leak) => {
    const note = await promptText({
      title: `Dismiss ${leak.title} in ${leakWhere(leak)}?`,
      message: "It stays dismissed whatever later scans see. Dismiss a test key kept on purpose. For a real key, mark it as rotated instead, so a scan confirms it.",
      label: "Note (which, and why)",
      action: "Dismiss",
      allowEmpty: true,
    });
    if (note === null) return;
    if (await act.run(() => api.post(`/leaks/${leak.id}/dismiss`, { note }))) onChanged();
  };
  const reopen = async (leak: Leak) => {
    if (await act.run(() => api.post(`/leaks/${leak.id}/undismiss`))) onChanged();
  };
  const checkAgain = async (leak: Leak) => {
    const c = await act.run(() => api.post<Check>(`/leaks/${leak.id}/check-again`));
    if (c) setPanel({ id: leak.id, kind: "checked", check: c });
  };
  const assign = async (leak: Leak, user: number | undefined, team: number | undefined) => {
    if (await act.run(() => api.post(`/leaks/${leak.id}/assign`, { user_id: user, team_id: team }))) {
      setPanel(null);
      onChanged();
    }
  };

  const menu = (l: Leak) => {
    const items: { label: string; onSelect: () => void }[] = [];
    if (l.status === "open") {
      if (engineer) {
        items.push({ label: "Assign…", onSelect: () => setPanel({ id: l.id, kind: "assign" }) });
        items.push({
          label: l.state === "needs_rotation" ? "Mark as rotated…" : "Mark as rotated again…",
          onSelect: () => setPanel({ id: l.id, kind: "rotate" }),
        });
        items.push({ label: "Check again", onSelect: () => void checkAgain(l) });
      }
      if (security) items.push({ label: "Dismiss…", onSelect: () => void dismiss(l) });
    } else if (l.resolution === "dismissed" && security) {
      items.push({ label: "Open again", onSelect: () => void reopen(l) });
    }
    return <RowMenu label={`Actions for ${l.title} in ${leakWhere(l)}`} items={items} />;
  };

  const cols: Column<Leak>[] = [
    { key: "severity", header: "Severity", cell: (l) => <SeverityBadge severity={l.severity} /> },
    {
      key: "what",
      header: "Key",
      cell: (l) => (
        <>
          <strong>{l.title}</strong>
          {l.name && <span className="mono small"> {l.name}</span>}
          {l.preview && <div className="mono small">{l.preview}</div>}
        </>
      ),
    },
    ...(showAsset
      ? [{ key: "asset", header: "Asset", cell: (l: Leak) => <Link to={`/assets/${l.asset_id}?tab=leaks`}>{l.asset_name}</Link> }]
      : []),
    {
      key: "where",
      header: "File",
      cell: (l) => (
        <>
          <span className="mono small break">{leakWhere(l)}</span>
          {l.exposure && (
            <div>
              <Badge status={l.exposure} tone="bad" label={EXPOSURE_LABEL[l.exposure] ?? l.exposure} />
            </div>
          )}
          <div className="small muted">{l.why}</div>
        </>
      ),
    },
    {
      key: "state",
      header: "State",
      cell: (l) => (
        <>
          <LeakStateBadge state={l.state} />
          {l.state === "still_found" && <div className="small text-bad">{LEAK_STATE.still_found.hint}</div>}
          {l.rotated_at && l.status === "open" && (
            <div className="small muted">
              Rotated <RelativeTime iso={l.rotated_at} />
              {l.rotated_by_name ? ` by ${l.rotated_by_name}` : ""}
            </div>
          )}
          {l.status !== "open" && (
            <div className="small muted">
              <RelativeTime iso={l.resolved_at} />
              {l.resolution_note && <div>{l.resolution_note}</div>}
            </div>
          )}
          {l.rotation_note && <div className="small">{l.rotation_note}</div>}
        </>
      ),
    },
    {
      key: "owner",
      header: "Owner",
      cell: (l) =>
        l.assignee_email || l.assignee_team ? (
          <Assignee email={l.assignee_email} team={l.assignee_team} />
        ) : (
          <>
            <span className="muted">unassigned</span>
            {l.asset_owner_team && <div className="small muted">asset owner: team {l.asset_owner_team}</div>}
          </>
        ),
    },
    {
      key: "due",
      header: "Due",
      cell: (l) =>
        l.status === "open" ? (
          <>
            <DueDate iso={l.due_at} overdue={l.overdue} label="Rotate by" />
            <div className="small muted">
              found <RelativeTime iso={l.first_seen} />
            </div>
          </>
        ) : (
          <span className="muted">—</span>
        ),
    },
    ...(engineer || security ? [{ key: "actions", header: "", cell: (l: Leak) => menu(l) }] : []),
  ];
  const current = panel ? leaks.find((l) => l.id === panel.id) : undefined;
  return (
    <>
      <ErrorBox error={act.error} />
      <Table
        caption="Leaked keys"
        columns={cols}
        rows={leaks}
        rowKey={(l) => l.id}
        selectedKey={panel?.id ?? null}
        renderExpanded={(l) => {
          if (!panel || !current || l.id !== panel.id) return null;
          if (panel.kind === "assign")
            return <AssignPanel myId={me?.user?.id} pending={act.pending} onCancel={() => setPanel(null)} onSubmit={(u, t) => void assign(l, u, t)} />;
          if (panel.kind === "rotate")
            return (
              <RotatePanel
                leak={l}
                onCancel={() => setPanel(null)}
                onDone={(c) => {
                  setPanel(c ? { id: l.id, kind: "checked", check: c } : null);
                  onChanged();
                }}
              />
            );
          return (
            <div className="action-panel">
              <p className="small">
                Asked for a new scan of {l.asset_name}. {panel.check ? checkNext(panel.check) : ""} A complete scan that no longer finds the
                key marks it verified gone; one that still finds it shows it as still found.{" "}
                <Link to="/checks">See checks</Link>
              </p>
              <button type="button" className="btn btn-sm" onClick={() => setPanel(null)}>
                Close
              </button>
            </div>
          );
        }}
      />
    </>
  );
}

/**
 * The summary strip at the top of Leaked keys: what needs rotating, what is
 * overdue, what waits for a scan and what scans confirmed gone lately.
 */
export function LeakSummaryStrip({ s }: { s: LeakSummary }) {
  const todo = s.needs_rotation + s.still_found;
  return (
    <div className="tiles" role="group" aria-label="Leaked keys that need action">
      <StatTile
        label="Need rotation"
        value={todo.toLocaleString()}
        tone={todo > 0 ? "bad" : "good"}
        sub={s.still_found > 0 ? `${s.still_found} still found after rotation` : "Critical and high, not rotated yet"}
      />
      <StatTile label="Overdue" value={s.overdue.toLocaleString()} tone={s.overdue > 0 ? "crit" : "good"} sub="Past their rotate-by date" />
      <StatTile
        label="Waiting for check"
        value={s.waiting_check.toLocaleString()}
        tone={s.waiting_check > 0 ? "warn" : undefined}
        sub="Rotated; a scan will confirm"
      />
      <StatTile label="Verified gone" value={s.verified_gone_30d.toLocaleString()} tone="good" sub="In the last 30 days" />
    </div>
  );
}

/**
 * Leaked keys on the Fixes page: open critical and high leaks are urgent
 * work too. Shown only when there is something to do.
 */
export function LeakFixesCard({ assetId }: { assetId?: number }) {
  const sum = useLoad(
    () => api.get<LeakSummary>("/leaks/summary", { severity: "critical,high", ...(assetId ? { asset_id: assetId } : {}) }),
    [assetId],
  );
  const s = sum.data;
  if (!s || s.needs_rotation + s.still_found + s.waiting_check === 0) return null;
  const to = assetId ? `/assets/${assetId}?tab=leaks` : "/fixes/leaks";
  return (
    <Card
      title="Leaked keys to rotate"
      description="Keys and passwords found in files that anyone with the file, the repository or the web address can use. Rotate them first: no upgrade fixes a leaked key."
      actions={
        <Link to={to} className="btn btn-sm btn-primary">
          Open leaked keys
        </Link>
      }
    >
      <p className={s.overdue > 0 || s.still_found > 0 ? "text-bad" : undefined}>
        <strong>{leakWorkLine(s)}</strong>
        {s.still_found > 0 && <> ({s.still_found} still found after rotation)</>}
      </p>
    </Card>
  );
}

export const VIEW_LABEL: Record<LeakView, string> = {
  action: "Needs action",
  kept: "Where keys are kept",
  resolved: "Resolved",
};

const VIEW_HINT: Record<LeakView, string> = {
  action:
    "Critical and high: keys the web server may send, keys committed to a repository or written into code. Rotate each one: revoke it, issue a new one, and remove it from the file. A scan then confirms it is gone.",
  kept: "Keys kept in configuration files, where they belong. Nothing to do now: this is where each key lives when you rotate it.",
  resolved: "Leaked keys a complete scan no longer finds, and those dismissed.",
};

const STATE_FILTERS: { value: string; label: string }[] = [
  { value: "", label: "Any state" },
  { value: "needs_rotation", label: LEAK_STATE.needs_rotation.label },
  { value: "still_found", label: LEAK_STATE.still_found.label },
  { value: "waiting_check", label: LEAK_STATE.waiting_check.label },
  { value: "overdue", label: "Overdue" },
];

/** Leaked keys, for the whole organisation or one asset, in three views. */
export function LeaksView({ assetId }: { assetId?: number }) {
  const { can, me } = useAuth();
  const [view, setView] = useState<LeakView>("action");
  const [state, setState] = useState("");
  const [owner, setOwner] = useState("");
  const [offset, setOffset] = useState(0);
  const path = assetId ? `/assets/${assetId}/leaks` : "/leaks";
  const ownerQuery: Record<string, string | number> =
    owner === "me" && me?.user ? { assignee_user: me.user.id } : owner === "none" ? { assignee: "none" } : {};
  const res = useLoad(
    () =>
      api.get<LeakList>(path, {
        ...LEAK_VIEW_QUERY[view],
        ...(view === "action" && state ? { state } : {}),
        ...ownerQuery,
        limit: LIMIT,
        offset,
      }),
    [path, view, state, owner, offset],
  );
  const summary = useLoad(
    () => api.get<LeakSummary>("/leaks/summary", { severity: "critical,high", ...(assetId ? { asset_id: assetId } : {}) }),
    [assetId, res.data],
  );
  const scans = res.data?.scans;
  const reset = () => setOffset(0);
  return (
    <>
      {assetId && scans && scans.length === 0 && (
        <Notice kind="warn">
          This asset's files have not been scanned for keys, so no leaks here does not mean none exist. Agents and{" "}
          <span className="mono">stackurity scan</span> from this version on scan them.
        </Notice>
      )}
      {scans
        ?.filter((s) => !s.complete)
        .map((s) => (
          <Notice key={s.collector_id} kind="warn">
            The last key scan by {s.collector_id} (<RelativeTime iso={s.scanned_at} />) was incomplete
            {s.reason ? `: ${s.reason}` : ""}. Leaks it could not see are not listed, and none were resolved.
          </Notice>
        ))}
      {summary.data && <LeakSummaryStrip s={summary.data} />}
      <Tabs<LeakView>
        label="Leaked key views"
        value={view}
        onChange={(v) => {
          setView(v);
          reset();
        }}
        tabs={(["action", "kept", "resolved"] as LeakView[]).map((v) => ({ id: v, label: VIEW_LABEL[v] }))}
      />
      <p className="hint">{VIEW_HINT[view]}</p>
      <div className="form-grid">
        {view === "action" && (
          <div className="field">
            <label htmlFor="leak-state">State</label>
            <select
              id="leak-state"
              value={state}
              onChange={(e) => {
                setState(e.target.value);
                reset();
              }}
            >
              {STATE_FILTERS.map((f) => (
                <option key={f.value} value={f.value}>
                  {f.label}
                </option>
              ))}
            </select>
          </div>
        )}
        <div className="field">
          <label htmlFor="leak-owner">Owner</label>
          <select
            id="leak-owner"
            value={owner}
            onChange={(e) => {
              setOwner(e.target.value);
              reset();
            }}
          >
            <option value="">Anyone</option>
            {me?.user && <option value="me">Assigned to me</option>}
            <option value="none">Unassigned</option>
          </select>
        </div>
      </div>
      <ErrorBox error={res.error} title="Could not load leaked keys" />
      {!res.data && !res.error && <Loading />}
      {res.data && res.data.items.length === 0 && (state || owner ? (
        <p className="muted">No leaked keys match these filters.</p>
      ) : (
        <EmptyState {...leaksEmpty(view, assetId ? undefined : res.data.scanned_assets, can("admin"))} />
      ))}
      {res.data && res.data.items.length > 0 && (
        <>
          <LeaksTable leaks={res.data.items} showAsset={!assetId} onChanged={res.reload} />
          <Pager total={res.data.total} limit={LIMIT} offset={offset} onChange={setOffset} />
        </>
      )}
    </>
  );
}
