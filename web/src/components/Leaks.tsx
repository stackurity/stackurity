import { useState } from "react";
import { Link } from "react-router";
import { api, type Leak, type LeakList } from "../api";
import { useAuth } from "../auth";
import { useAction, useLoad } from "../hooks";
import { Badge, SeverityBadge } from "./Badge";
import { promptText } from "./ConfirmDialog";
import { Table, type Column } from "./Table";
import { EmptyState, ErrorBox, Loading, Notice, Pager, RelativeTime, Tabs } from "./ui";

/**
 * Leaked keys: keys, tokens and passwords found written in files. The value
 * is never on the server; a row names the kind of key, the file and the
 * line, and says in one line (why) what its place means and what to do.
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

function LeakActions({ leak, onChanged }: { leak: Leak; onChanged: () => void }) {
  const act = useAction();
  if (leak.status === "open") {
    const dismiss = async () => {
      const note = await promptText({
        title: `Dismiss ${leak.title} in ${leakWhere(leak)}?`,
        message: "It stays dismissed whatever later scans see. Dismiss a test key kept on purpose, or one you have rotated.",
        label: "Note (which, and why)",
        action: "Dismiss",
        allowEmpty: true,
      });
      if (note === null) return;
      if (await act.run(() => api.post(`/leaks/${leak.id}/dismiss`, { note }))) onChanged();
    };
    return (
      <>
        <button type="button" className="btn btn-sm" disabled={act.pending} onClick={dismiss}>
          Dismiss
        </button>
        <ErrorBox error={act.error} />
      </>
    );
  }
  if (leak.resolution !== "dismissed") return null;
  const reopen = async () => {
    if (await act.run(() => api.post(`/leaks/${leak.id}/undismiss`))) onChanged();
  };
  return (
    <>
      <button type="button" className="btn btn-sm" disabled={act.pending} onClick={reopen}>
        Open again
      </button>
      <ErrorBox error={act.error} />
    </>
  );
}

export function LeaksTable({ leaks, showAsset, onChanged }: { leaks: Leak[]; showAsset: boolean; onChanged: () => void }) {
  const { canAct } = useAuth();
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
        </>
      ),
    },
    { key: "why", header: "Why it matters", cell: (l) => <span className="small">{l.why}</span> },
    {
      key: "seen",
      header: "First seen",
      cell: (l) =>
        l.status === "open" ? (
          <RelativeTime iso={l.first_seen} />
        ) : (
          <>
            {l.resolution === "dismissed" ? "Dismissed" : "Gone"} <RelativeTime iso={l.resolved_at} />
            {l.resolution_note && <div className="small">{l.resolution_note}</div>}
          </>
        ),
    },
    ...(canAct("security")
      ? [{ key: "actions", header: "", cell: (l: Leak) => <LeakActions leak={l} onChanged={onChanged} /> }]
      : []),
  ];
  return <Table caption="Leaked keys" columns={cols} rows={leaks} rowKey={(l) => l.id} />;
}

const VIEW_EMPTY: Record<LeakView, string> = {
  action: "No leaked keys need action",
  kept: "No keys found in configuration files",
  resolved: "No resolved leaked keys",
};

export const VIEW_LABEL: Record<LeakView, string> = {
  action: "Needs action",
  kept: "Where keys are kept",
  resolved: "Resolved",
};

const VIEW_HINT: Record<LeakView, string> = {
  action:
    "Critical and high: keys the web server may send, keys committed to a repository or written into code. Rotate each one: revoke it and issue a new one.",
  kept: "Keys kept in configuration files, where they belong. Nothing to do now: this is where each key lives when you rotate it.",
  resolved: "Leaked keys a complete scan no longer sees, and those dismissed.",
};

/** Leaked keys, for the whole organisation or one asset, in three views. */
export function LeaksView({ assetId }: { assetId?: number }) {
  const [view, setView] = useState<LeakView>("action");
  const [offset, setOffset] = useState(0);
  const path = assetId ? `/assets/${assetId}/leaks` : "/leaks";
  const res = useLoad(
    () => api.get<LeakList>(path, { ...LEAK_VIEW_QUERY[view], limit: LIMIT, offset }),
    [path, view, offset],
  );
  const scans = res.data?.scans;
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
      <Tabs<LeakView>
        label="Leaked key views"
        value={view}
        onChange={(v) => {
          setView(v);
          setOffset(0);
        }}
        tabs={(["action", "kept", "resolved"] as LeakView[]).map((v) => ({ id: v, label: VIEW_LABEL[v] }))}
      />
      <p className="hint">{VIEW_HINT[view]}</p>
      <ErrorBox error={res.error} title="Could not load leaked keys" />
      {!res.data && !res.error && <Loading />}
      {res.data && res.data.items.length === 0 && <EmptyState title={VIEW_EMPTY[view]} />}
      {res.data && res.data.items.length > 0 && (
        <>
          <LeaksTable leaks={res.data.items} showAsset={!assetId} onChanged={res.reload} />
          <Pager total={res.data.total} limit={LIMIT} offset={offset} onChange={setOffset} />
        </>
      )}
    </>
  );
}
