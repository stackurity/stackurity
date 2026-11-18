import { useState } from "react";
import { api, type AssistantFinding, type AssistantFindingList } from "../api";
import { useAuth } from "../auth";
import { assistantEmpty } from "../emptyCopy";
import { useAction, useLoad } from "../hooks";
import { SeverityBadge } from "./Badge";
import { promptText } from "./ConfirmDialog";
import { Table, type Column } from "./Table";
import { EmptyState, ErrorBox, Loading, Notice, Pager, RelativeTime, Tabs } from "./ui";

/**
 * Risky settings in AI coding assistants' configuration files: a Claude
 * Code hook, an MCP server or a VS Code task that runs on its own and
 * downloads or runs code. These files are committed with the code, so
 * whoever can change the repository decides what runs on every developer's
 * machine that opens it.
 */

/** The assistants that read each file, as people know them. */
export const ASSISTANT_TOOL: Record<string, string> = {
  "claude-code": "Claude Code",
  cursor: "Cursor",
  vscode: "VS Code",
  "gemini-cli": "Gemini CLI",
  "amazon-q": "Amazon Q",
  "roo-code": "Roo Code",
  mcp: "MCP clients",
};

type View = "open" | "resolved";

const VIEW_HINT: Record<View, string> = {
  open: "Settings that run on their own when a developer opens the project with the assistant. Remove what the team did not add on purpose; dismiss what it did.",
  resolved: "Settings a complete check no longer finds, and those dismissed.",
};

const LIMIT = 50;

function where(f: AssistantFinding): string {
  return f.line > 0 ? `${f.path}:${f.line}` : f.path;
}

function FindingsTable({ items, onChanged }: { items: AssistantFinding[]; onChanged: () => void }) {
  const { canAct } = useAuth();
  const act = useAction();
  const security = canAct("security");

  const dismiss = async (f: AssistantFinding) => {
    const note = await promptText({
      title: `Dismiss ${f.title.toLowerCase()} in ${where(f)}?`,
      message: "It stays dismissed whatever later checks see. Dismiss a setting the team added on purpose, and say who and why.",
      label: "Note (who added it, and why)",
      action: "Dismiss",
      allowEmpty: true,
    });
    if (note === null) return;
    if (await act.run(() => api.post(`/assistant-findings/${f.id}/dismiss`, { note }))) onChanged();
  };
  const reopen = async (f: AssistantFinding) => {
    if (await act.run(() => api.post(`/assistant-findings/${f.id}/undismiss`))) onChanged();
  };

  const cols: Column<AssistantFinding>[] = [
    { key: "severity", header: "Severity", cell: (f) => <SeverityBadge severity={f.severity} /> },
    {
      key: "what",
      header: "Setting",
      cell: (f) => (
        <>
          <strong>{f.title}</strong>
          <div className="small muted">
            {ASSISTANT_TOOL[f.tool] ?? f.tool} · <span className="mono">{f.setting}</span>
          </div>
          <div className="small">{f.why}</div>
        </>
      ),
    },
    {
      key: "where",
      header: "File",
      cell: (f) => (
        <>
          <span className="mono">{where(f)}</span>
          {f.command && (
            <div className="small mono muted" style={{ wordBreak: "break-all" }}>
              {f.command}
            </div>
          )}
        </>
      ),
    },
    {
      key: "seen",
      header: "Seen",
      cell: (f) =>
        f.status === "open" ? (
          <>
            First <RelativeTime iso={f.first_seen} />
          </>
        ) : (
          <>
            {f.resolution === "dismissed" ? "Dismissed" : "Gone"} <RelativeTime iso={f.resolved_at} />
            {f.resolution_note && <div className="small muted">{f.resolution_note}</div>}
          </>
        ),
    },
    ...(security
      ? [
          {
            key: "actions",
            header: "",
            cell: (f: AssistantFinding) =>
              f.status === "open" ? (
                <button type="button" className="btn btn-sm" disabled={act.pending} onClick={() => void dismiss(f)}>
                  Dismiss…
                </button>
              ) : f.resolution === "dismissed" ? (
                <button type="button" className="btn btn-sm" disabled={act.pending} onClick={() => void reopen(f)}>
                  Open again
                </button>
              ) : null,
          },
        ]
      : []),
  ];
  return (
    <>
      <ErrorBox error={act.error} />
      <Table caption="Risky AI assistant settings" columns={cols} rows={items} rowKey={(f) => f.id} />
    </>
  );
}

/** One asset's risky AI assistant settings, open or resolved. */
export function AssistantFindingsView({ assetId }: { assetId: number }) {
  const [view, setView] = useState<View>("open");
  const [offset, setOffset] = useState(0);
  const res = useLoad(
    () => api.get<AssistantFindingList>(`/assets/${assetId}/assistant-findings`, { status: view, limit: LIMIT, offset }),
    [assetId, view, offset],
  );
  const scans = res.data?.scans;
  return (
    <>
      <p className="hint">
        AI coding assistants read configuration committed with the code (<span className="mono">.claude/settings.json</span>,{" "}
        <span className="mono">.mcp.json</span>, <span className="mono">.vscode/tasks.json</span> and others). A hook, MCP server or task
        there runs with the developer's access whenever they open the project, so a change to the repository can install a backdoor on
        their machine.
      </p>
      {scans
        ?.filter((s) => !s.complete)
        .map((s) => (
          <Notice key={s.collector_id} kind="warn">
            The last check by {s.collector_id} (<RelativeTime iso={s.scanned_at} />) was incomplete{s.reason ? `: ${s.reason}` : ""}.
            Settings it could not read are not listed, and none were resolved.
          </Notice>
        ))}
      <Tabs<View>
        label="AI assistant setting views"
        value={view}
        onChange={(v) => {
          setView(v);
          setOffset(0);
        }}
        tabs={[
          { id: "open", label: "Open" },
          { id: "resolved", label: "Resolved" },
        ]}
      />
      <p className="hint">{VIEW_HINT[view]}</p>
      <ErrorBox error={res.error} title="Could not load AI assistant settings" />
      {!res.data && !res.error && <Loading />}
      {res.data && res.data.items.length === 0 && <EmptyState {...assistantEmpty(view, (scans?.length ?? 0) > 0)} />}
      {res.data && res.data.items.length > 0 && (
        <>
          <FindingsTable items={res.data.items} onChanged={res.reload} />
          <Pager total={res.data.total} limit={LIMIT} offset={offset} onChange={setOffset} />
        </>
      )}
    </>
  );
}
