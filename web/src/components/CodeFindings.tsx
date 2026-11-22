import { useState } from "react";
import { Link } from "react-router";
import { api, type CodeCategory, type CodeFinding, type CodeFindingList, type CodeSummary } from "../api";
import { useAuth } from "../auth";
import { codeEmpty, type CodeViewName } from "../emptyCopy";
import { useAction, useLoad } from "../hooks";
import { Badge, SeverityBadge } from "./Badge";
import { promptText } from "./ConfirmDialog";
import { Table, type Column } from "./Table";
import { EmptyState, ErrorBox, Loading, Notice, Pager, RelativeTime, StatTile, Tabs } from "./ui";

/**
 * Code findings: what code-review security scanners (deepsec, or any tool
 * that writes SARIF) found in a repository's source, imported from their
 * reports. Every text field is the scanner's and is shown as plain text,
 * never as HTML or Markdown.
 */

export const CODE_CATEGORY_LABEL: Record<CodeCategory, string> = {
  security: "Security",
  bug: "Bug (not security)",
  other: "Other rule",
};

const VERDICT_LABEL: Record<string, string> = {
  "true-positive": "Confirmed by the scanner",
  "false-positive": "False positive (scanner)",
  fixed: "Fixed (scanner)",
  uncertain: "Uncertain (scanner)",
  "accepted-risk": "Accepted risk (scanner)",
  duplicate: "Duplicate (scanner)",
  suppressed: "Suppressed in the scanner",
};

const VIEW_QUERY: Record<CodeViewName, { status: string; severity?: string; category?: string }> = {
  attention: { status: "open", severity: "critical,high,medium", category: "security" },
  listed: { status: "open" },
  resolved: { status: "resolved" },
};

const VIEW_LABEL: Record<CodeViewName, string> = {
  attention: "Needs a look",
  listed: "All open",
  resolved: "Resolved",
};

const VIEW_HINT: Record<CodeViewName, string> = {
  attention:
    "Critical, high and medium security findings. Only critical and high ones raise an incident, and only while the scanner has not closed them.",
  listed: "Every open finding, including low ones, non-security bugs and rules not tagged as security. Those never alert.",
  resolved:
    "Findings a complete import no longer has, those the scanner itself closed (false positive, fixed, accepted, duplicate, suppressed), and those dismissed here.",
};

const LIMIT = 50;

function where(f: CodeFinding): string {
  if (f.start_line > 0 && f.end_line > f.start_line) return `${f.path}:${f.start_line}-${f.end_line}`;
  return f.start_line > 0 ? `${f.path}:${f.start_line}` : f.path;
}

function sourceLabel(f: CodeFinding): string {
  const tool = f.tool || f.source;
  return f.tool_version ? `${tool} ${f.tool_version}` : tool;
}

/** Plain text with its line breaks; never parsed as HTML or Markdown. */
function Text({ text }: { text: string }) {
  return <p className="small pre-wrap break">{text}</p>;
}

function CodeTable({ items, showAsset, onChanged }: { items: CodeFinding[]; showAsset: boolean; onChanged: () => void }) {
  const { canAct } = useAuth();
  const act = useAction();
  const security = canAct("security");

  const dismiss = async (f: CodeFinding) => {
    const note = await promptText({
      title: `Dismiss ${f.title} in ${where(f)}?`,
      message: "It stays dismissed whatever later imports say. Dismiss a finding that is not a real issue or is accepted, and say why.",
      label: "Note (why)",
      action: "Dismiss",
      allowEmpty: true,
    });
    if (note === null) return;
    if (await act.run(() => api.post(`/code-findings/${f.id}/dismiss`, { note }))) onChanged();
  };
  const reopen = async (f: CodeFinding) => {
    if (await act.run(() => api.post(`/code-findings/${f.id}/undismiss`))) onChanged();
  };

  const cols: Column<CodeFinding>[] = [
    { key: "severity", header: "Severity", cell: (f) => <SeverityBadge severity={f.severity} /> },
    {
      key: "what",
      header: "Finding",
      cell: (f) => (
        <>
          <strong className="break">{f.title}</strong>
          <div className="small muted">
            {CODE_CATEGORY_LABEL[f.category] ?? f.category} · <span className="mono break">{f.rule}</span>
          </div>
          <div className="mono small break">{where(f)}</div>
        </>
      ),
    },
    ...(showAsset
      ? [
          {
            key: "asset",
            header: "Asset",
            cell: (f: CodeFinding) => <Link to={`/assets/${f.asset_id}?tab=code`}>{f.asset_name}</Link>,
          },
        ]
      : []),
    {
      key: "detail",
      header: "What and how to fix",
      cell: (f) => (
        <details>
          <summary className="small">Details</summary>
          {f.description && <Text text={f.description} />}
          {f.recommendation && (
            <>
              <strong className="small">Suggested fix</strong>
              <Text text={f.recommendation} />
            </>
          )}
          {f.verdict_note && (
            <>
              <strong className="small">Scanner's verdict</strong>
              <Text text={f.verdict_note} />
            </>
          )}
        </details>
      ),
    },
    {
      key: "source",
      header: "Reported by",
      cell: (f) => (
        <div className="small">
          <div>{sourceLabel(f)}</div>
          {f.model && <div className="muted">Model: {f.model}</div>}
          {f.confidence && <div className="muted">Confidence: {f.confidence}</div>}
          {f.verdict && (
            <Badge
              status={f.verdict}
              tone={f.verdict === "true-positive" ? "warn" : f.verdict === "uncertain" ? "info" : "muted"}
              label={VERDICT_LABEL[f.verdict] ?? f.verdict}
            />
          )}
        </div>
      ),
    },
    {
      key: "seen",
      header: "Found",
      cell: (f) =>
        f.status === "open" ? (
          <RelativeTime iso={f.first_seen} />
        ) : (
          <div className="small muted">
            {f.resolution === "dismissed" ? "Dismissed" : f.resolution === "verdict" ? "Closed by the scanner" : "Gone"}{" "}
            <RelativeTime iso={f.resolved_at} />
            {f.resolution_note && <div>{f.resolution_note}</div>}
          </div>
        ),
    },
    ...(security
      ? [
          {
            key: "actions",
            header: "",
            cell: (f: CodeFinding) =>
              f.status === "open" ? (
                <button type="button" className="btn btn-sm" onClick={() => void dismiss(f)}>
                  Dismiss…
                </button>
              ) : f.resolution === "dismissed" ? (
                <button type="button" className="btn btn-sm" onClick={() => void reopen(f)}>
                  Undo dismissal
                </button>
              ) : null,
          },
        ]
      : []),
  ];
  return (
    <>
      <ErrorBox error={act.error} title="Could not change the finding's state" />
      <Table caption="Code findings" columns={cols} rows={items} rowKey={(f) => f.id} />
    </>
  );
}

function SummaryStrip({ s }: { s: CodeSummary }) {
  const urgent = (s.by_severity.critical ?? 0) + (s.by_severity.high ?? 0);
  const medium = s.by_severity.medium ?? 0;
  return (
    <div className="tiles" role="group" aria-label="Open code findings">
      <StatTile
        label="Critical and high"
        value={urgent.toLocaleString()}
        tone={urgent > 0 ? "bad" : "good"}
        sub="Security findings open; alert"
      />
      <StatTile label="Medium" value={medium.toLocaleString()} tone={medium > 0 ? "warn" : undefined} sub="Needs a look; never alerts" />
      <StatTile
        label="Bugs and other"
        value={((s.by_category.bug ?? 0) + (s.by_category.other ?? 0)).toLocaleString()}
        sub="Not security issues; listed only"
      />
      <StatTile label="Assets with a report" value={s.imported_assets.toLocaleString()} sub="Repositories imported" />
    </div>
  );
}

/** Code findings for the whole organisation or one asset, in three views. */
export function CodeFindingsView({ assetId }: { assetId?: number }) {
  const [view, setView] = useState<CodeViewName>("attention");
  const [offset, setOffset] = useState(0);
  const path = assetId ? `/assets/${assetId}/code-findings` : "/code-findings";
  const res = useLoad(
    () => api.get<CodeFindingList>(path, { ...VIEW_QUERY[view], limit: LIMIT, offset }),
    [path, view, offset],
  );
  const summary = useLoad(
    () => api.get<CodeSummary>("/code-findings/summary", assetId ? { asset_id: assetId } : {}),
    [assetId, res.data],
  );
  const imports = res.data?.imports;
  return (
    <>
      {assetId && imports && imports.length === 0 && (
        <Notice kind="info">
          No code scanner's report has been imported for this asset, so an empty list does not mean its code has no issues. Import one
          with <span className="mono">stackurity import code-findings</span> (<Link to="/help/code-findings">how</Link>).
        </Notice>
      )}
      {imports && imports.length > 0 && (
        <p className="hint">
          Last imports:{" "}
          {imports.map((i, n) => (
            <span key={i.source}>
              {n > 0 && "; "}
              {i.tool || i.source}
              {i.tool_version && ` ${i.tool_version}`}
              {i.model && ` (model ${i.model})`}, {i.found.toLocaleString()} findings, <RelativeTime iso={i.imported_at} />
              {!i.complete && " (filtered report: nothing it left out was resolved)"}
            </span>
          ))}
        </p>
      )}
      {summary.data && <SummaryStrip s={summary.data} />}
      <Tabs<CodeViewName>
        label="Code finding views"
        value={view}
        onChange={(v) => {
          setView(v);
          setOffset(0);
        }}
        tabs={(["attention", "listed", "resolved"] as CodeViewName[]).map((v) => ({ id: v, label: VIEW_LABEL[v] }))}
      />
      <p className="hint">{VIEW_HINT[view]}</p>
      <ErrorBox error={res.error} title="Could not load code findings" />
      {!res.data && !res.error && <Loading />}
      {res.data && res.data.items.length === 0 && (
        <EmptyState {...codeEmpty(view, assetId ? (imports?.length ?? 0) : summary.data?.imported_assets)} />
      )}
      {res.data && res.data.items.length > 0 && (
        <>
          <CodeTable items={res.data.items} showAsset={!assetId} onChanged={res.reload} />
          <Pager total={res.data.total} limit={LIMIT} offset={offset} onChange={setOffset} />
        </>
      )}
    </>
  );
}
