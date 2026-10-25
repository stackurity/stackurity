import type { MouseEvent, ReactNode } from "react";
import { Link, useNavigate } from "react-router";
import { PRIORITIES, SEVERITIES, type Finding, type FindingSummary } from "../api";
import { plural } from "../format";
import { Badge, KevBadge, PriorityBadge, SeverityBadge, SosBadge, StateBadge, VerificationBadge } from "./Badge";
import { Assignee, DueDate } from "./Workflow";
import { Table, type Column } from "./Table";
import { RelativeTime, StatTile } from "./ui";

export function FixCell({ f }: { f: Finding }) {
  if (f.fixed_version)
    return (
      <span className="fix" title={`Upgrade to ${f.fixed_version} or later`}>
        → {f.fixed_version}
      </span>
    );
  if (f.kind === "end_of_life") return <span className="nofix">Move to a supported release</span>;
  return <span className="nofix">No fix listed</span>;
}

export function kindLabel(kind: string): string {
  return kind === "end_of_life" ? "End of life" : kind === "vulnerability" ? "Vulnerability" : kind;
}

/** Shared findings table; asset/component columns can be hidden in context. */
export function FindingsTable({
  rows,
  hideAsset,
  hideComponent,
  selected,
  onSelect,
  hideGroup,
}: {
  rows: Finding[];
  hideAsset?: boolean;
  hideComponent?: boolean;
  /** Hide the fix-group column (e.g. when already inside a group). */
  hideGroup?: boolean;
  /** When provided, rows get checkboxes for bulk actions. */
  selected?: Set<number>;
  onSelect?: (next: Set<number>) => void;
}) {
  const navigate = useNavigate();
  const stop = (e: MouseEvent) => e.stopPropagation();
  const cols: Column<Finding>[] = [];
  if (selected && onSelect) {
    const allOn = rows.length > 0 && rows.every((f) => selected.has(f.id));
    cols.push({
      key: "sel",
      className: "td-check",
      header: (
        <input
          type="checkbox"
          aria-label={allOn ? "Clear selection on this page" : "Select all findings on this page"}
          checked={allOn}
          onChange={() => {
            const n = new Set(selected);
            for (const f of rows) {
              if (allOn) n.delete(f.id);
              else n.add(f.id);
            }
            onSelect(n);
          }}
        />
      ),
      cell: (f) => (
        <input
          type="checkbox"
          aria-label={`Select ${f.key} on ${f.asset_name}`}
          checked={selected.has(f.id)}
          onClick={stop}
          onChange={() => {
            const n = new Set(selected);
            if (n.has(f.id)) n.delete(f.id);
            else n.add(f.id);
            onSelect(n);
          }}
        />
      ),
    });
  }
  cols.push(
    {
      key: "prio",
      header: "Priority",
      cell: (f) => (
        <span className="badges">
          <PriorityBadge priority={f.priority} />
          {f.sos && <SosBadge rule={f.sos_rule} />}
        </span>
      ),
    },
    {
      key: "sev",
      header: "Severity",
      cell: (f) => (
        <span className="badges">
          <SeverityBadge severity={f.severity} score={f.score} />
          {f.known_exploited && <KevBadge />}
        </span>
      ),
    },
    {
      key: "finding",
      header: "Finding",
      cell: (f) => (
        <>
          <Link to={`/findings/${f.id}`} className="mono" onClick={stop}>
            {f.key}
          </Link>
          {f.kind === "end_of_life" && (
            <>
              {" "}
              <Badge status="eol" tone="muted" label="end of life" />
            </>
          )}
          {f.verification !== "confirmed" && (
            <>
              {" "}
              <VerificationBadge verification={f.verification} />
            </>
          )}
          <EvidencePills f={f} />
          <span className="finding-title small">{f.title !== f.key ? f.title : ""}</span>
        </>
      ),
    },
  );
  if (!hideComponent)
    cols.push({
      key: "component",
      header: "Component",
      cell: (f) => (
        <>
          <Link to={`/components/${f.component_id}`} onClick={stop}>
            {f.component_name}
          </Link>
          <div className="small">
            <span className="mono break">{f.version || "?"}</span> <span className="muted">· {f.component_type}</span>
          </div>
        </>
      ),
    });
  else
    cols.push({ key: "version", header: "Version", cell: (f) => <span className="mono">{f.version || "?"}</span> });
  if (!hideAsset)
    cols.push(
      {
        key: "asset",
        header: "Asset",
        cell: (f) => (
          <>
            <Link to={`/assets/${f.asset_id}?tab=findings`} onClick={stop}>
              {f.asset_name}
            </Link>
            <div className="muted small">{f.environment || "no environment"}</div>
          </>
        ),
      },
    );
  cols.push(
    { key: "fix", header: "Fix", cell: (f) => <FixCell f={f} /> },
    ...(hideGroup
      ? []
      : [
          {
            key: "group",
            header: "Fix group",
            cell: (f: Finding) =>
              f.fix_group ? (
                <Link to={`/action-plan/${encodeURIComponent(f.fix_group)}`} onClick={stop} className="small">
                  {fixGroupKindLabel(f.fix_group)}
                </Link>
              ) : (
                <span className="muted">—</span>
              ),
          },
        ]),
    {
      key: "state",
      header: "State",
      cell: (f) => (f.status === "open" ? <StateBadge state={f.state} /> : <Badge status={f.status} />),
    },
    { key: "assignee", header: "Assignee", cell: (f) => <Assignee email={f.assignee_email} team={f.assignee_team} /> },
    {
      key: "due",
      header: "Fix due",
      cell: (f) =>
        f.status === "open" && f.state !== "suppressed" && f.state !== "risk_accepted" ? (
          <DueDate iso={f.fix_due} overdue={f.overdue} label="Fix due" />
        ) : (
          <span className="muted">—</span>
        ),
    },
    { key: "first", header: "First seen", cell: (f) => <RelativeTime iso={f.first_seen} /> },
  );
  return (
    <Table
      caption="Findings"
      columns={cols}
      rows={rows}
      rowKey={(f) => f.id}
      onRowClick={(f) => navigate(`/findings/${f.id}`)}
      rowClassName={(f) => (f.sos || f.overdue || f.known_exploited ? "row-stale" : undefined)}
    />
  );
}

/** Severity, KEV, fix and asset tiles from GET /findings/summary. */
export function FindingTiles({ s, link }: { s: FindingSummary; link?: (q: string) => string }) {
  const sev = s.by_severity ?? {};
  const to = (q: string) => (link ? link(q) : `/findings?${q}`);
  const tone: Record<string, "crit" | "bad" | "warn" | "muted" | undefined> = { critical: "crit", high: "bad", medium: "warn" };
  return (
    <div className="tiles tiles-tight">
      {SEVERITIES.map((k) => {
        const n = sev[k] ?? 0;
        return (
          <StatTile
            key={k}
            label={k}
            value={n.toLocaleString()}
            tone={n > 0 ? tone[k] : undefined}
            sub={n > 0 ? <Link to={to(`severity=${k}`)}>View</Link> : "none open"}
          />
        );
      })}
      <StatTile
        label="Known exploited"
        value={s.known_exploited.toLocaleString()}
        tone={s.known_exploited > 0 ? "crit" : undefined}
        sub={s.known_exploited > 0 ? <Link to={to("known_exploited=true")}>Fix these first</Link> : "none open"}
      />
      <StatTile label="Fix available" value={s.fix_available.toLocaleString()} sub="have a fixed version" />
      <StatTile label="Affected assets" value={s.affected_assets.toLocaleString()} sub="with open findings" />
    </div>
  );
}

/** Warnings that make clear the absence of findings is not proof of safety. */
export function IntelBanners({ s }: { s: FindingSummary }) {
  const problems: ReactNode[] = [];
  if (s.stale_feeds > 0)
    problems.push(
      <li key="feeds">
        <Link to="/intelligence">{plural(s.stale_feeds, "intelligence feed")}</Link> {s.stale_feeds === 1 ? "is" : "are"} stale or
        never synced. Vulnerabilities published since the last sync are not reflected.
      </li>,
    );
  if (s.evaluation_gaps > 0)
    problems.push(
      <li key="gaps">
        <Link to="/intelligence#gaps">{plural(s.evaluation_gaps, "component")}</Link> could not be checked (no feed for the
        ecosystem, feed never synced, or unparseable version). They may be vulnerable.
      </li>,
    );
  if (problems.length === 0) return null;
  return (
    <div className="alert alert-warn" role="alert">
      <strong>Findings are incomplete.</strong> No findings does not mean secure:
      <ul className="banner-list">{problems}</ul>
    </div>
  );
}

/** Active-finding priority tiles (P1..P4), SOS, overdue, unassigned and open incidents. */
export function PriorityTiles({ s, openIncidents }: { s: FindingSummary; openIncidents?: number }) {
  const bp = s.by_priority ?? {};
  const tone: Record<string, "crit" | "orange" | "warn" | undefined> = { P1: "crit", P2: "orange", P3: "warn" };
  const sos = s.sos ?? 0;
  const overdue = s.overdue ?? 0;
  const unassigned = s.unassigned ?? 0;
  return (
    <div className="tiles tiles-tight">
      <StatTile
        label="SOS"
        value={sos.toLocaleString()}
        tone={sos > 0 ? "crit" : undefined}
        sub={sos > 0 ? <Link to="/findings?sos=true&state=active">Act now</Link> : "none active"}
      />
      {PRIORITIES.map((p) => {
        const n = bp[p] ?? 0;
        return (
          <StatTile
            key={p}
            label={`${p} active`}
            value={n.toLocaleString()}
            tone={n > 0 ? tone[p] : undefined}
            sub={n > 0 ? <Link to={`/findings?priority=${p}&state=active`}>View</Link> : "none"}
          />
        );
      })}
      <StatTile
        label="Overdue"
        value={overdue.toLocaleString()}
        tone={overdue > 0 ? "bad" : undefined}
        sub={overdue > 0 ? <Link to="/findings?overdue=true&state=active">Past fix deadline</Link> : "none past deadline"}
      />
      <StatTile
        label="Unassigned"
        value={unassigned.toLocaleString()}
        tone={unassigned > 0 ? "warn" : undefined}
        sub={unassigned > 0 ? <Link to="/findings?assignee=none&state=active">Active, no owner</Link> : "all active ones assigned"}
      />
      {openIncidents !== undefined && (
        <StatTile label="Open incidents" value={openIncidents.toLocaleString()} sub={<Link to="/incidents">View incidents</Link>} />
      )}
    </div>
  );
}

const GROUP_KIND_LABEL: Record<string, string> = {
  security_updates: "Security updates",
  old_kernels: "Old kernels",
  release_upgrade: "Release upgrade",
  end_of_life: "End of life",
  package_upgrade: "Package upgrade",
  no_fix: "No fix yet",
};

/** Fix-group ids look like "<asset>:<kind>[:<detail>]"; label by kind. */
export function fixGroupKindLabel(id: string): string {
  const kind = id.split(":")[1] ?? id;
  return GROUP_KIND_LABEL[kind] ?? kind.replace(/_/g, " ");
}

/** Hints from evidence that change what the fix is. */
export function EvidencePills({ f }: { f: Finding }) {
  const ev = f.evidence ?? {};
  return (
    <>
      {ev.not_running_kernel === true && (
        <>
          {" "}
          <Badge status="kernel" tone="muted" label="kernel not running" title="This kernel is installed but not the one running; removing old kernels clears it" />
        </>
      )}
      {ev.requires_ubuntu_pro === true ? (
        <>
          {" "}
          <Badge status="pro" tone="info" label="fix needs Ubuntu Pro" title="The fixed package is published to Ubuntu Pro (ESM) subscribers" />
        </>
      ) : typeof ev.requires_subscription === "string" && ev.requires_subscription !== "" ? (
        <>
          {" "}
          <Badge status="pro" tone="info" label={`fix needs ${ev.requires_subscription}`} title={`The fixed package is published only to ${ev.requires_subscription} subscribers`} />
        </>
      ) : null}
    </>
  );
}
