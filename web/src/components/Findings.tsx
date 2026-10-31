import type { MouseEvent, ReactNode } from "react";
import { Link, useNavigate } from "react-router";
import { PRIORITIES, SEVERITIES, type Finding, type FindingSummary } from "../api";
import { epssTitle, percent, plural } from "../format";
import { Badge, KevBadge, PriorityBadge, SeverityBadge, SosBadge, FindingStateBadge } from "./Badge";
import { EvidenceStateBadge } from "./Provenance";
import { reportDate } from "../reporting";
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
/** Findings as cards, for phones (shown instead of the table under 720 px). */
export function FindingCards({ rows, hideAsset }: { rows: Finding[]; hideAsset?: boolean }) {
  return (
    <ul className="finding-cards only-narrow" aria-label="Issues">
      {rows.map((f) => (
        <li key={f.id} className={`finding-card${f.sos || f.overdue || f.known_exploited ? " finding-card-hot" : ""}`}>
          <div className="finding-card-top">
            <span className="badges">
              <PriorityBadge priority={f.priority} />
              {f.sos && <SosBadge rule={f.sos_rule} />}
              <SeverityBadge severity={f.severity} score={f.score} />
              {f.known_exploited && <KevBadge />}
              {f.epss != null && <EpssBadge f={f} />}
              <VexBadge f={f} />
            </span>
            <FindingStateBadge f={f} detail />
          </div>
          <Link to={`/findings/${f.id}`} className="finding-card-title">
            <span className="mono">{f.key}</span>
            {f.title && f.title !== f.key && <span className="finding-card-sub"> {f.title}</span>}
          </Link>
          <p className="small finding-card-where">
            {!hideAsset && (
              <>
                <Link to={`/assets/${f.asset_id}`} className="asset-cell">
                  {f.asset_name}
                </Link>
                {" · "}
              </>
            )}
            <span className="break">
              {f.component_name} <span className="mono">{f.version || "?"}</span>
            </span>
          </p>
          <p className="small finding-card-fix">
            <FixCell f={f} />
            {f.fix_group && (
              <>
                {" · "}
                <Link to={`/fixes/${encodeURIComponent(f.fix_group)}`}>{fixGroupKindLabel(f.fix_group)}</Link>
              </>
            )}
          </p>
        </li>
      ))}
    </ul>
  );
}

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
          {(f.verification !== "confirmed" || f.evidence?.feed_stale === true) && (
            <>
              {" "}
              <EvidenceStateBadge f={f} />
            </>
          )}
          <EvidencePills f={f} />
          {f.as_of && (
            <>
              {" "}
              <Badge status="as-of" tone="muted" label={`as of ${reportDate(f.as_of)}`} title="The asset was scanned once; this was true as of then" />
            </>
          )}
          {f.vex && (
            <>
              {" "}
              <VexBadge f={f} />
            </>
          )}
          <span className="finding-title small">{f.title !== f.key ? f.title : ""}</span>
        </>
      ),
    },
  );
  if (!hideAsset)
    cols.push(
      {
        key: "asset",
        header: "Asset",
        cell: (f) => (
          <>
            <Link to={`/assets/${f.asset_id}?tab=findings`} onClick={stop} className="asset-cell">
              {f.asset_name}
            </Link>
            <div className="muted small">{f.environment || "no environment"}</div>
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
  cols.push(
    {
      key: "epss",
      header: <abbr title="FIRST EPSS: the chance the CVE is exploited in the next 30 days">EPSS</abbr>,
      numeric: true,
      cell: (f) => <EpssCell f={f} />,
    },
    { key: "fix", header: "Fix", cell: (f) => <FixCell f={f} /> },
    ...(hideGroup
      ? []
      : [
          {
            key: "group",
            header: "Part of fix",
            cell: (f: Finding) =>
              f.fix_group ? (
                <Link to={`/fixes/${encodeURIComponent(f.fix_group)}`} onClick={stop} className="small">
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
      cell: (f) => <FindingStateBadge f={f} />,
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
  const to = (q: string) => (link ? link(q) : `/fixes/issues?${q}`);
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
        <Link to="/intelligence#gaps">{plural(s.evaluation_gaps, "component")}</Link> could not be checked (unsupported
        ecosystem or distribution, feed not synced, release without advisories, or unreadable version). They may be vulnerable.
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
        sub={sos > 0 ? <Link to="/fixes/issues?sos=true&state=active">Act now</Link> : "none active"}
      />
      {PRIORITIES.map((p) => {
        const n = bp[p] ?? 0;
        return (
          <StatTile
            key={p}
            label={`${p} active`}
            value={n.toLocaleString()}
            tone={n > 0 ? tone[p] : undefined}
            sub={n > 0 ? <Link to={`/fixes/issues?priority=${p}&state=active`}>View</Link> : "none"}
          />
        );
      })}
      <StatTile
        label="Overdue"
        value={overdue.toLocaleString()}
        tone={overdue > 0 ? "bad" : undefined}
        sub={overdue > 0 ? <Link to="/fixes/issues?overdue=true&state=active">Past fix deadline</Link> : "none past deadline"}
      />
      <StatTile
        label="Unassigned"
        value={unassigned.toLocaleString()}
        tone={unassigned > 0 ? "warn" : undefined}
        sub={unassigned > 0 ? <Link to="/fixes/issues?assignee=none&state=active">Active, no owner</Link> : "all active ones assigned"}
      />
      {openIncidents !== undefined && (
        <StatTile label="Open incidents" value={openIncidents.toLocaleString()} sub={<Link to="/incidents">View incidents</Link>} />
      )}
    </div>
  );
}

const GROUP_KIND_LABEL: Record<string, string> = {
  security_updates: "Security updates",
  windows_update: "Windows update",
  old_kernels: "Old kernels",
  release_upgrade: "Release upgrade",
  end_of_life: "End of life",
  package_upgrade: "Package upgrade",
  program_update: "Program update",
  no_fix: "No fix yet",
};

/** Fix-group ids look like "<asset>:<kind>[:<detail>]"; label by kind. */
export function fixGroupKindLabel(id: string): string {
  const kind = id.split(":")[1] ?? id;
  return GROUP_KIND_LABEL[kind] ?? kind.replace(/_/g, " ");
}

/** Hints from evidence that change what the fix is. */
/** The EPSS column: the probability, or a dash for findings without a score. */
export function EpssCell({ f }: { f: Finding }) {
  if (f.epss == null) return <span className="muted" title={f.kind === "vulnerability" ? "No EPSS score for this finding's CVEs" : undefined}>—</span>;
  return (
    <span className="mono" title={epssTitle(f.epss, f.epss_percentile, f.epss_date, f.epss_cve !== f.key ? f.epss_cve : null)}>
      {percent(f.epss)}
    </span>
  );
}

const VEX_STATUS_LABEL: Record<string, string> = {
  not_affected: "not affected",
  affected: "affected",
  fixed: "fixed",
  under_investigation: "under investigation",
};

/** One line saying what a VEX statement says and where it stands. */
export function vexSummary(v: NonNullable<Finding["vex"]>): string {
  let s = `VEX from ${v.source}: ${VEX_STATUS_LABEL[v.status] ?? v.status}`;
  if (v.justification) s += ` (${v.justification.replace(/_/g, " ")})`;
  if (v.status === "not_affected") {
    s += v.applied ? "; approved, ignores this issue" : v.request_status === "pending" ? "; waiting for approval" : "";
  }
  const text = v.impact_statement || v.action_statement || v.status_notes;
  return text ? `${s}. ${text}` : s;
}

/** A VEX badge: the statement's status, with the justification and source on hover. */
export function VexBadge({ f }: { f: Finding }) {
  const v = f.vex;
  if (!v) return null;
  const tone = v.status === "affected" ? "warn" : v.status === "not_affected" ? (v.applied ? "good" : "info") : "muted";
  const pending = v.status === "not_affected" && !v.applied && v.request_status === "pending";
  return <Badge status="vex" tone={tone} label={`VEX: ${VEX_STATUS_LABEL[v.status] ?? v.status}${pending ? " (pending)" : ""}`} title={vexSummary(v)} />;
}

/** EPSS on a phone card. */
export function EpssBadge({ f }: { f: Finding }) {
  if (f.epss == null) return null;
  return <Badge status="epss" tone="muted" label={`EPSS ${percent(f.epss)}`} title={epssTitle(f.epss, f.epss_percentile, f.epss_date, f.epss_cve !== f.key ? f.epss_cve : null)} />;
}

export function EvidencePills({ f }: { f: Finding }) {
  const ev = f.evidence ?? {};
  return (
    <>
      {f.second_check === "disagreed" && (
        <>
          {" "}
          <Badge
            status="second-check-disagreed"
            tone="warn"
            label="needs validation: second check disagreed"
            title={`Needs validation: the second check disagreed (${f.second_check_reason ?? ""}). Priority and alerts are unchanged; a person should review it.`}
          />
        </>
      )}
      {ev.not_running_kernel === true && (
        <>
          {" "}
          <Badge status="kernel" tone="muted" label="kernel not running" title="This kernel is installed but not the one running; removing old kernels clears it" />
        </>
      )}
      {typeof ev.kernel_release === "string" && Array.isArray(ev.kernel_packages) && ev.kernel_packages.length > 1 && (
        <>
          {" "}
          <Badge
            status="kernel"
            tone="muted"
            label={`kernel ${ev.kernel_release}`}
            title={`Reported once for this kernel version, covering ${ev.kernel_packages.join(", ")}`}
          />
        </>
      )}
      {ev.requires_ubuntu_pro === true || (typeof ev.requires_subscription === "string" && ev.requires_subscription !== "") ? (
        <>
          {" "}
          <Badge
            status="pro"
            tone="info"
            label="no free fix"
            title={`Fixed in ${typeof ev.requires_subscription === "string" && ev.requires_subscription ? ev.requires_subscription : "Ubuntu Pro"} (paid subscription); without it, upgrade to a supported release or install the update when the distribution publishes a free fix`}
          />
        </>
      ) : null}
    </>
  );
}
