import { useState, type ReactNode } from "react";
import { Link } from "react-router";
import { api, PRIORITIES, type Finding, type FixGroup, type FixGroupDetail, type FixGroupSummary, type List } from "../api";
import { plural } from "../format";
import { Badge, PriorityBadge, SosBadge, type Tone } from "./Badge";
import { FindingsTable } from "./Findings";
import { IconBan, IconClock, IconKernel, IconPackage, IconReleaseUp, IconUpdates } from "./Icons";
import { CodeBlock, ErrorBox, Loading, Pager } from "./ui";
import { useLoad } from "../hooks";

export const FIX_KIND_LABEL: Record<string, string> = {
  security_updates: "Security updates",
  old_kernels: "Old kernels",
  release_upgrade: "Release upgrade",
  end_of_life: "End of life",
  package_upgrade: "Package upgrade",
  no_fix: "No fix yet",
};

export const FIX_KIND_HELP: Record<string, string> = {
  security_updates: "OS packages with a fix in the current release: one package-manager upgrade fixes them all.",
  old_kernels: "Findings on kernels that are installed but not running: removing the old kernels clears them.",
  release_upgrade: "The OS release is end-of-life, or these issues have no free fix in this release: upgrade the release.",
  end_of_life: "Software that no longer receives security fixes: move to a supported version.",
  package_upgrade: "An application dependency with a fixed version: upgrade it in the repository.",
  no_fix: "No source lists a free fixed version yet: mitigate, accept the risk, or watch for a fix.",
};

export function FixKindIcon({ kind }: { kind: string }) {
  switch (kind) {
    case "security_updates":
      return <IconUpdates />;
    case "old_kernels":
      return <IconKernel />;
    case "release_upgrade":
      return <IconReleaseUp />;
    case "end_of_life":
      return <IconClock />;
    case "package_upgrade":
      return <IconPackage />;
    default:
      return <IconBan />;
  }
}

export function EffortPill({ effort }: { effort: string }) {
  const tone: Tone = effort === "low" ? "good" : effort === "medium" ? "warn" : "orange";
  const help: Record<string, string> = {
    low: "Low effort: routine update, little risk of breaking anything",
    medium: "Medium effort: test before rolling out",
    high: "High effort: plan it (release upgrade or major version change)",
  };
  return <Badge status={`effort-${effort}`} tone={tone} label={`${effort} effort`} title={help[effort]} />;
}

/** Plain-language urgency of a fix: urgent now, plan it, or when convenient. */
export function urgencyOf(g: FixGroup): { label: string; tone: Tone; title: string } {
  if (g.top_priority === "P1") return { label: "Urgent", tone: "crit", title: "Highest priority (P1)" };
  // An SOS rule makes a fix urgent whatever its priority; say so, or "Urgent"
  // next to a P2 badge reads as a mistake.
  if (g.sos) return { label: "Urgent: SOS rule", tone: "crit", title: "Matches an SOS rule in the risk policy" };
  if (g.kind === "release_upgrade" || g.kind === "end_of_life" || g.effort === "high")
    return { label: "Plan it", tone: "orange", title: "A bigger change: schedule and test it" };
  return { label: "When you can", tone: "muted", title: `Highest priority ${g.top_priority}` };
}

/** What kind of change a fix is, in words. */
export function changeText(g: FixGroup): string {
  if (g.requires_major || g.change_type === "major") return "major upgrade, may break things";
  if (g.change_type === "minor") return "minor upgrade";
  if (g.change_type === "patch") return "patch release";
  switch (g.kind) {
    case "security_updates":
      return "routine package updates";
    case "old_kernels":
      return "remove unused kernels";
    case "release_upgrade":
      return "operating system upgrade";
    case "end_of_life":
      return "move to a supported version";
    case "no_fix":
      return "no fix published yet";
  }
  return FIX_KIND_LABEL[g.kind] ?? g.kind;
}

export const PRIO_CLASS: Record<string, string> = { P1: "seg-crit", P2: "seg-orange", P3: "seg-warn", P4: "seg-muted" };
export const SEV_CLASS: Record<string, string> = {
  critical: "seg-crit",
  high: "seg-bad",
  medium: "seg-warn",
  low: "seg-muted",
  none: "seg-muted",
  unknown: "seg-info",
};

/** Stacked bar with its numbers written out beside it (never colour alone). */
export function BreakdownBar({ counts, order, classes, label }: { counts: Record<string, number> | null; order: readonly string[]; classes: Record<string, string>; label: string }) {
  const c = counts ?? {};
  const total = order.reduce((a, k) => a + (c[k] ?? 0), 0);
  if (total === 0) return null;
  const parts = order.filter((k) => (c[k] ?? 0) > 0);
  return (
    <div className="breakdown">
      <span className="breakdown-bar" aria-hidden="true">
        {parts.map((k) => (
          <span key={k} className={`seg ${classes[k] ?? "seg-info"}`} style={{ width: `${((c[k] ?? 0) / total) * 100}%` }} />
        ))}
      </span>
      <span className="breakdown-text small">
        <span className="sr-only">{label}: </span>
        {parts.map((k) => `${k} ${(c[k] ?? 0).toLocaleString()}`).join(" · ")}
      </span>
    </div>
  );
}

const COMMAND_RE = /^(sudo\s|apt(-get)?\s|dnf\s|yum\s|apk\s|zypper\s|npm\s|yarn\s|pnpm\s|composer\s|pip\s|do-release-upgrade|pro\s|snap\s|brew\s|winget\s)/;

/** The action as a copyable command when it is one, otherwise as text. */
export function ActionInstruction({ action }: { action: string }) {
  if (!action) return null;
  if (COMMAND_RE.test(action.trim())) return <CodeBlock label="Command" text={action.trim()} />;
  return <p className="fix-action">{action}</p>;
}

export function GroupBadges({ g }: { g: FixGroup }) {
  return (
    <span className="badges">
      <PriorityBadge priority={g.top_priority} />
      {g.sos && <SosBadge />}
      {g.known_exploited > 0 && <Badge status="kev" tone="crit" label={`${g.known_exploited} known exploited`} title="Listed in the CISA Known Exploited Vulnerabilities catalog" />}
      {g.needs && (
        <Badge
          status="needs"
          tone="muted"
          label={`${g.needs === "ubuntu-pro" ? "Ubuntu Pro" : g.needs} optional (paid)`}
          title={`Some of these fixes are also published in ${g.needs === "ubuntu-pro" ? "Ubuntu Pro" : g.needs}, a paid subscription. The action is the free path.`}
        />
      )}
      <EffortPill effort={g.effort} />
    </span>
  );
}

const LIMIT = 25;

/** Findings of one group, paginated, loaded on demand. */
export function GroupFindings({ groupId, hideAsset }: { groupId: string; hideAsset?: boolean }) {
  const [offset, setOffset] = useState(0);
  const res = useLoad(() => api.get<List<Finding>>("/findings", { fix_group: groupId, limit: LIMIT, offset }), [groupId, offset]);
  return (
    <div className="group-findings">
      <ErrorBox error={res.error} title="Could not load the issues in this fix" />
      {!res.data && !res.error && <Loading />}
      {res.data && res.data.items.length === 0 && <p className="muted">No open issues in this fix.</p>}
      {res.data && res.data.items.length > 0 && (
        <>
          <FindingsTable rows={res.data.items} hideAsset={hideAsset} hideGroup />
          <Pager total={res.data.total} limit={LIMIT} offset={offset} onChange={setOffset} />
        </>
      )}
    </div>
  );
}

export function FixGroupCard({ g, hideAsset, defaultOpen }: { g: FixGroup; hideAsset?: boolean; defaultOpen?: boolean }) {
  const [open, setOpen] = useState(Boolean(defaultOpen));
  const titleId = `fg-${g.id.replace(/[^a-zA-Z0-9_-]/g, "_")}`;
  const versions = g.from_version || g.to_version ? `${g.from_version ?? "?"} → ${g.to_version ?? "?"}` : "";
  return (
    <article className={`fix-card fix-${g.kind}${g.sos ? " fix-sos" : ""}`} aria-labelledby={titleId}>
      <div className="fix-icon" title={FIX_KIND_HELP[g.kind]}>
        <FixKindIcon kind={g.kind} />
      </div>
      <div className="fix-body">
        <div className="fix-head">
          <div>
            <span className="fix-kind">{FIX_KIND_LABEL[g.kind] ?? g.kind}</span>
            <h3 id={titleId} className="fix-title">
              <Link to={`/fixes/${encodeURIComponent(g.id)}`}>{g.title}</Link>
            </h3>
            <p className="fix-meta small">
              {[
                !hideAsset && <Link key="a" to={`/assets/${g.asset_id}?tab=action-plan`}>{g.asset_name}</Link>,
                !hideAsset && g.environment && <span key="e">{g.environment}</span>,
                (g.component || versions) && (
                  <span key="c" className="mono">
                    {[g.component, versions].filter(Boolean).join(" ")}
                  </span>
                ),
                g.recommended_version && g.recommended_version !== g.to_version && (
                  <span key="r" title={(g.rationale ?? []).join(" ")}>
                    recommended <span className="mono">{g.recommended_version}</span>
                  </span>
                ),
                g.requires_major && <span key="m">major upgrade</span>,
                g.recommended_yanked && <span key="y">recommended version withdrawn</span>,
                g.package_count > 0 && <span key="p">{plural(g.package_count, "package")}</span>,
              ]
                .filter(Boolean)
                .map((node, i) => (
                  <span key={i}>
                    {i > 0 && " · "}
                    {node}
                  </span>
                ))}
            </p>
          </div>
          <div className="fix-resolves">
            <span className="fix-count">{g.finding_count.toLocaleString()}</span>
            <span className="small">{g.finding_count === 1 ? "issue cleared" : "issues cleared"}</span>
            {g.unique_issues !== undefined && g.unique_issues !== g.finding_count && (
              <span className="small muted">{plural(g.unique_issues, "distinct vulnerability", "distinct vulnerabilities")}</span>
            )}
          </div>
        </div>
        <GroupBadges g={g} />
        <BreakdownBar counts={g.by_priority} order={PRIORITIES} classes={PRIO_CLASS} label="By priority" />
        <ActionInstruction action={g.action} />
        {g.note && <p className="hint">{g.note}</p>}
        {g.packages && g.packages.length > 0 && (
          <details className="fix-packages">
            <summary>
              Affected packages ({g.package_count.toLocaleString()}
              {g.package_count > g.packages.length ? `, first ${g.packages.length} shown` : ""})
            </summary>
            <p className="chips">
              {g.packages.map((p) => (
                <span key={p} className="chip mono">
                  {p}
                </span>
              ))}
            </p>
          </details>
        )}
        <div className="fix-actions">
          <button type="button" className="btn btn-sm" aria-expanded={open} onClick={() => setOpen(!open)}>
            {open ? "Hide the issues" : `Show ${plural(g.finding_count, "issue")}`}
          </button>
          <Link className="btn btn-sm btn-primary" to={`/fixes/${encodeURIComponent(g.id)}`}>
            How to fix
          </Link>
        </div>
        {open && <GroupFindings groupId={g.id} hideAsset={hideAsset} />}
      </div>
    </article>
  );
}

/** "N actions would resolve M issues" strip. */
export function FixSummaryStrip({ s, scope }: { s: FixGroupSummary; scope?: ReactNode }) {
  const kinds = Object.entries(s.by_kind ?? {}).sort((a, b) => b[1].findings - a[1].findings);
  return (
    <section className="fix-summary" aria-label="Action plan summary">
      <div className="fix-summary-main">
        <span className="fix-summary-big">
          {plural(s.groups, "action")} would resolve {plural(s.findings, "finding")}
          {s.unique_issues !== undefined && <> ({plural(s.unique_issues, "unique vulnerability", "unique vulnerabilities")})</>}
        </span>
        {scope && <span className="muted small"> {scope}</span>}
        <div className="small muted">
          A finding is one vulnerability on one installed package; {s.fixable_findings.toLocaleString()} can be fixed today
          with a routine update
          {s.sos > 0 && (
            <>
              {" "}
              · <strong className="text-bad">{plural(s.sos, "SOS action")}</strong>
              {s.sos_findings ? <> covering {plural(s.sos_findings, "SOS finding")}</> : null}
            </>
          )}
        </div>
      </div>
      {kinds.length > 0 && (
        <ul className="fix-summary-kinds">
          {kinds.map(([k, v]) => (
            <li key={k} title={FIX_KIND_HELP[k]}>
              <FixKindIcon kind={k} />
              <span>
                <strong>{FIX_KIND_LABEL[k] ?? k}</strong>
                <span className="small muted">
                  {" "}
                  {plural(v.groups, "action")} · {plural(v.findings, "finding")}
                </span>
              </span>
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}

/** "Part of: <group> (N issues)" for a finding. */
export function FindingFixGroup({ f }: { f: Finding }) {
  // limit=1 keeps the detail call light: we only need the group header.
  const res = useLoad(
    () => (f.fix_group ? api.get<FixGroupDetail>(`/fix-groups/${encodeURIComponent(f.fix_group)}`, { limit: 1 }) : Promise.resolve(null)),
    [f.fix_group],
  );
  if (!f.fix_group) return null;
  const g = res.data?.group;
  return (
    <div className="part-of">
      <span className="fix-icon fix-icon-inline">
        <FixKindIcon kind={g?.kind ?? f.fix_group.split(":")[1] ?? ""} />
      </span>
      <span>
        <strong>Part of:</strong>{" "}
        <Link to={`/fixes/${encodeURIComponent(f.fix_group)}`}>{g ? g.title : "an action in the action plan"}</Link>
        {g && (
          <span className="muted">
            {" "}
            ({plural(g.finding_count, "issue")} cleared together)
          </span>
        )}
      </span>
    </div>
  );
}
