import type { ReactNode } from "react";
import { Link } from "react-router";
import { api, safeHttpUrl, type Finding, type List } from "../api";
import { useLoad } from "../hooks";
import { currentDeadline, otherAssets, pendingApprover, whatIsWrong } from "../findingLayers";
import { FindingStateBadge, PriorityBadge, SosBadge, STATE_EXPLAINED } from "./Badge";
import { FindingFixGroup } from "./FixGroups";
import { Card, KeyValues } from "./ui";
import { Assignee, DueDate, FindingActions } from "./Workflow";

function ExtLink({ href, children }: { href: string | null; children: ReactNode }) {
  const safe = safeHttpUrl(href);
  if (!safe) return <>{children}</>;
  return (
    <a href={safe} target="_blank" rel="noopener noreferrer">
      {children}
      <span className="sr-only"> (opens in a new tab)</span>
    </a>
  );
}

/** The fix for this one issue, in a sentence. */
export function RecommendedAction({ f, hasUpgrade }: { f: Finding; hasUpgrade: boolean }) {
  const ev = f.evidence ?? {};
  if (f.kind === "end_of_life") {
    return (
      <div className="action-box">
        <p>
          <strong>Recommended action:</strong> move {f.component_name} off the {String(ev.cycle ?? "current")} release line to a
          supported release{ev.latest_in_cycle ? ` (the last release of this line was ${String(ev.latest_in_cycle)})` : ""}.
          {ev.link && (
            <>
              {" "}
              <ExtLink href={String(ev.link)}>Support dates on endoflife.date</ExtLink>.
            </>
          )}
        </p>
      </div>
    );
  }
  if (!f.fixed_version) {
    return (
      <div className="action-box action-none">
        <p>
          <strong>No fixed version listed by any source.</strong> Check the advisories under Technical details for workarounds, or consider
          replacing {f.component_name}.
        </p>
      </div>
    );
  }
  return (
    <div className="action-box">
      <p>
        <strong>Fixes this issue:</strong> upgrade <span className="mono">{f.component_name}</span> from{" "}
        <span className="mono">{f.version}</span> to <span className="mono">{f.fixed_version}</span> or later
        {f.direct === false ? " (it is a transitive dependency: upgrade the package that pulls it in, or add an override)" : ""}.
        {hasUpgrade ? (
          <>
            {" "}
            The <Link to="#upgrade">upgrade recommendation</Link> covers every open finding on this package.
          </>
        ) : null}
      </p>
    </div>
  );
}

/** Where the issue is: this asset, and other assets with the same open issue. */
function Where({ f }: { f: Finding }) {
  const open = f.status === "open";
  const res = useLoad(
    () => (open ? api.get<List<Finding>>("/findings", { key: f.key, status: "open", limit: 20 }) : Promise.resolve(null)),
    [f.key, open],
  );
  const others = res.data ? otherAssets(res.data.items ?? [], res.data.total, f) : null;
  return (
    <span>
      <Link to={`/assets/${f.asset_id}?tab=findings`}>{f.asset_name}</Link>
      {f.environment && <span className="muted small"> · {f.environment}</span>}
      {f.location && (
        <>
          <br />
          <span className="mono small break">{f.location}</span>
        </>
      )}
      {others && others.assets.length > 0 && (
        <>
          <br />
          <span className="small">
            Also open on{" "}
            {others.assets.map((a, i) => (
              <span key={a.id}>
                {i > 0 ? ", " : ""}
                <Link to={`/findings/${a.finding}`}>{a.name}</Link>
              </span>
            ))}
            {others.more === null ? " and more" : others.more > 0 ? ` and ${others.more} more` : ""} ·{" "}
            <Link to={`/fixes/issues?q=${encodeURIComponent(f.key)}`}>
              all {res.data!.total} open
            </Link>
          </span>
        </>
      )}
    </span>
  );
}

/**
 * The top of the finding page: what is wrong, where, how urgent, the fix
 * and its actions, and who owns it. Shows only the fields that have data;
 * the detail is in the sections below.
 */
export function FindingSummary({ f, hasUpgrade, onChanged }: { f: Finding; hasUpgrade: boolean; onChanged: () => void }) {
  const open = f.status === "open";
  const deadline = currentDeadline(f);
  const approver = pendingApprover(f);
  const stateHint = open && f.state && !f.until_fix ? STATE_EXPLAINED[f.state] : "";
  const left: [string, ReactNode][] = [
    ["where", <Where f={f} />],
    [
      "priority",
      <span className="badges">
        <PriorityBadge priority={f.priority} score={f.priority_score} />
        {f.sos && <SosBadge rule={f.sos_rule} />}
        {f.priority && (
          <Link to="#priority" className="small">
            why this priority
          </Link>
        )}
      </span>,
    ],
  ];
  const right: [string, ReactNode][] = [
    [
      "state",
      <span>
        <FindingStateBadge f={f} detail />
        {stateHint && <span className="muted small"> {stateHint}.</span>}
      </span>,
    ],
  ];
  if (open || f.assignee_email || f.assignee_team) right.push(["owner", <Assignee email={f.assignee_email} team={f.assignee_team} />]);
  if (deadline) right.push([deadline.label, <DueDate iso={deadline.iso} overdue={deadline.overdue} label={deadline.label} />]);
  if (approver)
    right.push([
      "approval needed from",
      <span>
        {approver}: <Link to="/approvals">open Approvals</Link>
      </span>,
    ]);
  return (
    <Card
      id="summary"
      title="What to do"
      description="What is wrong, where, how urgent it is, the fix and who is on it. The sections below hold the evidence and detail."
    >
      <p className="finding-what break">{whatIsWrong(f)}</p>
      <div className="grid-2 tight finding-glance">
        <KeyValues entries={left} />
        <KeyValues entries={right} />
      </div>
      {open && <RecommendedAction f={f} hasUpgrade={hasUpgrade} />}
      <FindingFixGroup f={f} />
      {open && <FindingActions target={{ type: "finding", id: f.id }} state={f.state} onDone={onChanged} />}
    </Card>
  );
}
