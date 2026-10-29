import type { ReactNode } from "react";
import { Link } from "react-router";
import { api, type DirectoryUser, type EpssDetail, type Finding, type FindingEvent, type List, type Team } from "../api";
import { useAuth } from "../auth";
import { useLoad } from "../hooks";
import { absTime } from "../format";
import { EscalationBadge, PriorityBadge, SosBadge, FindingStateBadge, IGNORE_REASON_LABEL, STATE_EXPLAINED } from "./Badge";
import { Card, ErrorBox, KeyValues, Loading, Notice, RelativeTime } from "./ui";
import { Assignee, DueDate, FindingActions } from "./Workflow";
import { FindingRemediation } from "./RemediationSummary";
import { closedReason, countsAsRemediation } from "../resolution";

function FactorTable({ f }: { f: Finding }) {
  const factors = f.priority_factors ?? [];
  if (factors.length === 0) return <p className="muted">No priority factors recorded.</p>;
  const sum = factors.reduce((a, x) => a + x.points, 0);
  const score = f.priority_score ?? sum;
  // When the total differs from the sum, a multiplier (unverified / stale) was applied.
  const scaled = Math.abs(sum - score) > 0.05;
  return (
    <div className="table-wrap">
      <table className="table">
        <caption className="sr-only">Why this priority</caption>
        <thead>
          <tr>
            <th scope="col">Factor</th>
            <th scope="col">Detail</th>
            <th scope="col" className="num">
              Points
            </th>
          </tr>
        </thead>
        <tbody>
          {factors.map((x, i) => (
            <tr key={i}>
              <td>{x.name}</td>
              <td className="muted">{x.detail}</td>
              <td className="num">
                {x.points > 0 ? "+" : ""}
                {x.points.toFixed(1)}
              </td>
            </tr>
          ))}
          {scaled && (
            <tr>
              <td colSpan={2} className="muted">
                Scaled for unverified or stale evidence
              </td>
              <td className="num">× {(score / sum).toFixed(2)}</td>
            </tr>
          )}
          <tr className="factor-total">
            <td colSpan={2}>Total score → {f.priority || "no priority"}</td>
            <td className="num">{score.toFixed(1)}</td>
          </tr>
        </tbody>
      </table>
    </div>
  );
}

export function WorkflowPanel({ f, onChanged, epss }: { f: Finding; onChanged: () => void; epss?: EpssDetail | null }) {
  const active = f.status === "open" && (f.state === "new" || f.state === "acknowledged" || f.state === "in_progress");
  const closedByDecision = f.state === "suppressed" || f.state === "risk_accepted";
  return (
    <Card
      title={
        <span className="badges">
          Workflow <FindingStateBadge f={f} detail />
          <PriorityBadge priority={f.priority} score={f.priority_score} />
          {f.sos && <SosBadge rule={f.sos_rule} />}
          <EscalationBadge level={f.escalation_level} />
        </span>
      }
    >
      {f.status !== "open" && <p className="hint">This finding is resolved; workflow actions no longer apply.</p>}
      {f.status === "open" && f.state && STATE_EXPLAINED[f.state] && !f.until_fix && <p className="hint">{STATE_EXPLAINED[f.state]}.</p>}
      {f.status === "open" && f.until_fix && closedByDecision && (
        <p className="hint">It comes back on its own when a free fixed version exists, or on the date below at the latest.</p>
      )}
      {f.status === "open" && f.regressed_at && (
        <Notice kind="warn">
          <strong>Came back after a fix</strong> <RelativeTime iso={f.regressed_at} />. It was fixed on this asset and a later check found it
          again. See the history below.
        </Notice>
      )}
      {f.verification === "rejected" && f.ignore_reason === "false_positive" && (
        <p className="hint">Marked a false positive: verification is rejected until someone reopens it.</p>
      )}
      {f.sos && (
        <div className="alert sos-banner" role="alert">
          <strong>SOS{f.sos_rule ? ` — ${f.sos_rule}` : ""}:</strong> this finding matches{" "}
          {f.sos_rule ? <>the rule “{f.sos_rule}”</> : "an SOS rule"} in the <Link to="/settings/risk-policy">risk policy</Link> and needs
          urgent attention.
        </div>
      )}
      <div className="grid-2 tight">
        <div>
          <KeyValues
            entries={[
              ["assignee", <Assignee email={f.assignee_email} team={f.assignee_team} />],
              [
                "acknowledge by",
                active && f.state === "new" ? (
                  <DueDate iso={f.ack_due} label="Acknowledge by" />
                ) : f.acknowledged_at ? (
                  <span>
                    acknowledged <RelativeTime iso={f.acknowledged_at} />
                  </span>
                ) : (
                  <span className="muted">—</span>
                ),
              ],
              ["fix by", active ? <DueDate iso={f.fix_due} overdue={f.overdue} label="Fix by" /> : <span className="muted">—</span>],
              ...(closedByDecision
                ? ([
                    ...(f.ignore_reason ? ([["why", IGNORE_REASON_LABEL[f.ignore_reason] ?? f.ignore_reason]] as [string, ReactNode][]) : []),
                    ["reason", <span className="break">{f.state_reason || <span className="muted">none given</span>}</span>],
                    ["mitigation", <span className="break">{f.mitigation || <span className="muted">none recorded</span>}</span>],
                    [
                      "until",
                      f.suppressed_until ? (
                        <span title={absTime(f.suppressed_until)}>
                          {f.until_fix ? "a fix ships, at the latest " : ""}
                          {absTime(f.suppressed_until)}
                        </span>
                      ) : f.until_fix ? (
                        "a fix ships"
                      ) : (
                        "no expiry"
                      ),
                    ],
                  ] as [string, ReactNode][])
                : []),
              ...(f.incident_id
                ? ([["incident", <Link to={`/incidents/${f.incident_id}`}>Incident #{f.incident_id}</Link>]] as [string, ReactNode][])
                : []),
            ]}
          />
          {f.kind === "vulnerability" && <FindingRemediation f={f} />}
          {f.status === "open" && <FindingActions target={{ type: "finding", id: f.id }} state={f.state} onDone={onChanged} />}
        </div>
        <div>
          <h3 className="h-sm">Why this priority</h3>
          <FactorTable f={f} />
          {epss && <p className="small">{epss.text}</p>}
          <p className="hint">
            Weights, thresholds and deadlines come from the <Link to="/settings/risk-policy">risk policy</Link>
            {f.priority_policy_version ? (
              <>
                {" "}
                (version <code>{f.priority_policy_version}</code>)
              </>
            ) : null}
            .
          </p>
        </div>
      </div>
    </Card>
  );
}

function describe(e: FindingEvent): string {
  const verb: Record<string, string> = {
    acknowledge: "acknowledged",
    start: "started work",
    reset: "reset to new",
    assign: "assigned",
    comment: "commented",
    suppress: "suppressed",
    accept_risk: "accepted the risk",
    reopen: "reopened",
    // Recorded by the matcher when it resolves a finding or detects it again.
    resolved: "resolved it",
    reopened: "reopened it",
    regressed: "found it again after it was fixed",
    ignore: "ignored it",
    ignored: "ignored it",
    applied: "applied the fix",
    expired: "ended the snooze or ignore",
    fix_available: "returned it: a fix shipped",
  };
  const kind = e.detail?.resolution_kind;
  if (e.action === "resolved" && typeof kind === "string" && kind && !countsAsRemediation(kind)) return "closed it (not remediation)";
  return verb[e.action] ?? e.action.replace(/_/g, " ");
}

/** The note shown under an event: for the matcher's closures, the specific reason. */
function eventNote(e: FindingEvent): string {
  const kind = e.detail?.resolution_kind;
  if (e.action === "resolved" && typeof kind === "string" && kind) return closedReason(kind, e.note, e.detail);
  return e.note;
}

export function FindingHistory({ id, tick }: { id: number; tick: number }) {
  const res = useLoad(() => api.get<List<FindingEvent>>(`/findings/${id}/events`), [id, tick]);
  // Events carry only IDs; resolve names where the viewer may list them.
  // Older events may lack user_email/team_name; fall back to lookups.
  const { me, canAct, projectOnly } = useAuth();
  const teams = useLoad(() => (projectOnly ? Promise.resolve(null) : api.get<List<Team>>("/teams")), [projectOnly]);
  const users = useLoad(() => (canAct("engineer") ? api.get<List<DirectoryUser>>("/users/directory") : Promise.resolve(null)), []);
  const userName = (uid: number) =>
    uid === me?.user?.id ? (me.user.email ?? "you") : (users.data?.items.find((u) => u.id === uid)?.email ?? `user #${uid}`);
  const teamName = (tid: number) => teams.data?.items.find((t) => t.id === tid)?.name ?? `team #${tid}`;
  return (
    <Card title="History">
      <ErrorBox error={res.error} title="Could not load history" />
      {!res.data && !res.error && <Loading />}
      {res.data && res.data.items.length === 0 && <p className="muted">No activity yet.</p>}
      {res.data && res.data.items.length > 0 && (
        <ol className="timeline">
          {res.data.items.map((e) => {
            const d = e.detail ?? {};
            const extra: string[] = [];
            if (typeof d.until === "string") extra.push(`until ${absTime(d.until)}`);
            if (d.until_fix) extra.push("until a fix ships");
            if (typeof d.reason === "string" && IGNORE_REASON_LABEL[d.reason]) extra.push(IGNORE_REASON_LABEL[d.reason].toLowerCase());
            if (d.scope === "everywhere") extra.push("on every asset");
            if (d.request_id) extra.push(`request #${String(d.request_id)}`);
            if (d.user_email) extra.push(`to ${String(d.user_email)}`);
            else if (d.user_id !== undefined && d.user_id !== null) extra.push(Number(d.user_id) === 0 ? "person cleared" : `to ${userName(Number(d.user_id))}`);
            if (d.team_name) extra.push(`team ${String(d.team_name)}`);
            else if (d.team_id !== undefined && d.team_id !== null) extra.push(Number(d.team_id) === 0 ? "team cleared" : `team ${teamName(Number(d.team_id))}`);
            return (
              <li key={e.id}>
                <div>
                  <strong>{e.actor_name || e.actor_type}</strong> {describe(e)}
                  {e.from_state && e.to_state && e.from_state !== e.to_state && (
                    <span className="muted">
                      {" "}
                      ({e.from_state.replace(/_/g, " ")} → {e.to_state.replace(/_/g, " ")})
                    </span>
                  )}
                  {extra.length > 0 && <span className="muted"> · {extra.join(" · ")}</span>} · <RelativeTime iso={e.at} />
                </div>
                {eventNote(e) && <p className="note">{eventNote(e)}</p>}
                {typeof d.mitigation === "string" && d.mitigation && (
                  <p className="note">
                    <span className="muted">Mitigation:</span> {d.mitigation}
                  </p>
                )}
              </li>
            );
          })}
        </ol>
      )}
    </Card>
  );
}
