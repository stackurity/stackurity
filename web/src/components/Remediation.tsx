import { useState, type ReactNode } from "react";
import { Link } from "react-router";
import type { Plan, RemediationAction } from "../api";
import { absTime } from "../format";
import { Badge, type Tone } from "./Badge";
import { RelativeTime } from "./ui";

export const CHANGE_TYPE_LABEL: Record<string, string> = {
  distro: "Security backport",
  patch: "Patch",
  minor: "Minor",
  major: "Major",
};
export const CHANGE_TYPE_HELP: Record<string, string> = {
  distro: "A distribution security backport within the same upstream version (e.g. 2.5.0-1+deb12u2 → +deb12u5)",
  patch: "A patch release (x.y.Z)",
  minor: "A minor release (x.Y.z); may add features",
  major: "A major release (X.y.z); may break compatibility",
};

export function ChangeTypeBadge({ type }: { type: string }) {
  const tone: Tone = type === "major" ? "crit" : type === "minor" ? "warn" : type === "patch" ? "info" : "good";
  return <Badge status={type} tone={tone} label={CHANGE_TYPE_LABEL[type] ?? type} title={CHANGE_TYPE_HELP[type]} />;
}

const PLAN_TONES: Record<string, Tone> = {
  proposed: "warn",
  approved: "info",
  in_progress: "info",
  succeeded: "good",
  failed: "bad",
  partially_failed: "bad",
  rejected: "muted",
  cancelled: "muted",
};
export const PLAN_STATUS_HELP: Record<string, string> = {
  proposed: "Waiting for a security or admin user to approve or reject it",
  approved: "Approved; actions are released within the policy's window and limits",
  in_progress: "Changes are being applied",
  succeeded: "Every change was applied and verified by fresh inventory",
  failed: "The rollout stopped after a failure; the findings stay open",
  partially_failed: "Some assets were changed, others failed; the rollout stopped",
  rejected: "Rejected; nothing was changed",
  cancelled: "Cancelled; pending changes were not applied",
};

export function PlanStatusBadge({ status }: { status: string }) {
  return <Badge status={status} tone={PLAN_TONES[status] ?? "info"} label={status.replace(/_/g, " ")} title={PLAN_STATUS_HELP[status]} />;
}

const ACTION_TONES: Record<string, Tone> = {
  pending: "muted",
  dispatched: "info",
  applied: "warn",
  verified: "good",
  failed: "bad",
  rolled_back: "orange",
  cancelled: "muted",
  skipped: "muted",
};
const ACTION_HELP: Record<string, string> = {
  pending: "Waiting for its stage, window or concurrency slot",
  dispatched: "Sent to the agent",
  applied: "The package manager reported success; waiting for fresh inventory to verify it",
  verified: "Fresh inventory shows the target version and health checks passed",
  failed: "The change failed; see the error and output",
  rolled_back: "The previous version was reinstalled",
  cancelled: "Not run because the plan was stopped",
  skipped: "Not needed (already at or past the target)",
};

export function ActionStatusBadge({ status }: { status: string }) {
  return <Badge status={status} tone={ACTION_TONES[status] ?? "info"} label={status.replace(/_/g, " ")} title={ACTION_HELP[status]} />;
}

export const ROLLBACK_LABEL: Record<string, string> = {
  best_effort: "Best-effort rollback",
  manual: "Manual rollback only",
  not_applicable: "Revert the pull request",
};
export const ROLLBACK_HELP: Record<string, string> = {
  best_effort:
    "apt/dnf: if the policy enables auto_rollback, the previous version is reinstalled after a failure, provided a repository or cache still has it.",
  manual: "apk: Alpine repositories keep only the current version, so a failed change must be fixed by hand.",
  not_applicable: "Repository changes arrive as pull requests; undo them by reverting the PR.",
};

export function RollbackText({ value }: { value: string }) {
  return (
    <span title={ROLLBACK_HELP[value]} className="small">
      {ROLLBACK_LABEL[value] ?? value.replace(/_/g, " ")}
    </span>
  );
}

export function planAssetCount(p: Plan): number {
  return Object.values(p.action_counts ?? {}).reduce((a, b) => a + b, 0);
}

export function TargetLabel({ target }: { target: string }) {
  return <>{target === "repository" ? "Repository (pull request)" : target === "host_package" ? "Host package" : target}</>;
}

function Output({ title, text }: { title: string; text: string | undefined }) {
  if (!text) return null;
  // Normalise carriage-return progress lines from apt.
  const clean = text.replace(/\r\n/g, "\n").replace(/\r/g, "\n");
  return (
    <details className="output">
      <summary>{title}</summary>
      <pre className="mono small">{clean}</pre>
    </details>
  );
}

function ActionDetail({ a }: { a: RemediationAction }) {
  const health = Object.entries(a.health ?? {});
  return (
    <div className="action-detail">
      {a.error && (
        <div className="alert alert-error" role="alert">
          <strong>Error:</strong> <span className="break">{a.error}</span>
        </div>
      )}
      <dl className="kv">
        {(
          [
            ["kind", a.kind.replace(/_/g, " ")],
            ["manager", a.manager],
            ["attempts", String(a.attempts)],
            ["released", a.released_at ? absTime(a.released_at) : "—"],
            ["dispatched", a.dispatched_at ? absTime(a.dispatched_at) : "—"],
            ["applied", a.applied_at ? absTime(a.applied_at) : "—"],
            ["verified", a.verified_at ? absTime(a.verified_at) : "—"],
            ["deadline", a.deadline ? absTime(a.deadline) : "—"],
          ] as [string, string][]
        ).map(([k, v]) => (
          <div key={k} className="kv-row">
            <dt>{k}</dt>
            <dd>{v}</dd>
          </div>
        ))}
      </dl>
      {health.length > 0 && (
        <>
          <h4 className="h-sm">Health checks</h4>
          <ul className="banner-list">
            {health.map(([unit, state]) => (
              <li key={unit}>
                <span className="mono">{unit}</span>:{" "}
                <Badge status={state} tone={state === "active" ? "good" : "bad"} label={state} />
              </li>
            ))}
          </ul>
        </>
      )}
      <Output title="Dry-run output" text={a.dry_run?.output} />
      <Output title="Command output" text={a.result?.output} />
      {!a.dry_run?.output && !a.result?.output && <p className="muted small">No output reported yet.</p>}
    </div>
  );
}

const STAGE_LABEL: Record<string, string> = { canary: "Canary", main: "Main rollout", rollback: "Rollback" };
const STAGE_ORDER = ["canary", "main", "rollback"];

/** Remediation actions grouped by stage, with expandable outputs. */
export function ActionsTable({ actions, showPlan, showAsset = true }: { actions: RemediationAction[]; showPlan?: boolean; showAsset?: boolean }) {
  const [open, setOpen] = useState<number | null>(null);
  const stages = [...new Set(actions.map((a) => a.stage))].sort((a, b) => STAGE_ORDER.indexOf(a) - STAGE_ORDER.indexOf(b));
  const cols = 6 + (showPlan ? 1 : 0) + (showAsset ? 2 : 0);
  return (
    <div className="table-wrap">
      <table className="table">
        <caption className="sr-only">Remediation actions</caption>
        <thead>
          <tr>
            {showPlan && <th scope="col">Plan</th>}
            {showAsset && <th scope="col">Asset</th>}
            {showAsset && <th scope="col">Environment</th>}
            <th scope="col">Change</th>
            <th scope="col">Status</th>
            <th scope="col">Updated</th>
            <th scope="col">Deadline</th>
            <th scope="col">Error</th>
            <th scope="col">
              <span className="sr-only">Details</span>
            </th>
          </tr>
        </thead>
        {stages.map((st) => (
          <tbody key={st}>
            <tr className="group-row">
              <th scope="rowgroup" colSpan={cols}>
                {STAGE_LABEL[st] ?? st} ({actions.filter((a) => a.stage === st).length})
              </th>
            </tr>
            {actions
              .filter((a) => a.stage === st)
              .flatMap((a) => {
                const last = a.verified_at ?? a.applied_at ?? a.dispatched_at ?? a.released_at ?? a.created_at;
                const rows: ReactNode[] = [
                  <tr key={a.id} className={a.status === "failed" ? "row-stale" : undefined}>
                    {showPlan && (
                      <td>
                        <Link to={`/remediation/plans/${a.plan_id}`}>#{a.plan_id}</Link>
                      </td>
                    )}
                    {showAsset && (
                      <td>
                        <Link to={`/assets/${a.asset_id}?tab=remediation`}>{a.asset_name}</Link>
                      </td>
                    )}
                    {showAsset && <td>{a.environment || <span className="muted">—</span>}</td>}
                    <td>
                      <span className="mono small">
                        {a.package} {a.from_version} → {a.to_version}
                      </span>
                    </td>
                    <td>
                      <ActionStatusBadge status={a.status} />
                    </td>
                    <td>
                      <RelativeTime iso={last} />
                    </td>
                    <td>
                      {a.deadline && !["verified", "failed", "rolled_back", "cancelled", "skipped"].includes(a.status) ? (
                        <RelativeTime iso={a.deadline} />
                      ) : (
                        <span className="muted">—</span>
                      )}
                    </td>
                    <td>{a.error ? <span className="text-bad small break">{a.error.length > 80 ? a.error.slice(0, 80) + "…" : a.error}</span> : <span className="muted">—</span>}</td>
                    <td>
                      <button type="button" className="btn btn-sm" aria-expanded={open === a.id} onClick={() => setOpen(open === a.id ? null : a.id)}>
                        {open === a.id ? "Hide" : "Details"}
                      </button>
                    </td>
                  </tr>,
                ];
                if (open === a.id)
                  rows.push(
                    <tr key={`${a.id}-d`} className="expanded">
                      <td colSpan={cols}>
                        <ActionDetail a={a} />
                      </td>
                    </tr>,
                  );
                return rows;
              })}
          </tbody>
        ))}
      </table>
    </div>
  );
}
