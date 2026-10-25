import { useState, type FormEvent, type ReactNode } from "react";
import { Link, useParams } from "react-router";
import { api, type List, type Plan, type PlanResponse, type RemediationPolicy } from "../api";
import { useAuth } from "../auth";
import { useAction, useLoad } from "../hooks";
import { absTime } from "../format";
import { Chip } from "../components/Badge";
import {
  ActionsTable,
  CHANGE_TYPE_HELP,
  ChangeTypeBadge,
  PLAN_STATUS_HELP,
  PlanStatusBadge,
  ROLLBACK_HELP,
  ROLLBACK_LABEL,
  TargetLabel,
} from "../components/Remediation";
import { Card, CodeBlock, ErrorBox, KeyValues, Loading, Notice, PageHeader, RelativeTime } from "../components/ui";

const DAYS = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"];

function policyWindow(p: RemediationPolicy | undefined): string {
  if (!p) return "unknown";
  if (!p.window_days?.length && !p.window_start) return "any time";
  const days = p.window_days?.length ? p.window_days.map((d) => DAYS[d - 1]).join(", ") : "any day";
  return `${days}${p.window_start ? `, ${p.window_start}–${p.window_end} ${p.timezone}` : ""}`;
}

function DecisionPanel({
  data,
  policy,
  onDone,
}: {
  data: PlanResponse;
  policy: RemediationPolicy | undefined;
  onDone: () => void;
}) {
  const { can } = useAuth();
  const plan = data.plan;
  const actions = data.actions ?? [];
  const [note, setNote] = useState("");
  const act = useAction();
  const admin = can("admin");
  const major = plan.change_type === "major";
  const assets = [...new Set(actions.map((a) => a.asset_name))];
  const envs = plan.environments?.length ? plan.environments : [...new Set(actions.map((a) => a.environment || "no environment"))];

  const decide = async (decision: "approve" | "reject" | "cancel") => {
    let msg = "";
    if (decision === "approve") {
      msg =
        `Approve upgrading ${plan.package} to ${plan.target_version}?\n\n` +
        `Assets (${assets.length}): ${assets.slice(0, 10).join(", ")}${assets.length > 10 ? ", …" : ""}\n` +
        `Environments: ${envs.join(", ")}\n` +
        `Window: ${policyWindow(policy)}\n` +
        `Canary: ${policy?.canary_count ?? "?"} asset(s), soak ${policy?.soak_minutes ?? "?"} min, max ${policy?.max_concurrent ?? "?"} at once\n` +
        `Rollback: ${ROLLBACK_LABEL[plan.rollback] ?? plan.rollback}\n\n` +
        `Changes start on enrolled hosts within the window.`;
    } else if (decision === "reject") {
      msg = `Reject this plan? Nothing will be changed. A new plan may be proposed if the policy still matches.`;
    } else {
      msg = `Cancel this plan? Pending changes are not applied. Changes already applied stay in place.`;
    }
    if (!window.confirm(msg)) return;
    const ok = await act.run(() => api.post(`/remediation/plans/${plan.id}/decision`, { decision, note: note.trim() }).then(() => true));
    if (ok) {
      setNote("");
      onDone();
    }
  };
  const submit = (e: FormEvent) => e.preventDefault();

  if (plan.status === "proposed") {
    return (
      <Card title="Approval">
        <form className="form form-compact" onSubmit={submit}>
          <p className="hint">
            Approving releases this change to {assets.length} asset{assets.length === 1 ? "" : "s"} ({envs.join(", ")}) within the policy
            window ({policyWindow(policy)}). It is dry-run on each host first, staged through the canary, and verified by fresh inventory.
          </p>
          <div className="field">
            <label htmlFor="dec-note">Note (recorded in the audit log)</label>
            <textarea id="dec-note" maxLength={2000} value={note} onChange={(e) => setNote(e.target.value)} placeholder="e.g. change ticket, reason for rejection" />
          </div>
          <ErrorBox error={act.error} title="Decision failed" />
          <div className="form-actions">
            <button
              type="button"
              className="btn btn-primary"
              disabled={act.pending || (major && !admin)}
              aria-describedby={major && !admin ? "major-help" : undefined}
              onClick={() => decide("approve")}
            >
              Approve
            </button>
            <button type="button" className="btn" disabled={act.pending} onClick={() => decide("reject")}>
              Reject
            </button>
          </div>
          {major && !admin && (
            <p className="hint" id="major-help">
              Major upgrades need an administrator's approval. You can still reject it.
            </p>
          )}
        </form>
      </Card>
    );
  }
  if (plan.status === "approved" || plan.status === "in_progress") {
    return (
      <Card title="Stop this plan">
        <form className="form form-compact" onSubmit={submit}>
          <div className="field">
            <label htmlFor="dec-note">Reason</label>
            <textarea id="dec-note" maxLength={2000} value={note} onChange={(e) => setNote(e.target.value)} />
          </div>
          <ErrorBox error={act.error} title="Cancel failed" />
          <div className="form-actions">
            <button type="button" className="btn btn-danger" disabled={act.pending} onClick={() => decide("cancel")}>
              Cancel plan
            </button>
          </div>
        </form>
      </Card>
    );
  }
  return null;
}

function RenovateHelp({ plan, assetId }: { plan: Plan; assetId: number | undefined }) {
  const q = plan.repository_url ? `repository=${encodeURIComponent(plan.repository_url)}` : assetId ? `asset_id=${assetId}` : null;
  const url = q ? `${window.location.origin}/api/v1/remediation/renovate.json?${q}&mode=exclusive` : null;
  return (
    <Card title="Pull requests via Renovate">
      <p>
        Stackurity does not edit code. Approved repository plans are published as Renovate configuration, so the change arrives as an
        ordinary pull request that goes through your review, tests and deployment approvals. Generated rules never auto-merge.
      </p>
      {plan.repository_url && (
        <p className="small">
          Repository: <span className="mono break">{plan.repository_url}</span>
        </p>
      )}
      {!url && <p className="muted">The repository is not known yet.</p>}
      {url && (
        <>
          <p className="small">
            Configuration URL (needs a Stackurity token with engineer or collector rights; <span className="mono">mode=exclusive</span>{" "}
            disables every update that is not approved):
          </p>
          <CodeBlock label="Renovate configuration URL" text={url} />
          <p className="small">Example: fetch it in the Renovate job before running Renovate:</p>
          <CodeBlock
            label="Renovate fetch snippet"
            text={`curl -fsS -H "Authorization: Bearer $STACKURITY_TOKEN" \\\n  "${url}" \\\n  -o renovate.json`}
          />
        </>
      )}
    </Card>
  );
}

export function PlanDetailPage() {
  const { id } = useParams();
  const { can } = useAuth();
  const res = useLoad(() => api.get<PlanResponse>(`/remediation/plans/${Number(id)}`), [id]);
  const policies = useLoad(() => (can("security") ? api.get<List<RemediationPolicy>>("/remediation/policies") : Promise.resolve(null)), []);

  if (res.error)
    return (
      <>
        <PageHeader help="remediation-overview" title="Remediation plan" />
        <ErrorBox error={res.error} title="Could not load plan" />
        <p>
          <Link to="/remediation">Back to plans</Link>
        </p>
      </>
    );
  if (!res.data) return <Loading />;
  const plan = res.data.plan;
  const actions = res.data.actions ?? [];
  const policy = policies.data?.items.find((p) => p.id === plan.policy_id);
  const froms = plan.from_versions?.length ? plan.from_versions : [...new Set(actions.map((a) => a.from_version).filter(Boolean))];
  const fromText = froms.length === 0 ? "?" : froms.length === 1 ? froms[0] : `${froms.length} versions`;
  const keys = plan.finding_keys ?? [];

  const entries: [string, ReactNode][] = [
    ["package", <span className="mono">{plan.purl_key || plan.package}</span>],
    ["change", <span className="fromto">{fromText} → {plan.target_version}</span>],
    [
      "change type",
      <span>
        <ChangeTypeBadge type={plan.change_type} /> <span className="muted small">{CHANGE_TYPE_HELP[plan.change_type]}</span>
      </span>,
    ],
    ["target", <TargetLabel target={plan.target} />],
    [
      "policy",
      plan.policy_id ? (
        can("security") ? (
          <Link to="/remediation?tab=policies">{plan.policy_name}</Link>
        ) : (
          plan.policy_name
        )
      ) : (
        <span className="muted">deleted</span>
      ),
    ],
    ["status", <span>
      <PlanStatusBadge status={plan.status} /> <span className="muted small">{PLAN_STATUS_HELP[plan.status]}</span>
    </span>],
    ["stage", plan.stage || "—"],
    [
      "rollback",
      <span>
        <strong>{ROLLBACK_LABEL[plan.rollback] ?? plan.rollback}.</strong> <span className="small">{ROLLBACK_HELP[plan.rollback]}</span>
        {plan.rollback === "best_effort" && policy && !policy.auto_rollback && (
          <span className="small"> This policy does not enable auto_rollback, so a failure is left for you to fix.</span>
        )}
      </span>,
    ],
    ["proposed", <span>
      <RelativeTime iso={plan.created_at} /> by {plan.created_by || "system"}
    </span>],
  ];
  if (plan.approved_at)
    entries.push([plan.status === "rejected" ? "decided" : "approved", <span title={absTime(plan.approved_at)}><RelativeTime iso={plan.approved_at} />{plan.approved_by_email ? ` by ${plan.approved_by_email}` : plan.approved_by ? ` by user #${plan.approved_by}` : ""}</span>]);
  if (plan.decision_note) entries.push(["decision note", <span className="break">{plan.decision_note}</span>]);
  if (plan.canary_done_at) entries.push(["canary finished", <RelativeTime iso={plan.canary_done_at} />]);

  return (
    <>
      <nav className="crumbs" aria-label="Breadcrumb">
        <Link to="/remediation">Remediation</Link> <span aria-hidden="true">/</span> <span>Plan #{plan.id}</span>
      </nav>
      <PageHeader help="remediation-overview"
        title={
          <>
            {plan.package} <span className="fromto">{fromText} → {plan.target_version}</span>
          </>
        }
        sub={
          <span className="badges">
            <ChangeTypeBadge type={plan.change_type} />
            <PlanStatusBadge status={plan.status} />
            <span>· plan #{plan.id}</span>
            {plan.stage && <span>· stage {plan.stage}</span>}
          </span>
        }
      />
      {(plan.status === "failed" || plan.status === "partially_failed") && (
        <div className="alert alert-error" role="alert">
          <strong>The rollout stopped after a failure.</strong> The findings stay open. Check the failed action's error and output below.
        </div>
      )}
      {plan.change_type === "major" && plan.status === "proposed" && (
        <Notice kind="warn">This is a major upgrade: it can break compatibility and needs an administrator's approval.</Notice>
      )}
      <div className="grid-2">
        <Card title="Plan">
          <KeyValues entries={entries} />
        </Card>
        <div>
          {can("security") && <DecisionPanel data={res.data} policy={policy} onDone={res.reload} />}
          <Card title={`Findings fixed (${keys.length})`}>
            {keys.length === 0 ? (
              <p className="muted">No findings listed.</p>
            ) : (
              <span className="chips">
                {keys.map((k) => (
                  <Link key={k} to={`/findings?key=${encodeURIComponent(k)}&status=all`}>
                    <Chip>
                      <span className="mono">{k}</span>
                    </Chip>
                  </Link>
                ))}
              </span>
            )}
          </Card>
        </div>
      </div>
      {plan.target === "repository" && <RenovateHelp plan={plan} assetId={actions[0]?.asset_id} />}
      <h2 className="section-title">Actions ({actions.length})</h2>
      {actions.length === 0 ? <p className="muted">No actions.</p> : <ActionsTable actions={actions} />}
    </>
  );
}
