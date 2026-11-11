import { Link } from "react-router";
import { api, type List, type Onboarding, type OwnerRule, type Overview, type RemediationPolicy, type RiskPolicyResponse } from "../api";
import { useAuth } from "../auth";
import { useAction, useLoad } from "../hooks";
import { progressText, setupItems, setupProgress, type SetupItem, type SetupProgress } from "../setupProgress";
import { ErrorBox } from "./ui";

/*
 * The Dashboard's setup checklist, for admins while setup is not hidden.
 * Each step says why it is worth doing, what you get, and opens the page
 * that does it; ticks come from what exists in the workspace. Hiding it is
 * remembered for the workspace (onboarding state "done"), for every admin.
 */
export function SetupChecklist({ o, onChange, compact }: { o: Onboarding; onChange: () => void; compact?: boolean }) {
  const act = useAction();
  const { me, has, can } = useAuth();
  const paid = has("remediation");
  // Every project, whatever the switcher says: setup is for the workspace.
  const overview = useLoad(() => api.getAll<Overview>("/overview"), []);
  const owners = useLoad(() => api.getAll<List<OwnerRule>>("/owner-rules"), []);
  const risk = useLoad(() => api.getAll<RiskPolicyResponse>("/risk-policy"), []);
  // Community is never asked (it would answer 402): the step shows the paid part locked instead.
  const fixes = useLoad(
    () => (paid && can("security") ? api.getAll<List<RemediationPolicy>>("/remediation/policies") : Promise.resolve(null)),
    [paid],
  );
  const items = setupItems({
    steps: o.steps,
    assets: overview.data?.assets ?? null,
    ownerRules: owners.data ? owners.data.items.length : null,
    riskPolicySaved: risk.data ? Boolean(risk.data.last_change) : null,
    remediationPaid: paid,
    remediationPolicies: fixes.data ? fixes.data.total : null,
    mfa: Boolean(me?.user?.mfa_enabled),
  });
  const p = setupProgress(items);

  const hide = async () => {
    const ok = await act.run(() => api.put("/onboarding", { state: "done" }));
    if (ok !== undefined) onChange();
  };
  const hideButton = (
    <button
      type="button"
      className={p.complete ? "btn btn-primary btn-sm" : "btn btn-link btn-sm"}
      onClick={hide}
      disabled={act.pending}
      title="Hides it for every admin in this workspace. Help, Your first ten minutes, lists the same steps."
    >
      {p.complete ? "Dismiss" : "Hide the checklist"}
    </button>
  );
  const body = (
    <>
      <ErrorBox error={act.error} title="Could not hide the checklist" />
      <ol className="setup-list">
        {items.map((i) => (
          <SetupRow key={i.key} item={i} next={p.next?.key === i.key} />
        ))}
      </ol>
    </>
  );

  // On the Dashboard with assets: one line under what needs you, opened on demand.
  if (compact)
    return (
      <details className="setup-compact" open={p.complete || undefined}>
        <summary>
          <span>Finish setting up</span>
          <ProgressBar p={p} />
        </summary>
        {body}
        {hideButton}
      </details>
    );
  return (
    <section className="card setup-checklist" aria-labelledby="setup-h">
      <header className="card-head card-head-desc">
        <div className="card-head-text">
          <h2 id="setup-h">{p.complete ? "Setup complete" : "Finish setting up"}</h2>
          <p className="card-desc">
            Each step makes Stackurity more useful to your team. Ticks come from what exists in this workspace, so a step done somewhere
            else counts too.
          </p>
        </div>
        <div className="card-actions">{hideButton}</div>
      </header>
      <ProgressBar p={p} />
      {body}
    </section>
  );
}

/** "3 of 8 done" and a bar: how far setup has got. */
function ProgressBar({ p }: { p: SetupProgress }) {
  return (
    <span className="setup-progress">
      <span className="setup-progress-text">{progressText(p)}</span>
      <span
        className="setup-progress-track"
        role="progressbar"
        aria-label="Setup progress"
        aria-valuemin={0}
        aria-valuemax={p.total}
        aria-valuenow={p.done}
        aria-valuetext={progressText(p)}
      >
        <span className={`setup-progress-fill${p.complete ? " complete" : ""}`} style={{ width: `${p.percent}%` }} />
      </span>
    </span>
  );
}

/** One step: done or not, why it is worth doing, what you get, and its button. */
function SetupRow({ item: i, next }: { item: SetupItem; next: boolean }) {
  const done = i.state === "done";
  return (
    <li className={`setup-row${done ? " done" : ""}`}>
      <span className="onboard-dot" aria-hidden="true">
        {done ? "✓" : ""}
      </span>
      <div className="setup-row-text">
        <strong>
          {i.title}
          <span className="sr-only">{done ? " (done)" : i.state === "unknown" ? " (could not check)" : " (not done)"}</span>
        </strong>
        <span className="setup-row-why">{i.benefit}</span>
        <span className="setup-row-after">
          {done ? "You have: " : "You get: "}
          {i.after}
        </span>
        {i.state === "unknown" && <span className="setup-row-after">Could not check this step just now; open it to see.</span>}
        {i.locked && (
          <span className="setup-row-locked">
            <span className="pro-badge">{i.locked.plan}</span> {i.locked.text} <Link to={i.locked.to}>What it does</Link>
          </span>
        )}
      </div>
      <Link to={i.action.to} className={`btn btn-sm${next ? " btn-primary" : ""}`}>
        {done ? "Open" : i.action.label}
      </Link>
    </li>
  );
}
