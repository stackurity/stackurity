import { useState, type FormEvent } from "react";
import { Link } from "react-router";
import { api, ASSET_KINDS, type GateException, type GateExceptionList, type GateMode, type GatePolicy, type GatePolicyItem, type GatePolicyRequest, type GateViolation, type InheritedGatePolicy, type ScopeGatePolicies } from "../api";
import { useAuth } from "../auth";
import { useAction, useLoad } from "../hooks";
import { absTime } from "../format";
import {
  activeExceptions,
  draftFrom,
  exceptionsInForceText,
  draftToRequest,
  filterSummary,
  GATE_KINDS,
  MODE_LABELS,
  modeOptions,
  modeStatus,
  modeTone,
  newDraft,
  ruleSummary,
  scopeSummary,
  SEVERITIES,
  violationCounts,
  violationsLink,
  violationText,
  type PolicyDraft,
  type Severity,
} from "../policyGates";
import { Badge } from "./Badge";
import { ExceptionAskButton, ExceptionAskedNotice, ExceptionAskPanel } from "./PolicyExceptions";
import { confirmAction } from "./ConfirmDialog";
import { ProBadge, ProNotice } from "./ProNotice";
import { Card, CardFooter, ChoiceCards, CheckCard, ErrorBox, FieldGroup, Loading, Notice, SettingRow } from "./ui";

/*
 * Policy gates (docs/policy-gates.md): the organisation's policies on
 * Settings → Policy gates, and a project's or asset's on its page, scoped
 * like notifications (ScopeNotifications.tsx): inherited policies can be
 * turned off here or edited for here only, and a project or asset can add
 * its own. Exceptions are asked for from a violation row
 * (pages/PolicyViolations.tsx) or, for a whole asset, from a policy on the
 * asset's card here; the cards say how many are in force.
 */

export function ModeBadge({ mode }: { mode: GateMode }) {
  return <Badge status={mode} tone={modeTone(mode)} label={MODE_LABELS[mode] ?? mode} />;
}

const KIND_NAMES: Record<string, string> = {
  host: "Servers",
  repository: "Repositories",
  image: "Images",
  application: "Applications",
  managed_service: "Managed services",
  sbom: "SBOMs",
  cluster: "Clusters",
  workload: "Workloads",
};

/**
 * The form for one policy: its rule and settings, the assets it looks at,
 * and its mode. Rendered inside a card (Settings) or a project's or asset's
 * Policy gates card. enforceAvailable: the plan lets enforce fail a build.
 */
export function PolicyForm({
  policy,
  enforceAvailable,
  pending = false,
  onCancel,
  onSave,
  idPrefix = "gp",
}: {
  /** null: a new policy. */
  policy: GatePolicy | null;
  enforceAvailable: boolean;
  pending?: boolean;
  onCancel: () => void;
  onSave: (req: GatePolicyRequest) => void;
  idPrefix?: string;
}) {
  const [d, setD] = useState<PolicyDraft>(() => (policy ? draftFrom(policy) : newDraft()));
  const [problem, setProblem] = useState("");
  const set = (patch: Partial<PolicyDraft>) => setD((x) => ({ ...x, ...patch }));
  const id = (s: string) => `${idPrefix}-${s}`;
  const isNew = policy === null;
  const submit = (e: FormEvent) => {
    e.preventDefault();
    const out = draftToRequest(d);
    setProblem(out.error ?? "");
    if (out.request) onSave(out.request);
  };
  const sevOptions = (none: string) =>
    SEVERITIES.map((s) => (
      <option key={s} value={s}>
        {s === "low" ? none : s === "critical" ? "Critical only" : `${s[0].toUpperCase()}${s.slice(1)} or higher`}
      </option>
    ));
  return (
    <form className="form policy-form" onSubmit={submit} aria-label={isNew ? "New policy" : `Edit ${policy.name}`}>
      <SettingRow title="Name" description="What people see in CI output, on the Violations page and in the weekly summary.">
        <div className="field">
          <label htmlFor={id("name")}>Name</label>
          <input id={id("name")} value={d.name} maxLength={200} placeholder="No known exploited vulnerabilities on internet-facing assets" onChange={(e) => set({ name: e.target.value })} />
        </div>
        <div className="field">
          <label htmlFor={id("desc")}>Why it matters (optional)</label>
          <textarea id={id("desc")} rows={2} maxLength={2000} value={d.description} onChange={(e) => set({ description: e.target.value })} />
        </div>
      </SettingRow>

      <SettingRow title="Rule" description="What an asset must not have. Snoozed issues, accepted risks and false positives never count.">
        <ChoiceCards name={id("kind")} legend="Rule" options={GATE_KINDS} value={d.kind} onChange={(kind) => set({ kind })} columns={2} />
        {d.kind === "end_of_life" && (
          <FieldGroup title="End of life" description="Leave products empty to count every component past its end of life.">
            <div className="field">
              <label htmlFor={id("products")}>Only these products</label>
              <input id={id("products")} value={d.products} placeholder="python, nodejs" onChange={(e) => set({ products: e.target.value })} />
              <p className="hint">Product names as endoflife.date spells them, separated by commas.</p>
            </div>
            <div className="field">
              <label htmlFor={id("after")}>End-of-life date to plan for (optional)</label>
              <input id={id("after")} type="date" value={d.after} onChange={(e) => set({ after: e.target.value })} />
              <p className="hint">Saved with the policy now; counting components whose end of life falls before this date comes in a later release.</p>
            </div>
          </FieldGroup>
        )}
        {d.kind === "finding_age" && (
          <FieldGroup title="Age limit" description="Counted from when the asset first had the vulnerability, the same clock as fix deadlines.">
            <div className="field">
              <label htmlFor={id("sev")}>Severity</label>
              <select id={id("sev")} value={d.minSeverity} onChange={(e) => set({ minSeverity: e.target.value as Severity })}>
                {sevOptions("Any severity")}
              </select>
            </div>
            <div className="field">
              <label htmlFor={id("days")}>Open for more than (days)</label>
              <input id={id("days")} type="number" min={1} max={3650} value={d.maxDays} onChange={(e) => set({ maxDays: e.target.value })} />
            </div>
            <CheckCard
              checked={d.onlyFixable}
              onChange={(onlyFixable) => set({ onlyFixable })}
              label="Only when a fix exists"
              description="Leaves out vulnerabilities nobody can fix yet, so the policy only asks for work that can be done."
            />
          </FieldGroup>
        )}
        {d.kind === "leaked_key" && (
          <FieldGroup title="Leaked keys" description="Keys that were dismissed or are no longer found never count.">
            <div className="field">
              <label htmlFor={id("lsev")}>Severity</label>
              <select id={id("lsev")} value={d.leakMinSeverity} onChange={(e) => set({ leakMinSeverity: e.target.value as Severity })}>
                {sevOptions("Any severity")}
              </select>
            </div>
            <CheckCard
              checked={d.servedOnly}
              onChange={(servedOnly) => set({ servedOnly })}
              label="Only keys in files served to the network"
              description="Such as a key in a web page or a public folder, which anyone can read."
            />
          </FieldGroup>
        )}
      </SettingRow>

      <SettingRow title="Assets it looks at" description="Leave everything empty to hold every asset to the policy. Each filter you fill in narrows it.">
        <FieldGroup title="Kinds of asset">
          <div className="checks" role="group" aria-label="Kinds of asset">
            {ASSET_KINDS.map((k) => (
              <label key={k} className="check">
                <input
                  type="checkbox"
                  checked={d.assetKinds.includes(k)}
                  onChange={(e) => set({ assetKinds: e.target.checked ? [...d.assetKinds, k] : d.assetKinds.filter((x) => x !== k) })}
                />{" "}
                {KIND_NAMES[k] ?? k}
              </label>
            ))}
          </div>
        </FieldGroup>
        <div className="field">
          <label htmlFor={id("envs")}>Environments</label>
          <input id={id("envs")} value={d.environments} placeholder="production" onChange={(e) => set({ environments: e.target.value })} />
          <p className="hint">Separated by commas. &quot;production&quot; stands for every environment your risk policy counts as production.</p>
        </div>
        <CheckCard
          checked={d.exposure === "exposed"}
          onChange={(on) => set({ exposure: on ? "exposed" : "any" })}
          label="Only internet-facing assets"
          description="Assets reachable from the internet, as the risk policy sees them."
        />
        <div className="field">
          <label htmlFor={id("tags")}>Tags</label>
          <input id={id("tags")} value={d.tags} placeholder="pci, customer-data" onChange={(e) => set({ tags: e.target.value })} />
          <p className="hint">Assets with at least one of these tags, separated by commas.</p>
        </div>
      </SettingRow>

      <SettingRow
        title="Mode"
        description="What a violation does to CI jobs and deploy checks."
        badge={!enforceAvailable && d.mode === "enforce" ? <ProBadge /> : undefined}
      >
        <ChoiceCards
          name={id("mode")}
          legend="Mode"
          columns={3}
          value={d.mode}
          onChange={(mode) => set({ mode })}
          options={modeOptions(enforceAvailable).map((o) => ({ ...o, badge: o.needsPlan ? <ProBadge /> : undefined }))}
        />
        {!enforceAvailable && <ProNotice feature="gate_enforce">You can still choose Enforce: checks then pass and report its violations as warnings.</ProNotice>}
      </SettingRow>

      {problem && <p className="hint hint-error" role="alert">{problem}</p>}
      <CardFooter status={modeStatus(d.mode, enforceAvailable, isNew)}>
        <button type="submit" className="btn btn-primary" disabled={pending}>
          {isNew ? "Add policy" : "Save policy"}
        </button>
        <button type="button" className="btn" disabled={pending} onClick={onCancel}>
          Cancel
        </button>
      </CardFooter>
    </form>
  );
}

/** One policy's line: name, mode, what it fails on, where it applies, and its violations. */
function PolicyLine({ p, extra, violations, exceptions }: { p: GatePolicy; extra?: string; violations?: string; exceptions?: string }) {
  return (
    <span className="grow">
      <strong>{p.name}</strong> <ModeBadge mode={p.mode} />
      <br />
      <span className="small muted">
        {extra && `${extra} · `}
        {ruleSummary(p.kind, p.params)} · {filterSummary(p.filters)}
      </span>
      {violations && (
        <>
          <br />
          <span className="small">{violations}</span>
        </>
      )}
      {exceptions && (
        <>
          <br />
          <span className="small">{exceptions}</span>
        </>
      )}
    </span>
  );
}

// --- Settings → Policy gates (the organisation's)

export interface OrgPolicyActions {
  save: (req: GatePolicyRequest, id?: number) => Promise<boolean>;
  remove: (p: GatePolicyItem) => void;
}

/** The organisation's policies, from the server's answer: rendered by tests as is. */
export function OrgPoliciesBody({
  items,
  violations,
  exceptions,
  canManage,
  enforceAvailable,
  pending = false,
  actions,
  editing: startEditing = null,
}: {
  items: GatePolicyItem[];
  /** Current violations; undefined while they load or when they failed. */
  violations?: GateViolation[];
  /** Exceptions in force; undefined while they load or when they failed. */
  exceptions?: GateException[];
  canManage: boolean;
  enforceAvailable: boolean;
  pending?: boolean;
  actions: OrgPolicyActions;
  /** The form open at first: "new", a policy id, or null. */
  editing?: "new" | number | null;
}) {
  const [editing, setEditing] = useState<"new" | number | null>(startEditing);
  const counts = violations ? violationCounts(violations) : undefined;
  const org = items.filter((p) => p.owner_project_id == null && p.owner_asset_id == null);
  const below = items.length - org.length;
  const form = (p: GatePolicyItem | null) => (
    <PolicyForm
      key={p ? p.id : "new"}
      policy={p}
      enforceAvailable={enforceAvailable}
      pending={pending}
      onCancel={() => setEditing(null)}
      onSave={async (req) => {
        if (await actions.save(req, p?.id)) setEditing(null);
      }}
    />
  );
  return (
    <Card
      title="Organisation policies"
      description="Rules every asset in the organisation is held to. A project or an asset can turn one off for itself, or edit its own copy, on its own page."
      actions={
        canManage && editing === null ? (
          <button type="button" className="btn btn-primary" disabled={pending} onClick={() => setEditing("new")}>
            Add policy
          </button>
        ) : undefined
      }
    >
      {org.length === 0 && editing !== "new" ? (
        <p className="muted">No organisation policy yet.{!canManage && " An administrator can add one."}</p>
      ) : (
        <ul className="project-list" aria-label="Organisation policies">
          {org.map((p) =>
            editing === p.id ? (
              <li key={p.id} className="policy-editing">
                {form(p)}
              </li>
            ) : (
              <li key={p.id}>
                <PolicyLine
                  p={p}
                  extra={scopeSummary(p)}
                  violations={p.mode === "off" ? undefined : counts ? violationText(counts.get(p.id)) : undefined}
                  exceptions={exceptionsInForceText(activeExceptions(exceptions, { policy_id: p.id }).length)}
                />
                {p.mode !== "off" && counts && (counts.get(p.id)?.violations ?? 0) > 0 && (
                  <Link className="btn btn-sm" to={violationsLink({ policy_id: p.id })}>
                    See violations
                  </Link>
                )}
                {canManage && (
                  <>
                    <button type="button" className="btn btn-sm" disabled={pending || editing !== null} onClick={() => setEditing(p.id)}>
                      Edit
                    </button>
                    <button type="button" className="btn btn-sm btn-link-danger" disabled={pending} onClick={() => actions.remove(p)}>
                      Delete
                    </button>
                  </>
                )}
              </li>
            ),
          )}
        </ul>
      )}
      {editing === "new" && form(null)}
      {below > 0 && (
        <p className="hint">
          Projects and assets have {below === 1 ? "1 policy" : `${below} policies`} of their own, set on their pages.
        </p>
      )}
    </Card>
  );
}

// --- a project's or asset's Policy gates card

export type GateScopeKind = "project" | "asset";

export interface ScopeGateActions {
  inherited: (p: InheritedGatePolicy, state: "on" | "off" | "edit") => void;
  save: (req: GatePolicyRequest, id?: number) => Promise<boolean>;
  remove: (p: GatePolicy) => void;
}

const STATE_LABEL: Record<InheritedGatePolicy["state"], (w: string) => string> = {
  on: () => "On",
  off: (w) => `Off for this ${w}`,
  edit: (w) => `Edited for this ${w}`,
};

/** The card on a project's or asset's page. Hidden from people who may not read it. */
export function ScopeGatePoliciesCard({ kind, id }: { kind: GateScopeKind; id: number }) {
  const { can, has, meta } = useAuth();
  const base = `/${kind}s/${id}/gate-policies`;
  const on = Boolean(meta?.features?.includes("gate_policies"));
  const res = useLoad(() => (on ? api.get<ScopeGatePolicies>(base) : Promise.resolve(null)), [base, on]);
  // An asset's exceptions waiting and in force, for its policies' lines.
  const exq = (status: string) => (on && kind === "asset" ? api.get<GateExceptionList>("/gate-policies/exceptions", { asset_id: id, status, limit: 500 }) : Promise.resolve(null));
  const waiting = useLoad(() => exq("pending"), [kind, id, on]);
  const inForce = useLoad(() => exq("approved"), [kind, id, on]);
  const act = useAction();
  const [note, setNote] = useState("");
  if (!on || res.data === null) return null;
  if (res.error?.status === 403 || res.error?.status === 404) return null;
  if (res.error) return <ErrorBox error={res.error} title="Could not load the policy gates" />;
  if (!res.data) return <Loading />;
  const done = (ok: unknown, msg: string) => {
    if (ok) {
      res.reload();
      setNote(msg);
    }
    return Boolean(ok);
  };
  const actions: ScopeGateActions = {
    inherited: async (p, state) => {
      if (state === "off") {
        const ok = await confirmAction({
          title: `Turn ${p.name} off for this ${kind}?`,
          consequence: `CI and deploy checks of this ${kind}'s assets stop reporting it, and its violations here are no longer counted. Everywhere else it is unchanged. The change is recorded in the audit log.`,
          action: "Turn off",
        });
        if (!ok) return;
      }
      const msg = state === "off" ? `${p.name} turned off for this ${kind}.` : state === "on" ? `${p.name} applies to this ${kind} again.` : `${p.name} copied for this ${kind}: edit the copy below.`;
      done(await act.run(() => api.put(`${base}/inherited/${p.id}`, { state }).then(() => true)), msg);
    },
    save: async (req, pid) =>
      done(await act.run(() => (pid ? api.put(`${base}/${pid}`, req) : api.post(`${base}`, req)).then(() => true)), `${req.name} saved.`),
    remove: async (p) => {
      const copy = p.inherits_policy_id != null;
      const ok = await confirmAction({
        title: `Delete ${p.name}?`,
        consequence: copy ? "The policy it replaced applies here again." : `It stops applying to this ${kind}. Its history stays in the audit log.`,
        action: "Delete policy",
        destructive: !copy,
        typeToConfirm: p.name,
      });
      if (ok) done(await act.run(() => api.del(`${base}/${p.id}`).then(() => true)), `${p.name} deleted.`);
    },
  };
  return (
    <>
      <ErrorBox error={act.error} title="Could not change the policy gates" />
      {note && <Notice kind="success">{note}</Notice>}
      <ScopeGatePoliciesBody
        kind={kind}
        view={res.data}
        enforceAvailable={has("gate_enforce")}
        pending={act.pending}
        actions={actions}
        violationsLinkShown={can("security")}
        exceptions={waiting.data && inForce.data ? [...waiting.data.items, ...inForce.data.items] : undefined}
        onExceptionAsked={waiting.reload}
      />
    </>
  );
}

/** Everything the card shows, from the server's answer: rendered by tests as is. */
export function ScopeGatePoliciesBody({
  kind,
  view,
  enforceAvailable,
  pending = false,
  actions,
  editing: startEditing = null,
  violationsLinkShown = true,
  exceptions,
  onExceptionAsked,
}: {
  kind: GateScopeKind;
  view: ScopeGatePolicies;
  enforceAvailable: boolean;
  pending?: boolean;
  actions: ScopeGateActions;
  editing?: "new" | number | null;
  violationsLinkShown?: boolean;
  /** An asset's exceptions waiting and in force: each policy line then offers Ask for an exception. */
  exceptions?: GateException[];
  onExceptionAsked?: () => void;
}) {
  const [editing, setEditing] = useState<"new" | number | null>(startEditing);
  const w = kind;
  const manage = view.can_manage;
  const copyOf = (p: InheritedGatePolicy) => view.policies.find((x) => x.id === p.copy_id);
  // Exceptions for the whole asset, from a policy's line (asset cards only).
  const asks = kind === "asset" && exceptions !== undefined;
  const inForce = (p: GatePolicy) => {
    if (!asks) return undefined;
    const xs = activeExceptions(exceptions, { policy_id: p.id, asset_id: view.scope.id });
    return xs.length ? `${exceptionsInForceText(xs.length)}; the first ends ${absTime(xs[0].expires_at)}` : undefined;
  };
  const [asking, setAsking] = useState<GatePolicy | null>(null);
  const [asked, setAsked] = useState<GateException | null>(null);
  const askFor = (p: GatePolicy) =>
    asks && p.mode !== "off" ? (
      <ExceptionAskButton
        waiting={exceptions.find((x) => x.status === "pending" && x.policy_id === p.id && x.asset_id === view.scope.id && x.target_kind === "asset")}
        disabled={asking !== null}
        onAsk={() => {
          setAsked(null);
          setAsking(p);
        }}
      />
    ) : null;
  const form = (p: GatePolicy | null) => (
    <PolicyForm
      key={p ? p.id : "new"}
      idPrefix={`gp-${kind}`}
      policy={p}
      enforceAvailable={enforceAvailable}
      pending={pending}
      onCancel={() => setEditing(null)}
      onSave={async (req) => {
        if (await actions.save(req, p?.id)) setEditing(null);
      }}
    />
  );
  return (
    <Card
      title="Policy gates"
      description={
        <>
          The rules this {w}&apos;s CI jobs and deploys are checked against. Policies of the{" "}
          {kind === "project" ? "organisation" : "organisation and this asset's projects"} apply here too: turn one off for this {w}, or edit it for this {w}{" "}
          only, and add policies only this {w} needs.
          {!manage && ` Only admins of this ${w} change them.`}
        </>
      }
      actions={
        violationsLinkShown ? (
          <Link className="btn btn-sm" to={violationsLink(kind === "project" ? { project_id: view.scope.id } : { asset_id: view.scope.id })}>
            See violations
          </Link>
        ) : undefined
      }
    >
      {asked && <ExceptionAskedNotice x={asked} />}
      {asking && (
        <ExceptionAskPanel
          ask={{ key: `scope-${asking.id}`, subject: { policy_id: asking.id, asset_id: view.scope.id }, policyName: asking.name, assetName: view.scope.name }}
          onCancel={() => setAsking(null)}
          onAsked={(x) => {
            setAsking(null);
            setAsked(x);
            onExceptionAsked?.();
          }}
        />
      )}
      <SettingRow
        title={kind === "project" ? "From the organisation" : "Inherited"}
        description={
          kind === "project"
            ? "Policies set for the whole organisation. They cover this project unless you turn them off or edit them here."
            : "Policies of the organisation and of this asset's projects. They cover this asset unless you turn them off or edit them here."
        }
      >
        {view.inherited.length === 0 ? (
          <p className="muted">No policy {kind === "project" ? "of the organisation" : "of the organisation or its projects"} reaches this {w}.</p>
        ) : (
          <ul className="project-list" aria-label="Inherited policies">
            {view.inherited.map((p) => (
              <li key={p.id}>
                <PolicyLine p={p} extra={p.from === "organisation" ? "Organisation" : "Project"} exceptions={p.state === "on" ? inForce(p) : undefined} />
                <Badge status={p.state} tone={p.state === "on" ? "good" : "muted"} label={STATE_LABEL[p.state](w)} />
                {manage && p.state === "on" && (
                  <>
                    <button type="button" className="btn btn-sm" disabled={pending} onClick={() => actions.inherited(p, "edit")}>
                      Edit for this {w}
                    </button>
                    <button type="button" className="btn btn-sm" disabled={pending} onClick={() => actions.inherited(p, "off")}>
                      Turn off for this {w}
                    </button>
                  </>
                )}
                {p.state === "on" && askFor(p)}
                {manage && p.state === "off" && (
                  <button type="button" className="btn btn-sm" disabled={pending} onClick={() => actions.inherited(p, "on")}>
                    Turn on again
                  </button>
                )}
                {manage && p.state === "edit" && (
                  <>
                    {copyOf(p) && (
                      <button type="button" className="btn btn-sm" disabled={pending} onClick={() => setEditing(p.copy_id ?? null)}>
                        Edit
                      </button>
                    )}
                    <button type="button" className="btn btn-sm" disabled={pending} onClick={() => actions.inherited(p, "on")}>
                      Use the {p.from === "organisation" ? "organisation's" : "project's"} policy again
                    </button>
                  </>
                )}
              </li>
            ))}
          </ul>
        )}
      </SettingRow>

      <SettingRow title={<>This {w}&apos;s policies</>} description={`Policies that only cover this ${w}, including edited copies of inherited ones.`}>
        {view.policies.length === 0 ? (
          <p className="muted">No policies of its own yet.</p>
        ) : (
          <ul className="project-list" aria-label={`Policies of this ${w}`}>
            {view.policies.map((p) =>
              editing === p.id ? (
                <li key={p.id} className="policy-editing">
                  {form(p)}
                </li>
              ) : (
                <li key={p.id}>
                  <PolicyLine p={p} extra={p.inherits_policy_id != null ? "Edited copy" : undefined} exceptions={inForce(p)} />
                  {askFor(p)}
                  {manage && (
                    <>
                      <button type="button" className="btn btn-sm" disabled={pending || editing !== null} onClick={() => setEditing(p.id)}>
                        Edit
                      </button>
                      <button type="button" className="btn btn-sm btn-link-danger" disabled={pending} onClick={() => actions.remove(p)}>
                        Delete
                      </button>
                    </>
                  )}
                </li>
              ),
            )}
          </ul>
        )}
        {manage && editing === null && (
          <div className="row-actions">
            <button type="button" className="btn" disabled={pending} onClick={() => setEditing("new")}>
              Add policy
            </button>
          </div>
        )}
        {manage && editing === "new" && form(null)}
      </SettingRow>
    </Card>
  );
}
