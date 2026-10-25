import { useState, type FormEvent, type ReactNode } from "react";
import { ProNotice } from "../components/ProNotice";
import { Link, useNavigate, useSearchParams } from "react-router";
import {
  api,
  CHANGE_TYPES,
  HOST_ECOSYSTEMS,
  PLAN_STATUSES,
  PRIORITIES,
  REPO_ECOSYSTEMS,
  type List,
  type Plan,
  type RemediationPolicy,
  type Team,
} from "../api";
import { useAuth } from "../auth";
import { useAction, useFacets, useLoad } from "../hooks";
import { Badge } from "../components/Badge";
import { Table, type Column } from "../components/Table";
import {
  CHANGE_TYPE_HELP,
  CHANGE_TYPE_LABEL,
  ChangeTypeBadge,
  planAssetCount,
  PlanStatusBadge,
  RollbackText,
  TargetLabel,
} from "../components/Remediation";
import { Card, EmptyState, ErrorBox, Loading, Notice, PageHeader, Pager, RelativeTime, Tabs } from "../components/ui";

type Tab = "plans" | "policies";

export function SafetyNote() {
  return (
    <div className="safety" role="note">
      <strong>Safety model.</strong> Nothing changes unless an enabled policy matches <em>and</em> a plan is approved (or the policy
      approves automatically). Major upgrades need <span className="mono">allow_major</span> and an admin's approval. Hosts must also be
      enrolled (bound token + agent running with <span className="mono">--remediate</span> and a local allowlist). Every change is
      dry-run first, staged through a canary, and verified by fresh inventory; the first failure halts the rollout.
    </div>
  );
}

export function RemediationPage() {
  const { can, has } = useAuth();
  const [params, setParams] = useSearchParams();
  const tab: Tab = params.get("tab") === "policies" && can("security") ? "policies" : "plans";
  return (
    <>
      <PageHeader help="remediation-overview" title="Remediation" sub="Policy-controlled security updates for hosts and repositories." />
      {!has("remediation") && (
        <ProNotice feature="remediation">
          The Action plan still lists every upgrade to make; Pro applies them for you, with approvals, canary hosts and rollback.{" "}
        </ProNotice>
      )}
      <Tabs<Tab>
        label="Remediation"
        value={tab}
        onChange={(t) => setParams(t === "plans" ? {} : { tab: t }, { replace: true })}
        tabs={[{ id: "plans", label: "Plans" }, ...(can("security") ? [{ id: "policies" as Tab, label: "Policies" }] : [])]}
      />
      <div role="tabpanel" id={`panel-${tab}`} aria-labelledby={`tab-${tab}`} className="tabpanel">
        {tab === "plans" ? <PlansTab /> : <PoliciesTab />}
      </div>
    </>
  );
}

// --- plans

const LIMIT = 50;

function PlansTab() {
  const [params, setParams] = useSearchParams();
  const navigate = useNavigate();
  const status = params.get("status") ?? "proposed";
  const offset = Number(params.get("offset") ?? 0) || 0;
  const res = useLoad(() => api.get<List<Plan>>("/remediation/plans", { status, limit: LIMIT, offset }), [status, offset]);
  const setStatus = (s: string) => setParams(s === "proposed" ? {} : { status: s }, { replace: true });

  const cols: Column<Plan>[] = [
    {
      key: "pkg",
      header: "Package",
      cell: (p) => (
        <>
          <Link to={`/remediation/plans/${p.id}`} onClick={(e) => e.stopPropagation()}>
            {p.package}
          </Link>
          <div className="mono small muted break">{p.purl_key}</div>
        </>
      ),
    },
    {
      key: "to",
      header: "Change",
      cell: (p) => {
        const froms = p.from_versions ?? [];
        return (
          <span className="fromto" title={froms.length > 1 ? froms.join(", ") : undefined}>
            {froms.length === 1 ? froms[0] : froms.length > 1 ? `${froms.length} versions` : "?"} → {p.target_version}
          </span>
        );
      },
    },
    { key: "type", header: "Type", cell: (p) => <ChangeTypeBadge type={p.change_type} /> },
    { key: "target", header: "Target", cell: (p) => <TargetLabel target={p.target} /> },
    {
      key: "assets",
      header: "Assets",
      numeric: true,
      cell: (p) => (
        <>
          {planAssetCount(p)}
          {p.environments?.length ? <div className="muted small">{p.environments.join(", ")}</div> : null}
        </>
      ),
    },
    { key: "fixes", header: "Findings fixed", numeric: true, cell: (p) => (p.finding_keys ?? []).length },
    { key: "policy", header: "Policy", cell: (p) => p.policy_name || <span className="muted">deleted policy</span> },
    {
      key: "status",
      header: "Status",
      cell: (p) => (
        <>
          <PlanStatusBadge status={p.status} />
          {p.stage && p.stage !== "done" && <div className="muted small">stage: {p.stage}</div>}
        </>
      ),
    },
    { key: "rollback", header: "Rollback", cell: (p) => <RollbackText value={p.rollback} /> },
    { key: "created", header: "Created", cell: (p) => <RelativeTime iso={p.created_at} /> },
  ];

  return (
    <>
      <div className="filters">
        <div className="field">
          <label htmlFor="pl-status">Show</label>
          <select id="pl-status" value={status} onChange={(e) => setStatus(e.target.value)}>
            <option value="proposed">Needs approval</option>
            {PLAN_STATUSES.filter((s) => s !== "proposed").map((s) => (
              <option key={s} value={s}>
                {s.replace(/_/g, " ")}
              </option>
            ))}
            <option value="failed,partially_failed">failed or partially failed</option>
            <option value="all">All plans</option>
          </select>
        </div>
        <button type="button" className="btn" onClick={res.reload}>
          Refresh
        </button>
      </div>
      <ErrorBox error={res.error} title="Could not load plans" />
      {!res.data && !res.error && <Loading />}
      {res.data && res.data.items.length === 0 && (
        <EmptyState title={status === "proposed" ? "Nothing needs approval" : "No plans"} help="remediation-overview" helpLabel="How remediation policies work">
          <p>
            Plans are proposed automatically when an enabled remediation policy covers open findings.{" "}
            {status === "proposed" && (
              <button type="button" className="btn btn-sm btn-link" onClick={() => setStatus("all")}>
                Show all plans
              </button>
            )}
          </p>
        </EmptyState>
      )}
      {res.data && res.data.items.length > 0 && (
        <>
          <Table
            caption="Remediation plans"
            columns={cols}
            rows={res.data.items}
            rowKey={(p) => p.id}
            onRowClick={(p) => navigate(`/remediation/plans/${p.id}`)}
            rowClassName={(p) => (p.status === "failed" || p.status === "partially_failed" ? "row-stale" : p.status === "proposed" ? "row-partial" : undefined)}
          />
          <Pager
            total={res.data.total}
            limit={LIMIT}
            offset={offset}
            onChange={(o) => {
              const n = new URLSearchParams(params);
              if (o) n.set("offset", String(o));
              else n.delete("offset");
              setParams(n, { replace: true });
            }}
          />
        </>
      )}
    </>
  );
}

// --- policies

const DAYS = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"];

function windowText(p: RemediationPolicy): string {
  const days = p.window_days?.length ? p.window_days.map((d) => DAYS[d - 1]).join(", ") : "any day";
  const hours = p.window_start ? `${p.window_start}–${p.window_end} ${p.timezone}` : "any time";
  return p.window_days?.length || p.window_start ? `${days}, ${hours}` : "Any time";
}

function scopeText(p: RemediationPolicy, teams: Team[]): ReactNode {
  const parts: string[] = [];
  parts.push((p.ecosystems ?? []).join(", ") || "no ecosystems");
  if (p.components?.length) parts.push(`components ${p.components.join(", ")}`);
  parts.push(p.environments?.length ? `envs ${p.environments.join(", ")}` : "all environments");
  if (p.team_ids?.length) parts.push(`teams ${p.team_ids.map((id) => teams.find((t) => t.id === id)?.name ?? `#${id}`).join(", ")}`);
  if (p.asset_tags?.length) parts.push(`tags ${p.asset_tags.join(", ")}`);
  parts.push(`${p.min_priority || "P4"} and above`);
  if (p.only_with_findings) parts.push("only with findings");
  return <span className="small break">{parts.join(" · ")}</span>;
}

function PoliciesTab() {
  const { can } = useAuth();
  const admin = can("admin");
  const res = useLoad(() => api.get<List<RemediationPolicy>>("/remediation/policies"), []);
  const teams = useLoad(() => api.get<List<Team>>("/teams"), []);
  const act = useAction();
  const [editing, setEditing] = useState<number | "new" | null>(null);
  const teamList = teams.data?.items ?? [];

  const remove = async (p: RemediationPolicy) => {
    if (!window.confirm(`Delete policy "${p.name}"? Its proposed, approved and in-progress plans are cancelled and nothing more is dispatched.`)) return;
    const ok = await act.run(() => api.del(`/remediation/policies/${p.id}`).then(() => true));
    if (ok) res.reload();
  };

  const cols: Column<RemediationPolicy>[] = [
    {
      key: "name",
      header: "Policy",
      cell: (p) => (
        <>
          <strong>{p.name}</strong>
          {p.description && <div className="muted small">{p.description}</div>}
        </>
      ),
    },
    { key: "enabled", header: "Status", cell: (p) => (p.enabled ? <Badge status="enabled" /> : <Badge status="disabled" />) },
    { key: "target", header: "Target", cell: (p) => <TargetLabel target={p.target} /> },
    { key: "scope", header: "Scope", cell: (p) => scopeText(p, teamList) },
    {
      key: "changes",
      header: "Change types",
      cell: (p) => (
        <span className="badges">
          {(p.change_types ?? []).map((c) => (
            <ChangeTypeBadge key={c} type={c} />
          ))}
        </span>
      ),
    },
    {
      key: "approval",
      header: "Approval",
      cell: (p) => (p.approval === "automatic" ? <Badge status="automatic" tone="warn" label="automatic" /> : <Badge status="required" tone="good" label="required" />),
    },
    { key: "window", header: "Window", cell: (p) => <span className="small">{windowText(p)}</span> },
  ];
  if (admin)
    cols.push({
      key: "actions",
      header: <span className="sr-only">Actions</span>,
      cell: (p) => (
        <div className="row-actions">
          <button type="button" className="btn btn-sm" onClick={() => setEditing(editing === p.id ? null : p.id)}>
            Edit
          </button>
          <button type="button" className="btn btn-sm btn-link-danger" disabled={act.pending} onClick={() => remove(p)}>
            Delete
          </button>
        </div>
      ),
    });
  const done = () => {
    setEditing(null);
    res.reload();
  };

  return (
    <>
      <SafetyNote />
      {!admin && <Notice kind="info">Read-only: only administrators can change remediation policies.</Notice>}
      {admin && editing !== "new" && (
        <p>
          <button type="button" className="btn btn-primary" onClick={() => setEditing("new")}>
            Add policy
          </button>
        </p>
      )}
      {editing === "new" && <PolicyForm teams={teamList} onCancel={() => setEditing(null)} onSaved={done} />}
      <ErrorBox error={act.error} title="Action failed" />
      <ErrorBox error={res.error} title="Could not load policies" />
      {!res.data && !res.error && <Loading />}
      {res.data && res.data.items.length === 0 && (
        <EmptyState title="No remediation policies" help="remediation-policy" helpLabel="Remediation policies, field by field">
          <p>Without a policy, Stackurity never proposes or applies changes. See docs/remediation.md for examples.</p>
        </EmptyState>
      )}
      {res.data && res.data.items.length > 0 && (
        <Table
          caption="Remediation policies"
          columns={cols}
          rows={res.data.items}
          rowKey={(p) => p.id}
          selectedKey={typeof editing === "number" ? editing : null}
          renderExpanded={(p) => <PolicyForm policy={p} teams={teamList} onCancel={() => setEditing(null)} onSaved={done} />}
          rowClassName={(p) => (!p.enabled ? "row-removed" : undefined)}
        />
      )}
    </>
  );
}

function listInput(v: string): string[] {
  return v
    .split(/[,\n]/)
    .map((x) => x.trim())
    .filter(Boolean);
}

function Checks<T extends string | number>({
  legend,
  options,
  value,
  onChange,
  label,
  hint,
}: {
  legend: string;
  options: T[];
  value: T[];
  onChange: (v: T[]) => void;
  label?: (x: T) => ReactNode;
  hint?: ReactNode;
}) {
  return (
    <fieldset className="field">
      <legend>{legend}</legend>
      <div className="multi">
        {options.length === 0 && <span className="muted small">none available</span>}
        {options.map((o) => (
          <label key={String(o)} className="check">
            <input
              type="checkbox"
              checked={value.includes(o)}
              onChange={() => onChange(value.includes(o) ? value.filter((x) => x !== o) : [...value, o])}
            />{" "}
            {label ? label(o) : String(o)}
          </label>
        ))}
      </div>
      {hint && <p className="hint">{hint}</p>}
    </fieldset>
  );
}

const EMPTY_POLICY: RemediationPolicy = {
  id: 0,
  name: "",
  description: "",
  enabled: false,
  target: "host_package",
  ecosystems: ["deb"],
  components: [],
  environments: [],
  team_ids: [],
  asset_tags: [],
  change_types: ["distro"],
  allow_major: false,
  min_priority: "P4",
  only_with_findings: true,
  approval: "required",
  window_days: [],
  window_start: "",
  window_end: "",
  timezone: "UTC",
  canary_count: 1,
  soak_minutes: 60,
  max_concurrent: 1,
  health_units: [],
  auto_rollback: false,
};

function PolicyForm({ policy, teams, onCancel, onSaved }: { policy?: RemediationPolicy; teams: Team[]; onCancel: () => void; onSaved: () => void }) {
  const facets = useFacets();
  const [p, setP] = useState<RemediationPolicy>(policy ? { ...policy } : { ...EMPTY_POLICY });
  const [components, setComponents] = useState((policy?.components ?? []).join("\n"));
  const [tags, setTags] = useState((policy?.asset_tags ?? []).join(", "));
  const [units, setUnits] = useState((policy?.health_units ?? []).join(", "));
  const [localErr, setLocalErr] = useState<string | null>(null);
  const act = useAction();
  const idp = policy ? `po${policy.id}` : "ponew";
  const set = <K extends keyof RemediationPolicy>(k: K, v: RemediationPolicy[K]) => setP({ ...p, [k]: v });
  const host = p.target === "host_package";
  const ecoOptions = host ? HOST_ECOSYSTEMS : REPO_ECOSYSTEMS;
  const envOptions = [...new Set([...(facets?.environments ?? []), ...(p.environments ?? [])])];
  const changeTypes = p.change_types ?? [];

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setLocalErr(null);
    if (changeTypes.includes("major") && (!p.allow_major || p.approval !== "required"))
      return setLocalErr("Major upgrades need “Allow major upgrades” and approval set to required.");
    if (Boolean(p.window_start) !== Boolean(p.window_end)) return setLocalErr("Set both window start and end, or neither.");
    const { id: _id, created_at: _c, updated_at: _u, ...rest } = p;
    void _id;
    void _c;
    void _u;
    const body = {
      ...rest,
      name: p.name.trim(),
      timezone: p.timezone.trim() || "UTC",
      ecosystems: (p.ecosystems ?? []).filter((x) => ecoOptions.includes(x)),
      components: listInput(components),
      asset_tags: listInput(tags),
      health_units: host ? listInput(units) : [],
      auto_rollback: host ? p.auto_rollback : false,
      environments: p.environments ?? [],
      team_ids: p.team_ids ?? [],
      window_days: p.window_days ?? [],
      change_types: changeTypes,
    };
    const ok = await act.run(() =>
      policy ? api.put<RemediationPolicy>(`/remediation/policies/${policy.id}`, body) : api.post<RemediationPolicy>("/remediation/policies", body),
    );
    if (ok) onSaved();
  };

  const form = (
    <form className="form" onSubmit={submit}>
      <ErrorBox error={act.error} title="Policy not saved" />
      {localErr && (
        <div className="alert alert-error" role="alert">
          {localErr}
        </div>
      )}
      <div className="form-grid">
        <div className="field">
          <label htmlFor={`${idp}-name`}>Name</label>
          <input id={`${idp}-name`} required value={p.name} onChange={(e) => set("name", e.target.value)} />
        </div>
        <div className="field field-span">
          <label htmlFor={`${idp}-desc`}>Description</label>
          <input id={`${idp}-desc`} value={p.description} onChange={(e) => set("description", e.target.value)} />
        </div>
        <div className="field">
          <label htmlFor={`${idp}-target`}>Target</label>
          <select
            id={`${idp}-target`}
            value={p.target}
            onChange={(e) => {
              const t = e.target.value as RemediationPolicy["target"];
              setP({ ...p, target: t, ecosystems: t === "host_package" ? ["deb"] : ["npm"], auto_rollback: t === "host_package" ? p.auto_rollback : false });
            }}
          >
            <option value="host_package">Host packages (agent applies them)</option>
            <option value="repository">Repositories (Renovate pull requests)</option>
          </select>
        </div>
        <div className="field">
          <label htmlFor={`${idp}-prio`}>Minimum finding priority</label>
          <select id={`${idp}-prio`} value={p.min_priority || "P4"} onChange={(e) => set("min_priority", e.target.value)}>
            {PRIORITIES.map((x) => (
              <option key={x} value={x}>
                {x} and above
              </option>
            ))}
          </select>
        </div>
        <div className="field">
          <label htmlFor={`${idp}-approval`}>Approval</label>
          <select id={`${idp}-approval`} value={p.approval} onChange={(e) => set("approval", e.target.value as RemediationPolicy["approval"])}>
            <option value="required">Required (a security or admin user approves each plan)</option>
            <option value="automatic">Automatic (plans start without approval)</option>
          </select>
          {p.approval === "automatic" && <p className="hint">Use automatic only for low-risk scopes, such as non-production backports.</p>}
        </div>
      </div>
      <div className="btn-group">
        <label className="check">
          <input type="checkbox" checked={p.enabled} onChange={(e) => set("enabled", e.target.checked)} /> Enabled
        </label>
        <label className="check">
          <input type="checkbox" checked={p.only_with_findings} onChange={(e) => set("only_with_findings", e.target.checked)} /> Only upgrade
          packages that have open findings
        </label>
      </div>

      <Checks
        legend="Ecosystems"
        options={ecoOptions}
        value={(p.ecosystems ?? []).filter((x) => ecoOptions.includes(x))}
        onChange={(v) => set("ecosystems", v)}
        hint={host ? "deb uses apt, rpm uses dnf, yum or zypper (chosen from the host's OS), apk uses apk." : "Changes are published as Renovate configuration."}
      />
      <div className="field">
        <label htmlFor={`${idp}-comp`}>Components (optional)</label>
        <textarea id={`${idp}-comp`} className="mono" rows={3} value={components} onChange={(e) => setComponents(e.target.value)} placeholder={host ? "pkg:deb/debian/libssl*\npkg:deb/debian/openssl" : "pkg:npm/lodash"} />
        <p className="hint">One versionless purl or glob per line. Empty means every package in the ecosystems above.</p>
      </div>

      <Checks
        legend="Change types"
        options={[...CHANGE_TYPES] as string[]}
        value={changeTypes}
        onChange={(v) => setP({ ...p, change_types: v, allow_major: v.includes("major") ? p.allow_major : false })}
        label={(c) => <span title={CHANGE_TYPE_HELP[c]}>{CHANGE_TYPE_LABEL[c]}</span>}
        hint="Security backport: same upstream version with a distribution fix (safest). Major upgrades can break compatibility."
      />
      {changeTypes.includes("major") && (
        <div className="alert alert-warn" role="note">
          <label className="check">
            <input
              type="checkbox"
              checked={p.allow_major}
              onChange={(e) => setP({ ...p, allow_major: e.target.checked, approval: e.target.checked ? "required" : p.approval })}
            />{" "}
            Allow major upgrades (separate explicit authorisation; approval stays required and only admins can approve)
          </label>
        </div>
      )}

      <Checks legend="Environments" options={envOptions} value={p.environments ?? []} onChange={(v) => set("environments", v)} hint="None ticked = all environments." />
      <Checks
        legend="Owner teams"
        options={teams.map((t) => t.id)}
        value={p.team_ids ?? []}
        onChange={(v) => set("team_ids", v)}
        label={(id) => teams.find((t) => t.id === id)?.name ?? `team #${id}`}
        hint="None ticked = all teams."
      />
      <div className="field">
        <label htmlFor={`${idp}-tags`}>Asset tags (optional)</label>
        <input id={`${idp}-tags`} value={tags} onChange={(e) => setTags(e.target.value)} placeholder="comma-separated; an asset with any of these tags matches" />
      </div>

      <Card title="Maintenance window">
        <Checks
          legend="Days"
          options={[1, 2, 3, 4, 5, 6, 7]}
          value={p.window_days ?? []}
          onChange={(v) => set("window_days", [...v].sort())}
          label={(d) => DAYS[d - 1]}
          hint="None ticked = any day."
        />
        <div className="form-grid">
          <div className="field">
            <label htmlFor={`${idp}-ws`}>From</label>
            <input id={`${idp}-ws`} type="time" value={p.window_start} onChange={(e) => set("window_start", e.target.value)} />
          </div>
          <div className="field">
            <label htmlFor={`${idp}-we`}>Until</label>
            <input id={`${idp}-we`} type="time" value={p.window_end} onChange={(e) => set("window_end", e.target.value)} />
          </div>
          <div className="field">
            <label htmlFor={`${idp}-tz`}>Time zone</label>
            <input id={`${idp}-tz`} value={p.timezone} onChange={(e) => set("timezone", e.target.value)} placeholder="UTC" />
            <p className="hint">IANA name, e.g. Europe/London.</p>
          </div>
        </div>
      </Card>

      <Card title="Rollout">
        <div className="form-grid">
          <div className="field">
            <label htmlFor={`${idp}-canary`}>Canary assets</label>
            <input id={`${idp}-canary`} type="number" min={0} value={String(p.canary_count)} onChange={(e) => set("canary_count", Math.max(0, Number(e.target.value) || 0))} />
            <p className="hint">Changed first (non-production and lower criticality first). 0 = no canary stage.</p>
          </div>
          <div className="field">
            <label htmlFor={`${idp}-soak`}>Soak time (minutes)</label>
            <input id={`${idp}-soak`} type="number" min={0} value={String(p.soak_minutes)} onChange={(e) => set("soak_minutes", Math.max(0, Number(e.target.value) || 0))} />
            <p className="hint">Wait after the canary succeeds before the rest.</p>
          </div>
          <div className="field">
            <label htmlFor={`${idp}-conc`}>Max concurrent changes</label>
            <input id={`${idp}-conc`} type="number" min={1} value={String(p.max_concurrent)} onChange={(e) => set("max_concurrent", Math.max(1, Number(e.target.value) || 1))} />
          </div>
        </div>
        {host ? (
          <>
            <div className="field">
              <label htmlFor={`${idp}-units`}>Health checks (systemd units)</label>
              <input id={`${idp}-units`} className="mono" value={units} onChange={(e) => setUnits(e.target.value)} placeholder="nginx.service, haproxy.service" />
              <p className="hint">Each must be active (systemctl is-active) after the change, or it counts as failed.</p>
            </div>
            <label className="check">
              <input type="checkbox" checked={p.auto_rollback} onChange={(e) => set("auto_rollback", e.target.checked)} /> Roll back automatically on
              failure (best effort: apt, dnf, yum and zypper, if the previous version is still available; not possible for apk)
            </label>
          </>
        ) : (
          <p className="hint">Repository changes are pull requests: review, tests and deployment approvals stay in your normal workflow.</p>
        )}
      </Card>

      <div className="form-actions">
        <button type="submit" className="btn btn-primary" disabled={act.pending}>
          {policy ? "Save policy" : "Create policy"}
        </button>
        <button type="button" className="btn" onClick={onCancel}>
          Cancel
        </button>
        {!policy && <span className="muted small">New policies start disabled; enable once reviewed.</span>}
      </div>
    </form>
  );
  return policy ? form : <Card title="Add remediation policy">{form}</Card>;
}
