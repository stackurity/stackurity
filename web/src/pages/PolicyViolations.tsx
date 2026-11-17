import { Link, useSearchParams } from "react-router";
import { api, type GatePolicyList, type GateViolation, type List } from "../api";
import { useAuth } from "../auth";
import { gateViolationsEmpty } from "../emptyCopy";
import { activeFilters, withoutFilter, withoutFilters, type FilterDef } from "../filterChips";
import { useLoad } from "../hooks";
import { filterViolations, GATE_KINDS, kindLabel, MODE_LABELS, violationTotals } from "../policyGates";
import { FilterChips, TableToolbar } from "../components/FilterChips";
import { ModeBadge } from "../components/PolicyGates";
import { TableSkeleton } from "../components/Skeleton";
import { Table, type Column } from "../components/Table";
import { EmptyState, ErrorBox, PageHeader } from "../components/ui";

/** The page's filters: policy, asset and project go to the server; mode and rule are applied here. */
export function violationFilterDefs(names: { policy: (id: string) => string; asset: (id: string) => string; project: (id: string) => string }): FilterDef[] {
  return [
    { key: "policy_id", label: "Policy", format: names.policy },
    { key: "asset_id", label: "Asset", format: names.asset },
    { key: "project_id", label: "Project", format: names.project },
    { key: "mode", label: "Mode", format: (v) => MODE_LABELS[v as keyof typeof MODE_LABELS] ?? v },
    { key: "kind", label: "Rule", format: kindLabel },
  ];
}

const plural = (n: number, w: string, many = w + "s") => `${n.toLocaleString()} ${n === 1 ? w : many}`;

/** What the table and the phone list show: rendered by tests as is. */
export function ViolationsTable({ rows }: { rows: GateViolation[] }) {
  const columns: Column<GateViolation>[] = [
    {
      key: "policy",
      header: "Policy",
      cell: (v) => (
        <>
          <Link to={`/fixes/policy-violations?policy_id=${v.policy_id}`}>{v.policy_name}</Link>
          <div className="small muted">{kindLabel(v.kind)}</div>
        </>
      ),
    },
    { key: "mode", header: "Mode", cell: (v) => <ModeBadge mode={v.mode} /> },
    { key: "asset", header: "Asset", cell: (v) => <Link to={`/assets/${v.asset_id}`}>{v.asset_name}</Link> },
    { key: "component", header: "Component", cell: (v) => v.component || <span className="muted">-</span> },
    { key: "reason", header: "Why it fails", cell: (v) => <span className="small">{v.reason}</span> },
    {
      key: "actions",
      header: <span className="sr-only">Open</span>,
      cell: (v) =>
        v.link ? (
          <Link className="btn btn-sm" to={v.link}>
            {v.leak_id ? "Open the key" : "Open the issue"}
          </Link>
        ) : null,
    },
  ];
  return (
    <>
      <div className="only-wide">
        <Table caption="Policy violations" columns={columns} rows={rows} rowKey={(v) => `${v.policy_id}:${v.violation_key}:${v.asset_id}`} />
      </div>
      <ul className="approval-list only-narrow" aria-label="Policy violations">
        {rows.map((v) => (
          <li key={`${v.policy_id}:${v.violation_key}:${v.asset_id}`} className="approval">
            <h3 className="badges">
              <ModeBadge mode={v.mode} />
              <Link to={`/fixes/policy-violations?policy_id=${v.policy_id}`} className="break">
                {v.policy_name}
              </Link>
            </h3>
            <p className="small">{v.reason}</p>
            <p className="small muted">
              <Link to={`/assets/${v.asset_id}`}>{v.asset_name}</Link>
              {v.component && <> · {v.component}</>}
              {v.link && (
                <>
                  {" · "}
                  <Link to={v.link}>{v.leak_id ? "Open the key" : "Open the issue"}</Link>
                </>
              )}
            </p>
          </li>
        ))}
      </ul>
    </>
  );
}

/**
 * Fixes → Policy violations: every current violation of a policy gate that
 * is not off, worked out now from the findings and leaked keys. Requests
 * for an exception will start from a row here (a later release).
 */
export function PolicyViolationsPage() {
  const { can, me } = useAuth();
  const [params, setParams] = useSearchParams();
  const get = (k: string) => params.get(k) ?? "";
  const server = { policy_id: get("policy_id"), asset_id: get("asset_id"), project_id: get("project_id") };
  const res = useLoad(() => api.get<List<GateViolation>>("/gate-policies/violations", server), [server.policy_id, server.asset_id, server.project_id]);
  const policies = useLoad(() => api.getAll<GatePolicyList>("/gate-policies"), []);
  const policyName = (id: string) => policies.data?.items.find((p) => String(p.id) === id)?.name ?? `#${id}`;
  const assetName = (id: string) => res.data?.items.find((v) => String(v.asset_id) === id)?.asset_name ?? `#${id}`;
  const projectName = (id: string) => me?.projects?.find((p) => String(p.id) === id)?.name ?? `#${id}`;
  const defs = violationFilterDefs({ policy: policyName, asset: assetName, project: projectName });
  const chips = activeFilters(params, defs);
  const update = (k: string, v: string) => {
    const next = new URLSearchParams(params);
    if (v) next.set(k, v);
    else next.delete(k);
    setParams(next, { replace: true });
  };
  const rows = res.data ? filterViolations(res.data.items, { mode: get("mode"), kind: get("kind") }) : [];
  const t = violationTotals(rows);
  const on = policies.data ? policies.data.items.filter((p) => p.mode !== "off").length : undefined;

  return (
    <>
      <PageHeader
        title="Policy violations"
        sub={
          <>
            Every asset that breaks a policy gate right now, with the reason and the issue to fix. Policies are set under{" "}
            <Link to="/settings/policy-gates">Settings → Policy gates</Link>.
          </>
        }
      />
      <form className="filters" onSubmit={(e) => e.preventDefault()}>
        <div className="field">
          <label htmlFor="pv-policy">Policy</label>
          <select id="pv-policy" value={get("policy_id")} onChange={(e) => update("policy_id", e.target.value)}>
            <option value="">Every policy</option>
            {(policies.data?.items ?? []).map((p) => (
              <option key={p.id} value={p.id}>
                {p.name}
              </option>
            ))}
          </select>
        </div>
        <div className="field">
          <label htmlFor="pv-mode">Mode</label>
          <select id="pv-mode" value={get("mode")} onChange={(e) => update("mode", e.target.value)}>
            <option value="">Warn and enforce</option>
            <option value="warn">Warn</option>
            <option value="enforce">Enforce</option>
          </select>
        </div>
        <div className="field">
          <label htmlFor="pv-kind">Rule</label>
          <select id="pv-kind" value={get("kind")} onChange={(e) => update("kind", e.target.value)}>
            <option value="">Every rule</option>
            {GATE_KINDS.map((k) => (
              <option key={k.value} value={k.value}>
                {k.label}
              </option>
            ))}
          </select>
        </div>
      </form>
      <TableToolbar>
        <FilterChips
          filters={chips}
          onRemove={(k) => setParams(withoutFilter(params, k), { replace: true })}
          onClear={() => setParams(withoutFilters(params, defs), { replace: true })}
        />
      </TableToolbar>
      <ErrorBox error={res.error} title="Could not load the violations" />
      {!res.data && !res.error && <TableSkeleton label="Loading violations…" columns={6} />}
      {res.data && rows.length === 0 && (
        <EmptyState
          {...gateViolationsEmpty({ policies: on, filtered: chips.length > 0 }, can("admin"))}
          action={
            chips.length > 0
              ? { label: "Clear filters", permitted: true, onClick: () => setParams(withoutFilters(params, defs), { replace: true }) }
              : gateViolationsEmpty({ policies: on, filtered: false }, can("admin")).action
          }
        />
      )}
      {rows.length > 0 && (
        <>
          <p className="small muted" role="status">
            {plural(t.violations, "violation")} on {plural(t.assets, "asset")}, from {plural(t.policies, "policy", "policies")}
            {t.enforced > 0 && <>; {plural(t.enforced, "violation")} of policies in enforce mode</>}.
          </p>
          <ViolationsTable rows={rows} />
        </>
      )}
    </>
  );
}
