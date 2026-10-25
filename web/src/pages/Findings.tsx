import { useEffect, useState } from "react";
import { useSearchParams } from "react-router";
import { api, FINDING_STATES, PRIORITIES, SEVERITIES, VERIFICATIONS, type Finding, type FindingSummary, type List, type FixGroup } from "../api";
import { useAuth } from "../auth";
import { FindingActions } from "../components/Workflow";
import { useDebounced, useFacets, useLoad } from "../hooks";
import { FindingTiles, FindingsTable, IntelBanners, PriorityTiles } from "../components/Findings";
import { EmptyState, ErrorBox, Loading, PageHeader, Pager } from "../components/ui";

const LIMIT = 50;

export function FindingsPage() {
  const [params, setParams] = useSearchParams();
  const status = params.get("status") ?? "open";
  const kind = params.get("kind") ?? "";
  const severity = (params.get("severity") ?? "").split(",").filter(Boolean);
  const verification = params.get("verification") ?? "";
  const environment = params.get("environment") ?? "";
  const exploited = params.get("known_exploited") === "true";
  const qParam = params.get("q") ?? "";
  const priority = (params.get("priority") ?? "").split(",").filter(Boolean);
  const state = params.get("state") ?? "";
  const sos = params.get("sos") === "true";
  const overdue = params.get("overdue") === "true";
  const assigneeUser = params.get("assignee_user") ?? "";
  const assigneeTeam = params.get("assignee_team") ?? "";
  const unassigned = params.get("assignee") === "none";
  const incidentId = params.get("incident_id") ?? "";
  const keyParam = params.get("key") ?? "";
  const fixGroup = params.get("fix_group") ?? "";
  const groups = useLoad(() => api.get<List<FixGroup>>("/fix-groups", { asset_id: params.get("asset_id") ?? "", limit: 100 }), [params.get("asset_id")]);
  const { me, can } = useAuth();
  const myId = me?.user?.id ? String(me.user.id) : "";
  const mine = Boolean(myId) && assigneeUser === myId;
  const [selected, setSelected] = useState<Set<number>>(new Set());
  const assetId = params.get("asset_id") ?? "";
  const componentId = params.get("component_id") ?? "";
  const offset = Number(params.get("offset") ?? 0) || 0;
  const [q, setQ] = useState(qParam);
  const dq = useDebounced(q);
  const facets = useFacets();

  const update = (patch: Record<string, string>) => {
    const next = new URLSearchParams(params);
    for (const [k, v] of Object.entries(patch)) {
      if (v) next.set(k, v);
      else next.delete(k);
    }
    if (!("offset" in patch)) next.delete("offset");
    setParams(next, { replace: true });
  };
  useEffect(() => {
    if (dq !== qParam) update({ q: dq });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [dq]);
  useEffect(() => setQ(qParam), [qParam]);

  const sevKey = severity.join(",");
  const prioKey = priority.join(",");
  const summary = useLoad(() => api.get<FindingSummary>("/findings/summary"), []);
  const res = useLoad(
    () =>
      api.get<List<Finding>>("/findings", {
        status,
        kind,
        severity: sevKey,
        verification,
        environment,
        known_exploited: exploited ? "true" : undefined,
        q: qParam,
        asset_id: assetId,
        component_id: componentId,
        priority: prioKey,
        state,
        sos: sos ? "true" : undefined,
        overdue: overdue ? "true" : undefined,
        assignee_user: assigneeUser,
        assignee_team: assigneeTeam,
        assignee: unassigned ? "none" : undefined,
        incident_id: incidentId,
        key: keyParam,
        fix_group: fixGroup,
        limit: LIMIT,
        offset,
      }),
    [status, kind, sevKey, verification, environment, exploited, qParam, assetId, componentId, prioKey, state, sos, overdue, assigneeUser, assigneeTeam, unassigned, incidentId, keyParam, fixGroup, offset],
  );

  // Selection is per result set; clear it whenever the filters or page change.
  const resultKey = params.toString();
  useEffect(() => setSelected(new Set()), [resultKey]);

  const togglePrio = (p: string) => {
    const set = new Set(priority);
    if (set.has(p)) set.delete(p);
    else set.add(p);
    update({ priority: PRIORITIES.filter((x) => set.has(x)).join(",") });
  };

  const toggleSev = (s: string) => {
    const set = new Set(severity);
    if (set.has(s)) set.delete(s);
    else set.add(s);
    update({ severity: SEVERITIES.filter((x) => set.has(x)).join(",") });
  };
  const filtered = Boolean(
    kind ||
      severity.length ||
      verification ||
      environment ||
      exploited ||
      qParam ||
      assetId ||
      componentId ||
      status !== "open" ||
      priority.length ||
      state ||
      sos ||
      overdue ||
      assigneeUser ||
      assigneeTeam ||
      unassigned ||
      keyParam ||
      fixGroup ||
      incidentId,
  );
  const envs = [...(facets?.environments ?? [])];
  if (environment && !envs.includes(environment)) envs.push(environment);

  return (
    <>
      <PageHeader help="findings"
        title="Findings"
        sub="Known vulnerabilities and end-of-life software matched against your inventory. SOS first, then by priority."
      />
      <ErrorBox error={summary.error} title="Could not load summary" />
      {summary.data && (
        <>
          <IntelBanners s={summary.data} />
          <PriorityTiles s={summary.data} />
          <details className="sev-tiles">
            <summary>By severity</summary>
            <FindingTiles s={summary.data} />
          </details>
        </>
      )}

      <form className="filters" role="search" onSubmit={(e) => e.preventDefault()}>
        <div className="field">
          <label htmlFor="fd-q">Search</label>
          <input id="fd-q" type="search" placeholder="CVE, package, title or asset" value={q} onChange={(e) => setQ(e.target.value)} />
        </div>
        <div className="field">
          <label htmlFor="fd-status">Status</label>
          <select id="fd-status" value={status} onChange={(e) => update({ status: e.target.value === "open" ? "" : e.target.value })}>
            <option value="open">Open</option>
            <option value="resolved">Resolved</option>
            <option value="all">All</option>
          </select>
        </div>
        <div className="field">
          <label htmlFor="fd-state">Workflow state</label>
          <select id="fd-state" value={state} onChange={(e) => update({ state: e.target.value })}>
            <option value="">Any state</option>
            <option value="active">Active (not suppressed or accepted)</option>
            {FINDING_STATES.map((x) => (
              <option key={x} value={x}>
                {x.replace(/_/g, " ")}
              </option>
            ))}
          </select>
        </div>
        <div className="field">
          <label htmlFor="fd-group">Fix group</label>
          <select id="fd-group" value={fixGroup} onChange={(e) => update({ fix_group: e.target.value })}>
            <option value="">Any group</option>
            {fixGroup && !groups.data?.items.some((g) => g.id === fixGroup) && <option value={fixGroup}>{fixGroup}</option>}
            {groups.data?.items.map((g) => (
              <option key={g.id} value={g.id}>
                {g.title} — {g.asset_name} ({g.finding_count})
              </option>
            ))}
          </select>
        </div>
        <fieldset className="field">
          <legend>Priority</legend>
          <div className="multi">
            {PRIORITIES.map((p) => (
              <label key={p} className="check">
                <input type="checkbox" checked={priority.includes(p)} onChange={() => togglePrio(p)} /> {p}
              </label>
            ))}
          </div>
        </fieldset>
        <div className="field">
          <label htmlFor="fd-kind">Kind</label>
          <select id="fd-kind" value={kind} onChange={(e) => update({ kind: e.target.value })}>
            <option value="">All kinds</option>
            <option value="vulnerability">Vulnerability</option>
            <option value="end_of_life">End of life</option>
          </select>
        </div>
        <fieldset className="field">
          <legend>Severity</legend>
          <div className="multi">
            {SEVERITIES.map((s) => (
              <label key={s} className="check">
                <input type="checkbox" checked={severity.includes(s)} onChange={() => toggleSev(s)} /> {s}
              </label>
            ))}
          </div>
        </fieldset>
        <div className="field">
          <label htmlFor="fd-ver">Verification</label>
          <select id="fd-ver" value={verification} onChange={(e) => update({ verification: e.target.value })}>
            <option value="">Any</option>
            {VERIFICATIONS.map((v) => (
              <option key={v} value={v}>
                {v.replace(/_/g, " ")}
              </option>
            ))}
          </select>
        </div>
        <div className="field">
          <label htmlFor="fd-env">Environment</label>
          <select id="fd-env" value={environment} onChange={(e) => update({ environment: e.target.value })}>
            <option value="">Any environment</option>
            {envs.map((x) => (
              <option key={x} value={x}>
                {x}
              </option>
            ))}
          </select>
        </div>
        <label className="check">
          <input type="checkbox" checked={sos} onChange={(e) => update({ sos: e.target.checked ? "true" : "" })} /> SOS only
        </label>
        <label className="check">
          <input type="checkbox" checked={overdue} onChange={(e) => update({ overdue: e.target.checked ? "true" : "" })} /> Overdue
        </label>
        <label className="check">
          <input
            type="checkbox"
            checked={unassigned}
            onChange={(e) => update({ assignee: e.target.checked ? "none" : "", assignee_user: "", assignee_team: "" })}
          />{" "}
          Unassigned
        </label>
        {myId && (
          <label className="check">
            <input type="checkbox" checked={mine} onChange={(e) => update({ assignee_user: e.target.checked ? myId : "" })} /> Assigned to me
          </label>
        )}
        <label className="check">
          <input type="checkbox" checked={exploited} onChange={(e) => update({ known_exploited: e.target.checked ? "true" : "" })} /> Known
          exploited only
        </label>
        {(assetId || componentId || incidentId || keyParam || assigneeTeam || (assigneeUser && !mine)) && (
          <span className="chip">
            Limited to{" "}
            {[
              assetId && `asset #${assetId}`,
              componentId && `component #${componentId}`,
              incidentId && `incident #${incidentId}`,
              keyParam && keyParam,
              assigneeTeam && `team #${assigneeTeam}`,
              assigneeUser && !mine && `user #${assigneeUser}`,
            ]
              .filter(Boolean)
              .join(", ")}{" "}
            <button
              type="button"
              className="btn btn-sm btn-link"
              onClick={() => update({ asset_id: "", component_id: "", incident_id: "", key: "", assignee_team: "", assignee_user: mine ? assigneeUser : "" })}
            >
              Remove
            </button>
          </span>
        )}
        {filtered && (
          <button
            type="button"
            className="btn btn-link"
            onClick={() => {
              setQ("");
              setParams(new URLSearchParams(), { replace: true });
            }}
          >
            Clear filters
          </button>
        )}
      </form>

      <ErrorBox error={res.error} title="Could not load findings" />
      {!res.data && !res.error && <Loading />}
      {res.data && res.data.items.length === 0 && (
        <EmptyState title={filtered ? "No findings match these filters" : "No open findings"}>
          <p>
            {filtered
              ? "Try clearing a filter."
              : "Nothing in the inventory matched a known vulnerability or end-of-life release. That only covers what was inventoried and evaluated — check Coverage and Intelligence for gaps."}
          </p>
        </EmptyState>
      )}
      {res.data && res.data.items.length > 0 && (
        <>
          {can("engineer") && selected.size > 0 && (
            <div className="bulkbar" role="region" aria-label="Bulk actions">
              <strong>{selected.size} selected</strong>
              <FindingActions target={{ type: "bulk", ids: [...selected] }} onDone={() => { res.reload(); summary.reload(); }} compact />
              <button type="button" className="btn btn-sm btn-link" onClick={() => setSelected(new Set())}>
                Clear selection
              </button>
            </div>
          )}
          <FindingsTable rows={res.data.items} selected={can("engineer") ? selected : undefined} onSelect={setSelected} />
          <Pager total={res.data.total} limit={LIMIT} offset={offset} onChange={(o) => update({ offset: o ? String(o) : "" })} />
        </>
      )}
    </>
  );
}
