import { Fragment, useEffect, useState } from "react";
import { Link, useSearchParams } from "react-router";
import { api, FINDING_STATES, PRIORITIES, SEVERITIES, VERIFICATIONS, type Finding, type FindingSummary, type List, type FixGroup } from "../api";
import { useAuth } from "../auth";
import { FindingActions } from "../components/Workflow";
import { useDebounced, useFacets, useLoad } from "../hooks";
import { humanize, plural } from "../format";
import { FindingCards, FindingsTable, FindingTiles, IntelBanners, PriorityTiles } from "../components/Findings";
import { EmptyState, ErrorBox, FilterPanel, Loading, PageHeader, Pager, PresetChips } from "../components/ui";

const LIMIT = 50;

/** Stored states under the names people see. */
const STATE_FILTER_LABEL: Record<string, string> = {
  new: "New",
  acknowledged: "To do",
  in_progress: "In progress",
  suppressed: "Snoozed",
  risk_accepted: "Accepted (ignored)",
};

/** Filters that the preset chips and the panel share, as URL parameters. */
const PARAMS = [
  "status",
  "kind",
  "severity",
  "verification",
  "second_check",
  "environment",
  "known_exploited",
  "q",
  "priority",
  "state",
  "sos",
  "overdue",
  "assignee_user",
  "assignee_team",
  "assignee",
  "incident_id",
  "key",
  "fix_group",
  "asset_id",
  "component_id",
  "resolved_within",
  "resolution_kind",
  "new_within",
] as const;

/** All issues: every finding, filterable, as a table on wide screens and cards on phones. */
export function IssuesPage() {
  const [params, setParams] = useSearchParams();
  const get = (k: string) => params.get(k) ?? "";
  const status = get("status") || "open";
  const severity = get("severity").split(",").filter(Boolean);
  const priority = get("priority").split(",").filter(Boolean);
  const byAsset = get("sort") === "asset";
  const fixGroup = get("fix_group");
  const assetId = get("asset_id");
  const groups = useLoad(() => api.get<List<FixGroup>>("/fix-groups", { asset_id: assetId, limit: 100 }), [assetId]);
  const { me, canAct } = useAuth();
  const myId = me?.user?.id ? String(me.user.id) : "";
  const mine = Boolean(myId) && get("assignee_user") === myId;
  const [selected, setSelected] = useState<Set<number>>(new Set());
  const offset = Number(get("offset")) || 0;
  const qParam = get("q");
  const [q, setQ] = useState(qParam);
  const dq = useDebounced(q);
  const facets = useFacets();

  const with_ = (patch: Record<string, string>) => {
    const next = new URLSearchParams(params);
    for (const [k, v] of Object.entries(patch)) {
      if (v) next.set(k, v);
      else next.delete(k);
    }
    if (!("offset" in patch)) next.delete("offset");
    return next;
  };
  const update = (patch: Record<string, string>) => setParams(with_(patch), { replace: true });
  useEffect(() => {
    if (dq !== qParam) update({ q: dq });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [dq]);
  useEffect(() => setQ(qParam), [qParam]);

  const query: Record<string, string> = {};
  for (const k of PARAMS) if (params.get(k)) query[k] = params.get(k)!;
  const queryKey = JSON.stringify(query) + (byAsset ? "|asset" : "");
  const summary = useLoad(() => api.get<FindingSummary>("/findings/summary"), []);
  const res = useLoad(
    () => api.get<List<Finding>>("/findings", { ...query, status, sort: byAsset ? "asset" : undefined, limit: LIMIT, offset }),
    [queryKey, status, offset],
  );

  // Selection is per result set; clear it whenever the filters or page change.
  const resultKey = params.toString();
  useEffect(() => setSelected(new Set()), [resultKey]);

  const toggle = (key: string, all: readonly string[], cur: string[], v: string) => {
    const set = new Set(cur);
    if (set.has(v)) set.delete(v);
    else set.add(v);
    update({ [key]: all.filter((x) => set.has(x)).join(",") });
  };

  // Presets: one tap each, and each is a shareable link.
  const presetIs = (p: Record<string, string>) => {
    const keys = PARAMS.filter((k) => params.get(k));
    return Object.keys(p).length === keys.length && Object.entries(p).every(([k, v]) => params.get(k) === v);
  };
  const preset = (p: Record<string, string>) => {
    const n = new URLSearchParams(p);
    if (byAsset) n.set("sort", "asset");
    return `/fixes/issues?${n.toString()}`;
  };
  const presets = [
    { label: "Open", p: {} as Record<string, string> },
    { label: "Urgent", p: { priority: "P1", state: "active" } },
    ...(myId ? [{ label: "Assigned to me", p: { assignee_user: myId } }] : []),
    { label: "New this week", p: { new_within: "7" } },
    { label: "Known exploited", p: { known_exploited: "true" } },
    { label: "Came back", p: { state: "regressed" } },
  ];
  // Panel filters: everything except the presets' own keys that are visible as chips.
  const active = PARAMS.filter((k) => params.get(k) && !(k === "status" && params.get(k) === "open")).length;
  const envs = [...(facets?.environments ?? [])];
  const environment = get("environment");
  if (environment && !envs.includes(environment)) envs.push(environment);
  const limitedTo = [
    assetId && `asset #${assetId}`,
    get("component_id") && `component #${get("component_id")}`,
    get("incident_id") && `incident #${get("incident_id")}`,
    get("key"),
    get("assignee_team") && `team #${get("assignee_team")}`,
    get("assignee_user") && !mine && `user #${get("assignee_user")}`,
    get("resolution_kind") && `closed as ${get("resolution_kind").split(",").map(humanize).join(" or ")}`,
  ].filter(Boolean);
  const rows = res.data?.items ?? [];
  const assetName = assetId ? rows[0]?.asset_name : undefined;

  return (
    <>
      <PageHeader
        help="findings"
        title="All issues"
        sub="Every known vulnerability and end-of-life release found in your assets, one per package. SOS first, then by priority."
      />
      {summary.data && <IntelBanners s={summary.data} />}
      {summary.data && (
        <details className="sev-tiles">
          <summary>Counts by priority and severity</summary>
          <PriorityTiles s={summary.data} />
          <FindingTiles s={summary.data} />
        </details>
      )}

      <PresetChips label="Presets" chips={presets.map((x) => ({ to: preset(x.p), label: x.label, active: presetIs(x.p) }))} />
      <div className="issues-toolbar">
        <FilterPanel
          active={active}
          onClear={() => {
            setQ("");
            setParams(byAsset ? new URLSearchParams({ sort: "asset" }) : new URLSearchParams(), { replace: true });
          }}
        >
          <div className="field">
            <label htmlFor="fd-q">Search</label>
            <input id="fd-q" type="search" placeholder="CVE, package, title or asset" value={q} onChange={(e) => setQ(e.target.value)} />
          </div>
          <div className="field">
            <label htmlFor="fd-status">Status</label>
            <select id="fd-status" value={status} onChange={(e) => update({ status: e.target.value === "open" ? "" : e.target.value, resolved_within: "" })}>
              <option value="open">Open</option>
              <option value="resolved">Fixed (resolved)</option>
              <option value="all">All</option>
            </select>
          </div>
          <div className="field">
            <label htmlFor="fd-state">Workflow state</label>
            <select id="fd-state" value={get("state")} onChange={(e) => update({ state: e.target.value })}>
              <option value="">Any state</option>
              <option value="active">Active (not snoozed or accepted)</option>
              {FINDING_STATES.map((x) => (
                <option key={x} value={x}>
                  {STATE_FILTER_LABEL[x] ?? x.replace(/_/g, " ")}
                </option>
              ))}
              <option value="regressed">Regressed (came back after a fix)</option>
            </select>
          </div>
          <div className="field">
            <label htmlFor="fd-group">Fix</label>
            <select id="fd-group" value={fixGroup} onChange={(e) => update({ fix_group: e.target.value })}>
              <option value="">Any fix</option>
              {fixGroup && !groups.data?.items.some((g) => g.id === fixGroup) && <option value={fixGroup}>{fixGroup}</option>}
              {groups.data?.items.map((g) => (
                <option key={g.id} value={g.id}>
                  {g.title}, {g.asset_name} ({g.finding_count})
                </option>
              ))}
            </select>
          </div>
          <fieldset className="field">
            <legend>Priority</legend>
            <div className="multi">
              {PRIORITIES.map((p) => (
                <label key={p} className="check">
                  <input type="checkbox" checked={priority.includes(p)} onChange={() => toggle("priority", PRIORITIES, priority, p)} /> {p}
                </label>
              ))}
            </div>
          </fieldset>
          <fieldset className="field">
            <legend>Severity</legend>
            <div className="multi">
              {SEVERITIES.map((s) => (
                <label key={s} className="check">
                  <input type="checkbox" checked={severity.includes(s)} onChange={() => toggle("severity", SEVERITIES, severity, s)} /> {s}
                </label>
              ))}
            </div>
          </fieldset>
          <div className="field">
            <label htmlFor="fd-kind">Kind</label>
            <select id="fd-kind" value={get("kind")} onChange={(e) => update({ kind: e.target.value })}>
              <option value="">All kinds</option>
              <option value="vulnerability">Vulnerability</option>
              <option value="end_of_life">End of life</option>
            </select>
          </div>
          <div className="field">
            <label htmlFor="fd-ver">Verification</label>
            <select id="fd-ver" value={get("verification")} onChange={(e) => update({ verification: e.target.value })}>
              <option value="">Any</option>
              {VERIFICATIONS.map((v) => (
                <option key={v} value={v}>
                  {v.replace(/_/g, " ")}
                </option>
              ))}
            </select>
          </div>
          <div className="field">
            <label htmlFor="fd-sc">Second check</label>
            <select id="fd-sc" value={get("second_check")} onChange={(e) => update({ second_check: e.target.value })}>
              <option value="">Any</option>
              <option value="disagreed">Disagreed</option>
              <option value="agreed">Agreed</option>
              <option value="could_not_check">Could not check</option>
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
          <div className="checks">
            <label className="check">
              <input type="checkbox" checked={get("sos") === "true"} onChange={(e) => update({ sos: e.target.checked ? "true" : "" })} /> SOS only
            </label>
            <label className="check">
              <input type="checkbox" checked={get("overdue") === "true"} onChange={(e) => update({ overdue: e.target.checked ? "true" : "" })} /> Overdue
            </label>
            <label className="check">
              <input
                type="checkbox"
                checked={get("assignee") === "none"}
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
              <input
                type="checkbox"
                checked={get("known_exploited") === "true"}
                onChange={(e) => update({ known_exploited: e.target.checked ? "true" : "" })}
              />{" "}
              Known exploited only
            </label>
          </div>
        </FilterPanel>
        <label className="check group-toggle">
          <input type="checkbox" checked={byAsset} onChange={(e) => update({ sort: e.target.checked ? "asset" : "" })} /> Group by asset
        </label>
      </div>
      {limitedTo.length > 0 && (
        <p className="chip limited-to">
          Limited to {assetName && assetId ? <Link to={`/assets/${assetId}`}>{assetName}</Link> : null}
          {assetName && limitedTo.length > 1 ? ", " : ""}
          {limitedTo.filter((x) => !(assetName && x === `asset #${assetId}`)).join(", ")}{" "}
          <button
            type="button"
            className="btn btn-sm btn-link"
            onClick={() =>
              update({ asset_id: "", component_id: "", incident_id: "", key: "", assignee_team: "", resolution_kind: "", assignee_user: mine ? get("assignee_user") : "" })
            }
          >
            Remove
          </button>
        </p>
      )}

      <ErrorBox error={res.error} title="Could not load issues" />
      {!res.data && !res.error && <Loading />}
      {res.data && (
        <p className="small muted result-count" aria-live="polite">
          {plural(res.data.total, status === "resolved" ? "fixed issue" : "issue")}
          {res.loading ? ", updating" : ""}
        </p>
      )}
      {res.data && rows.length === 0 && (
        <EmptyState title={active ? "No issues match these filters" : "No open issues"}>
          <p>
            {active
              ? "Try clearing a filter."
              : "Nothing in the inventory matched a known vulnerability or end-of-life release. That only covers what was inventoried and checked; see Coverage and Intelligence for gaps."}
          </p>
        </EmptyState>
      )}
      {res.data && rows.length > 0 && (
        <>
          {canAct("viewer") && selected.size > 0 && (
            <div className="bulkbar" role="region" aria-label="Bulk actions">
              <strong>{selected.size} selected</strong>
              <FindingActions
                target={{ type: "bulk", ids: [...selected] }}
                onDone={() => {
                  res.reload();
                  summary.reload();
                }}
                compact
              />
              <button type="button" className="btn btn-sm btn-link" onClick={() => setSelected(new Set())}>
                Clear selection
              </button>
            </div>
          )}
          {byAsset ? (
            groupByAsset(rows).map(([id, name, list]) => (
              <Fragment key={id}>
                <h2 className="asset-group-head">
                  <Link to={`/assets/${id}`}>{name}</Link>{" "}
                  <Link to={`/fixes/issues?${with_({ asset_id: String(id), sort: "" }).toString()}`} className="small">
                    only this asset
                  </Link>
                </h2>
                <div className="only-wide">
                  <FindingsTable rows={list} hideAsset selected={canAct("viewer") ? selected : undefined} onSelect={setSelected} />
                </div>
                <FindingCards rows={list} hideAsset />
              </Fragment>
            ))
          ) : (
            <>
              <div className="only-wide">
                <FindingsTable rows={rows} selected={canAct("viewer") ? selected : undefined} onSelect={setSelected} />
              </div>
              <FindingCards rows={rows} />
            </>
          )}
          <Pager total={res.data.total} limit={LIMIT} offset={offset} onChange={(o) => update({ offset: o ? String(o) : "" })} />
        </>
      )}
    </>
  );
}

function groupByAsset(rows: Finding[]): [number, string, Finding[]][] {
  const out: [number, string, Finding[]][] = [];
  for (const f of rows) {
    const last = out[out.length - 1];
    if (last && last[0] === f.asset_id) last[2].push(f);
    else out.push([f.asset_id, f.asset_name, [f]]);
  }
  return out;
}
