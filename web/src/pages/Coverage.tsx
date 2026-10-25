import { useState } from "react";
import { Link } from "react-router";
import { api, type CoverageRow, type List, type Overview } from "../api";
import { useLoad } from "../hooks";
import { Table } from "../components/Table";
import { Card, EmptyState, ErrorBox, Loading, PageHeader, Pager } from "../components/ui";
import { coverageColumns } from "./AssetDetail";
import { ASSET_STATE_MEANINGS, AssetStateBadge } from "../components/Coverage";

const LIMIT = 100;

export function CoveragePage() {
  const [problems, setProblems] = useState(true);
  const [offset, setOffset] = useState(0);
  const res = useLoad(
    () => api.get<List<CoverageRow>>("/coverage", { problems: problems ? "true" : undefined, limit: LIMIT, offset }),
    [problems, offset],
  );
  const overview = useLoad(() => api.get<Overview>("/overview"), []);
  const states = overview.data?.asset_coverage ?? {};

  return (
    <>
      <PageHeader help="coverage-intelligence"
        title="Coverage"
        sub="How far findings can be trusted, and what collectors checked on each asset. Unsupported, failed and skipped areas are not covered: components there are not in the inventory."
      />
      <h2 className="section-title">Assets by coverage state</h2>
      <Card>
        <dl className="coverage-states">
          {ASSET_STATE_MEANINGS.map(([state, meaning]) => (
            <div key={state}>
              <dt>
                <AssetStateBadge state={state} /> <span className="mono">{(states[state] ?? 0).toLocaleString()}</span>
              </dt>
              <dd className="small">{meaning}</dd>
            </div>
          ))}
        </dl>
        <p className="hint">
          Each asset's page shows its states and reasons, and its Inventory tab marks every component that could not be checked.
          Components that could not be checked are listed on the <Link to="/intelligence#gaps">Intelligence page</Link>.
        </p>
      </Card>
      <h2 className="section-title">Collector scopes</h2>
      <div className="filters">
        <label className="check">
          <input
            type="checkbox"
            checked={problems}
            onChange={(e) => {
              setProblems(e.target.checked);
              setOffset(0);
            }}
          />{" "}
          Problems only (hide checked)
        </label>
      </div>
      <ErrorBox error={res.error} title="Could not load coverage" />
      {!res.data && !res.error && <Loading />}
      {res.data && res.data.items.length === 0 && (
        <EmptyState title={problems ? "No coverage problems" : "No coverage recorded yet"}>
          {problems ? (
            <p>Every recorded scope was checked successfully. Untick “Problems only” to see them.</p>
          ) : (
            <p>Coverage rows appear after the first collection.</p>
          )}
        </EmptyState>
      )}
      {res.data && res.data.items.length > 0 && (
        <>
          <Table
            caption="Coverage"
            columns={coverageColumns(true)}
            rows={res.data.items}
            rowKey={(r) => `${r.asset_id}|${r.collector_id}|${r.scope}`}
            rowClassName={(r) => (r.status === "failed" ? "row-stale" : undefined)}
          />
          <Pager total={res.data.total} limit={LIMIT} offset={offset} onChange={setOffset} />
        </>
      )}
    </>
  );
}
