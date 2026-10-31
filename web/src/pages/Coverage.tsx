import { useState } from "react";
import { Link } from "react-router";
import { api, type CoverageRow, type List, type Overview, type SecondCheckSummary } from "../api";
import { useLoad } from "../hooks";
import { Table } from "../components/Table";
import { Card, EmptyState, ErrorBox, Loading, PageHeader, Pager } from "../components/ui";
import { coverageColumns } from "./AssetDetail";
import { ASSET_STATE_MEANINGS, AssetStateBadge } from "../components/Coverage";
import { UncheckedBreakdown, useUnchecked } from "../components/Unchecked";

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
  const checks = useLoad(() => api.get<SecondCheckSummary>("/second-checks"), []);
  const unchecked = useUnchecked();

  return (
    <>
      <PageHeader help="coverage-intelligence"
        title="Coverage"
        sub="How far findings can be trusted, and what collectors checked on each asset. Unsupported, failed and skipped areas are not covered: components there are not in the inventory."
      />
      <h2 className="section-title">Components not checked, by who acts</h2>
      <Card>
        <ErrorBox error={unchecked.error} title="Could not load what was not checked" />
        {!unchecked.data && !unchecked.error && <Loading />}
        {unchecked.data && <UncheckedBreakdown u={unchecked.data} />}
        <p className="hint">Each asset's page shows the same split for that asset, and its Inventory tab marks every component that was not checked.</p>
      </Card>
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
        <p className="hint">Each asset's page shows its states and reasons.</p>
      </Card>
      <h2 className="section-title">Second check of high-impact findings</h2>
      <Card>
        <p className="small">
          P1, SOS, known exploited, regressed, unconfirmed and ambiguous findings are re-derived from the raw advisory record and the
          raw observed version by a separate, simpler code path. A disagreement marks the finding for review; its priority and alerts stay as they are.{" "}
          <Link to="/help/how-stackurity-knows">How Stackurity knows</Link>
        </p>
        <ErrorBox error={checks.error} title="Could not load second checks" />
        {checks.data && (
          <>
            <dl className="coverage-states">
              <div>
                <dt>
                  <Link to="/fixes/issues?second_check=disagreed">Disagreed</Link>{" "}
                  <span className="mono">{checks.data.disagreed.toLocaleString()}</span>
                </dt>
                <dd className="small">Open findings the second check derived differently. A person should look; they keep their priority.</dd>
              </div>
              <div>
                <dt>
                  <Link to="/fixes/issues?second_check=agreed">Agreed</Link> <span className="mono">{checks.data.agreed.toLocaleString()}</span>
                </dt>
                <dd className="small">Open findings the second check reached on its own.</dd>
              </div>
              <div>
                <dt>
                  <Link to="/fixes/issues?second_check=could_not_check">Could not check</Link>{" "}
                  <span className="mono">{checks.data.could_not_check.toLocaleString()}</span>
                </dt>
                <dd className="small">Versions or channels the simpler check does not read (pre-releases, SUSE, FIPS builds). Each says why.</dd>
              </div>
              <div>
                <dt>
                  Waiting <span className="mono">{checks.data.pending.toLocaleString()}</span>
                </dt>
                <dd className="small">Covered findings not checked yet. The check runs in the background, a batch each minute.</dd>
              </div>
            </dl>
            <p className="hint">{checks.data.logged_30d.toLocaleString()} disagreements logged in the last 30 days, kept for new matching tests.</p>
            {checks.data.recent.length > 0 && (
              <details>
                <summary>Latest disagreements ({checks.data.recent.length})</summary>
                <ul className="ref-list small">
                  {checks.data.recent.map((d) => (
                    <li key={d.id} className="break">
                      {d.finding_id ? <Link to={`/findings/${d.finding_id}`}>{d.key}</Link> : <span className="mono">{d.key}</span>}{" "}
                      <span className="mono">{d.purl}</span>:{" "}
                      {d.differences.map((x) => `${x.field.replace(/_/g, " ")} (matcher ${x.matcher}, second check ${x.independent})`).join("; ")}
                    </li>
                  ))}
                </ul>
              </details>
            )}
          </>
        )}
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
