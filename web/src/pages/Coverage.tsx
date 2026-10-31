import { useState } from "react";
import { Link, useSearchParams } from "react-router";
import {
  api,
  type AssetCoverageGroup,
  type AssetCoverageList,
  type CoverageOverview,
  type CoverageRow,
  type EcosystemCoverage,
  type InventoryRow,
  type List,
  type Overview,
  type SecondCheckSummary,
} from "../api";
import { useAuth } from "../auth";
import { useLoad } from "../hooks";
import { Table } from "../components/Table";
import { EmptyState, ErrorBox, Loading, PageHeader, Pager } from "../components/ui";
import { coverageColumns } from "./AssetDetail";
import { useUnchecked } from "../components/Unchecked";
import { group } from "../unchecked";
import { notReportingText } from "../reporting";
import { actionCards, headline, reportingLine } from "../coverage";
import {
  ActionCards,
  AssetCoverageTable,
  CoverageHeadline,
  EcosystemGrid,
  GroupChips,
  ProblemScopes,
  SECTION_ICONS,
  Section,
  SecondCheckPanel,
} from "../components/CoverageParts";

const ASSETS = 50;
const ROWS = 200;

/**
 * Coverage: one answer at the top (the share of components checked, as one
 * segmented bar), then what the user can fix, what Stackurity checks per
 * ecosystem, each asset worst first, and how findings are verified.
 */
export function CoveragePage() {
  const { can } = useAuth();
  const [params, setParams] = useSearchParams();
  const groupParam = (params.get("group") ?? "") as AssetCoverageGroup | "";
  const offset = Number(params.get("offset") ?? 0) || 0;
  const showScopes = params.get("scopes") === "all";
  const setParam = (patch: Record<string, string>) => {
    const next = new URLSearchParams(params);
    for (const [k, v] of Object.entries(patch)) {
      if (v) next.set(k, v);
      else next.delete(k);
    }
    setParams(next, { replace: true });
  };

  const ov = useLoad(() => api.get<CoverageOverview>("/coverage/overview"), []);
  const overview = useLoad(() => api.get<Overview>("/overview"), []);
  const unchecked = useUnchecked();
  const u = unchecked.data;
  const hasRows = !!(group(u, "unreadable_version") || group(u, "other"));
  const hasFiles = !!group(u, "unreadable_files");
  const needRows = useLoad(
    () =>
      hasRows
        ? Promise.all(
            (["unreadable_version", "other"] as const).map((x) => api.get<List<InventoryRow>>("/inventory", { unchecked: x, limit: ROWS })),
          ).then((ls) => ls.flatMap((l) => l.items))
        : Promise.resolve([] as InventoryRow[]),
    [hasRows],
  );
  const fileScopes = useLoad(
    () => (hasFiles ? api.get<List<CoverageRow>>("/coverage", { problems: "true", limit: 500 }).then((l) => l.items) : Promise.resolve([] as CoverageRow[])),
    [hasFiles],
  );
  const assets = useLoad(
    () => api.get<AssetCoverageList>("/coverage/assets", { group: groupParam || undefined, limit: ASSETS, offset }),
    [groupParam, offset],
  );
  const checks = useLoad(() => api.get<SecondCheckSummary>("/second-checks"), []);

  const [pending, setPending] = useState<string | null>(null);
  const [requestError, setRequestError] = useState<unknown>(null);
  const request = async (e: EcosystemCoverage) => {
    setPending(e.key);
    setRequestError(null);
    try {
      await api.post("/coverage/support-requests", { ecosystem: e.key });
      ov.reload();
    } catch (err) {
      setRequestError(err);
    } finally {
      setPending(null);
    }
  };

  const cards = u ? actionCards(u, needRows.data ?? [], fileScopes.data ?? []) : [];
  const cardsReady = !!u && !needRows.loading && !fileScopes.loading;

  return (
    <div className="cov-page">
      <PageHeader help="coverage-intelligence" title="Coverage" />
      <ErrorBox error={ov.error} title="Could not load coverage" />
      {!ov.data && !ov.error && <Loading />}
      {ov.data && (
        <CoverageHeadline
          h={headline(ov.data)}
          reporting={reportingLine(overview.data?.asset_status)}
          notReporting={notReportingText(overview.data?.not_reporting)}
        />
      )}

      <Section id="needs-you" className="cov-actions-section" icon={SECTION_ICONS.actions} title="Fix these to see everything"
        aside={cards.length > 0 ? <span className="cov-count">{cards.length}</span> : undefined}>
        <ErrorBox error={unchecked.error ?? needRows.error ?? fileScopes.error} title="Could not load what needs you" />
        {!cardsReady && !unchecked.error ? <Loading /> : <ActionCards cards={cards} />}
      </Section>

      <Section id="cov-ecosystems" className="cov-eco-section" icon={SECTION_ICONS.ecosystems} title="What Stackurity checks on your estate">
        {ov.data && <EcosystemGrid ecosystems={ov.data.ecosystems} onRequest={request} pending={pending} />}
        {requestError != null && <p className="small text-bad" role="alert">Could not send the request. Try again.</p>}
      </Section>

      <Section
        id="cov-assets"
        className="cov-assets-section"
        icon={SECTION_ICONS.assets}
        title="Coverage by asset"
        aside={
          can("admin") ? (
            <Link to={showScopes ? "/coverage" : "/coverage?scopes=all#cov-scopes"} className="small">
              {showScopes ? "Hide all scopes" : "Show all scopes"}
            </Link>
          ) : undefined
        }
      >
        <ErrorBox error={assets.error} title="Could not load assets" />
        {!assets.data && !assets.error && <Loading />}
        {assets.data && (
          <>
            <GroupChips groups={assets.data.groups} active={groupParam} onChange={(g) => setParam({ group: g, offset: "" })} />
            {assets.data.total === 0 && !groupParam ? (
              <EmptyState title="No assets yet">
                <p>
                  Assets appear here after their first report. <Link to="/assets/add">Add an asset</Link>
                </p>
              </EmptyState>
            ) : (
              <>
                <AssetCoverageTable list={assets.data} renderProblems={(a) => <AssetProblems assetId={a.id} />} />
                <Pager total={assets.data.total} limit={ASSETS} offset={offset} onChange={(o) => setParam({ offset: o ? String(o) : "" })} />
              </>
            )}
          </>
        )}
      </Section>

      <div className="cov-verify-section">
        <ErrorBox error={checks.error} title="Could not load second checks" />
        <SecondCheckPanel checks={checks.data} />
      </div>

      {showScopes && can("admin") && <AllScopes />}
    </div>
  );
}

/** An asset's problem collector scopes, loaded when its row is opened. */
function AssetProblems({ assetId }: { assetId: number }) {
  const res = useLoad(() => api.get<List<CoverageRow>>("/coverage", { asset_id: assetId, problems: "true", limit: 100 }), [assetId]);
  if (res.error) return <ErrorBox error={res.error} title="Could not load what the scan read" />;
  if (!res.data) return <Loading />;
  return (
    <>
      <ProblemScopes rows={res.data.items} />
      {res.data.total > res.data.items.length && (
        <Link className="small" to={`/assets/${assetId}?tab=coverage`}>
          See all {res.data.total.toLocaleString("en")}
        </Link>
      )}
    </>
  );
}

const SCOPES = 100;

/** Every collector scope, for administrators ("Show all scopes"). */
function AllScopes() {
  const [problems, setProblems] = useState(true);
  const [offset, setOffset] = useState(0);
  const res = useLoad(
    () => api.get<List<CoverageRow>>("/coverage", { problems: problems ? "true" : undefined, limit: SCOPES, offset }),
    [problems, offset],
  );
  return (
    <section className="cov-section" id="cov-scopes" aria-labelledby="cov-scopes-title">
      <h2 id="cov-scopes-title" className="section-title">
        Everything the collectors read
      </h2>
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
          Problems only
        </label>
      </div>
      <ErrorBox error={res.error} title="Could not load coverage" />
      {!res.data && !res.error && <Loading />}
      {res.data && res.data.items.length === 0 && <p className="cov-empty">{problems ? "Every part was read." : "Nothing recorded yet."}</p>}
      {res.data && res.data.items.length > 0 && (
        <>
          <Table
            caption="Coverage"
            columns={coverageColumns(true)}
            rows={res.data.items}
            rowKey={(r) => `${r.asset_id}|${r.collector_id}|${r.scope}`}
            rowClassName={(r) => (r.status === "failed" ? "row-stale" : undefined)}
          />
          <Pager total={res.data.total} limit={SCOPES} offset={offset} onChange={setOffset} />
        </>
      )}
    </section>
  );
}
