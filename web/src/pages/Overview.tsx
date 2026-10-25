import { Link } from "react-router";
import { api, ASSET_STATUSES, COVERAGE_STATUSES, type FindingSummary, type Incident, type List, type Overview } from "../api";
import { FindingTiles, IntelBanners, PriorityTiles } from "../components/Findings";
import { RemediationTiles } from "../components/RemediationSummary";
import { ActionPlanLead } from "../components/ActionPlanLead";
import { PackSuggestions } from "../components/PackSuggestions";
import { useAuth } from "../auth";
import { useLoad } from "../hooks";
import { assetKindLabel, humanize, plural } from "../format";
import { toneFor } from "../components/Badge";
import { BarRows, Card, Code, EmptyState, ErrorBox, Loading, PageHeader, RelativeTime, StatTile, type Bar } from "../components/ui";

function sum(m: Record<string, number> | null | undefined): number {
  return Object.values(m ?? {}).reduce((a, b) => a + b, 0);
}

function sortedBars(m: Record<string, number> | null | undefined, toLabel?: (k: string) => Bar["label"]): Bar[] {
  return Object.entries(m ?? {})
    .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))
    .map(([k, v]) => ({ key: k, label: toLabel ? toLabel(k) : humanize(k), value: v }));
}

export function OverviewPage() {
  const { can } = useAuth();
  const ov = useLoad(() => api.get<Overview>("/overview"), []);
  const fs = useLoad(() => api.get<FindingSummary>("/findings/summary"), []);
  const incidents = useLoad(() => api.get<List<Incident>>("/incidents", { status: "open", limit: 1 }), []);

  if (ov.error) return <ErrorBox error={ov.error} title="Could not load overview" />;
  if (!ov.data) return <Loading />;
  const o = ov.data;
  const totalAssets = sum(o.assets);
  const st = o.asset_status ?? {};
  const stale = st.stale ?? 0;
  const partial = st.partial ?? 0;
  const cov = o.coverage_status ?? {};
  const covProblems = (cov.failed ?? 0) + (cov.unsupported ?? 0) + (cov.skipped ?? 0) + (cov.partial ?? 0);

  if (totalAssets === 0) {
    return (
      <>
        <PageHeader help="daily-workflow" title="Overview" />
        <EmptyState title="No assets yet" help="add-server" helpLabel="Add your first server">
          <p>
            Run <Code>stackurity agent --once</Code> on a host, <Code>stackurity scan DIR</Code> in CI, or add a Git
            repository under <Link to="/integrations">Integrations</Link>.
          </p>
        </EmptyState>
      </>
    );
  }

  // Asset status: show every known status, even at zero, so "0 stale" is explicit.
  const statusBars: Bar[] = [...ASSET_STATUSES, ...Object.keys(st).filter((k) => !(ASSET_STATUSES as readonly string[]).includes(k))].map(
    (k) => ({ key: k, label: <Link to={`/assets?status=${k}`}>{humanize(k)}</Link>, value: st[k] ?? 0, tone: toneFor(k) }),
  );
  const covBars: Bar[] = [...COVERAGE_STATUSES, ...Object.keys(cov).filter((k) => !(COVERAGE_STATUSES as readonly string[]).includes(k))]
    .map((k) => ({ key: k, label: humanize(k), value: cov[k] ?? 0, tone: toneFor(k) }));

  return (
    <>
      <PageHeader help="daily-workflow"
        title="Overview"
        sub={
          <>
            Last collection: <RelativeTime iso={o.last_collection} empty="never" />
          </>
        }
      />

      <PackSuggestions />
      <ActionPlanLead />

      <section aria-labelledby="ov-findings">
        <div className="card-head">
          <h2 id="ov-findings">Open findings</h2>
          <Link to="/findings">All findings</Link>
        </div>
        <ErrorBox error={fs.error} title="Could not load findings summary" />
        {fs.data && (
          <>
            <IntelBanners s={fs.data} />
            {(fs.data.sos ?? 0) > 0 && (
              <div className="alert sos-banner" role="alert">
                <strong>SOS:</strong> {fs.data.sos} active finding{fs.data.sos === 1 ? "" : "s"} match an SOS rule.{" "}
                <Link to="/incidents?sos=true">See SOS incidents</Link>.
              </div>
            )}
            <PriorityTiles s={fs.data} openIncidents={incidents.data?.total} />
            <h3 className="h-sm">By severity</h3>
            <FindingTiles s={fs.data} />
          </>
        )}
      </section>

      <RemediationTiles />

      <h2 className="section-title">Inventory</h2>
      {(stale > 0 || partial > 0) && (
        <div className="alert alert-warn" role="alert">
          <strong>Collection problems:</strong>{" "}
          {stale > 0 && (
            <>
              <Link to="/assets?status=stale">{plural(stale, "asset")} stale</Link> (no recent data — inventory may be out of date)
            </>
          )}
          {stale > 0 && partial > 0 && "; "}
          {partial > 0 && (
            <>
              <Link to="/assets?status=partial">{plural(partial, "asset")} partially collected</Link>
            </>
          )}
          .
        </div>
      )}

      <div className="tiles">
        <StatTile label="Assets" value={totalAssets.toLocaleString()} sub={<Link to="/assets">View assets</Link>} />
        <StatTile
          label="Stale assets"
          value={stale.toLocaleString()}
          tone={stale > 0 ? "bad" : undefined}
          sub={stale > 0 ? <Link to="/assets?status=stale">Investigate</Link> : "none"}
        />
        <StatTile
          label="Partial assets"
          value={partial.toLocaleString()}
          tone={partial > 0 ? "warn" : undefined}
          sub={partial > 0 ? <Link to="/assets?status=partial">Investigate</Link> : "none"}
        />
        <StatTile
          label="Hosts needing a reboot"
          value={(o.reboot_required ?? 0).toLocaleString()}
          tone={(o.reboot_required ?? 0) > 0 ? "warn" : undefined}
          sub={(o.reboot_required ?? 0) > 0 ? <Link to="/assets?reboot_required=true">View hosts</Link> : "none"}
        />
        <StatTile label="Components" value={o.components.toLocaleString()} sub={`${plural(o.inventory_rows, "inventory row")}`} />
        <StatTile
          label="Coverage gaps"
          value={covProblems.toLocaleString()}
          tone={covProblems > 0 ? "warn" : undefined}
          sub={<Link to="/coverage">View coverage</Link>}
        />
        <StatTile
          label="Identity conflicts"
          value={o.identity_conflicts.toLocaleString()}
          tone={o.identity_conflicts > 0 ? "warn" : undefined}
          sub={o.identity_conflicts > 0 && can("admin") ? <Link to="/settings/conflicts">Resolve</Link> : "open"}
        />
      </div>

      <div className="grid-2">
        <Card title="Assets by kind">
          <BarRows bars={sortedBars(o.assets, (k) => <Link to={`/assets?kind=${k}`}>{assetKindLabel(k)}</Link>)} />
        </Card>
        <Card title="Asset collection status">
          <BarRows bars={statusBars} />
          <p className="hint">Stale and partial assets may be missing components; their inventory should not be treated as complete.</p>
        </Card>
        <Card title="Components by ecosystem">
          <BarRows
            bars={sortedBars(o.ecosystems, (k) => <Link to={`/components?type=${encodeURIComponent(k)}`}>{k}</Link>)}
            emptyText="No components collected yet."
          />
        </Card>
        <Card title="Coverage status">
          <BarRows bars={covBars} emptyText="No coverage recorded yet." />
          <p className="hint">Unsupported, failed and skipped areas were not inventoried. Stackurity cannot vouch for them.</p>
        </Card>
        {o.confidence && Object.keys(o.confidence).length > 0 && (
          <Card title="Inventory version confidence">
            <BarRows bars={sortedBars(o.confidence).map((b) => ({ ...b, tone: toneFor(b.key) }))} />
          </Card>
        )}
      </div>
    </>
  );
}
