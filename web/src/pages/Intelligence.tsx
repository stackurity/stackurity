import { useEffect, useState } from "react";
import { Link, useLocation } from "react-router";
import { api, feedPath, type EvaluationGap, type Feed, type List, type Queued } from "../api";
import { useAuth } from "../auth";
import { useAction, useJobRunner, useLoad } from "../hooks";
import { displayPurl, minutesLabel } from "../format";
import { Badge, type Tone } from "../components/Badge";
import { ROW_COVERAGE_LABELS } from "../components/Coverage";
import { Table, type Column } from "../components/Table";
import { Card, EmptyState, ErrorBox, JobStatus, Loading, PageHeader, Pager, RelativeTime } from "../components/ui";

function feedStatus(f: Feed): { label: string; tone: Tone; title: string } {
  if (!f.enabled) return { label: "Disabled", tone: "muted", title: "Not synced; nothing from this feed is evaluated" };
  if (!f.last_success && f.last_error) return { label: "Error", tone: "bad", title: "Has never synced successfully" };
  if (!f.last_success) return { label: "Never synced", tone: "warn", title: "No data yet" };
  if (f.stale) return { label: "Stale", tone: "bad", title: `No successful sync within ${minutesLabel(f.stale_after_minutes)}` };
  if (f.last_error) return { label: "Error", tone: "bad", title: "The last attempt failed; older data is still used" };
  return { label: "OK", tone: "good", title: "Synced recently" };
}

const KIND_LABEL: Record<string, string> = { vulnerability: "Vulnerabilities", release: "Releases", lifecycle: "Lifecycle" };

const GAP_LIMIT = 100;

export function IntelligencePage() {
  const { can } = useAuth();
  const engineer = can("engineer");
  const admin = can("admin");
  const feeds = useLoad(() => api.get<List<Feed>>("/feeds"), []);
  const [gapOffset, setGapOffset] = useState(0);
  const gaps = useLoad(() => api.get<List<EvaluationGap>>("/evaluation-gaps", { limit: GAP_LIMIT, offset: gapOffset }), [gapOffset]);
  const job = useJobRunner(() => {
    feeds.reload();
    gaps.reload();
  });
  const toggle = useAction();
  const location = useLocation();

  useEffect(() => {
    if (location.hash === "#gaps" && gaps.data) document.getElementById("gaps")?.scrollIntoView();
  }, [location.hash, gaps.data]);

  const refresh = (f: Feed) =>
    job.start(`Refresh ${f.name}`, () => api.post<Queued>(`/feeds/${feedPath(f.name)}/refresh`));
  const setEnabled = async (f: Feed) => {
    const pin = f.auto ? " Stackurity will stop enabling or disabling it automatically based on your inventory." : "";
    const q = f.enabled
      ? `Disable ${f.name}? Findings from it will no longer be updated.${pin}`
      : `Enable ${f.name}?${pin}`;
    if (!window.confirm(q)) return;
    const ok = await toggle.run(() => api.patch<Feed>(`/feeds/${feedPath(f.name)}`, { enabled: !f.enabled }));
    if (ok) feeds.reload();
  };

  const columns: Column<Feed>[] = [
    { key: "name", header: "Feed", cell: (f) => <span className="mono">{f.name}</span> },
    { key: "kind", header: "Provides", cell: (f) => KIND_LABEL[f.kind] ?? f.kind },
    {
      key: "status",
      header: "Status",
      cell: (f) => {
        const s = feedStatus(f);
        return <Badge status={s.label.toLowerCase()} tone={s.tone} label={s.label} title={s.title} />;
      },
    },
    { key: "success", header: "Last success", cell: (f) => <RelativeTime iso={f.last_success} /> },
    { key: "attempt", header: "Last attempt", cell: (f) => <RelativeTime iso={f.last_attempt} /> },
    { key: "records", header: "Records", numeric: true, cell: (f) => f.records.toLocaleString() },
    { key: "changed", header: "Changed last sync", numeric: true, cell: (f) => f.last_changed.toLocaleString() },
    { key: "every", header: "Every", cell: (f) => minutesLabel(f.refresh_minutes) },
    {
      key: "mode",
      header: "Managed",
      cell: (f) =>
        f.auto ? (
          <span title="Enabled automatically when your inventory contains this ecosystem">auto</span>
        ) : (
          <span title="Enabled or disabled by an administrator">manual</span>
        ),
    },
    {
      key: "error",
      header: "Last error",
      cell: (f) =>
        f.last_error ? (
          <details>
            <summary className="text-bad small">{f.last_error.length > 40 ? f.last_error.slice(0, 40) + "…" : f.last_error}</summary>
            <pre className="mono small break">{f.last_error}</pre>
          </details>
        ) : (
          <span className="muted">—</span>
        ),
    },
  ];
  if (engineer)
    columns.push({
      key: "actions",
      header: <span className="sr-only">Actions</span>,
      cell: (f) => (
        <div className="row-actions">
          <button type="button" className="btn btn-sm" disabled={job.busy || !f.enabled} onClick={() => refresh(f)}>
            Refresh
          </button>
          {admin && (
            <button type="button" className="btn btn-sm" disabled={toggle.pending} onClick={() => setEnabled(f)}>
              {f.enabled ? "Disable" : "Enable"}
            </button>
          )}
        </div>
      ),
    });

  const gapColumns: Column<EvaluationGap>[] = [
    { key: "c", header: "Component", cell: (g) => <Link to={`/components/${g.component_id}`} className="mono">{displayPurl(g.purl_key)}</Link> },
    {
      key: "coverage",
      header: "Coverage",
      cell: (g) => <Badge status={g.coverage} tone={g.coverage === "unsupported" ? "muted" : "warn"} label={ROW_COVERAGE_LABELS[g.coverage] ?? g.coverage} />,
    },
    { key: "reason", header: "Why it was not checked", cell: (g) => g.reason },
    { key: "assets", header: "Assets", numeric: true, cell: (g) => g.asset_count.toLocaleString() },
    { key: "upd", header: "Since", cell: (g) => <RelativeTime iso={g.updated_at} /> },
  ];

  const problemFeeds = (feeds.data?.items ?? []).filter((f) => f.enabled && feedStatus(f).label !== "OK").length;

  return (
    <>
      <PageHeader help="coverage-intelligence"
        title="Intelligence"
        sub="Feeds that supply vulnerability, release and end-of-life data, and inventory that could not be evaluated."
        actions={
          engineer && (
            <button
              type="button"
              className="btn"
              disabled={job.busy}
              onClick={() => job.start("Re-evaluate all inventory", () => api.post<Queued>("/evaluate"))}
            >
              Re-evaluate all
            </button>
          )
        }
      />
      <ErrorBox error={job.error} title="Could not start job" />
      <JobStatus state={job.state} onDismiss={job.reset} />
      <ErrorBox error={toggle.error} title="Could not update feed" />

      <h2 className="section-title">Feeds</h2>
      {problemFeeds > 0 && (
        <div className="alert alert-warn" role="alert">
          {problemFeeds} enabled feed{problemFeeds === 1 ? " is" : "s are"} not healthy. Findings that depend on {problemFeeds === 1 ? "it" : "them"}{" "}
          may be missing or out of date.
        </div>
      )}
      <ErrorBox error={feeds.error} title="Could not load feeds" />
      {!feeds.data && !feeds.error && <Loading />}
      {feeds.data && feeds.data.items.length === 0 && <EmptyState title="No feeds configured" />}
      {feeds.data && feeds.data.items.length > 0 && (
        <Table
          caption="Intelligence feeds"
          columns={columns}
          rows={feeds.data.items}
          rowKey={(f) => f.name}
          rowClassName={(f) => (f.enabled && feedStatus(f).tone === "bad" ? "row-stale" : !f.enabled ? "row-removed" : undefined)}
        />
      )}

      <section id="gaps" aria-labelledby="gaps-title">
        <h2 className="section-title" id="gaps-title">
          Evaluation gaps
        </h2>
        <Card>
          <p className="hint">
            These components were <strong>not</strong> checked for vulnerabilities. <em>Unsupported</em>: no source exists for their
            ecosystem, distribution or install method. <em>Not checked</em>: a source exists but could not be used (the feed has not
            synced, the release has no advisories, the version could not be read). They may be vulnerable even though they have no
            findings. Each asset's Inventory tab marks them too.
          </p>
        </Card>
        <ErrorBox error={gaps.error} title="Could not load evaluation gaps" />
        {!gaps.data && !gaps.error && <Loading />}
        {gaps.data && gaps.data.items.length === 0 && (
          <EmptyState title="No evaluation gaps">
            <p>Every inventoried component with a supported ecosystem was evaluated.</p>
          </EmptyState>
        )}
        {gaps.data && gaps.data.items.length > 0 && (
          <>
            <Table caption="Evaluation gaps" columns={gapColumns} rows={gaps.data.items} rowKey={(g) => `${g.component_id}|${g.reason}`} />
            <Pager total={gaps.data.total} limit={GAP_LIMIT} offset={gapOffset} onChange={setGapOffset} />
          </>
        )}
      </section>
    </>
  );
}
