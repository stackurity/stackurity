import { api, type CoverageGap, type CoverageGapReport, type SupportRequestTotal } from "../../api";
import { useLoad } from "../../hooks";
import { Table, type Column } from "../../components/Table";
import {
  Card,
  EmptyState,
  ErrorBox,
  Loading,
  PageHeader,
  RelativeTime,
} from "../../components/ui";
import { plural } from "../../format";

const DOCS =
  "https://github.com/stackurity/stackurity/blob/main/docs/compatibility.md#what-stackurity-cannot-check";

/** Who can close a gap, in the words the workspace banners use. */
const ACTOR_LABELS: Record<string, string> = {
  stackurity: "Stackurity",
  user: "The workspace",
  automatic: "Resolves on its own",
  none: "Nothing to check against",
};

function columns(what: string, components = false): Column<CoverageGap>[] {
  const cols: Column<CoverageGap>[] = [
    {
      key: "label",
      header: what,
      cell: (g) => (
        <>
          <span className="mono">{g.label}</span>
          {g.detail && <div className="small muted">{g.detail}</div>}
        </>
      ),
    },
    { key: "actor", header: "Who acts", cell: (g) => ACTOR_LABELS[g.actor ?? ""] ?? "" },
    { key: "assets", header: "Assets", numeric: true, cell: (g) => g.assets },
    {
      key: "workspaces",
      header: "Workspaces",
      numeric: true,
      cell: (g) => g.workspaces,
    },
  ];
  if (components)
    cols.splice(1, 0, {
      key: "components",
      header: "Components",
      numeric: true,
      cell: (g) => g.components ?? 0,
    });
  return cols;
}

function GapCard({
  title,
  about,
  empty,
  what,
  rows,
  components,
}: {
  title: string;
  about: string;
  empty: string;
  what: string;
  rows: CoverageGap[];
  components?: boolean;
}) {
  return (
    <Card title={title}>
      <p className="small muted">{about}</p>
      {rows.length === 0 ? (
        <EmptyState title={empty} />
      ) : (
        <Table
          columns={columns(what, components)}
          rows={rows}
          rowKey={(g) => g.kind}
          caption={title}
        />
      )}
    </Card>
  );
}

const REQUEST_COLUMNS: Column<SupportRequestTotal>[] = [
  {
    key: "ecosystem",
    header: "Ecosystem",
    cell: (r) => (
      <>
        {r.label || r.ecosystem} <span className="mono small muted">{r.ecosystem}</span>
      </>
    ),
  },
  { key: "workspaces", header: "Workspaces", numeric: true, cell: (r) => r.workspaces },
  { key: "latest", header: "Latest", cell: (r) => <RelativeTime iso={r.latest} /> },
];

/**
 * Instance administration: what Stackurity cannot check, counted across every
 * workspace. Counts and type names only: no workspace, asset, path or package
 * is named here.
 */
export function CoverageGapsPage() {
  const res = useLoad(
    () => api.get<CoverageGapReport>("/admin/coverage-gaps"),
    [],
  );
  const d = res.data;
  return (
    <>
      <PageHeader
        title="Coverage gaps"
        sub="What Stackurity cannot check across every workspace on this installation, counted by assets and workspaces. Workspaces, assets, paths and packages are never named here."
        actions={
          <button type="button" className="btn" onClick={res.reload}>
            Refresh
          </button>
        }
      />
      <ErrorBox error={res.error} title="Could not load coverage gaps" />
      {!d && !res.error && <Loading />}
      {d && (
        <>
          <p className="small muted">
            {plural(d.assets, "asset")} in {plural(d.workspaces, "workspace")},
            checked <RelativeTime iso={d.checked_at} />. Lifecycle mappings:
            overlay <span className="mono">{d.overlay_version}</span> on top of
            endoflife.date.{" "}
            <a href={DOCS} target="_blank" rel="noopener noreferrer">
              What is and is not covered
            </a>
          </p>
          <Card title="Support requested">
            <p className="small muted">
              Ecosystems workspaces asked Stackurity to support from their Coverage page, counted in workspaces: a roadmap signal.
            </p>
            {(d.support_requests ?? []).length === 0 ? (
              <EmptyState title="No requests yet" />
            ) : (
              <Table
                caption="Support requested"
                columns={REQUEST_COLUMNS}
                rows={d.support_requests ?? []}
                rowKey={(r) => r.ecosystem}
              />
            )}
          </Card>
          <GapCard
            title="Files nothing reads"
            about="Files a scan found that no built-in reader or installed stack pack can read, so their dependencies are not in the inventory."
            empty="Every file found was read"
            what="File kind"
            rows={d.unread_files}
          />
          <GapCard
            title="Components with no vulnerability source"
            about="Installed components no vulnerability source covers. They are shown as unsupported coverage, never as clean."
            empty="Every component has a vulnerability source"
            what="Package type"
            rows={d.no_vulnerability_source}
            components
          />
          <GapCard
            title="Components not checked for another reason"
            about="Components a vulnerability source exists for that were still not checked: waiting for the source to sync, a release with no published advisories, a version that could not be read, or a release the matcher does not read yet. With the table above, every component that was not checked is counted here."
            empty="Every component with a vulnerability source was checked"
            what="Reason and subject"
            rows={d.not_checked ?? []}
            components
          />
          <GapCard
            title="Products with no lifecycle match"
            about="Products Stackurity recognises but cannot give an end-of-life date: no lifecycle source tracks them, the installed release line is not in the data, or a runtime or operating system has no lifecycle product."
            empty="Every recognised product has lifecycle data"
            what="Product"
            rows={d.no_lifecycle}
          />
        </>
      )}
    </>
  );
}
