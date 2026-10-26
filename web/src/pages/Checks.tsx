import { useState } from "react";
import { Link } from "react-router";
import { api, type Check, type List } from "../api";
import { useLoad } from "../hooks";
import { CheckBadge } from "../components/CheckAgain";
import { Table, type Column } from "../components/Table";
import { EmptyState, ErrorBox, Loading, PageHeader, Pager, RelativeTime } from "../components/ui";

const LIMIT = 50;

function What({ c }: { c: Check }) {
  return c.fix_group ? (
    <Link to={`/fixes/${encodeURIComponent(c.fix_group)}`} className="break">
      {c.fix_title || "A fix"}
    </Link>
  ) : (
    <span className="muted">Whole asset</span>
  );
}

/** Counts of a finished check: fixed, left and new. */
function Counts({ c }: { c: Check }) {
  if (c.status !== "done" || c.outcome === "expired") return <span className="muted">-</span>;
  const parts = [`${c.fixed.toLocaleString()} fixed`, `${c.remaining.toLocaleString()} left`];
  if (!c.fix_group && c.new_issues > 0) parts.push(`${c.new_issues.toLocaleString()} new`);
  return <span className="small">{parts.join(", ")}</span>;
}

/** Activity > Checks: every check again, newest first, with its result. */
export function ChecksPage() {
  const [offset, setOffset] = useState(0);
  const [open, setOpen] = useState(false);
  const res = useLoad(() => api.get<List<Check>>("/checks", { limit: LIMIT, offset, open: open ? "true" : undefined }), [offset, open]);

  const columns: Column<Check>[] = [
    { key: "asset", header: "Asset", cell: (c) => <Link to={`/assets/${c.asset_id}`}>{c.asset_name}</Link> },
    { key: "what", header: "Fix", cell: (c) => <What c={c} /> },
    {
      key: "who",
      header: "Asked",
      cell: (c) => (
        <>
          {c.requested_by || <span className="muted">someone</span>}
          <div className="muted small">
            <RelativeTime iso={c.requested_at} />
            {c.reason === "applied" ? ", after I applied this" : ""}
          </div>
        </>
      ),
    },
    { key: "result", header: "Result", cell: (c) => <CheckBadge c={c} /> },
    { key: "counts", header: "Issues", cell: (c) => <Counts c={c} /> },
    { key: "done", header: "Finished", cell: (c) => <RelativeTime iso={c.completed_at} empty="not yet" /> },
  ];

  return (
    <>
      <PageHeader help="check-again" title="Checks" sub="Every Check again and I applied this, with what the fresh report showed." />
      <label className="check">
        <input
          type="checkbox"
          checked={open}
          onChange={(e) => {
            setOpen(e.target.checked);
            setOffset(0);
          }}
        />{" "}
        Only checks still waiting
      </label>
      <ErrorBox error={res.error} title="Could not load checks" />
      {!res.data && !res.error && <Loading />}
      {res.data && res.data.items.length === 0 && (
        <EmptyState title="No checks yet" help="check-again">
          <p>Press Check again on a fix or an asset to ask for a fresh report.</p>
        </EmptyState>
      )}
      {res.data && res.data.items.length > 0 && (
        <>
          <div className="only-wide">
            <Table caption="Checks" columns={columns} rows={res.data.items} rowKey={(c) => c.id} />
          </div>
          <ul className="approval-list only-narrow" aria-label="Checks">
            {res.data.items.map((c) => (
              <li key={c.id} className="approval">
                <h3 className="badges">
                  <CheckBadge c={c} />
                  <Link to={`/assets/${c.asset_id}`} className="break">
                    {c.asset_name}
                  </Link>
                </h3>
                <p className="small">
                  <What c={c} /> · <Counts c={c} />
                </p>
                <p className="small muted">
                  Asked by {c.requested_by || "someone"} <RelativeTime iso={c.requested_at} />
                  {c.completed_at && (
                    <>
                      , finished <RelativeTime iso={c.completed_at} />
                    </>
                  )}
                </p>
              </li>
            ))}
          </ul>
          <Pager total={res.data.total} limit={LIMIT} offset={offset} onChange={setOffset} />
        </>
      )}
    </>
  );
}
