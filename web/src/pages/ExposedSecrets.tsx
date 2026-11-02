import { useState } from "react";
import { Link, useSearchParams } from "react-router";
import { api, type Asset, type ExposedSecret, type List } from "../api";
import { useAuth } from "../auth";
import { useAction, useLoad } from "../hooks";
import { plural } from "../format";
import { AssetSelect, ProjectFilter } from "../components/AssetPicker";
import { Badge, SeverityBadge } from "../components/Badge";
import { promptText } from "../components/ConfirmDialog";
import { Table, type Column } from "../components/Table";
import { Code, EmptyState, ErrorBox, Loading, Notice, PageHeader, Pager, RelativeTime } from "../components/ui";

const LIMIT = 50;

const EXPOSURE: Record<string, { label: string; title: string }> = {
  public: { label: "Public", title: "In a file the web server sends to anyone" },
  repository: { label: "Repository", title: "Committed to a repository: everyone with access to it, and its history, has it" },
};

/** Where: the asset and the file and line. */
function Where({ e }: { e: ExposedSecret }) {
  return (
    <>
      <Link to={`/assets/${e.asset_id}`} className="break">
        {e.asset_name}
      </Link>
      <div className="small">
        <Code>{e.line > 0 ? `${e.location}:${e.line}` : e.location}</Code>
      </div>
    </>
  );
}

function What({ e }: { e: ExposedSecret }) {
  return (
    <>
      <strong>{e.title}</strong> <span className="muted small">{e.preview}</span>
      {e.places > 1 && <div className="small text-warn-strong">Same secret in {plural(e.places, "place")}</div>}
      {e.note && <div className="small muted">{e.note}</div>}
      {e.status === "ignored" && (
        <div className="small muted">
          Ignored by {e.ignored_by || "someone"} <RelativeTime iso={e.ignored_at ?? null} />: {e.ignore_reason}
        </div>
      )}
    </>
  );
}

/** Fixes > Exposed secrets: keys, tokens and passwords found where others can read them. */
export function ExposedSecretsPage() {
  const { canAct } = useAuth();
  const [params, setParams] = useSearchParams();
  const [offset, setOffset] = useState(0);
  const status = params.get("status") ?? "open";
  const severity = params.get("severity") ?? "";
  const asset = params.get("asset_id") ?? "";
  const set = (k: string, v: string) => {
    const next = new URLSearchParams(params);
    if (v) next.set(k, v);
    else next.delete(k);
    setParams(next, { replace: true });
    setOffset(0);
  };
  const assets = useLoad(() => api.get<List<Asset>>("/assets", { limit: 200 }), []);
  const res = useLoad(
    () => api.get<List<ExposedSecret>>("/exposed-secrets", { status, severity, asset_id: asset, limit: LIMIT, offset }),
    [status, severity, asset, offset],
  );
  const act = useAction();
  const [msg, setMsg] = useState<string | null>(null);
  const decider = canAct("security");

  const ignore = async (e: ExposedSecret) => {
    const reason = await promptText({
      title: `Ignore this ${e.title}?`,
      message:
        e.places > 1
          ? `It is ignored in all ${e.places} places it was found. Ignore only a test key, or one you have already revoked.`
          : "Ignore only a test key, or one you have already revoked.",
      label: "Why it needs no action",
      action: "Ignore",
    });
    if (reason === null) return;
    const ok = await act.run(() => api.post<{ changed: number }>(`/exposed-secrets/${e.id}/ignore`, { reason }));
    if (ok) {
      setMsg(`Ignored in ${plural(ok.changed, "place")}.`);
      res.reload();
    }
  };
  const reopen = async (e: ExposedSecret) => {
    const ok = await act.run(() => api.post<{ changed: number }>(`/exposed-secrets/${e.id}/reopen`, {}));
    if (ok) {
      setMsg(`Reopened in ${plural(ok.changed, "place")}.`);
      res.reload();
    }
  };

  const actions = (e: ExposedSecret) =>
    decider && e.status !== "resolved" ? (
      <button type="button" className="btn btn-sm" disabled={act.pending} onClick={() => void (e.status === "ignored" ? reopen(e) : ignore(e))}>
        {e.status === "ignored" ? "Reopen" : "Ignore"}
      </button>
    ) : null;

  const columns: Column<ExposedSecret>[] = [
    { key: "sev", header: "Severity", cell: (e) => <SeverityBadge severity={e.severity} /> },
    { key: "what", header: "Secret", cell: (e) => <What e={e} /> },
    { key: "where", header: "Where", cell: (e) => <Where e={e} /> },
    {
      key: "exposure",
      header: "Who can read it",
      cell: (e) => <Badge status={e.exposure} tone={e.exposure === "public" ? "crit" : "warn"} label={EXPOSURE[e.exposure]?.label} title={EXPOSURE[e.exposure]?.title} />,
    },
    {
      key: "seen",
      header: status === "resolved" ? "Gone" : "First found",
      cell: (e) => <RelativeTime iso={status === "resolved" ? (e.resolved_at ?? null) : e.first_seen} />,
    },
    { key: "actions", header: <span className="sr-only">Actions</span>, cell: actions },
  ];

  return (
    <>
      <PageHeader
        help="exposed-secrets"
        title="Exposed secrets"
        sub="API keys, tokens and passwords found in repositories and in files your web servers send. Values are never stored."
      />
      <Notice>
        Removing a secret from the code does not make it safe: it stays in the repository's history and in every copy already downloaded.
        Revoke it and issue a new one first, then remove it.
      </Notice>
      <form className="filters" onSubmit={(ev) => ev.preventDefault()}>
        <ProjectFilter id="es-project" onChange={() => set("asset_id", "")} />
        <div className="field">
          <label htmlFor="es-asset">Asset</label>
          <AssetSelect id="es-asset" value={asset} onChange={(v) => set("asset_id", v)} assets={assets.data?.items} />
        </div>
        <div className="field">
          <label htmlFor="es-severity">Severity</label>
          <select id="es-severity" value={severity} onChange={(ev) => set("severity", ev.target.value)}>
            <option value="">Any</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </select>
        </div>
        <div className="field">
          <label htmlFor="es-status">Status</label>
          <select id="es-status" value={status} onChange={(ev) => set("status", ev.target.value === "open" ? "" : ev.target.value)}>
            <option value="open">Open</option>
            <option value="ignored">Ignored</option>
            <option value="resolved">Gone</option>
            <option value="all">All</option>
          </select>
        </div>
      </form>
      {msg && (
        <div className="alert alert-info" role="status">
          {msg}
        </div>
      )}
      <ErrorBox error={res.error} title="Could not load exposed secrets" />
      <ErrorBox error={act.error} title="Could not change it" />
      {!res.data && !res.error && <Loading />}
      {res.data && res.data.items.length === 0 && (
        <EmptyState title={status === "open" ? "No exposed secrets found" : "Nothing here"} help="exposed-secrets">
          <p>
            Repository scans and the agent look for keys, tokens and passwords on every run. Only files others can read are checked: a repository's
            tracked files, and what a web server sends to browsers.
          </p>
        </EmptyState>
      )}
      {res.data && res.data.items.length > 0 && (
        <>
          <div className="only-wide">
            <Table caption="Exposed secrets" columns={columns} rows={res.data.items} rowKey={(e) => e.id} />
          </div>
          <ul className="approval-list only-narrow" aria-label="Exposed secrets">
            {res.data.items.map((e) => (
              <li key={e.id} className="approval">
                <h3 className="badges">
                  <SeverityBadge severity={e.severity} />
                  <Badge status={e.exposure} tone={e.exposure === "public" ? "crit" : "warn"} label={EXPOSURE[e.exposure]?.label} />
                </h3>
                <p className="small">
                  <What e={e} />
                </p>
                <p className="small">
                  <Where e={e} />
                </p>
                {actions(e)}
              </li>
            ))}
          </ul>
          <Pager total={res.data.total} limit={LIMIT} offset={offset} onChange={setOffset} />
        </>
      )}
    </>
  );
}
