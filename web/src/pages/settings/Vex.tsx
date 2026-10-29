import { useState, type FormEvent } from "react";
import { Link, useParams, useSearchParams } from "react-router";
import {
  api,
  importVEX,
  vexExportURL,
  type List,
  type Token,
  type VEXDocument,
  type VEXImportResult,
  type VEXProblem,
  type VEXSource,
  type VEXStatement,
} from "../../api";
import { useAuth } from "../../auth";
import { useAction, useLoad } from "../../hooks";
import { plural } from "../../format";
import { Badge, type Tone } from "../../components/Badge";
import { Table } from "../../components/Table";
import { Card, EmptyState, ErrorBox, KeyValues, Loading, Notice, PageHeader, Pager, RelativeTime } from "../../components/ui";

const LIMIT = 50;

const SIGNATURE_LABEL: Record<string, string> = { none: "not signed", verified: "signature verified", unverified: "signed, not verified" };
const STATUS_TONE: Record<string, Tone> = { not_affected: "good", affected: "warn", fixed: "muted", under_investigation: "info", invalid: "bad" };

function Problems({ problems, max = 20 }: { problems: VEXProblem[]; max?: number }) {
  if (!problems?.length) return null;
  return (
    <ul className="small">
      {problems.slice(0, max).map((p, i) => (
        <li key={i}>
          <Badge status={p.kind} tone={p.kind === "ambiguous" ? "warn" : "muted"} label={p.kind} /> <span className="mono break">{p.product}</span>: {p.reason}
        </li>
      ))}
      {problems.length > max && <li className="muted">and {problems.length - max} more</li>}
    </ul>
  );
}

function ImportCard({ sources, onDone }: { sources: VEXSource[]; onDone: () => void }) {
  const act = useAction();
  const [file, setFile] = useState<File | null>(null);
  const [source, setSource] = useState("");
  const [asset, setAsset] = useState("");
  const [result, setResult] = useState<VEXImportResult | null>(null);
  const submit = async (e: FormEvent) => {
    e.preventDefault();
    if (!file) return;
    setResult(null);
    const r = await act.run(() =>
      importVEX(file, { filename: file.name, source_id: Number(source) || undefined, asset_id: Number(asset) || undefined }),
    );
    if (r) {
      setResult(r);
      onDone();
    }
  };
  return (
    <Card title="Import a VEX document">
      <p className="hint">
        OpenVEX or CycloneDX VEX (also embedded in a CycloneDX SBOM), plain or as a signed attestation (<span className="mono">cosign attest</span>{" "}
        output). <strong>Not affected</strong> statements wait under <Link to="/approvals">Approvals</Link> until a security or admin user approves
        them, unless the source is trusted to apply on its own.
      </p>
      <form className="form" onSubmit={submit}>
        <ErrorBox error={act.error} title="Could not import" />
        <div className="field">
          <label htmlFor="vex-file">Document</label>
          <input id="vex-file" type="file" accept=".json,application/json" required onChange={(e) => setFile(e.target.files?.[0] ?? null)} />
        </div>
        <div className="field">
          <label htmlFor="vex-source">Source (optional)</label>
          <select id="vex-source" value={source} onChange={(e) => setSource(e.target.value)}>
            <option value="">None: every statement needs approval</option>
            {sources.map((s) => (
              <option key={s.id} value={s.id}>
                {s.name}
                {s.auto_apply ? " (applies on its own)" : ""}
              </option>
            ))}
          </select>
        </div>
        <div className="field">
          <label htmlFor="vex-asset">Asset id (optional)</label>
          <input id="vex-asset" inputMode="numeric" pattern="[0-9]*" value={asset} onChange={(e) => setAsset(e.target.value)} />
          <p className="hint">Match only on this asset. Needed for a document about a product with no package URL or digest of its own.</p>
        </div>
        <div className="form-actions">
          <button type="submit" className="btn btn-primary" disabled={act.pending || !file}>
            {act.pending ? "Importing…" : "Import"}
          </button>
        </div>
      </form>
      {result && (
        <Notice kind={result.matched > 0 ? "success" : "warn"}>
          <strong>
            {plural(result.statements, "statement")}: {result.matched} matched, {result.unmatched} not.
          </strong>{" "}
          {result.pending > 0 && <>{plural(result.pending, "not affected statement")} wait for approval. </>}
          {result.auto_approved > 0 && <>{plural(result.auto_approved, "statement")} applied on import, {plural(result.ignored, "issue")} ignored. </>}
          {result.ended > 0 && <>{plural(result.ended, "earlier VEX rule")} ended by newer statements. </>}
          <Link to={`/settings/vex/${result.document.id}`}>See the document</Link>
          <Problems problems={result.problems} />
        </Notice>
      )}
    </Card>
  );
}

function Documents({ reloadKey }: { reloadKey: number }) {
  const { can } = useAuth();
  const [offset, setOffset] = useState(0);
  const act = useAction();
  const [done, setDone] = useState<string | null>(null);
  const res = useLoad(() => api.getAll<List<VEXDocument>>("/vex/documents", { limit: LIMIT, offset }), [offset, reloadKey]);
  const decide = async (d: VEXDocument, decision: "approve" | "decline") => {
    const r = await act.run(() => api.post<{ decided: number; applied: number }>(`/vex/documents/${d.id}/decision`, { decision }));
    if (r) {
      setDone(`${d.filename || "Document " + d.id}: ${plural(r.decided, "statement")} ${decision === "approve" ? "approved" : "declined"}, ${plural(r.applied, "issue")} ignored.`);
      res.reload();
    }
  };
  if (res.error) return <ErrorBox error={res.error} title="Could not load VEX documents" />;
  if (!res.data) return <Loading />;
  return (
    <Card title="Imported documents">
      {done && <Notice kind="success">{done}</Notice>}
      <ErrorBox error={act.error} title="Could not decide" />
      {res.data.items.length === 0 ? (
        <EmptyState title="No VEX imported yet" help="vex" />
      ) : (
        <Table
          rows={res.data.items}
          rowKey={(d) => d.id}
          columns={[
            {
              key: "file",
              header: "Document",
              cell: (d) => (
                <>
                  <Link to={`/settings/vex/${d.id}`}>{d.filename || d.doc_id || `Document ${d.id}`}</Link>
                  <div className="small muted">
                    {d.format === "openvex" ? "OpenVEX" : "CycloneDX"} · {SIGNATURE_LABEL[d.signature]}
                    {d.via === "sbom" ? " · in an SBOM" : ""}
                  </div>
                </>
              ),
            },
            { key: "source", header: "Source", cell: (d) => d.source },
            { key: "statements", header: "Statements", numeric: true, cell: (d) => `${d.matched} of ${d.statements} matched` },
            {
              key: "pending",
              header: "Waiting",
              cell: (d) =>
                d.pending > 0 ? (
                  <span className="badges">
                    <Badge status="pending" tone="warn" label={`${d.pending} pending`} />
                    {can("security") && (
                      <>
                        <button type="button" className="btn btn-sm btn-primary" disabled={act.pending} onClick={() => decide(d, "approve")}>
                          Approve all
                        </button>
                        <button type="button" className="btn btn-sm" disabled={act.pending} onClick={() => decide(d, "decline")}>
                          Decline all
                        </button>
                      </>
                    )}
                  </span>
                ) : d.auto_applied ? (
                  <Badge status="auto" tone="info" label="applied on import" />
                ) : (
                  <span className="muted">none</span>
                ),
            },
            {
              key: "imported",
              header: "Imported",
              cell: (d) => (
                <>
                  <RelativeTime iso={d.imported_at} />
                  <div className="small muted">{d.imported_by}</div>
                </>
              ),
            },
          ]}
        />
      )}
      <Pager total={res.data.total} limit={LIMIT} offset={offset} onChange={setOffset} />
    </Card>
  );
}

function Sources({ sources, reload, error }: { sources: VEXSource[] | null; reload: () => void; error: unknown }) {
  const { can } = useAuth();
  const admin = can("admin");
  const act = useAction();
  const tokens = useLoad(() => (admin ? api.getAll<List<Token>>("/tokens") : Promise.resolve({ items: [], total: 0 } as List<Token>)), [admin]);
  const [name, setName] = useState("");
  const [key, setKey] = useState("");
  const [token, setToken] = useState("");
  const [auto, setAuto] = useState(false);
  const add = async (e: FormEvent) => {
    e.preventDefault();
    const body: Record<string, unknown> = { name: name.trim(), auto_apply: auto };
    if (key.trim()) body.public_key = key.trim();
    if (Number(token) > 0) body.token_id = Number(token);
    if (await act.run(() => api.post<VEXSource>("/vex/sources", body))) {
      setName("");
      setKey("");
      setToken("");
      setAuto(false);
      reload();
    }
  };
  const toggle = async (s: VEXSource) => {
    if (await act.run(() => api.patch<VEXSource>(`/vex/sources/${s.id}`, { auto_apply: !s.auto_apply }))) reload();
  };
  const remove = async (s: VEXSource) => {
    if (await act.run(() => api.del(`/vex/sources/${s.id}`))) reload();
  };
  return (
    <Card title="Sources">
      <p className="hint">
        A document's author is whatever it says, so a source can apply its not affected statements without approval only when it is pinned: to
        a public key its signed attestations must verify with, or to the API token its uploads come from. Everything else waits for a person.
      </p>
      <ErrorBox error={act.error} title="Could not change the source" />
      {error ? <ErrorBox error={error as never} title="Could not load sources" /> : null}
      {sources && sources.length > 0 && (
        <ul className="approval-list">
          {sources.map((s) => (
            <li key={s.id} className="approval">
              <h3 className="badges">
                <span>{s.name}</span>
                {s.auto_apply ? <Badge status="auto" tone="warn" label="applies on its own" /> : <Badge status="manual" tone="muted" label="needs approval" />}
              </h3>
              <p className="small">
                {s.key_fingerprint ? (
                  <>
                    Key <span className="mono">{s.key_fingerprint.slice(0, 16)}…</span>
                  </>
                ) : (
                  "No key"
                )}{" "}
                · {s.token_id ? `token ${s.token_name || "#" + s.token_id}` : "any uploader"} · {plural(s.documents, "document")}
              </p>
              {admin && (
                <div className="approval-actions">
                  <button type="button" className="btn btn-sm" disabled={act.pending} onClick={() => toggle(s)}>
                    {s.auto_apply ? "Require approval" : "Let it apply on its own"}
                  </button>
                  <button type="button" className="btn btn-sm" disabled={act.pending} onClick={() => remove(s)}>
                    Remove
                  </button>
                </div>
              )}
            </li>
          ))}
        </ul>
      )}
      {admin && (
        <form className="form" onSubmit={add}>
          <div className="field">
            <label htmlFor="vs-name">Name</label>
            <input id="vs-name" required maxLength={100} value={name} onChange={(e) => setName(e.target.value)} placeholder="e.g. Acme images" />
          </div>
          <div className="field">
            <label htmlFor="vs-key">Public key (optional)</label>
            <textarea id="vs-key" rows={4} className="mono" value={key} onChange={(e) => setKey(e.target.value)} placeholder="-----BEGIN PUBLIC KEY-----" />
            <p className="hint">The source's cosign.pub (ECDSA, Ed25519 or RSA). Uploads for this source must then be signed attestations.</p>
          </div>
          <div className="field">
            <label htmlFor="vs-token">API token (optional)</label>
            <select id="vs-token" value={token} onChange={(e) => setToken(e.target.value)}>
              <option value="">Any uploader</option>
              {(tokens.data?.items ?? [])
                .filter((t) => !t.revoked_at)
                .map((t) => (
                  <option key={t.id} value={t.id}>
                    {t.name} ({t.role})
                  </option>
                ))}
            </select>
          </div>
          <label className="check">
            <input type="checkbox" checked={auto} onChange={(e) => setAuto(e.target.checked)} /> Apply its not affected statements without approval
            (needs a key or a token)
          </label>
          <div className="form-actions">
            <button type="submit" className="btn" disabled={act.pending || !name.trim()}>
              Add source
            </button>
          </div>
        </form>
      )}
    </Card>
  );
}

/** Settings, VEX: import documents, the sources and how far each is trusted, and export. */
export function VexPage() {
  const { can } = useAuth();
  const [tick, setTick] = useState(0);
  const sources = useLoad(() => (can("security") ? api.getAll<List<VEXSource>>("/vex/sources") : Promise.resolve({ items: [], total: 0 })), [tick]);
  return (
    <>
      <PageHeader
        help="vex"
        title="VEX"
        sub="Vendors' statements about whether their products are affected by a vulnerability, and your own decisions to share."
        actions={
          <>
            <a className="btn" href={vexExportURL("openvex")} download>
              Export OpenVEX
            </a>
            <a className="btn" href={vexExportURL("cyclonedx")} download>
              Export CycloneDX VEX
            </a>
          </>
        }
      />
      {can("engineer") && <ImportCard sources={sources.data?.items ?? []} onDone={() => setTick((t) => t + 1)} />}
      <Documents reloadKey={tick} />
      {can("security") && <Sources sources={sources.data?.items ?? null} error={sources.error} reload={() => setTick((t) => t + 1)} />}
    </>
  );
}

/** One imported document and what each statement matched. */
export function VexDocumentPage() {
  const id = Number(useParams().id);
  const [params, setParams] = useSearchParams();
  const outcome = params.get("outcome") ?? "";
  const [offset, setOffset] = useState(0);
  const doc = useLoad(() => api.getAll<VEXDocument>(`/vex/documents/${id}`), [id]);
  const sts = useLoad(
    () => api.getAll<List<VEXStatement>>(`/vex/documents/${id}/statements`, { outcome: outcome || undefined, limit: LIMIT, offset }),
    [id, outcome, offset],
  );
  if (doc.error) return <ErrorBox error={doc.error} title="Could not load the document" />;
  if (!doc.data) return <Loading />;
  const d = doc.data;
  return (
    <>
      <nav className="crumbs" aria-label="Breadcrumb">
        <Link to="/settings/vex">VEX</Link> <span aria-hidden="true">/</span> <span>{d.filename || d.doc_id || `Document ${d.id}`}</span>
      </nav>
      <PageHeader title={d.filename || d.doc_id || `Document ${d.id}`} sub={`${d.matched} of ${plural(d.statements, "statement")} matched`} />
      <Card>
        <KeyValues
          entries={[
            ["source", d.source],
            ["author (as written)", d.author || <span className="muted">none</span>],
            ["format", d.format === "openvex" ? "OpenVEX" : "CycloneDX"],
            ["document id", <span className="mono break">{d.doc_id || "none"}</span>],
            ["SHA-256", <span className="mono break">{d.sha256}</span>],
            ["signature", SIGNATURE_LABEL[d.signature] + (d.key_fingerprint ? ` (key ${d.key_fingerprint.slice(0, 16)}…)` : "")],
            ["limited to", d.scope_asset_id ? <Link to={`/assets/${d.scope_asset_id}`}>asset {d.scope_asset_id}</Link> : d.scope_project_id ? `project ${d.scope_project_id}` : "every asset"],
            ["imported", <><RelativeTime iso={d.imported_at} /> by {d.imported_by}</>],
            ["waiting for approval", d.pending > 0 ? <Link to="/approvals">{plural(d.pending, "statement")}</Link> : "none"],
          ]}
        />
      </Card>
      <nav className="link-tabs" aria-label="Statements">
        <ul>
          {[
            ["", "All"],
            ["matched", "Matched"],
            ["unmatched", "Not matched"],
            ["pending", "Waiting for approval"],
          ].map(([v, label]) => (
            <li key={v}>
              <button
                type="button"
                className={`tab${outcome === v ? " tab-active" : ""}`}
                aria-current={outcome === v ? "page" : undefined}
                onClick={() => {
                  setOffset(0);
                  setParams(v ? { outcome: v } : {}, { replace: true });
                }}
              >
                {label}
              </button>
            </li>
          ))}
        </ul>
      </nav>
      <ErrorBox error={sts.error} title="Could not load statements" />
      {!sts.data && !sts.error && <Loading />}
      {sts.data && sts.data.items.length === 0 && <EmptyState title="No statements here" />}
      {sts.data && sts.data.items.length > 0 && (
        <ul className="approval-list">
          {sts.data.items.map((s) => (
            <li key={s.id} className="approval">
              <h3 className="badges">
                <Badge status={s.status} tone={STATUS_TONE[s.status] ?? "muted"} label={s.status.replace(/_/g, " ")} />
                {s.request_status && <Badge status={s.request_status} tone={s.request_status === "pending" ? "warn" : "muted"} label={s.request_status} />}
                <span className="mono">{s.vulnerability}</span>
              </h3>
              <p className="small">
                {s.justification && <>{s.justification.replace(/_/g, " ")} · </>}
                {s.matches > 0 ? (
                  <Link to={`/fixes/issues?key=${encodeURIComponent(s.vulnerability)}&status=all`}>
                    {plural(s.matches, "component version")} on {plural(s.assets, "asset")}, {plural(s.findings, "open issue")}
                  </Link>
                ) : (
                  "matched nothing"
                )}
              </p>
              {(s.impact_statement || s.action_statement || s.status_notes) && (
                <p className="small">{s.impact_statement || s.action_statement || s.status_notes}</p>
              )}
              <Problems problems={s.problems} max={5} />
            </li>
          ))}
        </ul>
      )}
      {sts.data && <Pager total={sts.data.total} limit={LIMIT} offset={offset} onChange={setOffset} />}
    </>
  );
}
