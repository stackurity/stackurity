import { useEffect, useState, type FormEvent } from "react";
import { useSearchParams } from "react-router";
import {
  evidenceApi,
  type ApiError,
  type DrataConnect,
  type EvidenceChange,
  type EvidenceConnection,
  type EvidenceInterval,
  type EvidenceRegion,
  type EvidenceStatus,
  type EvidenceSyncRun,
  type EvidenceVendor,
  type VantaDocument,
} from "../api";
import { useAuth } from "../auth";
import { useAction, useLoad } from "../hooks";
import { Badge } from "./Badge";
import { confirmAction } from "./ConfirmDialog";
import { ProNotice } from "./ProNotice";
import { Card, ErrorBox, GoodToKnow, Loading, Notice, RelativeTime, SettingRow } from "./ui";
import {
  connectionState,
  DRATA_API_KEYS_HELP,
  EVIDENCE_DOCS,
  evidenceReturnNotice,
  INTERVALS,
  lastSyncText,
  REGIONS,
  rowPurpose,
  VANTA_SETUP_DOCS,
  VENDOR_NAME,
  withoutEvidenceReturn,
} from "../evidenceConnectors";

/*
 * Settings → Integrations, "Compliance evidence": sends the asset inventory,
 * open vulnerabilities (with their SLA status) and the evidence pack to Vanta
 * and Drata on a schedule. Part of the Compliance add-on: without it the card
 * shows the locked paid-plans notice. An organisation whose plan dropped the
 * add-on still sees its existing connections with Disconnect (the list and
 * the delete work without the add-on), so the stored tokens and key can be
 * removed. The routes exist only in the licensed build
 * (docs/evidence-connectors.md).
 */

const TITLE = "Compliance evidence";
const DESCRIPTION =
  "Keep your compliance platform up to date with what Stackurity checks: your assets, their open vulnerabilities and whether each is being fixed within its deadline. Stackurity only sends; it changes nothing in your estate.";

/** The card on the Integrations page, for admins. */
export function ComplianceEvidenceCard() {
  const { has, can } = useAuth();
  if (!can("admin")) return null;
  if (!has("compliance_addon")) return <EvidenceWithoutAddon />;
  return <EvidenceConnectorsLoaded />;
}

/**
 * Without the add-on: the locked card, unless connections are left from
 * when the plan had it (a downgrade). Those stay listed with Disconnect.
 */
function EvidenceWithoutAddon() {
  const res = useLoad(() => evidenceApi.status(), []);
  const act = useAction();
  const [done, setDone] = useState<string | null>(null);
  const data = res.data;
  if (!data || connectedVendors(data).length === 0) {
    // Nothing connected (or nothing to load, as in the Community build).
    return done ? (
      <Card id="compliance-evidence" title={TITLE} description={DESCRIPTION}>
        <Notice kind="success">{done}</Notice>
      </Card>
    ) : (
      <EvidenceLockedCard />
    );
  }
  const disconnect = async (vendor: EvidenceVendor) => {
    if (!(await confirmDisconnect(vendor))) return;
    const ok = await act.run(() => evidenceApi.disconnect(vendor).then(() => true));
    if (ok) {
      setDone(`${VENDOR_NAME[vendor]} disconnected.`);
      res.reload();
    }
  };
  return <EvidenceDowngradedCard status={data} busy={act.pending} error={act.error} done={done} onDisconnect={disconnect} />;
}

function connectedVendors(status: EvidenceStatus): EvidenceVendor[] {
  return (["vanta", "drata"] as const).filter((v) => status[v].connection);
}

/**
 * The plan lost the Compliance add-on while Vanta or Drata was connected:
 * syncing is off, and each connection can still be disconnected.
 */
export function EvidenceDowngradedCard({
  status,
  busy,
  error,
  done,
  onDisconnect,
}: {
  status: EvidenceStatus;
  busy: boolean;
  error?: ApiError | null;
  done?: string | null;
  onDisconnect: (vendor: EvidenceVendor) => void | Promise<void>;
}) {
  return (
    <Card id="compliance-evidence" title={TITLE} description={DESCRIPTION}>
      <Notice kind="warn">
        Syncing is off: this workspace&apos;s plan no longer includes the Compliance add-on, so Stackurity sends nothing to Vanta or Drata. The connections
        below are kept and start syncing again when the add-on is back. You can disconnect them now, which deletes the stored access.
      </Notice>
      {done && <Notice kind="success">{done}</Notice>}
      <ErrorBox error={error} title="Could not disconnect" />
      {connectedVendors(status).map((v) => (
        <SettingRow key={v} title={VENDOR_NAME[v]} badge={<span className="pro-badge">Compliance add-on</span>} description={rowPurpose(v, status[v].connection)}>
          <p className="small">
            <strong>Syncing off.</strong> Last sync: <RelativeTime iso={status[v].connection?.last_sync_at} />.
          </p>
          <div className="row-actions">
            <button type="button" className="btn btn-sm btn-link-danger" disabled={busy} onClick={() => void onDisconnect(v)}>
              Disconnect
            </button>
          </div>
        </SettingRow>
      ))}
      <SettingRow title="Included in this workspace" description="Syncing needs the Compliance add-on.">
        <ProNotice feature="compliance_addon">Add it back to keep the vulnerability-management evidence in Vanta or Drata current. </ProNotice>
      </SettingRow>
    </Card>
  );
}

function confirmDisconnect(vendor: EvidenceVendor): Promise<boolean> {
  return confirmAction({
    title: `Disconnect ${VENDOR_NAME[vendor]}?`,
    consequence:
      vendor === "vanta"
        ? "Stackurity stops sending to Vanta and deletes its access. What was already sent stays in Vanta until you remove it there."
        : "Stackurity stops sending to Drata and deletes the stored API key. What was already sent stays in Drata until you remove it there; revoke the key in Drata too.",
    action: `Disconnect ${VENDOR_NAME[vendor]}`,
  });
}

/** Without the Compliance add-on: what it would do, and how to get it. Nothing is loaded. */
export function EvidenceLockedCard() {
  return (
    <Card id="compliance-evidence" title={TITLE} description={DESCRIPTION}>
      <SettingRow title="Vanta" badge={<span className="pro-badge">Compliance add-on</span>} description={rowPurpose("vanta", null)}>
        <span className="muted">Not included</span>
      </SettingRow>
      <SettingRow title="Drata" badge={<span className="pro-badge">Compliance add-on</span>} description={rowPurpose("drata", null)}>
        <span className="muted">Not included</span>
      </SettingRow>
      <SettingRow title="Included in this workspace" description="The connectors need the licensed build and the Compliance add-on.">
        <ProNotice feature="compliance_addon">
          It keeps the vulnerability-management evidence in Vanta or Drata current, so auditors see the same numbers as Stackurity.{" "}
        </ProNotice>
      </SettingRow>
    </Card>
  );
}

function EvidenceConnectorsLoaded() {
  const [params, setParams] = useSearchParams();
  const res = useLoad(() => evidenceApi.status(), []);
  const act = useAction();
  const returned = evidenceReturnNotice(params);
  const [done, setDone] = useState<string | null>(null);
  // Back from Vanta's consent page: bring the card and its notice into view.
  const back = Boolean(returned);
  useEffect(() => {
    if (back) document.getElementById("compliance-evidence")?.scrollIntoView({ block: "start" });
  }, [back]);

  const actions: EvidenceActions = {
    busy: act.pending,
    connectVanta: async (region) => {
      const r = await act.run(() => evidenceApi.connectVanta(region));
      if (r && /^https:\/\//.test(r.authorize_url)) window.location.assign(r.authorize_url);
    },
    connectDrata: async (b) => {
      const ok = await act.run(() => evidenceApi.connectDrata(b).then(() => true));
      if (ok) {
        setDone("Drata connected. The first sync starts within a few minutes.");
        res.reload();
      }
      return Boolean(ok);
    },
    update: async (vendor, b) => {
      const ok = await act.run(() => evidenceApi.update(vendor, b).then(() => true));
      if (ok) {
        setDone(b.status === "paused" ? `${VENDOR_NAME[vendor]} paused.` : b.status === "active" ? `${VENDOR_NAME[vendor]} resumed.` : `${VENDOR_NAME[vendor]} saved.`);
        res.reload();
      }
    },
    sync: async (vendor) => {
      const ok = await act.run(() => evidenceApi.sync(vendor).then(() => true));
      if (ok) setDone(`${VENDOR_NAME[vendor]} sync queued. It usually finishes within a few minutes.`);
    },
    disconnect: async (vendor) => {
      if (!(await confirmDisconnect(vendor))) return;
      const ok = await act.run(() => evidenceApi.disconnect(vendor).then(() => true));
      if (ok) {
        setDone(`${VENDOR_NAME[vendor]} disconnected.`);
        res.reload();
      }
    },
    loadDocuments: () => evidenceApi.vantaDocuments().then((r) => r.items),
    loadRuns: (vendor) => evidenceApi.runs(vendor).then((r) => r.items),
  };

  // The Community build does not serve these routes even with a licence.
  const notServed = res.error?.status === 404;
  return (
    <Card id="compliance-evidence" title={TITLE} description={DESCRIPTION}>
      {returned && (
        <Notice kind={returned.kind}>
          {returned.text}{" "}
          <button type="button" className="btn btn-link" onClick={() => setParams(withoutEvidenceReturn(params), { replace: true })}>
            Dismiss
          </button>
        </Notice>
      )}
      {done && <Notice kind="success">{done}</Notice>}
      <ErrorBox error={act.error} title="Could not change the compliance evidence connection" />
      {notServed ? (
        <Notice kind="warn">
          This server runs the Community build, which does not include the evidence connectors even with a licence. Ask whoever runs this server to switch to the
          licensed build (<a href={EVIDENCE_DOCS}>how it works</a>).
        </Notice>
      ) : (
        <>
          <ErrorBox error={res.error} title="Could not load the compliance evidence connections" />
          {res.loading && !res.data ? <Loading /> : res.data ? <EvidenceRows status={res.data} actions={actions} /> : null}
        </>
      )}
    </Card>
  );
}

/** What the rows can do; the card passes the API calls, tests pass stubs. */
export interface EvidenceActions {
  busy: boolean;
  connectVanta: (region: EvidenceRegion) => void | Promise<void>;
  /** true when Drata accepted the key. */
  connectDrata: (b: DrataConnect) => Promise<boolean>;
  update: (vendor: EvidenceVendor, b: EvidenceChange) => void | Promise<void>;
  sync: (vendor: EvidenceVendor) => void | Promise<void>;
  disconnect: (vendor: EvidenceVendor) => void | Promise<void>;
  loadDocuments: () => Promise<VantaDocument[]>;
  loadRuns: (vendor: EvidenceVendor) => Promise<EvidenceSyncRun[]>;
}

/** The Vanta and Drata rows, from GET /integrations/evidence. */
export function EvidenceRows({ status, actions }: { status: EvidenceStatus; actions: EvidenceActions }) {
  return (
    <>
      <VantaRow available={status.vanta.available} connection={status.vanta.connection} actions={actions} />
      <DrataRow connection={status.drata.connection} actions={actions} />
      <GoodToKnow>
        Everything sent comes from the evidence pack for the last 30 days: the same assets, open vulnerabilities and SLA status as the evidence report. Each
        sync replaces what Stackurity sent before, so fixed vulnerabilities disappear from the vendor. Vanta has no field for SLA status, so the deadlines
        and whether each was met travel in the evidence file. <a href={EVIDENCE_DOCS}>What is sent, and when</a>
      </GoodToKnow>
    </>
  );
}

function StateBadge({ connection }: { connection: EvidenceConnection | null }) {
  const s = connectionState(connection);
  return <Badge status={s.label} tone={s.tone} label={s.label} />;
}

function RegionSelect({ vendor, id, value, onChange }: { vendor: EvidenceVendor; id: string; value: EvidenceRegion; onChange: (r: EvidenceRegion) => void }) {
  return (
    <div className="field">
      <label htmlFor={id}>{VENDOR_NAME[vendor]} region</label>
      <select id={id} value={value} onChange={(e) => onChange(e.target.value as EvidenceRegion)}>
        {REGIONS[vendor].map((r) => (
          <option key={r.value} value={r.value}>
            {r.label}
          </option>
        ))}
      </select>
    </div>
  );
}

export function VantaRow({ available, connection, actions }: { available: boolean; connection: EvidenceConnection | null; actions: EvidenceActions }) {
  const [region, setRegion] = useState<EvidenceRegion>(connection?.region ?? "us");
  const needsConnect = !connection || connection.status === "reconnect_needed";
  return (
    <SettingRow title="Vanta" badge={<StateBadge connection={connection} />} description={rowPurpose("vanta", connection)}>
      {!available ? (
        <p className="small">
          <strong>Not set up on this server.</strong> Whoever runs this server registers a Vanta app once, then Connect Vanta appears here.{" "}
          <a href={VANTA_SETUP_DOCS}>How to set it up</a>
        </p>
      ) : (
        <>
          {connection && <ConnectionDetails vendor="vanta" connection={connection} actions={actions} />}
          {needsConnect && (
            <div className="form">
              <p className="small">You approve on Vanta&apos;s page and come back here. Stackurity asks only to write its own resources and evidence documents.</p>
              <RegionSelect vendor="vanta" id="evidence-vanta-region" value={region} onChange={setRegion} />
              <button type="button" className="btn btn-primary" disabled={actions.busy} onClick={() => void actions.connectVanta(region)}>
                {connection ? "Reconnect Vanta" : "Connect Vanta"}
              </button>
            </div>
          )}
          {connection && connection.status !== "reconnect_needed" && <VantaDocumentPicker connection={connection} actions={actions} />}
        </>
      )}
    </SettingRow>
  );
}

function VantaDocumentPicker({ connection, actions }: { connection: EvidenceConnection; actions: EvidenceActions }) {
  const [docs, setDocs] = useState<VantaDocument[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [pick, setPick] = useState(connection.config.document_id ?? "");
  const current = connection.config.document_id;
  const load = () => {
    setError(null);
    actions.loadDocuments().then(setDocs, (e: unknown) => setError(e instanceof Error ? e.message : String(e)));
  };
  return (
    <div className="form">
      <p className="small">
        <strong>Evidence file goes to:</strong>{" "}
        {current ? connection.config.document_title || current : <span className="muted">no document chosen yet, so only the assets and vulnerabilities are sent</span>}
      </p>
      {docs === null ? (
        <button type="button" className="btn" onClick={load} disabled={actions.busy}>
          {current ? "Change document" : "Choose a Vanta document"}
        </button>
      ) : docs.length === 0 ? (
        <p className="small muted">Vanta lists no documents this connection can upload to. Create one in Vanta, then try again.</p>
      ) : (
        <div className="field">
          <label htmlFor="evidence-vanta-document">Vanta document for the evidence file</label>
          <select id="evidence-vanta-document" value={pick} onChange={(e) => setPick(e.target.value)}>
            <option value="">Choose…</option>
            {docs.map((d) => (
              <option key={d.id} value={d.id}>
                {d.title}
              </option>
            ))}
          </select>
          <button type="button" className="btn" disabled={!pick || pick === current || actions.busy} onClick={() => void actions.update("vanta", { vanta_document_id: pick })}>
            Save document
          </button>
        </div>
      )}
      {error && <p className="small">Could not list Vanta documents: {error}</p>}
    </div>
  );
}

export function DrataRow({ connection, actions }: { connection: EvidenceConnection | null; actions: EvidenceActions }) {
  const needsKey = !connection || connection.status === "reconnect_needed";
  return (
    <SettingRow title="Drata" badge={<StateBadge connection={connection} />} description={rowPurpose("drata", connection)}>
      {connection && <ConnectionDetails vendor="drata" connection={connection} actions={actions} />}
      {needsKey && <DrataConnectForm connection={connection} actions={actions} />}
    </SettingRow>
  );
}

function DrataConnectForm({ connection, actions }: { connection: EvidenceConnection | null; actions: EvidenceActions }) {
  const [apiKey, setApiKey] = useState("");
  const [region, setRegion] = useState<EvidenceRegion>(connection?.region ?? "us");
  const [workspace, setWorkspace] = useState(connection?.config.workspace_id != null ? String(connection.config.workspace_id) : "");
  const submit = async (e: FormEvent) => {
    e.preventDefault();
    await actions.connectDrata({ api_key: apiKey.trim(), region, drata_workspace_id: workspace.trim() });
    // The key is never kept in the page once it was sent, accepted or not.
    setApiKey("");
  };
  return (
    <form className="form" onSubmit={submit} autoComplete="off">
      <p className="small">
        In Drata, an admin creates an API key with read and write access to custom connections and evidence (<a href={DRATA_API_KEYS_HELP}>Drata&apos;s API
        documentation</a>). Stackurity checks it with one read, then stores it encrypted. It is never shown again.
      </p>
      <p className="small">
        <strong>Drata must have &ldquo;Custom Connections and Tests&rdquo; enabled</strong> for your account, or Drata refuses the data.
      </p>
      <div className="field">
        <label htmlFor="evidence-drata-key">Drata API key</label>
        <input id="evidence-drata-key" type="password" autoComplete="off" required value={apiKey} onChange={(e) => setApiKey(e.target.value)} />
      </div>
      <RegionSelect vendor="drata" id="evidence-drata-region" value={region} onChange={setRegion} />
      <div className="field">
        <label htmlFor="evidence-drata-workspace">Drata workspace ID</label>
        <input id="evidence-drata-workspace" inputMode="numeric" required value={workspace} onChange={(e) => setWorkspace(e.target.value)} />
        <p className="hint">The ID of the Drata workspace the evidence belongs to, as Drata shows it in its workspace settings or API.</p>
      </div>
      <button type="submit" className="btn btn-primary" disabled={actions.busy || !apiKey.trim() || !workspace.trim()}>
        {connection ? "Reconnect Drata" : "Connect Drata"}
      </button>
    </form>
  );
}

/** A connected vendor: its status, last sync and controls. */
function ConnectionDetails({ vendor, connection: c, actions }: { vendor: EvidenceVendor; connection: EvidenceConnection; actions: EvidenceActions }) {
  const paused = c.status === "paused";
  const broken = c.status === "reconnect_needed";
  const tone = c.last_sync_status === "ok" ? "good" : c.last_sync_status === "partial" ? "warn" : c.last_sync_status === "failed" ? "bad" : undefined;
  return (
    <div className="form">
      {broken && (
        <p className="small">
          <strong>{VENDOR_NAME[vendor]} stopped accepting this connection</strong>
          {c.status_reason ? `: ${c.status_reason}` : "."} Syncs are stopped until you reconnect.
        </p>
      )}
      <p className="small">
        <strong>Last sync:</strong> <RelativeTime iso={c.last_sync_at} />{" "}
        {c.last_sync_status && tone && <Badge status={c.last_sync_status} tone={tone} />} {lastSyncText(c)}
      </p>
      {!broken && (
        <p className="small">
          <strong>Next sync:</strong> {paused ? "none while paused" : <RelativeTime iso={c.next_sync_at} empty="soon" />}
        </p>
      )}
      <div className="field">
        <label htmlFor={`evidence-${vendor}-interval`}>How often</label>
        <select
          id={`evidence-${vendor}-interval`}
          value={c.interval_hours}
          disabled={actions.busy}
          onChange={(e) => void actions.update(vendor, { interval_hours: Number(e.target.value) as EvidenceInterval })}
        >
          {INTERVALS.map((i) => (
            <option key={i.value} value={i.value}>
              {i.label}
            </option>
          ))}
        </select>
      </div>
      <div className="row-actions">
        {!broken && (
          <button type="button" className="btn" disabled={actions.busy || paused} onClick={() => void actions.sync(vendor)} title={paused ? "Resume it first" : undefined}>
            Sync now
          </button>
        )}
        {!broken && (
          <button type="button" className="btn" disabled={actions.busy} onClick={() => void actions.update(vendor, { status: paused ? "active" : "paused" })}>
            {paused ? "Resume" : "Pause"}
          </button>
        )}
        <button type="button" className="btn btn-sm btn-link-danger" disabled={actions.busy} onClick={() => void actions.disconnect(vendor)}>
          Disconnect
        </button>
      </div>
      <RecentRuns vendor={vendor} actions={actions} />
    </div>
  );
}

function RecentRuns({ vendor, actions }: { vendor: EvidenceVendor; actions: EvidenceActions }) {
  const [runs, setRuns] = useState<EvidenceSyncRun[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  return (
    <details
      className="small"
      onToggle={(e) => {
        if (e.currentTarget.open && runs === null) actions.loadRuns(vendor).then(setRuns, (err: unknown) => setError(err instanceof Error ? err.message : String(err)));
      }}
    >
      <summary>Recent syncs</summary>
      {error ? (
        <p>Could not load the syncs: {error}</p>
      ) : runs === null ? (
        <Loading />
      ) : runs.length === 0 ? (
        <p className="muted">No syncs yet.</p>
      ) : (
        <ul>
          {runs.map((r) => (
            <li key={r.id}>
              <RelativeTime iso={r.started_at} /> <Badge status={r.status} />{" "}
              {typeof r.counts.assets === "number" && `${r.counts.assets} assets, `}
              {typeof r.counts.vulnerabilities === "number" && `${r.counts.vulnerabilities} vulnerabilities`}
              {r.counts.evidence_uploaded ? ", evidence file" : ""}
              {r.error ? `: ${r.error}` : ""}
            </li>
          ))}
        </ul>
      )}
    </details>
  );
}
