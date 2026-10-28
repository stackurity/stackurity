import { useState } from "react";
import { Link, useSearchParams } from "react-router";
import { api, type IgnoreRequest, type IgnoreRequestList, type IgnoreRule, type List } from "../api";
import { useAuth } from "../auth";
import { useAction, useLoad } from "../hooks";
import { absTime, plural } from "../format";
import { Badge, IGNORE_REASON_LABEL, type Tone } from "../components/Badge";
import { EmptyState, ErrorBox, Loading, Notice, PageHeader, Pager, RelativeTime } from "../components/ui";

const LIMIT = 50;

type Tab = "pending" | "all" | "rules";

const STATUS_TONE: Record<string, Tone> = { pending: "warn", approved: "good", declined: "muted" };

function expiryText(expiry: string, expiresAt: string | null): string {
  if (expiry === "never") return "never expires";
  if (expiry === "until_fix") return "until a fix ships";
  return expiresAt ? `until ${absTime(expiresAt)}` : "until a date";
}

function scopeText(scope: string, asset: string): string {
  return scope === "everywhere" ? "every asset, including ones found later" : asset ? `this asset (${asset})` : "this asset";
}

/** What was asked: the issues, the reason, where and until when. */
function RequestBody({ r }: { r: IgnoreRequest }) {
  const issues = r.fix_group ? (
    <Link to={`/fixes/${encodeURIComponent(r.fix_group)}`}>{plural(r.finding_ids.length, "issue")} of this fix</Link>
  ) : r.finding_ids.length === 1 ? (
    <Link to={`/findings/${r.finding_ids[0]}`}>1 issue</Link>
  ) : (
    plural(r.finding_ids.length, "issue")
  );
  return (
    <>
      <p className="small">
        <strong>{IGNORE_REASON_LABEL[r.reason] ?? r.reason}</strong> · {issues} · {scopeText(r.scope, r.asset_name)} · {expiryText(r.expiry, r.expires_at)}
      </p>
      <p className="small">
        <span className="muted">Why:</span> {r.note}
      </p>
      {r.mitigation && (
        <p className="small">
          <span className="muted">Mitigation:</span> {r.mitigation}
        </p>
      )}
      <p className="small muted">
        Asked by {r.requested_by || "someone"} <RelativeTime iso={r.requested_at} />
        {r.decided_at && (
          <>
            {" "}
            · {r.status} by {r.decided_by || "someone"} <RelativeTime iso={r.decided_at} />
            {r.status === "approved" ? `, ${plural(r.applied, "issue")} ignored` : ""}
          </>
        )}
      </p>
      {r.decision_note && (
        <p className="small">
          <span className="muted">Decision note:</span> {r.decision_note}
        </p>
      )}
    </>
  );
}

function Decide({ r, onDone }: { r: IgnoreRequest; onDone: () => void }) {
  const act = useAction();
  const [note, setNote] = useState("");
  const id = `dn-${r.id}`;
  const decide = async (decision: "approve" | "decline") => {
    if (await act.run(() => api.post(`/ignore-requests/${r.id}/decision`, { decision, note: note.trim() }))) onDone();
  };
  return (
    <>
      <div className="approval-actions form form-compact">
        <div className="field">
          <label htmlFor={id}>Note (optional)</label>
          <input id={id} maxLength={2000} value={note} onChange={(e) => setNote(e.target.value)} />
        </div>
        <button type="button" className="btn btn-sm btn-primary" disabled={act.pending} onClick={() => decide("approve")}>
          Approve
        </button>
        <button type="button" className="btn btn-sm" disabled={act.pending} onClick={() => decide("decline")}>
          Decline
        </button>
      </div>
      <ErrorBox error={act.error} title="Could not decide" />
    </>
  );
}

function Requests({ status }: { status: "pending" | "all" }) {
  const [offset, setOffset] = useState(0);
  const [done, setDone] = useState<string | null>(null);
  const res = useLoad(() => api.get<IgnoreRequestList>("/ignore-requests", { status, limit: LIMIT, offset }), [status, offset]);
  if (res.error) return <ErrorBox error={res.error} title="Could not load requests" />;
  if (!res.data) return <Loading />;
  const items = res.data.items;
  const canDecide = res.data.can_decide;
  return (
    <>
      {!canDecide && (
        <p className="hint">
          You see your own requests. Security and admin users decide them. To ask, use <strong>Ask to ignore</strong> on an issue or a fix.
        </p>
      )}
      {done && <Notice kind="success">{done}</Notice>}
      {items.length === 0 ? (
        <EmptyState title={status === "pending" ? "No requests waiting" : "No requests yet"} help="approvals">
          <p>{status === "pending" ? "Requests to ignore issues show up here until someone decides." : "Every request, waiting, approved or declined, shows up here."}</p>
        </EmptyState>
      ) : (
        <ul className="approval-list">
          {items.map((r) => (
            <li key={r.id} className="approval">
              <h3 className="badges">
                <Badge status={r.status} tone={STATUS_TONE[r.status]} label={r.status} />
                <span className="break">{r.title || `Request #${r.id}`}</span>
              </h3>
              <RequestBody r={r} />
              {canDecide && r.status === "pending" && (
                <Decide
                  r={r}
                  onDone={() => {
                    setDone(`Request #${r.id} decided.`);
                    res.reload();
                  }}
                />
              )}
            </li>
          ))}
        </ul>
      )}
      <Pager total={res.data.total} limit={LIMIT} offset={offset} onChange={setOffset} />
    </>
  );
}

function Rules() {
  const { canAct: can, can: orgCan } = useAuth();
  const [all, setAll] = useState(false);
  const [offset, setOffset] = useState(0);
  const act = useAction();
  const [done, setDone] = useState<string | null>(null);
  const res = useLoad(() => api.get<List<IgnoreRule>>("/ignore-rules", { status: all ? "all" : undefined, limit: LIMIT, offset }), [all, offset]);
  const end = async (r: IgnoreRule) => {
    const out = await act.run(() => api.del<{ reopened: number }>(`/ignore-rules/${r.id}`));
    if (out) {
      setDone(`Rule #${r.id} ended: ${plural(out.reopened, "issue")} back to new.`);
      res.reload();
    }
  };
  return (
    <>
      <p className="hint">
        Each rule ignores one issue (a component and an advisory) on one asset or on every asset, including issues found later. Ending a
        rule returns what it ignores to new.
      </p>
      <label className="check">
        <input
          type="checkbox"
          checked={all}
          onChange={(e) => {
            setAll(e.target.checked);
            setOffset(0);
          }}
        />{" "}
        Show ended rules too
      </label>
      {done && <Notice kind="success">{done}</Notice>}
      <ErrorBox error={act.error ?? res.error} title="Ignore rules" />
      {!res.data && !res.error && <Loading />}
      {res.data && res.data.items.length === 0 && <EmptyState title="No ignore rules" help="ignore-issues" />}
      {res.data && res.data.items.length > 0 && (
        <ul className="approval-list">
          {res.data.items.map((r) => (
            <li key={r.id} className="approval">
              <h3 className="badges">
                <Badge status={r.reason} tone="muted" label={IGNORE_REASON_LABEL[r.reason] ?? r.reason} />
                {r.ended_at && <Badge status="ended" tone="muted" label={r.ended_reason === "expired" ? "expired" : "ended"} />}
                <span className="break">
                  <span className="mono">{r.key}</span> in {r.component_name}
                </span>
              </h3>
              <p className="small">
                {r.scope === "everywhere" ? "Every asset" : <Link to={`/assets/${r.asset_id}`}>{r.asset_name || "one asset"}</Link>} ·{" "}
                {r.until_fix ? "until a fix ships" : r.expires_at ? `until ${absTime(r.expires_at)}` : "never expires"} ·{" "}
                <Link to={`/fixes/issues?key=${encodeURIComponent(r.key)}&state=risk_accepted`}>{plural(r.findings, "open issue")} ignored</Link>
              </p>
              <p className="small">
                <span className="muted">Why:</span> {r.note}
              </p>
              <p className="small muted">
                By {r.created_by || "someone"} <RelativeTime iso={r.created_at} />
                {r.request_id ? ` (request #${r.request_id})` : ""}
                {r.ended_at && (
                  <>
                    {" "}
                    · ended <RelativeTime iso={r.ended_at} />
                    {r.ended_by ? ` by ${r.ended_by}` : ""}
                  </>
                )}
              </p>
              {(r.scope === "everywhere" ? orgCan("security") : can("security")) && !r.ended_at && (
                <div className="approval-actions">
                  <button type="button" className="btn btn-sm" disabled={act.pending} onClick={() => end(r)}>
                    End rule
                  </button>
                </div>
              )}
            </li>
          ))}
        </ul>
      )}
      {res.data && <Pager total={res.data.total} limit={LIMIT} offset={offset} onChange={setOffset} />}
    </>
  );
}

/** The approval inbox: requests to ignore issues, and the ignore rules in force. */
export function ApprovalsPage() {
  const [params, setParams] = useSearchParams();
  const tab = (params.get("tab") as Tab) || "pending";
  const tabs: { id: Tab; label: string }[] = [
    { id: "pending", label: "Pending" },
    { id: "all", label: "All requests" },
    { id: "rules", label: "Ignore rules" },
  ];
  return (
    <>
      <PageHeader
        help="approvals"
        title="Approvals"
        sub="Requests to ignore issues, from people whose role cannot ignore them, and the ignore rules in force."
      />
      <nav className="link-tabs" aria-label="Approvals">
        <ul>
          {tabs.map((t) => (
            <li key={t.id}>
              <Link
                to={`/approvals${t.id === "pending" ? "" : `?tab=${t.id}`}`}
                className={`tab${tab === t.id ? " tab-active" : ""}`}
                aria-current={tab === t.id ? "page" : undefined}
                onClick={() => setParams(t.id === "pending" ? {} : { tab: t.id }, { replace: true })}
              >
                {t.label}
              </Link>
            </li>
          ))}
        </ul>
      </nav>
      {tab === "rules" ? <Rules /> : <Requests key={tab} status={tab === "all" ? "all" : "pending"} />}
    </>
  );
}
