import { useState } from "react";
import { api, type List } from "../../api";
import { useLoad } from "../../hooks";
import { Card, ErrorBox, GoodToKnow, Loading, PageHeader } from "../../components/ui";

/*
 * Admin, Trust badges: Stackurity operators' evidence viewer. For any badge
 * of any organisation it shows every status decision with its full
 * evidence: the inputs, each source's freshness and cursor, the conditions
 * that failed, the rule version and the timeline. Listing badges and
 * opening a history are each written to the audit log.
 */

interface AdminBadge {
  id: number;
  workspace_id: number;
  workspace_name: string;
  slug: string;
  enabled: boolean;
  last_result: string | null;
  last_reason: string | null;
  last_decided_at: string | null;
}

interface StatusEntry {
  id: number;
  decided_at: string;
  result: string;
  reason: string;
  rule_version: string;
  previous_result: string | null;
  evidence: {
    inputs: {
      assets: { id: number; kind: string; last_report: string | null; latest_complete: boolean; failed_scopes: number; processed_at: string | null }[];
      sources: Record<string, { exists: boolean; enabled: boolean; cursor: string; last_success: string | null; stale_after: number }>;
      pairs: { class: string; kind?: string; source?: string; count: number }[];
    };
    decision: { failed: string[]; states: Record<string, number>; unsupported_kinds: string[]; oldest_evaluated: string | null };
  };
}

const when = (s: string | null | undefined) => (s ? new Date(s).toUTCString() : "never");

export function TrustBadgesAdminPage() {
  const res = useLoad(() => api.get<List<AdminBadge>>("/admin/trust-badges"), []);
  const [open, setOpen] = useState<number | null>(null);
  return (
    <>
      <PageHeader
        title="Trust badges"
        sub="Every organisation’s trust badges and why each one is, or isn’t, active. Open a badge to see the evidence behind each decision."
      />
      <GoodToKnow title="Every view is audited">
        Listing badges and opening a badge’s history are each written to the audit log with your name. Open a history only when you need
        it, for example to answer a customer or counsel.
      </GoodToKnow>
      <ErrorBox error={res.error} title="Could not load trust badges" />
      {!res.data && !res.error && <Loading />}
      {res.data && (
        <Card title="Badges" description="The last decision for each badge. Decisions are made hourly, and when a badge is turned on or changed.">
          <table className="table">
            <thead>
              <tr>
                <th>Organisation</th>
                <th>Address</th>
                <th>On</th>
                <th>Last decision</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {(res.data.items ?? []).map((b) => (
                <tr key={b.id}>
                  <td>{b.workspace_name}</td>
                  <td className="mono">{b.slug}</td>
                  <td>{b.enabled ? "Yes" : "No"}</td>
                  <td>
                    {b.last_result ? `${b.last_result} (${b.last_reason}) at ${when(b.last_decided_at)}` : "No decision yet"}
                  </td>
                  <td>
                    <button className="btn" onClick={() => setOpen(open === b.id ? null : b.id)}>
                      {open === b.id ? "Close" : "Evidence"}
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </Card>
      )}
      {open !== null && <Evidence id={open} />}
    </>
  );
}

function Evidence({ id }: { id: number }) {
  const res = useLoad(() => api.get<{ items: StatusEntry[]; reasons: Record<string, string> }>(`/admin/trust-badges/${id}/history`, { limit: 200 }), [id]);
  const [pick, setPick] = useState(0);
  if (res.error) return <ErrorBox error={res.error} title="Could not load the evidence" />;
  if (!res.data) return <Loading />;
  const items = res.data.items ?? [];
  const reasons = res.data.reasons ?? {};
  const e = items[pick];
  return (
    <>
      <Card title="Timeline" description="Each decision, newest first. Pick one to see its evidence.">
        <table className="table">
          <thead>
            <tr>
              <th>When</th>
              <th>Result</th>
              <th>Reason</th>
              <th>Rule</th>
              <th>Before</th>
            </tr>
          </thead>
          <tbody>
            {items.map((x, i) => (
              <tr key={x.id} className={i === pick ? "selected" : undefined} onClick={() => setPick(i)} style={{ cursor: "pointer" }}>
                <td>{when(x.decided_at)}</td>
                <td>{x.result}</td>
                <td>{reasons[x.reason] ?? x.reason}</td>
                <td className="mono">{x.rule_version}</td>
                <td>{x.previous_result ?? "none"}</td>
              </tr>
            ))}
          </tbody>
        </table>
        {items.length === 0 && <p className="muted">No decisions recorded.</p>}
      </Card>
      {e && (
        <Card title={`Evidence for the decision at ${when(e.decided_at)}`} description="The inputs the rule read and what it concluded. The decision can be rebuilt from these.">
          <h3>Failed conditions</h3>
          <p>{e.evidence.decision.failed.length ? e.evidence.decision.failed.map((f) => reasons[f] ?? f).join("; ") : "None"}</p>
          <h3>Component states</h3>
          <p>
            {Object.entries(e.evidence.decision.states)
              .map(([k, v]) => `${k}: ${v}`)
              .join(", ") || "None"}
            . Oldest evaluation: {when(e.evidence.decision.oldest_evaluated)}.
          </p>
          <h3>Systems</h3>
          <table className="table">
            <thead>
              <tr>
                <th>Asset id</th>
                <th>Kind</th>
                <th>Last report</th>
                <th>Latest inventory complete</th>
                <th>Failed collection scopes</th>
                <th>Processed</th>
              </tr>
            </thead>
            <tbody>
              {e.evidence.inputs.assets.map((a) => (
                <tr key={a.id}>
                  <td className="mono">{a.id}</td>
                  <td>{a.kind}</td>
                  <td>{when(a.last_report)}</td>
                  <td>{a.latest_complete ? "Yes" : "No"}</td>
                  <td>{a.failed_scopes}</td>
                  <td>{when(a.processed_at)}</td>
                </tr>
              ))}
            </tbody>
          </table>
          <h3>Sources</h3>
          <table className="table">
            <thead>
              <tr>
                <th>Source</th>
                <th>Enabled</th>
                <th>Last successful sync</th>
                <th>Freshness window</th>
                <th>Cursor</th>
              </tr>
            </thead>
            <tbody>
              {Object.entries(e.evidence.inputs.sources).map(([name, s]) => (
                <tr key={name}>
                  <td className="mono">{name}</td>
                  <td>{s.exists ? (s.enabled ? "Yes" : "No") : "Missing"}</td>
                  <td>{when(s.last_success)}</td>
                  <td>{Math.round(s.stale_after / 3.6e12)} h</td>
                  <td className="mono small">{s.cursor || "none"}</td>
                </tr>
              ))}
            </tbody>
          </table>
          <details>
            <summary>Raw evidence (JSON)</summary>
            <pre className="small">{JSON.stringify(e.evidence, null, 2)}</pre>
          </details>
        </Card>
      )}
    </>
  );
}
