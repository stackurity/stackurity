import { useState } from "react";
import { Link } from "react-router";
import { api, type Conflict, type List } from "../../api";
import { useAction, useLoad } from "../../hooks";
import { humanize } from "../../format";
import { Card, EmptyState, ErrorBox, Loading, Notice, PageHeader, RelativeTime } from "../../components/ui";

export function ConflictsPage() {
  const res = useLoad(() => api.get<List<Conflict>>("/conflicts"), []);
  const [msg, setMsg] = useState<string | null>(null);

  return (
    <>
      <PageHeader help="admin-tools"
        title="Identity conflicts"
        sub="A collector reported identifiers that match more than one asset. Choose the asset to keep; the others are merged into it (inventory, coverage, history and relations move over)."
      />
      {msg && <Notice kind="success">{msg}</Notice>}
      <ErrorBox error={res.error} title="Could not load conflicts" />
      {!res.data && !res.error && <Loading />}
      {res.data && res.data.items.length === 0 && (
        <EmptyState title="No open identity conflicts">
          <p>Nothing to do. Conflicts appear here when one machine or repository is reported under two identities.</p>
        </EmptyState>
      )}
      {res.data?.items.map((c) => (
        <ConflictCard
          key={c.id}
          conflict={c}
          onResolved={(name, notice) => {
            setMsg(`Conflict #${c.id} resolved: merged into ${name}.${notice ? ` ${notice}` : ""}`);
            res.reload();
          }}
        />
      ))}
    </>
  );
}

function ConflictCard({ conflict, onResolved }: { conflict: Conflict; onResolved: (name: string, notice?: string) => void }) {
  // Candidate details come with the conflict; any ID missing from
  // `assets` (e.g. deleted since) is still listed so it can be seen.
  const byId = new Map((conflict.assets ?? []).map((a) => [a.id, a]));
  const candidates = conflict.asset_ids.map((id) => ({ id, asset: byId.get(id) }));
  const [target, setTarget] = useState<number | null>(null);
  const act = useAction();

  const resolve = async () => {
    if (target === null) return;
    const a = byId.get(target);
    const name = a?.name ?? `asset #${target}`;
    const others = conflict.asset_ids.length - 1;
    if (!window.confirm(`Merge ${others} other asset(s) into "${name}"? This cannot be undone.`)) return;
    // The kept asset joins the merged assets' projects and takes their
    // access grants; the server says so in `notice`.
    const res = await act.run(() => api.post<{ notice?: string }>(`/conflicts/${conflict.id}/resolve`, { target_asset_id: target }));
    if (res) onResolved(name, res.notice);
  };

  return (
    <Card
      title={
        <>
          Conflict #{conflict.id} <span className="muted small">detected <RelativeTime iso={conflict.detected_at} /></span>
        </>
      }
    >
      {conflict.identifiers && conflict.identifiers.length > 0 && (
        <p className="small">
          Shared identifiers:{" "}
          {conflict.identifiers.map((i, n) => (
            <span key={n}>
              {n > 0 && ", "}
              <span className="mono">
                {i.scheme}={i.value}
              </span>
            </span>
          ))}
        </p>
      )}
      {(
        <fieldset className="field">
          <legend>Keep which asset?</legend>
          <ul className="choice-list">
            {candidates.map(({ id, asset: a }) => {
              return (
                <li key={id}>
                  <label className="choice">
                    <input type="radio" name={`conflict-${conflict.id}`} checked={target === id} onChange={() => setTarget(id)} />
                    <span>
                      {a ? (
                        <>
                          <strong>{a.name}</strong> <span className="muted">#{id}</span>
                          <span className="muted small block">
                            {humanize(a.kind)} · {a.component_count} components · last seen{" "}
                            <RelativeTime iso={a.last_seen} /> ·{" "}
                            <Link to={`/assets/${id}`} target="_blank" rel="noreferrer">
                              open
                            </Link>
                          </span>
                        </>
                      ) : (
                        <>
                          Asset #{id} <span className="text-bad small">(no longer available)</span>
                        </>
                      )}
                    </span>
                  </label>
                </li>
              );
            })}
          </ul>
        </fieldset>
      )}
      <ErrorBox error={act.error} title="Could not resolve" />
      <div className="form-actions">
        <button type="button" className="btn btn-primary" disabled={target === null || act.pending} onClick={resolve}>
          Merge into selected asset
        </button>
      </div>
    </Card>
  );
}
