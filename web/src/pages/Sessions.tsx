import { useState } from "react";
import { Link } from "react-router";
import { api, ApiError } from "../api";
import { Badge } from "../components/Badge";
import { confirmAction } from "../components/ConfirmDialog";
import { ErrorBox, Loading, Notice, RelativeTime } from "../components/ui";
import { useAction, useLoad } from "../hooks";
import { describeUserAgent, signInMethod, sortSessions, type ActiveSession, type SessionList } from "../sessions";

/** Your account → Active sessions: where you are signed in, and signing those sessions out. */
export function ActiveSessionsCard() {
  const res = useLoad(() => api.get<SessionList>("/auth/sessions"), []);
  return (
    <section id="sessions" className="card">
      <header className="card-head">
        <h2>Active sessions</h2>
      </header>
      <ErrorBox error={res.error} title="Could not load your sessions" />
      {!res.data && !res.error && <Loading />}
      {res.data && <ActiveSessionsBody list={res.data} reload={res.reload} />}
    </section>
  );
}

export function ActiveSessionsBody({ list, reload }: { list: SessionList; reload: () => void }) {
  const act = useAction();
  const [ended, setEnded] = useState<number | null>(null);
  const sessions = sortSessions(list.items);
  const others = sessions.filter((s) => !s.current).length;

  const signOut = async (s: ActiveSession) => {
    setEnded(null);
    const ok = await act.run(() =>
      api
        .del(`/auth/sessions/${encodeURIComponent(s.id)}`)
        .then(() => true)
        // Already ended (it expired, or another tab signed it out): gone either way.
        .catch((e: unknown) => {
          if (e instanceof ApiError && e.status === 404) return true;
          throw e;
        }),
    );
    if (ok) reload();
  };
  const signOutOthers = async () => {
    const yes = await confirmAction({
      title: "Sign out of all other sessions?",
      consequence: `${others} other session${others === 1 ? "" : "s"} will be signed out. This one stays signed in.`,
      action: "Sign out others",
    });
    if (!yes) return;
    const r = await act.run(() => api.post<{ sessions_ended: number }>("/auth/sessions/revoke-others"));
    if (r) {
      setEnded(r.sessions_ended);
      reload();
    }
  };

  return (
    <>
      <p>
        Browsers signed in to your account. If you do not recognise one, sign it out and change your password. API tokens are not sessions: see{" "}
        <Link to="/integrations/tokens">Integrations → API tokens</Link>.
      </p>
      {list.pinned && (
        <Notice kind="info">You signed in with your organisation's single sign-on, so only sessions from that sign-on are shown here.</Notice>
      )}
      <ErrorBox error={act.error} title="Could not sign the session out" />
      {ended !== null && (
        <Notice kind="success">
          {ended === 0 ? "There were no other sessions." : `${ended} other session${ended === 1 ? " was" : "s were"} signed out.`}
        </Notice>
      )}
      <ul className="session-list">
        {sessions.map((s) => (
          <li key={s.id}>
            <div>
              <strong>{describeUserAgent(s.user_agent)}</strong>
              {s.current && (
                <>
                  {" "}
                  <Badge status="current" tone="good" label="This device" />
                </>
              )}
              <div className="muted small">
                {s.ip ? <>From {s.ip} · </> : null}
                {signInMethod(s)}
              </div>
              <div className="muted small">
                Signed in <RelativeTime iso={s.signed_in_at} /> · last active {s.current ? "now" : <RelativeTime iso={s.last_seen_at} />}
              </div>
            </div>
            {!s.current && (
              <div className="row-actions">
                <button type="button" className="btn btn-sm btn-link-danger" disabled={act.pending} onClick={() => void signOut(s)}>
                  Sign out
                </button>
              </div>
            )}
          </li>
        ))}
      </ul>
      {others > 0 && (
        <button type="button" className="btn" disabled={act.pending} onClick={() => void signOutOthers()}>
          Sign out of all other sessions
        </button>
      )}
      {others === 0 && <p className="hint">You are not signed in anywhere else.</p>}
    </>
  );
}
