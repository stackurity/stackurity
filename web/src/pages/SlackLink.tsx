import { useEffect, useState } from "react";
import { Link } from "react-router";
import { api, ApiError, type List, type SlackLink, type SlackLinkPreview } from "../api";
import { useAuth } from "../auth";
import { useAction, useLoad } from "../hooks";
import { absTime } from "../format";
import { ErrorBox, Loading, Notice, RelativeTime } from "../components/ui";
import { confirmAction } from "../components/ConfirmDialog";

function slackWho(l: { slack_user_name: string; slack_user_id: string; team_name: string; team_id: string }) {
  return (
    <>
      <strong>{l.slack_user_name || l.slack_user_id}</strong> <span className="muted">({l.slack_user_id})</span> in the Slack workspace{" "}
      <strong>{l.team_name || l.team_id}</strong> <span className="muted">({l.team_id})</span>
    </>
  );
}

/**
 * /slack/link#<token>: confirm that a Slack account (the one that clicked a
 * button in Slack) acts as the signed-in person. The token stays in the
 * address's fragment, which browsers never send to a server, and goes to
 * the API in a request body only.
 */
export function SlackLinkPage() {
  const { me, logout } = useAuth();
  const [token] = useState(() => window.location.hash.replace(/^#/, "").trim());
  const [pv, setPv] = useState<{ link: SlackLinkPreview; signed_in_as: string } | null>(null);
  const [error, setError] = useState<ApiError | null>(null);
  const [done, setDone] = useState(false);
  const act = useAction();

  useEffect(() => {
    if (!token) return;
    api
      .post<{ link: SlackLinkPreview; signed_in_as: string }>("/slack/links/preview", { token })
      .then((r) => {
        setPv(r);
        setError(null);
      })
      .catch((e) => setError(e as ApiError));
  }, [token]);

  const linkAccount = async () => {
    const r = await act.run(() => api.post<SlackLink>("/slack/links/confirm", { token }));
    if (r) {
      // Drop the token from the address and the browser's history.
      window.history.replaceState(null, "", "/slack/link");
      setDone(true);
    }
  };

  const org = me?.workspace?.name ?? "this organisation";
  let body;
  if (!token) {
    body = <Notice kind="warn">This page needs the whole link from Slack. Click the button in Slack again for a new one.</Notice>;
  } else if (done && pv) {
    body = (
      <>
        <Notice kind="success">
          Linked. {slackWho(pv.link)} now acts as {pv.signed_in_as} in {org}.
        </Notice>
        <p>Go back to Slack and click the button again.</p>
        <p className="small">
          <Link to="/account#slack">Your linked Slack accounts</Link> · <Link to="/">Dashboard</Link>
        </p>
      </>
    );
  } else if (error) {
    body =
      error.status === 410 ? (
        <Notice kind="warn">
          This link does not work any more. It works once, for 15 minutes, and only in the organisation of the Slack channel. Click the button in Slack again for a new
          one. If you belong to several organisations, switch to the one the Slack channel is for first.
        </Notice>
      ) : (
        <ErrorBox error={error} title="Could not open the link" />
      );
  } else if (!pv) {
    body = <Loading />;
  } else if (pv.link.linked_to_you) {
    body = (
      <>
        <Notice kind="info">
          {slackWho(pv.link)} is already linked to your account. Go back to Slack and click the button again.
        </Notice>
        <p className="small">
          <Link to="/account#slack">Your linked Slack accounts</Link>
        </p>
      </>
    );
  } else if (pv.link.linked_to_other) {
    body = (
      <Notice kind="warn">
        This Slack account is already linked to another Stackurity account in {org}. That person has to unlink it first (account menu, Your account).
      </Notice>
    );
  } else {
    body = (
      <>
        <p>
          Link {slackWho(pv.link)} to your Stackurity account <strong>{pv.signed_in_as}</strong> in <strong>{org}</strong>?
        </p>
        <p className="hint">
          Buttons that Slack account clicks in Stackurity messages (Assign to me, Snooze) will act as you, with your role and projects, and show in the activity
          log as yours. Only link your own Slack account. The link works until {absTime(pv.link.expires_at)}; you can unlink it any time.
        </p>
        <ErrorBox error={act.error} title="Could not link" />
        <div className="slack-link-actions">
          <button type="button" className="btn btn-primary btn-block" onClick={() => void linkAccount()} disabled={act.pending} autoFocus>
            {act.pending ? "Linking…" : "Link my Slack account"}
          </button>
          <Link to="/" className="btn btn-block">
            Cancel
          </Link>
        </div>
        <p className="small muted">
          Not you?{" "}
          <button type="button" className="btn-link" onClick={() => void logout()}>
            Sign out
          </button>{" "}
          and open the link again.
        </p>
      </>
    );
  }

  return (
    <div className="center-screen">
      <div className="auth-card auth-card-wide accept-invite">
        <div className="auth-logo">
          <img src="/logo-login.png" alt="Stackurity" width={120} height={120} />
        </div>
        <h1 className="auth-title">Link your Slack account</h1>
        {body}
      </div>
    </div>
  );
}

/**
 * The signed-in person's linked Slack accounts in this organisation, with
 * Unlink: on Your account (/account#slack). Clicks in Slack by these
 * accounts act as the person.
 */
export function LinkedSlackAccounts() {
  const res = useLoad(() => api.get<List<SlackLink>>("/slack/links"), []);
  const act = useAction();
  const unlink = async (l: SlackLink) => {
    if (
      !(await confirmAction({
        title: `Unlink ${l.slack_user_name || l.slack_user_id}?`,
        consequence: "Its clicks in Slack will ask to link again.",
        action: "Unlink Slack account",
      }))
    )
      return;
    const ok = await act.run(() => api.del(`/slack/links/${l.id}`).then(() => true));
    if (ok) res.reload();
  };
  const items = res.data?.items ?? [];
  return (
    <>
      <ErrorBox error={res.error ?? act.error} title="Could not load or change the links" />
      {!res.data && !res.error ? (
        <Loading />
      ) : items.length === 0 ? (
        <p className="muted">
          None yet. The first time you click Assign to me or Snooze in a Stackurity message in Slack, Slack shows you a link to connect your Slack account.{" "}
          <Link to="/help/notifications">Acting from Slack</Link>
        </p>
      ) : (
        <ul className="slack-links">
          {items.map((l) => (
            <li key={l.id} className="slack-link-row">
              <div className="slack-link-who">
                <div className="break">{slackWho(l)}</div>
                <div className="small muted">
                  Linked <RelativeTime iso={l.created_at} />, last used <RelativeTime iso={l.last_used_at} />
                </div>
              </div>
              <button type="button" className="btn btn-sm btn-link-danger" onClick={() => void unlink(l)} disabled={act.pending}>
                Unlink
              </button>
            </li>
          ))}
        </ul>
      )}
    </>
  );
}
