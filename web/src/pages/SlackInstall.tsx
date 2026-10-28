import { useEffect, useRef, useState, type ReactNode } from "react";
import { Link } from "react-router";
import { api, ApiError } from "../api";
import { useAuth } from "../auth";
import { ErrorBox, Loading, Notice } from "../components/ui";
import { planInstall } from "../slackInstall";

/*
 * /integrations/slack/install (the Slack app's Direct install URL, signed
 * in) and /integrations/slack/add (from the callback page after an install
 * Slack started): pick the organisation, then Add to Slack as usual, with a
 * state bound to this person and organisation. Signing in comes first; the
 * address stays the same meanwhile.
 */

export function SlackInstallPage() {
  const { me } = useAuth();
  const plan = planInstall(me?.workspaces ?? [], me?.workspace?.id ?? null);
  const [chosen, setChosen] = useState<number>(plan.kind === "choose" ? plan.preselect : 0);
  const [error, setError] = useState<ApiError | null>(null);
  const [going, setGoing] = useState<string | null>(null);
  const started = useRef(false);

  const start = async (id: number, name: string) => {
    setError(null);
    setGoing(name);
    try {
      if (id !== me?.workspace?.id) await api.post(`/workspaces/${id}/activate`);
      const r = await api.post<{ url: string }>("/integrations/slack/install", { return_to: "/settings/integrations" });
      window.location.assign(r.url);
    } catch (e) {
      setError(e instanceof ApiError ? e : new ApiError(0, "client", String(e)));
      setGoing(null);
    }
  };

  // One organisation: no question to ask.
  useEffect(() => {
    if (plan.kind !== "go" || started.current) return;
    started.current = true;
    void start(plan.org.workspace_id, plan.org.name);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [plan.kind]);

  let body: ReactNode;
  if (error) {
    body = (
      <>
        {error.status === 404 ? (
          <Notice kind="warn">
            Add to Slack is not set up on this server. An administrator can still connect Slack with an incoming webhook under Settings → Integrations → Slack.
          </Notice>
        ) : error.status === 403 ? (
          <Notice kind="warn">Only an organisation&apos;s administrators can add Stackurity to Slack, and this organisation is read-only or you are not one of them.</Notice>
        ) : (
          <ErrorBox error={error} title="Could not open Slack" />
        )}
        <div className="slack-link-actions">
          {/* A full load: the organisation may have changed. */}
          <a className="btn btn-block" href="/settings/integrations">
            Go to Stackurity
          </a>
        </div>
      </>
    );
  } else if (going) {
    body = <Loading label={`Opening Slack for ${going}…`} />;
  } else if (plan.kind === "none") {
    body = (
      <>
        <Notice kind="warn">Your account does not belong to an organisation yet. Ask an administrator to invite you, then add Stackurity to Slack.</Notice>
        <div className="slack-link-actions">
          <Link className="btn btn-block" to="/">
            Go to Stackurity
          </Link>
        </div>
      </>
    );
  } else if (plan.kind === "not_admin") {
    const names = plan.orgs.map((o) => o.name).join(", ");
    body = (
      <>
        <Notice kind="warn">
          Only an organisation&apos;s administrators can add Stackurity to Slack. You are not an administrator in {names}. Ask one of them to add it, or to
          make you an administrator.
        </Notice>
        <div className="slack-link-actions">
          <Link className="btn btn-block" to="/">
            Go to Stackurity
          </Link>
        </div>
      </>
    );
  } else if (plan.kind === "choose") {
    const org = plan.orgs.find((o) => o.workspace_id === chosen) ?? plan.orgs[0];
    body = (
      <form
        className="form"
        onSubmit={(e) => {
          e.preventDefault();
          void start(org.workspace_id, org.name);
        }}
      >
        <fieldset className="field">
          <legend>Which organisation should Slack send to?</legend>
          <ul className="choice-list">
            {plan.orgs.map((o) => (
              <li key={o.workspace_id}>
                <label className="choice">
                  <input type="radio" name="slack-org" checked={chosen === o.workspace_id} onChange={() => setChosen(o.workspace_id)} />
                  <span>
                    <strong>{o.name}</strong>
                    {o.workspace_id === me?.workspace?.id && <span className="hint"> (current)</span>}
                  </span>
                </label>
              </li>
            ))}
          </ul>
          <p className="hint">Only organisations where you are an administrator are listed. Slack then asks you to pick the channel.</p>
        </fieldset>
        <div className="slack-link-actions">
          <button type="submit" className="btn btn-primary btn-block">
            Continue to Slack
          </button>
          <Link className="btn btn-block" to="/">
            Cancel
          </Link>
        </div>
      </form>
    );
  } else {
    body = <Loading label="Opening Slack…" />;
  }

  return (
    <div className="center-screen">
      <div className="auth-card auth-card-wide">
        <div className="auth-logo">
          <img src="/logo-login.png" alt="Stackurity" width={120} height={120} />
        </div>
        <h1 className="auth-title">Add Stackurity to Slack</h1>
        {body}
      </div>
    </div>
  );
}
