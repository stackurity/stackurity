import { useEffect, useState, type ReactNode } from "react";
import { Link } from "react-router";
import { api, ApiError, type GitHubSetupResult } from "../api";
import { useAuth } from "../auth";
import { ErrorBox, Loading, Notice } from "../components/ui";
import { errorView } from "../errors";
import { InstallOnGitHubButton } from "./settings/GitHubApp";

/*
 * /integrations/github/callback?code=…&installation_id=…&setup_action=…&state=…:
 * GitHub sends the browser here after "Install on GitHub". The state works
 * once, so the request runs once per state even when React runs effects
 * twice (StrictMode).
 *
 * The server never trusts installation_id on its own: it checks, with the
 * code, that this person's GitHub account can see that installation.
 * Installs started on GitHub's side come back without our state; nothing is
 * connected then, and the page offers a proper install instead.
 */

const setups = new Map<string, Promise<GitHubSetupResult>>();

export function GitHubCallbackPage() {
  const { can } = useAuth();
  const [q] = useState(() => new URLSearchParams(window.location.search));
  const code = q.get("code") ?? "";
  const state = q.get("state") ?? "";
  const installation = q.get("installation_id") ?? "";
  const action = q.get("setup_action") ?? "";
  const denied = q.get("error");
  const admin = can("admin");
  const [error, setError] = useState<ApiError | null>(null);
  const [result, setResult] = useState<GitHubSetupResult | null>(null);

  useEffect(() => {
    if (denied || !state || !admin) return;
    let p = setups.get(state);
    if (!p) {
      p = api.post<GitHubSetupResult>("/integrations/github/setup", { state, code, installation_id: installation, setup_action: action });
      setups.set(state, p);
    }
    let live = true;
    p.then((r) => live && setResult(r)).catch((e) => live && setError(e instanceof ApiError ? e : new ApiError(0, "client", String(e))));
    return () => {
      live = false;
    };
  }, [state, code, installation, action, denied, admin]);

  const again = (label: string) => (
    <div className="slack-link-actions">
      {admin ? <InstallOnGitHubButton className="btn btn-primary btn-block" /> : null}
      <Link className="btn btn-block" to="/integrations">
        {label}
      </Link>
    </div>
  );

  let title = "Install on GitHub";
  let body: ReactNode;
  if (!admin) {
    body = <Notice kind="warn">Only administrators can connect GitHub. Ask one to do it.</Notice>;
  } else if (denied) {
    body = (
      <>
        <Notice kind="info">
          {denied === "access_denied" ? "You cancelled on GitHub, so nothing was connected." : `GitHub did not finish (${denied}). Nothing was connected.`}
        </Notice>
        {again("Back to integrations")}
      </>
    );
  } else if (!state) {
    title = "Finish connecting GitHub";
    body = (
      <>
        <p>
          The Stackurity app was installed from GitHub&apos;s side, so Stackurity cannot tell which organisation it is for, and has connected nothing. Continue
          here: GitHub shows the installation again, and <strong>Save</strong> brings you back to connect it to this organisation.
        </p>
        {again("Not now")}
      </>
    );
  } else if (error) {
    const code = error.code;
    body = (
      <>
        {code === "github_state" ? (
          <Notice kind="warn">
            This Install on GitHub request cannot be used: it was started by someone else or in another organisation, it was already used, or it is more than
            10 minutes old. Nothing was connected.
          </Notice>
        ) : code === "github_installation" || code === "github_installation_taken" || code === "github_suspended" || error.status === 502 ? (
          <Notice kind="warn">{errorView(error).text}</Notice>
        ) : (
          <ErrorBox error={error} title="Could not connect GitHub" />
        )}
        {again("Back to integrations")}
      </>
    );
  } else if (result?.requested) {
    body = (
      <>
        <Notice kind="info">
          GitHub sent your request to the organisation&apos;s owners. Once one of them approves the Stackurity app, click <strong>Install on GitHub</strong>{" "}
          again to connect it.
        </Notice>
        <Link className="btn btn-block" to="/integrations">
          Back to integrations
        </Link>
      </>
    );
  } else if (result?.installation) {
    const i = result.installation;
    body = (
      <>
        <Notice kind="success">GitHub is connected: {i.account_login}. Its repositories are listed and scanned in the next few minutes.</Notice>
        <div className="form-actions">
          <Link className="btn btn-primary" to="/integrations">
            See the repositories
          </Link>
        </div>
      </>
    );
  } else {
    body = <Loading label="Connecting GitHub…" />;
  }

  return (
    <div className="center-screen">
      <div className="auth-card auth-card-wide">
        <div className="auth-logo">
          <img src="/logo-login.png" alt="Stackurity" width={120} height={120} />
        </div>
        <h1 className="auth-title">{title}</h1>
        {body}
      </div>
    </div>
  );
}
