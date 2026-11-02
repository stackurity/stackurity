import { useEffect, useState, type ReactNode } from "react";
import { Link, useNavigate } from "react-router";
import { api, ApiError, type JiraOAuthResult } from "../api";
import { useAuth } from "../auth";
import { ErrorBox, Loading, Notice } from "../components/ui";
import { errorView } from "../errors";

/*
 * /integrations/jira/oauth/callback?code=…&state=…: Atlassian sends the
 * browser here after Connect Jira. The state works once, so the exchange
 * runs once per state even when React runs effects twice (StrictMode).
 * The person then picks the site, project and issue type where they
 * started (return_to), with ?jira_connection=<id>.
 */

const exchanges = new Map<string, Promise<JiraOAuthResult>>();

/** Only addresses inside the dashboard. */
function safeReturn(to: string | undefined): string {
  return to && to.startsWith("/") && !to.startsWith("//") ? to : "/settings/integrations/new/jira";
}

function withConnection(to: string, id: number): string {
  const u = new URL(to, window.location.origin);
  u.searchParams.set("jira_connection", String(id));
  return u.pathname + u.search;
}

export function JiraOAuthCallbackPage() {
  const { can } = useAuth();
  const navigate = useNavigate();
  const [q] = useState(() => new URLSearchParams(window.location.search));
  const code = q.get("code") ?? "";
  const state = q.get("state") ?? "";
  const denied = q.get("error");
  const [error, setError] = useState<ApiError | null>(null);
  const admin = can("admin");

  useEffect(() => {
    if (denied || !code || !state || !admin) return;
    let p = exchanges.get(state);
    if (!p) {
      p = api.post<JiraOAuthResult>("/integrations/jira/oauth", { code, state });
      exchanges.set(state, p);
    }
    let live = true;
    p.then((r) => {
      if (live) navigate(withConnection(safeReturn(r.return_to), r.connection.id), { replace: true });
    }).catch((e) => {
      if (live) setError(e instanceof ApiError ? e : new ApiError(0, "client", String(e)));
    });
    return () => {
      live = false;
    };
  }, [code, state, denied, admin, navigate]);

  const again = (
    <div className="form-actions">
      <Link className="btn btn-primary" to="/settings/integrations/new/jira">
        Start again
      </Link>
      <Link className="btn" to="/settings/integrations">
        Back to Integrations
      </Link>
    </div>
  );

  let body: ReactNode;
  if (denied) {
    body = (
      <>
        <Notice kind="info">
          {denied === "access_denied" ? "You cancelled on Atlassian's page, so Jira was not connected." : `Atlassian did not connect Jira (${denied}).`}
        </Notice>
        {again}
      </>
    );
  } else if (!code || !state) {
    body = (
      <>
        <Notice kind="warn">This page needs the whole address Atlassian sent you back to. Jira was not connected.</Notice>
        {again}
      </>
    );
  } else if (!admin) {
    body = <Notice kind="warn">Only administrators can connect Jira. Ask one to do it.</Notice>;
  } else if (error) {
    body = (
      <>
        {error.code === "jira_state" ? (
          <Notice kind="warn">
            This Connect Jira request cannot be used: it was started by someone else or in another organisation, it was already used, or it is more than 10
            minutes old. Jira was not connected.
          </Notice>
        ) : error.status === 502 || error.code === "jira_no_site" ? (
          <Notice kind="warn">Atlassian did not complete the connection: {errorView(error).text}</Notice>
        ) : (
          <ErrorBox error={error} title="Could not connect Jira" />
        )}
        {again}
      </>
    );
  } else {
    body = <Loading label="Connecting Jira…" />;
  }

  return (
    <div className="center-screen">
      <div className="auth-card auth-card-wide">
        <div className="auth-logo">
          <img src="/logo-login.png" alt="Stackurity" width={120} height={120} />
        </div>
        <h1 className="auth-title">Connect Jira</h1>
        {body}
      </div>
    </div>
  );
}
