import { useEffect, useState, type ReactNode } from "react";
import { Link, useNavigate, useSearchParams } from "react-router";
import { ApiError, evidenceApi, type VantaOAuthResult } from "../api";
import { useAuth } from "../auth";
import { ErrorBox, Loading, Notice } from "../components/ui";
import { VANTA_CONNECTED_PATH, vantaErrorText } from "../evidenceConnectors";

/*
 * /integrations/vanta/oauth/callback?code=…&state=…: the redirect URI of the
 * operator's Vanta app. Vanta sends the browser here after Connect Vanta.
 * The session cookie is SameSite=Strict, so it is not sent on that redirect
 * from vanta.com; this page then posts the code and state from the
 * dashboard (same-origin, with the session) to
 * POST /integrations/evidence/vanta/oauth. The state works once, so the
 * exchange runs once per state even when React runs effects twice
 * (StrictMode). On success the Integrations card shows "Vanta connected".
 */

const exchanges = new Map<string, Promise<VantaOAuthResult>>();

const CARD = "/integrations#compliance-evidence";

export function VantaOAuthCallbackPage() {
  const { can } = useAuth();
  const navigate = useNavigate();
  const [q] = useSearchParams();
  const code = q.get("code") ?? "";
  const state = q.get("state") ?? "";
  const denied = q.get("error");
  const [error, setError] = useState<ApiError | null>(null);
  const admin = can("admin");

  useEffect(() => {
    if (denied || !code || !state || !admin) return;
    let p = exchanges.get(state);
    if (!p) {
      p = evidenceApi.finishVanta({ code, state });
      exchanges.set(state, p);
    }
    let live = true;
    p.then(() => {
      if (live) navigate(VANTA_CONNECTED_PATH, { replace: true });
    }).catch((e: unknown) => {
      if (live) setError(e instanceof ApiError ? e : new ApiError(0, "client", String(e)));
    });
    return () => {
      live = false;
    };
  }, [code, state, denied, admin, navigate]);

  return <VantaCallbackView denied={denied} hasCode={Boolean(code && state)} admin={admin} error={error} />;
}

/** What the page says, from what Vanta sent back and how the exchange went. */
export function VantaCallbackView({ denied, hasCode, admin, error }: { denied: string | null; hasCode: boolean; admin: boolean; error: ApiError | null }) {
  const again = (
    <div className="form-actions">
      <Link className="btn btn-primary" to={CARD}>
        Back to Compliance evidence
      </Link>
    </div>
  );

  let body: ReactNode;
  if (denied) {
    body = (
      <>
        <Notice kind="info">
          {denied === "access_denied"
            ? "You cancelled on Vanta's page, so Vanta was not connected. Nothing was stored."
            : `Vanta did not connect (${denied.replace(/[\r\n\t]+/g, " ").slice(0, 100)}). Nothing was stored.`}
        </Notice>
        {again}
      </>
    );
  } else if (!hasCode) {
    body = (
      <>
        <Notice kind="warn">This page needs the whole address Vanta sent you back to. Vanta was not connected; start again with Connect Vanta.</Notice>
        {again}
      </>
    );
  } else if (!admin) {
    body = (
      <>
        <Notice kind="warn">Only administrators of this organisation can connect Vanta. Ask one to do it.</Notice>
        {again}
      </>
    );
  } else if (error) {
    const known = vantaErrorText(error.code);
    body = (
      <>
        {known ? <Notice kind="warn">{known}</Notice> : <ErrorBox error={error} title="Could not connect Vanta" />}
        {again}
      </>
    );
  } else {
    body = <Loading label="Connecting Vanta…" />;
  }

  return (
    <div className="center-screen">
      <div className="auth-card auth-card-wide">
        <div className="auth-logo">
          <img src="/logo-login.png" alt="Stackurity" width={120} height={120} />
        </div>
        <h1 className="auth-title">Connect Vanta</h1>
        <p className="muted small">Stackurity sends your asset inventory, open vulnerabilities and evidence pack to Vanta once you approve.</p>
        {body}
      </div>
    </div>
  );
}
