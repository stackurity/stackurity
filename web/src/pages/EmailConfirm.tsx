import { useEffect, useState, type ReactNode } from "react";
import { api, ApiError } from "../api";
import { ErrorBox, Loading, Notice } from "../components/ui";

/*
 * /email/confirm#<token>: someone outside the organisation confirms they
 * want Stackurity notifications. Works signed in or not. The token stays in
 * the fragment (never sent to a server by the browser) and goes to the API
 * in the request body only.
 */

const confirmations = new Map<string, Promise<{ email: string; organisation: string }>>();

export function EmailConfirmPage() {
  const [token] = useState(() => window.location.hash.replace(/^#/, "").trim());
  const [done, setDone] = useState<{ email: string; organisation: string } | null>(null);
  const [error, setError] = useState<ApiError | null>(null);

  useEffect(() => {
    if (!token) return;
    // The link works once: one request per token, even if effects run twice.
    let p = confirmations.get(token);
    if (!p) {
      p = api.post<{ email: string; organisation: string }>("/email-recipients/confirm", { token });
      confirmations.set(token, p);
    }
    let live = true;
    p.then((r) => {
      if (!live) return;
      window.history.replaceState(null, "", "/email/confirm");
      setDone(r);
    }).catch((e) => {
      if (live) setError(e instanceof ApiError ? e : new ApiError(0, "client", String(e)));
    });
    return () => {
      live = false;
    };
  }, [token]);

  let body: ReactNode;
  if (!token || error?.status === 410) {
    body = <Notice kind="warn">This link is not valid any more. Ask the person who added your address to send a new one.</Notice>;
  } else if (error) {
    body = <ErrorBox error={error} title="Could not confirm" />;
  } else if (done) {
    body = (
      <Notice kind="success">
        Confirmed: {done.email} will get Stackurity notifications from {done.organisation}.
      </Notice>
    );
  } else {
    body = <Loading label="Confirming…" />;
  }

  return (
    <div className="center-screen">
      <div className="auth-card">
        <div className="auth-logo">
          <img src="/logo-login.png" alt="Stackurity" width={120} height={120} />
        </div>
        <h1 className="auth-title">Email notifications</h1>
        {body}
      </div>
    </div>
  );
}
