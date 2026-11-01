import { useEffect, useRef, useState } from "react";
import { api, ApiError } from "../api";
import { useAuth } from "../auth";
import { ErrorBox, Loading, Notice } from "../components/ui";
import { KEY_RETURN_PATH, parseKeyReturn } from "../keyLink";
import { KeyForm } from "./KeyStep";
import { LoginPage } from "./Login";

/**
 * /setup/community-key#key=…&state=…: back from Stackurity Cloud with this
 * server's free key ("Get a free key"). The fragment is read once and
 * dropped from the address bar and history; the key and its state go to
 * this server in a request body, which checks the state (this session's,
 * once, within 15 minutes) and verifies the key offline.
 */
export function KeyReturnPage() {
  const { me, refresh } = useAuth();
  const [ret] = useState(() => parseKeyReturn(window.location.hash));
  const [error, setError] = useState<ApiError | null>(null);
  const [done, setDone] = useState(false);
  const started = useRef(false);
  const admin = Boolean(me?.user?.instance_admin);

  useEffect(() => {
    window.history.replaceState(null, "", KEY_RETURN_PATH);
    if (ret.kind !== "key" || !admin || started.current) return;
    started.current = true;
    api
      .claimKeyLink(ret.key, ret.state)
      .then(() => {
        setDone(true);
        void refresh();
      })
      .catch((e) => setError(e instanceof ApiError ? e : new ApiError(0, "client", String(e))));
  }, [ret, admin, refresh]);

  let body;
  if (!admin) {
    body = <Notice kind="warn">Only an instance administrator of this server can install its key. Sign in as one and get the key again.</Notice>;
  } else if (ret.kind === "none") {
    body = <Notice kind="info">Nothing to install here: this page takes the key back from Stackurity Cloud.</Notice>;
  } else if (ret.kind === "error") {
    body = <Notice kind="warn">{ret.reason}</Notice>;
  } else if (error) {
    body =
      error.status === 410 ? (
        <Notice kind="warn">
          This key did not come back in time, was already used, or the trip started from another sign-in. Nothing was installed. Get the key again
          below; you are probably still signed in to Stackurity Cloud.
        </Notice>
      ) : (
        <ErrorBox error={error} title="The key was not installed" />
      );
  } else if (done) {
    body = (
      <>
        <Notice kind="success">The free key is installed. It was checked on this server, offline, and does not expire.</Notice>
        <div className="form-actions">
          <a className="btn btn-primary" href="/">
            Continue to the dashboard
          </a>
        </div>
      </>
    );
  } else {
    body = <Loading label="Installing the key…" />;
  }
  // When nothing was installed: get the key again, or paste one.
  const status = me?.license_key;
  const retry = admin && !done && (ret.kind !== "key" || error !== null) && status && status.state !== "installed";
  return (
    <div className="center-screen">
      <div className="auth-card auth-card-wide">
        <h1 className="auth-title">This server&apos;s free key</h1>
        {body}
        {retry && (
          <KeyForm
            status={status}
            onDone={() => {
              setDone(true);
              void refresh();
            }}
          />
        )}
        {!done && (
          <p className="small" style={{ textAlign: "center" }}>
            <a href="/">Back to the dashboard</a>
          </p>
        )}
      </div>
    </div>
  );
}

/**
 * The same address signed out: the key is dropped from the address at
 * once (it was bound to the session that asked for it), then sign in.
 */
export function KeyReturnSignIn() {
  useEffect(() => {
    if (window.location.hash) window.history.replaceState(null, "", KEY_RETURN_PATH);
  }, []);
  return <LoginPage />;
}
