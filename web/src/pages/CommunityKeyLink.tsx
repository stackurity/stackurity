import { useEffect, useRef, useState } from "react";
import { useNavigate } from "react-router";
import { api, ApiError, type KeyLinkPreview, type KeyLinkRequest } from "../api";
import { useAuth } from "../auth";
import { ErrorBox, Loading, Notice } from "../components/ui";
import { KEY_LINK_PATH, KEY_LINK_RESUME, safeRedirect } from "../keyLink";
import { LoginPage } from "./Login";

function request(): KeyLinkRequest {
  const q = new URLSearchParams(window.location.search);
  const r: KeyLinkRequest = { return: q.get("return") ?? "", state: q.get("state") ?? "" };
  const id = q.get("server_id");
  if (id) r.server_id = id;
  return r;
}

/**
 * /community-key/new on Stackurity Cloud, signed out: sign in (the address
 * stays), or sign up, after which VerifySignupPage comes back here.
 */
export function CommunityKeyLinkSignIn() {
  useEffect(() => {
    try {
      localStorage.setItem(KEY_LINK_RESUME, JSON.stringify({ path: KEY_LINK_PATH + window.location.search, at: Date.now() }));
    } catch {
      // Not kept: after sign-up, click Get a free key on the server again.
    }
  }, []);
  return <LoginPage />;
}

/**
 * /community-key/new?return=…&state=…&server_id=… on Stackurity Cloud,
 * signed in: a self-hosted server's "Get a free key". The server's address
 * is checked by the Cloud and shown before anything is issued; the key is
 * issued to the signed-in person only when they confirm, and the browser
 * takes it back in the address's fragment.
 */
export function CommunityKeyLinkPage() {
  const { me } = useAuth();
  const navigate = useNavigate();
  const [req] = useState(request);
  const [preview, setPreview] = useState<KeyLinkPreview | null>(null);
  const [error, setError] = useState<ApiError | null>(null);
  const [sending, setSending] = useState(false);
  const started = useRef(false);

  useEffect(() => {
    try {
      localStorage.removeItem(KEY_LINK_RESUME);
    } catch {
      // nothing kept
    }
    if (started.current) return;
    started.current = true;
    api
      .previewKeyLink(req)
      .then(setPreview)
      .catch((e) => setError(e instanceof ApiError ? e : new ApiError(0, "client", String(e))));
  }, [req]);

  const send = async () => {
    if (!preview) return;
    setSending(true);
    setError(null);
    try {
      const r = await api.confirmKeyLink(req);
      const to = safeRedirect(r.redirect, preview.host);
      if (!to) throw new ApiError(0, "client", "The address to send the key to changed; nothing was sent.");
      window.location.assign(to);
    } catch (e) {
      setSending(false);
      setError(e instanceof ApiError ? e : new ApiError(0, "client", String(e)));
    }
  };

  let body;
  if (!preview && error) {
    body = (
      <>
        <ErrorBox error={error} title="This link cannot be used" />
        <p className="small">
          Start again from your server: <strong>Get a free key</strong>, where it asks for its key. Or{" "}
          <a href="/self-hosted-key">get a key by email</a> and paste it.
        </p>
      </>
    );
  } else if (!preview) {
    body = <Loading label="Checking the link…" />;
  } else {
    body = (
      <>
        <p>
          Send a free key for a self-hosted Stackurity server to <strong className="break">{preview.host}</strong>?
        </p>
        <p className="small muted">
          Continue only if you just clicked <strong>Get a free key</strong> on that server. The key is issued to you (
          <span className="break">{me?.user?.email}</span>) and your browser takes it back to the server, which checks it offline. Nothing else about the
          server is sent to us.
        </p>
        {preview.insecure && (
          <Notice kind="warn">This server&apos;s address uses plain http on a private network, so the key travels unencrypted on that network.</Notice>
        )}
        <ErrorBox error={error} title="No key was sent" />
        <div className="form-actions">
          <button type="button" className="btn btn-primary" onClick={() => void send()} disabled={sending}>
            {sending ? "Sending…" : `Send the key to ${preview.host}`}
          </button>
          <button type="button" className="btn" onClick={() => navigate("/", { replace: true })} disabled={sending}>
            Cancel
          </button>
        </div>
      </>
    );
  }
  return (
    <div className="center-screen">
      <div className="auth-card auth-card-wide">
        <div className="auth-logo">
          <img src="/logo-login.png" alt="Stackurity" width={140} height={140} />
        </div>
        <h1 className="auth-title">Free key for your server</h1>
        {body}
      </div>
    </div>
  );
}
