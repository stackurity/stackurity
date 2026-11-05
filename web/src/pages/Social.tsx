import { useEffect, useRef, useState, type FormEvent } from "react";
import { Link, Navigate, useLocation, useNavigate } from "react-router";
import { api, ApiError, type MfaSignInMethod, type SignupMeta, type SocialConnection, type SocialMeta, type SocialSignupPreview } from "../api";
import { useAuth } from "../auth";
import { useAction, useLoad } from "../hooks";
import { confirmAction } from "../components/ConfirmDialog";
import { Card, ErrorBox, GoodToKnow, Loading, Notice, RelativeTime } from "../components/ui";
import { MfaLoginStep } from "./TwoFactor";

// Signing up and signing in with Google, Microsoft or GitHub (Stackurity
// Cloud). The server offers only the providers it has configured
// (meta.social); every page here is shown only when it does.

/**
 * "Continue with Google / Microsoft / GitHub": full-page navigations to the
 * provider. On the sign-in page, returnTo is where the sign-in continues.
 */
export function SocialButtons({ social, returnTo }: { social: SocialMeta; returnTo?: string }) {
  const q = returnTo && returnTo !== "/" ? `?return_to=${encodeURIComponent(returnTo)}` : "";
  return (
    <div className="social-buttons">
      {social.providers.map((p) => (
        <a key={p.id} className="btn btn-block" href={p.start_url + q}>
          Continue with {p.label}
        </a>
      ))}
    </div>
  );
}

/** The fragment of the address, which browsers never send to a server. */
function fragmentToken(): string {
  return window.location.hash.replace(/^#/, "").trim();
}

/**
 * /signup/social#<token>: a provider vouched for the address and it has no
 * account yet. The organisation's name and the terms finish the sign-up, as
 * on the email form; there is no password (the provider signs you in).
 */
export function SocialSignupPage({ signup }: { signup: SignupMeta }) {
  const { refresh } = useAuth();
  const navigate = useNavigate();
  const [token] = useState(fragmentToken);
  const preview = useLoad<SocialSignupPreview | null>(() => (token ? api.socialSignupPreview(token) : Promise.resolve(null)), [token]);
  const [name, setName] = useState<string | null>(null);
  const [organisation, setOrganisation] = useState("");
  const [accept, setAccept] = useState(false);
  const [localErr, setLocalErr] = useState<string | null>(null);
  const act = useAction();
  const p = preview.data;

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setLocalErr(null);
    if (!accept) return setLocalErr("Please agree to the Terms of Service and the Privacy Policy.");
    const r = await act.run(() =>
      api.socialSignup({
        token,
        name: (name ?? p?.name ?? "").trim(),
        organisation: organisation.trim(),
        accept_terms: true,
        email_notice_version: signup.email_notice ? signup.email_notice_version : undefined,
      }),
    );
    if (r) {
      // Drop the token from the address and history, then open the new
      // organisation (a GitHub sign-up goes on to choose repositories).
      navigate(r.next || "/", { replace: true });
      await refresh();
    }
  };

  let body;
  if (!token) {
    body = <Notice kind="warn">This page is reached from a sign-in with Google, Microsoft or GitHub. Start again from the sign-up page.</Notice>;
  } else if (preview.error) {
    body =
      preview.error.status === 410 ? (
        <Notice kind="warn">
          This sign-up has expired (30 minutes), was finished already, or was started in another browser. <a href="/signup">Start again</a>, or{" "}
          <a href="/">sign in</a> if you finished before.
        </Notice>
      ) : (
        <ErrorBox error={preview.error} title="Could not continue" />
      );
  } else if (!p) {
    body = <Loading />;
  } else {
    const expired = act.error?.status === 410;
    body = (
      <form className="form" onSubmit={submit}>
        <p>
          {p.provider_label} confirmed your email address <strong className="break">{p.email}</strong>
          {p.login ? ` (${p.login})` : ""}.{" "}
          {signup.trial_days ? `Start a free ${signup.trial_days}-day trial, no card needed.` : "Create your organisation."}
        </p>
        {p.colleagues_domain && (
          <Notice>
            People at {p.colleagues_domain} already use Stackurity Cloud. If your company has an organisation there, you can ask one of its admins to
            invite you instead; to start a separate one, continue.
          </Notice>
        )}
        {expired ? (
          <Notice kind="warn">
            This sign-up has expired or was finished already. <a href="/signup">Start again</a>.
          </Notice>
        ) : (
          <ErrorBox error={act.error} title="Sign-up failed" />
        )}
        {localErr && (
          <div className="alert alert-error" role="alert">
            {localErr}
          </div>
        )}
        <div className="field">
          <label htmlFor="ss-name">Your name</label>
          <input id="ss-name" autoComplete="name" maxLength={200} value={name ?? p.name} onChange={(e) => setName(e.target.value)} />
        </div>
        <div className="field">
          <label htmlFor="ss-org">Organisation name</label>
          <input
            id="ss-org"
            required
            autoComplete="organization"
            maxLength={100}
            value={organisation}
            onChange={(e) => setOrganisation(e.target.value)}
            autoFocus
          />
        </div>
        <label className="check-row">
          <input type="checkbox" checked={accept} onChange={(e) => setAccept(e.target.checked)} required />
          <span>
            I agree to the{" "}
            <a href={signup.terms_url} target="_blank" rel="noopener noreferrer">
              Terms of Service
            </a>{" "}
            and the{" "}
            <a href={signup.privacy_url} target="_blank" rel="noopener noreferrer">
              Privacy Policy
            </a>
            .
          </span>
        </label>
        {signup.email_notice && <p className="small muted">{signup.email_notice}</p>}
        <p className="small muted">Your data is stored in {signup.region_label}.</p>
        <button type="submit" className="btn btn-primary btn-block" disabled={act.pending}>
          {act.pending ? "Creating…" : "Create account"}
        </button>
      </form>
    );
  }
  return (
    <div className="center-screen">
      <div className="auth-card auth-card-wide">
        <h1 className="auth-title">Create your account</h1>
        {body}
      </div>
    </div>
  );
}

/**
 * /social/confirm#<token>: the link emailed when a provider sign-in matched
 * an existing account's address. Opened in the browser that tried to sign
 * in, it connects the provider to the account and signs in (with the
 * account's second factor first, if it has one).
 */
export function SocialConfirmPage() {
  const { refresh } = useAuth();
  const navigate = useNavigate();
  const [token] = useState(fragmentToken);
  const [error, setError] = useState<ApiError | null>(null);
  const [mfa, setMfa] = useState<MfaSignInMethod[] | null>(null);
  const started = useRef(false);

  const done = async () => {
    navigate("/account?connected=1#sign-in", { replace: true });
    await refresh();
  };

  useEffect(() => {
    if (!token || started.current) return;
    started.current = true;
    api
      .confirmSocialLink(token)
      .then((r) => (r.mfa_required ? setMfa(r.methods ?? ["totp", "recovery_code"]) : done()))
      .catch((e) => setError(e instanceof ApiError ? e : new ApiError(0, "client", String(e))));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [token]);

  if (mfa) return <MfaLoginStep methods={mfa} onDone={done} onRestart={() => window.location.assign("/")} />;
  let body;
  if (!token) body = <Notice kind="warn">This page needs the whole link from the email. Open it again from the email.</Notice>;
  else if (error)
    body =
      error.status === 410 ? (
        <Notice kind="warn">
          {error.message.charAt(0).toUpperCase() + error.message.slice(1)}. <a href="/">Back to sign-in</a>
        </Notice>
      ) : (
        <ErrorBox error={error} title="Could not connect" />
      );
  else body = <Loading label="Connecting…" />;
  return (
    <div className="center-screen">
      <div className="auth-card auth-card-wide">
        <h1 className="auth-title">Connect your sign-in</h1>
        {body}
      </div>
    </div>
  );
}

/**
 * /welcome/repositories: after signing up with GitHub, choose the
 * repositories to check by installing the Stackurity GitHub App. Without
 * the app (meta.social.github_install_url absent) the ordinary first-run
 * flow takes over.
 */
export function PickRepositoriesPage() {
  const { meta } = useAuth();
  const url = meta?.social?.github_install_url;
  if (!url || !/^https:\/\//.test(url)) return <Navigate replace to="/" />;
  return (
    <div className="center-screen">
      <div className="auth-card auth-card-wide">
        <h1 className="auth-title">Pick repositories</h1>
        <p>
          Install the Stackurity GitHub App on your account or organisation and choose the repositories to check. The first results arrive in about
          two minutes.
        </p>
        <a className="btn btn-primary btn-block" href={url}>
          Choose repositories on GitHub
        </a>
        <p className="small" style={{ textAlign: "center" }}>
          <Link to="/">Skip for now</Link>
        </p>
      </div>
    </div>
  );
}

/** Your account → Sign-in with Google, Microsoft or GitHub. */
export function SocialConnectionsCard() {
  const res = useLoad(() => api.socialConnections(), []);
  const act = useAction();
  const { search } = useLocation();
  const [asking, setAsking] = useState<SocialConnection | null>(null);
  const [password, setPassword] = useState("");
  const connected = new URLSearchParams(search).get("connected");

  const connect = async (c: SocialConnection, pw: string) => {
    const r = await act.run(() => api.connectSocial(c.id, pw));
    if (r) window.location.assign(r.redirect_url);
  };
  const start = (c: SocialConnection) => {
    act.clear();
    if (res.data?.has_password) {
      setAsking(c);
      setPassword("");
    } else void connect(c, "");
  };
  const disconnect = async (c: SocialConnection) => {
    if (
      !(await confirmAction({
        title: `Disconnect ${c.label}?`,
        consequence: `You will no longer be able to sign in with this ${c.label} account.`,
        action: `Disconnect ${c.label}`,
      }))
    )
      return;
    const ok = await act.run(() => api.disconnectSocial(c.id).then(() => true));
    if (ok) res.reload();
  };

  const items = res.data?.providers ?? [];
  return (
    <Card
      id="sign-in"
      title="Sign in with Google, Microsoft or GitHub"
      description={
        <>
          Connect an account you already have at one of these providers, then use its button on the sign-in page instead of typing your password.{" "}
          <Link to="/help/social-sign-in">How this works</Link>
        </>
      }
    >
      {connected && <Notice kind="success">Connected. You can now sign in with it.</Notice>}
      <ErrorBox error={res.error ?? act.error} title="Could not load or change your sign-in methods" />
      {!res.data && !res.error ? (
        <Loading />
      ) : (
        <ul className="slack-links">
          {items.map((c) => (
            <li key={c.id} className="slack-link-row">
              <div className="slack-link-who">
                <div>
                  {c.label}
                  {c.connected && (
                    <span className="muted break">
                      {" "}
                      · {c.login ? `${c.login} · ` : ""}
                      {c.email}
                    </span>
                  )}
                </div>
                {c.connected && (
                  <div className="small muted">
                    Connected <RelativeTime iso={c.created_at} />, last used <RelativeTime iso={c.last_used_at} />
                  </div>
                )}
              </div>
              {c.connected ? (
                <button type="button" className="btn btn-sm btn-link-danger" onClick={() => void disconnect(c)} disabled={act.pending}>
                  Disconnect
                </button>
              ) : (
                <button type="button" className="btn btn-sm" onClick={() => start(c)} disabled={act.pending || c.unavailable}>
                  Connect
                </button>
              )}
            </li>
          ))}
        </ul>
      )}
      {asking && (
        <form
          className="form"
          onSubmit={(e) => {
            e.preventDefault();
            void connect(asking, password);
          }}
        >
          <div className="field">
            <label htmlFor="social-password">Your Stackurity password, to connect {asking.label}</label>
            <input
              id="social-password"
              type="password"
              autoComplete="current-password"
              required
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              autoFocus
            />
          </div>
          <div className="row-actions">
            <button type="submit" className="btn btn-primary" disabled={act.pending}>
              Continue to {asking.label}
            </button>
            <button type="button" className="btn btn-link" onClick={() => setAsking(null)}>
              Cancel
            </button>
          </div>
        </form>
      )}
      <GoodToKnow>
        <ul>
          <li>Your two-factor sign-in, if you set it up, is still asked for.</li>
          <li>Organisations that require their own single sign-on still require it.</li>
          {res.data && !res.data.has_password && (
            <li>
              Your account has no password: you sign in with a provider. To add one, sign out and use Forgot password. Two-factor sign-in needs a password.
            </li>
          )}
        </ul>
      </GoodToKnow>
    </Card>
  );
}
