import { useEffect, useRef, useState, type FormEvent } from "react";
import { useNavigate } from "react-router";
import { api, ApiError, type SignupMeta } from "../api";
import { useAuth } from "../auth";
import { useAction } from "../hooks";
import { ErrorBox, Loading, Notice } from "../components/ui";

// The sign-up challenge widget, loaded only on the sign-up page.
interface ChallengeWidget {
  render: (el: HTMLElement, opts: Record<string, unknown>) => string;
  reset: (id?: string) => void;
  remove: (id?: string) => void;
}
declare global {
  interface Window {
    turnstile?: ChallengeWidget;
  }
}

const CHALLENGE_SCRIPT = "https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit";

let scriptPromise: Promise<ChallengeWidget> | null = null;

function loadChallenge(): Promise<ChallengeWidget> {
  if (window.turnstile) return Promise.resolve(window.turnstile);
  if (!scriptPromise) {
    scriptPromise = new Promise((resolve, reject) => {
      const s = document.createElement("script");
      s.src = CHALLENGE_SCRIPT;
      s.async = true;
      s.onload = () => (window.turnstile ? resolve(window.turnstile) : reject(new Error("no widget")));
      s.onerror = () => {
        scriptPromise = null;
        s.remove();
        reject(new Error("load failed"));
      };
      document.head.appendChild(s);
    });
  }
  return scriptPromise;
}

/** The challenge that shows a person, not a script, is signing up. */
function Challenge({ siteKey, onToken, resetKey }: { siteKey: string; onToken: (t: string) => void; resetKey: number }) {
  const box = useRef<HTMLDivElement>(null);
  const widget = useRef<{ api: ChallengeWidget; id: string } | null>(null);
  const [failed, setFailed] = useState(false);
  const tokenRef = useRef(onToken);
  tokenRef.current = onToken;

  useEffect(() => {
    let gone = false;
    loadChallenge()
      .then((t) => {
        if (gone || !box.current) return;
        const id = t.render(box.current, {
          sitekey: siteKey,
          // The site key is shared with other forms: the server accepts
          // only tokens made for sign-up.
          action: "signup",
          size: "flexible",
          callback: (token: string) => tokenRef.current(token),
          "expired-callback": () => tokenRef.current(""),
          "error-callback": () => tokenRef.current(""),
        });
        widget.current = { api: t, id };
      })
      .catch(() => !gone && setFailed(true));
    return () => {
      gone = true;
      if (widget.current) widget.current.api.remove(widget.current.id);
      widget.current = null;
    };
  }, [siteKey]);

  useEffect(() => {
    if (resetKey > 0 && widget.current) {
      widget.current.api.reset(widget.current.id);
      tokenRef.current("");
    }
  }, [resetKey]);

  if (failed) {
    return (
      <Notice kind="warn">
        The check that keeps automated sign-ups out could not load. Turn off any script or ad blocker for this page, or try another browser or
        network, then reload this page.
      </Notice>
    );
  }
  return <div ref={box} className="challenge" />;
}

/** /signup: someone creating an account and a new organisation. */
export function SignupPage({ signup }: { signup: SignupMeta }) {
  const [f, setF] = useState({ email: "", name: "", organisation: "", password: "", confirm: "" });
  const [accept, setAccept] = useState(false);
  const [token, setToken] = useState("");
  const [resetKey, setResetKey] = useState(0);
  const [localErr, setLocalErr] = useState<string | null>(null);
  const [sentTo, setSentTo] = useState<string | null>(null);
  const act = useAction();
  const set = (k: keyof typeof f) => (e: { target: { value: string } }) => setF({ ...f, [k]: e.target.value });

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setLocalErr(null);
    if (f.password.length < 12) return setLocalErr("Use at least 12 characters for your password.");
    if (f.password !== f.confirm) return setLocalErr("The passwords do not match.");
    if (!accept) return setLocalErr("Please agree to the Terms of Service and the Privacy Policy.");
    if (!token) return setLocalErr("Please complete the check above the button first.");
    const email = f.email.trim();
    const r = await act.run(() =>
      api.signup({
        email,
        name: f.name.trim(),
        organisation: f.organisation.trim(),
        password: f.password,
        turnstile_token: token,
        accept_terms: true,
        // Which notice about product emails was on screen.
        email_notice_version: signup.email_notice ? signup.email_notice_version : undefined,
      }),
    );
    if (r) setSentTo(email);
    // A challenge answer works once.
    else setResetKey((k) => k + 1);
  };

  if (sentTo) {
    return (
      <div className="center-screen">
        <div className="auth-card auth-card-wide">
          <h1 className="auth-title">Check your email</h1>
          <p>
            We sent a link to <strong className="break">{sentTo}</strong>. It works once, for 24 hours. Open it to finish creating your account.
          </p>
          <p className="small muted">
            Nothing arrived after a few minutes? Check your spam folder, or <a href="/signup">sign up again</a>.
          </p>
        </div>
      </div>
    );
  }

  return (
    <div className="center-screen">
      <form className="auth-card auth-card-wide form" onSubmit={submit} aria-labelledby="signup-title">
        <div className="auth-logo">
          <img src="/logo-login.png" alt="Stackurity" width={140} height={140} />
        </div>
        <h1 id="signup-title" className="auth-title">
          Create your account
        </h1>
        <p>
          {signup.trial_days
            ? `Start with a free ${signup.trial_days}-day trial, no card needed.`
            : "Create your organisation."}{" "}
          You can invite your team and add servers, repositories and images right after.
        </p>
        <ErrorBox error={act.error} title="Sign-up failed" />
        {localErr && (
          <div className="alert alert-error" role="alert">
            {localErr}
          </div>
        )}
        <div className="field">
          <label htmlFor="su-email">Work email</label>
          <input id="su-email" type="email" required autoComplete="email" value={f.email} onChange={set("email")} autoFocus />
        </div>
        <div className="field">
          <label htmlFor="su-name">Your name</label>
          <input id="su-name" required autoComplete="name" maxLength={200} value={f.name} onChange={set("name")} />
        </div>
        <div className="field">
          <label htmlFor="su-org">Organisation name</label>
          <input id="su-org" required autoComplete="organization" maxLength={100} value={f.organisation} onChange={set("organisation")} />
        </div>
        <div className="field">
          <label htmlFor="su-password">Password</label>
          <input
            id="su-password"
            type="password"
            required
            minLength={12}
            autoComplete="new-password"
            value={f.password}
            onChange={set("password")}
            aria-describedby="su-password-hint"
          />
          <p className="hint" id="su-password-hint">
            At least 12 characters.
          </p>
        </div>
        <div className="field">
          <label htmlFor="su-confirm">Confirm password</label>
          <input id="su-confirm" type="password" required autoComplete="new-password" value={f.confirm} onChange={set("confirm")} />
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
        {signup.email_notice && (
          <p className="small muted" id="su-email-notice">
            {signup.email_notice}
          </p>
        )}
        <Challenge siteKey={signup.turnstile_site_key} onToken={setToken} resetKey={resetKey} />
        <p className="small muted">Your data is stored in {signup.region_label}.</p>
        <button type="submit" className="btn btn-primary btn-block" disabled={act.pending}>
          {act.pending ? "Creating…" : "Create account"}
        </button>
        <p className="small" style={{ textAlign: "center" }}>
          Already have an account? <a href="/">Sign in</a>
        </p>
      </form>
    </div>
  );
}

/**
 * /signup/verify#<token>: the link from the sign-up email. The token stays in
 * the address's fragment, which browsers never send to a server, and goes to
 * the API in a request body only.
 */
export function VerifySignupPage() {
  const { refresh } = useAuth();
  const navigate = useNavigate();
  const [token] = useState(() => window.location.hash.replace(/^#/, "").trim());
  const [error, setError] = useState<ApiError | null>(null);
  const started = useRef(false);

  useEffect(() => {
    if (!token || started.current) return;
    started.current = true;
    api
      .verifySignup(token)
      .then(async () => {
        // Drop the link from the address bar and history, then open the
        // new organisation: its first-run flow starts by itself.
        navigate("/", { replace: true });
        await refresh();
      })
      .catch((e) => setError(e instanceof ApiError ? e : new ApiError(0, "client", String(e))));
  }, [token, refresh, navigate]);

  let body;
  if (!token) {
    body = <Notice kind="warn">This page needs the whole link from the email. Open it again from the email.</Notice>;
  } else if (error) {
    body =
      error.status === 410 ? (
        <Notice kind="warn">
          This link does not work any more: it was already used, or it is more than 24 hours old. <a href="/signup">Sign up again</a> to get a new
          one, or <a href="/">sign in</a> if you finished before.
        </Notice>
      ) : (
        <>
          <ErrorBox error={error} title="Could not finish creating your account" />
          <p className="small">
            <a href="/signup">Sign up again</a> or <a href="/">sign in</a>.
          </p>
        </>
      );
  } else {
    body = <Loading label="Creating your organisation…" />;
  }
  return (
    <div className="center-screen">
      <div className="auth-card auth-card-wide">
        <h1 className="auth-title">Confirm your email</h1>
        {body}
      </div>
    </div>
  );
}
