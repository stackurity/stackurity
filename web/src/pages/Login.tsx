import { useState, type ChangeEvent, type FormEvent } from "react";
import { api } from "../api";
import { useAuth } from "../auth";
import { useAction } from "../hooks";
import { Code, ErrorBox } from "../components/ui";
import { MfaLoginStep } from "./TwoFactor";
import { ForgotPasswordLink } from "./Password";

export function LoginPage() {
  const { refresh, state } = useAuth();
  const sso = state.phase === "login" ? state.meta.sso : undefined;
  const signup = state.phase === "login" ? state.meta.signup : undefined;
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const act = useAction();
  // The password was right and the account has two-factor sign-in.
  const [mfa, setMfa] = useState(false);

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    const ok = await act.run(() => api.login(email.trim(), password));
    if (ok?.mfa_required) setMfa(true);
    else if (ok) await refresh();
  };
  if (mfa) return <MfaLoginStep onDone={refresh} onRestart={() => (setMfa(false), setPassword(""))} />;

  return (
    <div className="center-screen">
      <form className="auth-card form" onSubmit={submit} aria-labelledby="login-title">
        <div className="auth-logo">
          <img src="/logo-login.png" alt="Stackurity" width={180} height={180} />
        </div>
        <h1 id="login-title" className="auth-title">
          Sign in
        </h1>
        <ErrorBox error={act.error} title="Sign-in failed" />
        {sso && (
          <>
            {/* A full-page navigation: the identity provider takes over from here. */}
            <a className="btn btn-primary btn-block" href={sso.login_url}>
              Sign in with {sso.label}
            </a>
            <p className="muted small" style={{ textAlign: "center" }}>
              or use an email and password
            </p>
          </>
        )}
        <div className="field">
          <label htmlFor="login-email">Email</label>
          <input id="login-email" type="email" autoComplete="username" required value={email} onChange={(e) => setEmail(e.target.value)} autoFocus={!sso} />
        </div>
        <div className="field">
          <label htmlFor="login-password">Password</label>
          <input
            id="login-password"
            type="password"
            autoComplete="current-password"
            required
            value={password}
            onChange={(e) => setPassword(e.target.value)}
          />
        </div>
        <button type="submit" className={sso ? "btn btn-block" : "btn btn-primary btn-block"} disabled={act.pending}>
          {act.pending ? "Signing in…" : "Sign in"}
        </button>
        <ForgotPasswordLink />
        {signup && (
          <p className="small" style={{ textAlign: "center" }}>
            New here? <a href="/signup">Create an account</a>
          </p>
        )}
      </form>
    </div>
  );
}

export function SetupPage() {
  const { refresh } = useAuth();
  const [f, setF] = useState({ setup_token: "", email: "", name: "", password: "", confirm: "" });
  const [localErr, setLocalErr] = useState<string | null>(null);
  const act = useAction();
  const set = (k: keyof typeof f) => (e: ChangeEvent<HTMLInputElement>) => setF({ ...f, [k]: e.target.value });

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setLocalErr(null);
    if (f.password.length < 12) return setLocalErr("Password must be at least 12 characters.");
    if (f.password !== f.confirm) return setLocalErr("Passwords do not match.");
    const ok = await act.run(() =>
      api.setup({ setup_token: f.setup_token.trim(), email: f.email.trim(), name: f.name.trim(), password: f.password }),
    );
    if (ok) await refresh();
  };

  return (
    <div className="center-screen">
      <form className="auth-card auth-card-wide form" onSubmit={submit} aria-labelledby="setup-title">
        <div className="auth-logo">
          <img src="/logo-login.png" alt="Stackurity" width={160} height={160} />
        </div>
        <h1 id="setup-title" className="auth-title">
          Set up Stackurity
        </h1>
        <p>Create the first administrator account. This screen is only shown until an account exists.</p>
        <ErrorBox error={act.error} title="Setup failed" />
        {localErr && (
          <div className="alert alert-error" role="alert">
            {localErr}
          </div>
        )}
        <div className="field">
          <label htmlFor="setup-token">Setup token</label>
          <input id="setup-token" required autoComplete="off" className="mono" value={f.setup_token} onChange={set("setup_token")} />
          <p className="hint">
            The one-time setup token is printed in the server log at startup, e.g. <Code>docker compose logs stackurity</Code>.
          </p>
        </div>
        <div className="field">
          <label htmlFor="setup-email">Email</label>
          <input id="setup-email" type="email" required autoComplete="username" value={f.email} onChange={set("email")} />
        </div>
        <div className="field">
          <label htmlFor="setup-name">Name</label>
          <input id="setup-name" autoComplete="name" value={f.name} onChange={set("name")} />
        </div>
        <div className="field">
          <label htmlFor="setup-password">Password</label>
          <input
            id="setup-password"
            type="password"
            required
            minLength={12}
            autoComplete="new-password"
            value={f.password}
            onChange={set("password")}
            aria-describedby="setup-password-hint"
          />
          <p className="hint" id="setup-password-hint">
            At least 12 characters.
          </p>
        </div>
        <div className="field">
          <label htmlFor="setup-confirm">Confirm password</label>
          <input id="setup-confirm" type="password" required autoComplete="new-password" value={f.confirm} onChange={set("confirm")} />
        </div>
        <button type="submit" className="btn btn-primary btn-block" disabled={act.pending}>
          {act.pending ? "Creating…" : "Create administrator"}
        </button>
      </form>
    </div>
  );
}
