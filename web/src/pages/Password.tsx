import { useEffect, useState, type FormEvent } from "react";
import { api } from "../api";
import { useAuth } from "../auth";
import { useAction } from "../hooks";
import { Card, ErrorBox, Loading, Notice } from "../components/ui";

/** Shown under the sign-in form: email a reset link, or ask an administrator. */
export function ForgotPasswordLink() {
  const { meta } = useAuth();
  if (meta?.password_reset === "email") {
    return (
      <p className="small" style={{ textAlign: "center" }}>
        <a href="/forgot-password">Forgot your password?</a>
      </p>
    );
  }
  return (
    <p className="small muted" style={{ textAlign: "center" }}>
      Forgot your password? Ask an administrator of your organisation to set a temporary one.
    </p>
  );
}

/** /forgot-password: email a reset link. The answer is the same whether or not the account exists. */
export function ForgotPasswordPage() {
  const [email, setEmail] = useState("");
  const [sent, setSent] = useState<string | null>(null);
  const act = useAction();
  const submit = async (e: FormEvent) => {
    e.preventDefault();
    const r = await act.run(() => api.post<{ status: string }>("/auth/password-reset", { email: email.trim() }));
    if (r) setSent(r.status);
  };
  return (
    <div className="center-screen">
      <form className="auth-card form" onSubmit={submit} aria-labelledby="forgot-title">
        <h1 id="forgot-title" className="auth-title">
          Reset your password
        </h1>
        {sent ? (
          <Notice kind="success">{sent}</Notice>
        ) : (
          <>
            <p>Enter the email you sign in with. We email you a link to choose a new password.</p>
            <ErrorBox error={act.error} title="Could not send the link" />
            <div className="field">
              <label htmlFor="forgot-email">Email</label>
              <input id="forgot-email" type="email" autoComplete="username" required autoFocus value={email} onChange={(e) => setEmail(e.target.value)} />
            </div>
            <button type="submit" className="btn btn-primary btn-block" disabled={act.pending}>
              {act.pending ? "Sending…" : "Email me a link"}
            </button>
          </>
        )}
        <p className="small" style={{ textAlign: "center" }}>
          <a href="/">Back to sign in</a>
        </p>
      </form>
    </div>
  );
}

/** /reset-password#token: choose a new password with the emailed link. */
export function ResetPasswordPage() {
  const [token] = useState(() => window.location.hash.slice(1));
  const [preview, setPreview] = useState<{ email: string; tokens: number; assistants: number } | null>(null);
  const [f, setF] = useState({ password: "", confirm: "", revokeTokens: true });
  const [localErr, setLocalErr] = useState<string | null>(null);
  const [done, setDone] = useState(false);
  const load = useAction();
  const act = useAction();

  useEffect(() => {
    // Keep the token out of the address bar and history.
    if (token) window.history.replaceState(null, "", "/reset-password");
    void load.run(() => api.post<{ email: string; tokens: number; assistants: number }>("/auth/password-reset/preview", { token })).then((p) => p && setPreview(p));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setLocalErr(null);
    if (f.password !== f.confirm) return setLocalErr("Passwords do not match.");
    const ok = await act.run(() => api.post("/auth/password-reset/confirm", { token, new_password: f.password, revoke_tokens: f.revokeTokens }));
    if (ok) setDone(true);
  };

  return (
    <div className="center-screen">
      <form className="auth-card form" onSubmit={submit} aria-labelledby="reset-title">
        <h1 id="reset-title" className="auth-title">
          Choose a new password
        </h1>
        <ErrorBox error={load.error} title="This link does not work" />
        {load.pending && <Loading />}
        {done && (
          <>
            <Notice kind="success">Your password was changed. Every session was signed out and your AI assistants were disconnected.</Notice>
            <a className="btn btn-primary btn-block" href="/">
              Sign in
            </a>
          </>
        )}
        {preview && !done && (
          <>
            <p>
              For <strong>{preview.email}</strong>.
            </p>
            <ErrorBox error={act.error} title="Could not change the password" />
            {localErr && (
              <div className="alert alert-error" role="alert">
                {localErr}
              </div>
            )}
            <NewPasswordFields value={f} onChange={(v) => setF({ ...f, ...v })} />
            {preview.tokens > 0 && (
              <label className="check">
                <input type="checkbox" checked={f.revokeTokens} onChange={(e) => setF({ ...f, revokeTokens: e.target.checked })} /> Also revoke my{" "}
                {preview.tokens} API token{preview.tokens === 1 ? "" : "s"}
              </label>
            )}
            <p className="hint">Every session ends{preview.assistants > 0 ? ", and your connected AI assistants are disconnected" : ""}.</p>
            <button type="submit" className="btn btn-primary btn-block" disabled={act.pending}>
              Change password
            </button>
          </>
        )}
        {!preview && !done && !load.pending && (
          <p className="small" style={{ textAlign: "center" }}>
            <a href="/forgot-password">Ask for a new link</a>
          </p>
        )}
      </form>
    </div>
  );
}

function NewPasswordFields({ value, onChange }: { value: { password: string; confirm: string }; onChange: (v: { password?: string; confirm?: string }) => void }) {
  return (
    <>
      <div className="field">
        <label htmlFor="new-password">New password</label>
        <input
          id="new-password"
          type="password"
          required
          minLength={12}
          maxLength={256}
          autoComplete="new-password"
          value={value.password}
          onChange={(e) => onChange({ password: e.target.value })}
          aria-describedby="new-password-hint"
        />
        <p className="hint" id="new-password-hint">
          At least 12 characters. A passphrase of a few words is easy to remember and hard to guess. Passwords found in known data breaches are refused.
        </p>
      </div>
      <div className="field">
        <label htmlFor="new-password-confirm">Confirm new password</label>
        <input id="new-password-confirm" type="password" required autoComplete="new-password" value={value.confirm} onChange={(e) => onChange({ confirm: e.target.value })} />
      </div>
    </>
  );
}

interface ChangeResult {
  revoked?: { sessions: number; tokens: number; assistants: number };
  tokens_kept?: number;
}

/** Your account → Password, and the screen after an administrator set a temporary password. */
export function ChangePasswordForm({ onDone }: { onDone?: (r: ChangeResult | undefined) => void }) {
  const [f, setF] = useState({ current: "", password: "", confirm: "" });
  const [localErr, setLocalErr] = useState<string | null>(null);
  const [msg, setMsg] = useState<string | null>(null);
  const act = useAction();
  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setLocalErr(null);
    setMsg(null);
    if (f.password !== f.confirm) return setLocalErr("Passwords do not match.");
    const r = await act.run(() => api.post<ChangeResult | undefined>("/auth/password", { current_password: f.current, new_password: f.password }).then((x) => x ?? {}));
    if (r === undefined) return;
    setF({ current: "", password: "", confirm: "" });
    setMsg("Your password was changed. Your other sessions were signed out.");
    onDone?.(r);
  };
  return (
    <form className="form" onSubmit={submit}>
      {msg && <Notice kind="success">{msg}</Notice>}
      <ErrorBox error={act.error} title="Could not change the password" />
      {localErr && (
        <div className="alert alert-error" role="alert">
          {localErr}
        </div>
      )}
      <div className="field">
        <label htmlFor="current-password">Current password</label>
        <input id="current-password" type="password" required autoComplete="current-password" value={f.current} onChange={(e) => setF({ ...f, current: e.target.value })} />
      </div>
      <NewPasswordFields value={f} onChange={(v) => setF({ ...f, ...v })} />
      <div className="form-actions">
        <button type="submit" className="btn btn-primary" disabled={act.pending}>
          Change password
        </button>
      </div>
    </form>
  );
}

export function PasswordCard() {
  return (
    <Card title="Password">
      <ChangePasswordForm />
    </Card>
  );
}

/** Shown instead of the dashboard while an administrator's temporary password is in use. */
export function ChangeTemporaryPasswordPage() {
  const { refresh, logout } = useAuth();
  return (
    <div className="center-screen">
      <div className="auth-card auth-card-wide">
        <h1 className="auth-title">Choose your own password</h1>
        <p>An administrator set a temporary password for your account. Choose your own to continue.</p>
        <ChangePasswordForm onDone={() => void refresh()} />
        <p className="small" style={{ textAlign: "center" }}>
          <button type="button" className="btn btn-link" onClick={() => void logout()}>
            Sign out
          </button>
        </p>
      </div>
    </div>
  );
}
