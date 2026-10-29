import { useState, type FormEvent } from "react";
import { Link } from "react-router";
import { api } from "../api";
import { useAuth } from "../auth";
import { useAction, useLoad } from "../hooks";
import { Card, CopyBox, ErrorBox, Loading, Notice } from "../components/ui";

/** GET /auth/mfa: the signed-in person's two-factor sign-in. */
export interface MfaStatus {
  enabled: boolean;
  enabled_at: string | null;
  recovery_codes_left: number;
  /** The current organisation requires two-factor sign-in. */
  required: boolean;
  /** The server can store secrets (STACKURITY_SECRET_KEY). */
  available: boolean;
  /** API tokens and connected assistants keep working without a second factor. */
  tokens: number;
  assistants: number;
}

interface TotpStart {
  secret: string;
  otpauth_url: string;
  qr_png: string;
}

/** The second step of a password sign-in: a code from the app, or a recovery code. */
export function MfaLoginStep({ onDone, onRestart }: { onDone: () => Promise<void>; onRestart: () => void }) {
  const [code, setCode] = useState("");
  const [recovery, setRecovery] = useState(false);
  const act = useAction();
  const expired = act.error?.code === "mfa_expired";

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    const ok = await act.run(() => api.post("/auth/mfa/verify", { code: code.trim() }));
    if (ok !== undefined) await onDone();
    else setCode("");
  };

  return (
    <div className="center-screen">
      <form className="auth-card form" onSubmit={submit} aria-labelledby="mfa-title">
        <h1 id="mfa-title" className="auth-title">
          Two-factor sign-in
        </h1>
        <ErrorBox error={act.error} title="Sign-in failed" />
        {expired ? (
          <button type="button" className="btn btn-primary btn-block" onClick={onRestart}>
            Sign in again
          </button>
        ) : (
          <>
            <div className="field">
              <label htmlFor="mfa-code">{recovery ? "Recovery code" : "Code from your authenticator app"}</label>
              <input
                id="mfa-code"
                autoComplete="one-time-code"
                inputMode={recovery ? "text" : "numeric"}
                maxLength={recovery ? 24 : 7}
                required
                autoFocus
                className="mono"
                value={code}
                onChange={(e) => setCode(e.target.value)}
              />
              <p className="hint">
                {recovery ? "One of the codes you saved when you set up two-factor sign-in. Each works once." : "Six digits; a new one every 30 seconds."}
              </p>
            </div>
            <button type="submit" className="btn btn-primary btn-block" disabled={act.pending}>
              {act.pending ? "Checking…" : "Verify"}
            </button>
            <p className="small" style={{ textAlign: "center" }}>
              <button
                type="button"
                className="btn btn-link"
                onClick={() => {
                  setRecovery(!recovery);
                  setCode("");
                }}
              >
                {recovery ? "Use a code from the app" : "Use a recovery code"}
              </button>
            </p>
          </>
        )}
      </form>
    </div>
  );
}

/** Your account → Two-factor sign-in: turn on, new recovery codes, turn off. */
export function TwoFactorCard() {
  const res = useLoad(() => api.get<MfaStatus>("/auth/mfa"), []);
  return (
    <section id="mfa" className="card">
      <header className="card-head">
        <h2>Two-factor sign-in</h2>
      </header>
      <ErrorBox error={res.error} title="Could not load two-factor sign-in" />
      {!res.data && !res.error && <Loading />}
      {res.data && <TwoFactorBody st={res.data} reload={res.reload} />}
    </section>
  );
}

function TwoFactorBody({ st, reload }: { st: MfaStatus; reload: () => void }) {
  const [mode, setMode] = useState<"idle" | "enrol" | "codes" | "off">("idle");
  const [codes, setCodes] = useState<string[] | null>(null);

  if (codes) return <RecoveryCodes codes={codes} onDone={() => (setCodes(null), setMode("idle"), reload())} />;
  if (mode === "enrol") return <Enrol onCancel={() => setMode("idle")} onDone={(c) => setCodes(c)} />;

  if (!st.enabled) {
    return (
      <>
        <p>
          Two-factor sign-in asks for a code from an authenticator app (such as 1Password, Google Authenticator or Microsoft Authenticator) after your
          password, so a stolen password alone is not enough.
        </p>
        {st.required && <Notice kind="warn">Your organisation requires two-factor sign-in.</Notice>}
        {!st.available ? (
          <Notice kind="warn">This server cannot store two-factor secrets yet: an administrator must set STACKURITY_SECRET_KEY.</Notice>
        ) : (
          <button type="button" className="btn btn-primary" onClick={() => setMode("enrol")}>
            Set up two-factor sign-in
          </button>
        )}
      </>
    );
  }
  return (
    <>
      <p>
        <strong>On</strong>. {st.recovery_codes_left} of 10 recovery codes left.
        {st.recovery_codes_left <= 3 && " Make new ones before you run out."}
      </p>
      <BypassNote st={st} />
      {mode === "codes" && (
        <PasswordConfirm
          label="Make new recovery codes"
          hint="Your current recovery codes stop working."
          run={(password) => api.post<{ recovery_codes: string[] }>("/auth/mfa/recovery-codes", { password })}
          onDone={(r) => setCodes(r.recovery_codes)}
          onCancel={() => setMode("idle")}
        />
      )}
      {mode === "off" && (
        <PasswordConfirm
          label="Turn off two-factor sign-in"
          danger
          hint="Your password alone will sign you in again."
          run={(password) => api.del("/auth/mfa", { password }).then(() => true)}
          onDone={() => (setMode("idle"), reload())}
          onCancel={() => setMode("idle")}
        />
      )}
      {mode === "idle" && (
        <div className="form-actions">
          <button type="button" className="btn" onClick={() => setMode("codes")}>
            New recovery codes
          </button>
          {!st.required && (
            <button type="button" className="btn btn-link-danger" onClick={() => setMode("off")}>
              Turn off
            </button>
          )}
        </div>
      )}
    </>
  );
}

/** API tokens and assistants are not asked for a second factor (as on GitHub). */
function BypassNote({ st }: { st: MfaStatus }) {
  if (st.tokens === 0 && st.assistants === 0) {
    return <p className="hint">API tokens and connected AI assistants are not asked for a code: treat them like passwords.</p>;
  }
  return (
    <Notice kind="info">
      You have {st.tokens} API token{st.tokens === 1 ? "" : "s"} and {st.assistants} connected AI assistant{st.assistants === 1 ? "" : "s"}. They keep
      working without a code: review them under <Link to="/settings/tokens">API tokens</Link> and{" "}
      <Link to="/settings/ai-assistants#connected">AI assistants</Link>.
    </Notice>
  );
}

function PasswordConfirm<T>({
  label,
  hint,
  danger,
  run,
  onDone,
  onCancel,
}: {
  label: string;
  hint: string;
  danger?: boolean;
  run: (password: string) => Promise<T>;
  onDone: (r: T) => void;
  onCancel: () => void;
}) {
  const [password, setPassword] = useState("");
  const act = useAction();
  const submit = async (e: FormEvent) => {
    e.preventDefault();
    const r = await act.run(() => run(password));
    if (r !== undefined) onDone(r);
  };
  return (
    <form className="form" onSubmit={submit}>
      <ErrorBox error={act.error} title="That did not work" />
      <div className="field">
        <label htmlFor="mfa-pw">Your password</label>
        <input id="mfa-pw" type="password" autoComplete="current-password" required autoFocus value={password} onChange={(e) => setPassword(e.target.value)} />
        <p className="hint">{hint}</p>
      </div>
      <div className="form-actions">
        <button type="submit" className={danger ? "btn btn-danger" : "btn btn-primary"} disabled={act.pending}>
          {label}
        </button>
        <button type="button" className="btn" onClick={onCancel}>
          Cancel
        </button>
      </div>
    </form>
  );
}

/** Password, then a QR code (and the secret as text), then a code to confirm. */
function Enrol({ onCancel, onDone }: { onCancel: () => void; onDone: (codes: string[]) => void }) {
  const [start, setStart] = useState<TotpStart | null>(null);
  const [code, setCode] = useState("");
  const act = useAction();
  const { refresh } = useAuth();

  if (!start) {
    return (
      <PasswordConfirm
        label="Continue"
        hint="To set up two-factor sign-in, enter your password again."
        run={(password) => api.post<TotpStart>("/auth/mfa/totp", { password })}
        onDone={setStart}
        onCancel={onCancel}
      />
    );
  }
  const confirm = async (e: FormEvent) => {
    e.preventDefault();
    const r = await act.run(() => api.post<{ recovery_codes: string[] }>("/auth/mfa/totp/confirm", { code: code.trim() }));
    if (r) {
      onDone(r.recovery_codes);
      void refresh();
    }
  };
  return (
    <form className="form" onSubmit={confirm}>
      <ol className="steps">
        <li>
          Scan this QR code with your authenticator app.
          <div className="mfa-qr">
            <img src={start.qr_png} alt="QR code for your authenticator app" width={240} height={240} />
          </div>
          <CopyBox value={start.secret} label="Or enter this key by hand" />
        </li>
        <li>
          <div className="field">
            <label htmlFor="mfa-confirm">Enter the six-digit code the app shows</label>
            <input
              id="mfa-confirm"
              autoComplete="one-time-code"
              inputMode="numeric"
              pattern="[0-9 ]{6,7}"
              maxLength={7}
              required
              autoFocus
              className="mono"
              value={code}
              onChange={(e) => setCode(e.target.value)}
            />
          </div>
        </li>
      </ol>
      <ErrorBox error={act.error} title="Could not turn on two-factor sign-in" />
      <div className="form-actions">
        <button type="submit" className="btn btn-primary" disabled={act.pending}>
          Turn on
        </button>
        <button type="button" className="btn" onClick={onCancel}>
          Cancel
        </button>
      </div>
    </form>
  );
}

function RecoveryCodes({ codes, onDone }: { codes: string[]; onDone: () => void }) {
  const text = codes.join("\n");
  return (
    <>
      <Notice kind="success">Two-factor sign-in is on. Your other sessions were signed out.</Notice>
      <p>
        <strong>Save these recovery codes</strong> somewhere safe, such as your password manager. Each one signs you in once if you lose your phone. They
        are shown only now.
      </p>
      <ul className="mfa-codes mono">
        {codes.map((c) => (
          <li key={c}>{c}</li>
        ))}
      </ul>
      <div className="form-actions">
        <CopyBox value={text} label="Copy all codes" />
        <a className="btn" href={"data:text/plain;charset=utf-8," + encodeURIComponent(text + "\n")} download="stackurity-recovery-codes.txt">
          Download
        </a>
        <button type="button" className="btn btn-primary" onClick={onDone}>
          I saved them
        </button>
      </div>
    </>
  );
}

/** Shown instead of the dashboard when the organisation requires two-factor sign-in and you have none. */
export function MfaEnrolmentPage() {
  const { me, logout, refresh } = useAuth();
  const [codes, setCodes] = useState<string[] | null>(null);
  return (
    <div className="center-screen">
      <div className="auth-card auth-card-wide">
        <h1 className="auth-title">Set up two-factor sign-in</h1>
        {codes ? (
          <RecoveryCodes codes={codes} onDone={() => void refresh()} />
        ) : (
          <>
            <p>
              {me?.workspace?.name ?? "Your organisation"} requires two-factor sign-in for every member. Set it up to continue; it takes a minute with an
              authenticator app on your phone.
            </p>
            <Enrol onCancel={() => void logout()} onDone={setCodes} />
          </>
        )}
      </div>
    </div>
  );
}

/** Settings → Users: "Require two-factor sign-in for all members" (admins). */
export function RequireMfaCard() {
  const res = useLoad(() => api.get<{ require_mfa: boolean; members_without_mfa: number }>("/settings/security"), []);
  const act = useAction();
  const set = async (on: boolean) => {
    const ok = await act.run(() => api.put("/settings/security", { require_mfa: on }));
    if (ok) res.reload();
  };
  if (!res.data) return <ErrorBox error={res.error} title="Could not load security settings" />;
  const d = res.data;
  return (
    <Card title="Two-factor sign-in">
      <ErrorBox error={act.error} title="Could not change the setting" />
      <label className="check">
        <input type="checkbox" checked={d.require_mfa} disabled={act.pending} onChange={(e) => void set(e.target.checked)} />
        Require two-factor sign-in for all members
      </label>
      <p className="hint">
        {d.members_without_mfa === 0
          ? "Every member has two-factor sign-in."
          : `${d.members_without_mfa} member${d.members_without_mfa === 1 ? " has" : "s have"} no second factor${
              d.require_mfa ? " and will be asked to set one up at their next sign-in with a password." : "."
            }`}{" "}
        People who sign in with single sign-on use their identity provider's second factor instead.
      </p>
    </Card>
  );
}
