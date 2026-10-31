import { useState, type FormEvent } from "react";
import { Link, useLocation, useNavigate, useSearchParams } from "react-router";
import { safeReturn } from "../returnTo";
import { MFA_METHODS, mustSetUpOwnFirst } from "../mfa";
import { api, type MfaMethod, type MfaSignInMethod } from "../api";
import { useAuth } from "../auth";
import { useAction, useLoad } from "../hooks";
import { Card, CopyBox, ErrorBox, Loading, Notice, RelativeTime } from "../components/ui";
import { ProNotice } from "../components/ProNotice";
import { createPasskey, getPasskey, passkeysSupported } from "../webauthn";

/** A registered passkey or security key. */
export interface Passkey {
  id: number;
  name: string;
  /** A synced passkey (password manager, platform account) rather than one device. */
  backed_up: boolean;
  discoverable: boolean | null;
  created_at: string;
  last_used_at: string | null;
  /** Its signature counter went backwards once: that sign-in was refused. */
  clone_warning_at: string | null;
}

/** GET /auth/mfa: the signed-in person's two-factor methods. */
export interface MfaStatus {
  enabled: boolean;
  methods: MfaMethod[];
  /** When the authenticator app was set up (null: none). */
  enabled_at: string | null;
  totp: boolean;
  email: boolean;
  recovery_codes_left: number;
  passkeys: Passkey[];
  /** The current organisation requires a second factor of you, and the methods that count there. */
  required: boolean;
  accepted: MfaMethod[];
  /** "enrol" or "step_up" when this session must set up or confirm one. */
  need: "" | "enrol" | "step_up";
  /** Organisations whose policy your factors must keep meeting. */
  required_by: string[];
  /** The server can store authenticator-app secrets (STACKURITY_SECRET_KEY). */
  available: boolean;
  passkeys_available: boolean;
  passkeys_unavailable?: string;
  rp_id?: string;
  /** API tokens and connected assistants keep working without a second factor. */
  tokens: number;
  assistants: number;
}

interface TotpStart {
  secret: string;
  otpauth_url: string;
  qr_png: string;
}

const METHOD_NAMES: Record<MfaMethod, string> = { passkey: "a passkey", totp: "an authenticator app", email: "email codes" };

/** "a passkey or an authenticator app" */
export function methodList(ms: MfaMethod[] | null | undefined): string {
  if (!ms || ms.length === 0) return "a second factor";
  return ms.map((m) => METHOD_NAMES[m]).join(" or ");
}

// --- signing in

/** The second step of a password sign-in: a passkey, a code from the app, or a recovery code. */
export function MfaLoginStep({ methods, onDone, onRestart }: { methods: MfaSignInMethod[]; onDone: () => Promise<void>; onRestart: () => void }) {
  const hasPasskey = methods.includes("passkey") && passkeysSupported();
  const hasApp = methods.includes("totp");
  const [mode, setMode] = useState<"passkey" | "totp" | "recovery_code">(hasPasskey ? "passkey" : hasApp ? "totp" : "recovery_code");
  const [code, setCode] = useState("");
  const act = useAction();
  const expired = act.error?.code === "mfa_expired";

  const usePasskey = async () => {
    const ok = await act.run(async () => {
      const begin = await api.post<{ options: unknown }>("/auth/mfa/passkey/begin");
      const credential = await getPasskey(begin.options);
      return api.post("/auth/mfa/passkey/finish", { credential });
    });
    if (ok !== undefined) await onDone();
  };
  const submit = async (e: FormEvent) => {
    e.preventDefault();
    const ok = await act.run(() => api.post("/auth/mfa/verify", { code: code.trim() }));
    if (ok !== undefined) await onDone();
    else setCode("");
  };
  const switchTo = (m: typeof mode) => {
    setMode(m);
    setCode("");
    act.clear();
  };

  return (
    <div className="center-screen">
      <div className="auth-card form">
        <h1 id="mfa-title" className="auth-title">
          Two-factor sign-in
        </h1>
        <ErrorBox error={act.error} title="Sign-in failed" />
        {expired ? (
          <button type="button" className="btn btn-primary btn-block" onClick={onRestart}>
            Sign in again
          </button>
        ) : mode === "passkey" ? (
          <>
            <p>Use your passkey or security key: your device asks for your fingerprint, face, PIN or a touch.</p>
            <button type="button" className="btn btn-primary btn-block" disabled={act.pending} onClick={() => void usePasskey()} autoFocus>
              {act.pending ? "Waiting for your passkey…" : "Use a passkey"}
            </button>
          </>
        ) : (
          <form onSubmit={submit} aria-labelledby="mfa-title" className="form">
            <div className="field">
              <label htmlFor="mfa-code">{mode === "recovery_code" ? "Recovery code" : "Code from your authenticator app"}</label>
              <input
                id="mfa-code"
                autoComplete="one-time-code"
                inputMode={mode === "recovery_code" ? "text" : "numeric"}
                maxLength={mode === "recovery_code" ? 24 : 7}
                required
                autoFocus
                className="mono"
                value={code}
                onChange={(e) => setCode(e.target.value)}
              />
              <p className="hint">
                {mode === "recovery_code"
                  ? "One of the codes you saved when you set up two-factor sign-in. Each works once."
                  : "Six digits; a new one every 30 seconds."}
              </p>
            </div>
            <button type="submit" className="btn btn-primary btn-block" disabled={act.pending}>
              {act.pending ? "Checking…" : "Verify"}
            </button>
          </form>
        )}
        {!expired && (
          <p className="small" style={{ textAlign: "center" }}>
            {hasPasskey && mode !== "passkey" && (
              <button type="button" className="btn btn-link" onClick={() => switchTo("passkey")}>
                Use a passkey
              </button>
            )}
            {hasApp && mode !== "totp" && (
              <button type="button" className="btn btn-link" onClick={() => switchTo("totp")}>
                Use a code from the app
              </button>
            )}
            {methods.includes("recovery_code") && mode !== "recovery_code" && (
              <button type="button" className="btn btn-link" onClick={() => switchTo("recovery_code")}>
                Use a recovery code
              </button>
            )}
          </p>
        )}
      </div>
    </div>
  );
}

/** "Sign in with a passkey" on the sign-in page: no email or password. */
export function PasskeySignInButton({ onDone, primary }: { onDone: () => Promise<void>; primary?: boolean }) {
  const act = useAction();
  if (!passkeysSupported()) return null;
  const go = async () => {
    const ok = await act.run(async () => {
      const begin = await api.post<{ options: unknown }>("/auth/passkey/begin");
      const credential = await getPasskey(begin.options);
      return api.post("/auth/passkey/finish", { credential });
    });
    if (ok !== undefined) await onDone();
  };
  return (
    <>
      <ErrorBox error={act.error?.code === "passkey_cancelled" ? null : act.error} title="Passkey sign-in failed" />
      <button type="button" className={primary ? "btn btn-primary btn-block" : "btn btn-block"} disabled={act.pending} onClick={() => void go()}>
        {act.pending ? "Waiting for your passkey…" : "Sign in with a passkey"}
      </button>
    </>
  );
}

// --- Your account → Two-factor methods

/** Your account → Two-factor methods: passkeys first, then the authenticator app and recovery codes. */
export function TwoFactorCard() {
  const res = useLoad(() => api.get<MfaStatus>("/auth/mfa"), []);
  return (
    <section id="mfa" className="card">
      <header className="card-head">
        <h2>Two-factor methods</h2>
      </header>
      <ErrorBox error={res.error} title="Could not load two-factor sign-in" />
      {!res.data && !res.error && <Loading />}
      {res.data && <TwoFactorBody st={res.data} reload={res.reload} />}
    </section>
  );
}

function TwoFactorBody({ st, reload }: { st: MfaStatus; reload: () => void }) {
  const [codes, setCodes] = useState<string[] | null>(null);
  // Sent here to set it up (?return=/settings/users): go back once done.
  const [params] = useSearchParams();
  const back = safeReturn(params.get("return"));
  const navigate = useNavigate();
  const { refresh } = useAuth();
  const added = () => {
    reload();
    if (back) void refresh().then(() => navigate(back));
  };
  if (codes)
    return (
      <RecoveryCodes
        codes={codes}
        onDone={() => {
          setCodes(null);
          added();
        }}
      />
    );
  return (
    <>
      <p>
        A second factor means a stolen password alone is not enough to sign in. Passkeys are the strongest: they cannot be phished, and on most devices they
        sign you in without a password. Methods: {MFA_METHODS}. <Link to="/help/two-factor">How two-factor sign-in works</Link>
      </p>
      {back && !st.enabled && <Notice kind="info">Once it is set up, you go back to where you were.</Notice>}
      {st.required_by.length > 0 && (
        <Notice kind="info">
          {st.required_by.join(", ")} require{st.required_by.length === 1 ? "s" : ""} two-factor sign-in, so you cannot remove the last method that counts
          there.
        </Notice>
      )}
      {st.required && !st.enabled && <Notice kind="warn">Your organisation requires {methodList(st.accepted)}. Set one up below.</Notice>}
      <PasskeysSection st={st} reload={reload} onAdded={added} onCodes={setCodes} />
      <AppSection st={st} reload={reload} onAdded={added} onCodes={setCodes} />
      {(st.totp || st.passkeys.length > 0) && <RecoveryCodesSection st={st} onCodes={setCodes} />}
      <BypassNote st={st} />
    </>
  );
}

function PasskeysSection({
  st,
  reload,
  onAdded,
  onCodes,
}: {
  st: MfaStatus;
  reload: () => void;
  onAdded: () => void;
  onCodes: (c: string[]) => void;
}) {
  const [adding, setAdding] = useState(false);
  const [renaming, setRenaming] = useState<number | null>(null);
  const [removing, setRemoving] = useState<number | null>(null);
  const { refresh } = useAuth();
  return (
    <section className="mfa-method" aria-labelledby="mfa-passkeys">
      <h3 id="mfa-passkeys">Passkeys and security keys</h3>
      {!st.passkeys_available ? (
        <p className="hint">{st.passkeys_unavailable ?? "Passkeys are not available on this server."}</p>
      ) : !passkeysSupported() ? (
        <p className="hint">This browser cannot use passkeys.</p>
      ) : null}
      {st.passkeys.length > 0 && (
        <ul className="mfa-passkeys">
          {st.passkeys.map((pk) => (
            <li key={pk.id}>
              {renaming === pk.id ? (
                <RenamePasskey pk={pk} onDone={() => (setRenaming(null), reload())} onCancel={() => setRenaming(null)} />
              ) : removing === pk.id ? (
                <PasswordConfirm
                  label={`Remove ${pk.name}`}
                  danger
                  hint="Your other sessions are signed out."
                  run={(password) => api.del(`/auth/mfa/passkeys/${pk.id}`, { password }).then(() => true)}
                  onDone={() => (setRemoving(null), reload(), void refresh())}
                  onCancel={() => setRemoving(null)}
                />
              ) : (
                <>
                  <div>
                    <strong>{pk.name}</strong> <span className="muted small">{pk.backed_up ? "synced passkey" : "on one device or key"}</span>
                    <div className="muted small">
                      Added <RelativeTime iso={pk.created_at} /> · last used <RelativeTime iso={pk.last_used_at} />
                    </div>
                    {pk.clone_warning_at && (
                      <Notice kind="warn">
                        A sign-in with this passkey was refused <RelativeTime iso={pk.clone_warning_at} />: its counter went backwards, which can mean the key
                        was copied. Remove it if you did not expect this.
                      </Notice>
                    )}
                  </div>
                  <div className="row-actions">
                    <button type="button" className="btn btn-sm" onClick={() => setRenaming(pk.id)}>
                      Rename
                    </button>
                    <button type="button" className="btn btn-sm btn-link-danger" onClick={() => setRemoving(pk.id)}>
                      Remove
                    </button>
                  </div>
                </>
              )}
            </li>
          ))}
        </ul>
      )}
      {st.passkeys_available &&
        passkeysSupported() &&
        (adding ? (
          <AddPasskey
            onCancel={() => setAdding(false)}
            onDone={(codes) => {
              setAdding(false);
              void refresh();
              if (codes) onCodes(codes);
              else onAdded();
            }}
          />
        ) : (
          <button type="button" className={st.passkeys.length === 0 ? "btn btn-primary" : "btn"} onClick={() => setAdding(true)}>
            Add a passkey or security key
          </button>
        ))}
      {st.rp_id && st.passkeys.length > 0 && <p className="hint">Your passkeys work on {st.rp_id}.</p>}
    </section>
  );
}

function RenamePasskey({ pk, onDone, onCancel }: { pk: Passkey; onDone: () => void; onCancel: () => void }) {
  const [name, setName] = useState(pk.name);
  const act = useAction();
  const submit = async (e: FormEvent) => {
    e.preventDefault();
    const ok = await act.run(() => api.patch(`/auth/mfa/passkeys/${pk.id}`, { name: name.trim() }).then(() => true));
    if (ok) onDone();
  };
  return (
    <form className="form inline-form" onSubmit={submit}>
      <ErrorBox error={act.error} title="Could not rename it" />
      <div className="field">
        <label htmlFor={`pk-name-${pk.id}`}>Name</label>
        <input id={`pk-name-${pk.id}`} required maxLength={64} autoFocus value={name} onChange={(e) => setName(e.target.value)} />
      </div>
      <div className="form-actions">
        <button type="submit" className="btn btn-primary" disabled={act.pending}>
          Save
        </button>
        <button type="button" className="btn" onClick={onCancel}>
          Cancel
        </button>
      </div>
    </form>
  );
}

/** Name and password, then the browser's prompt. */
function AddPasskey({ onCancel, onDone }: { onCancel: () => void; onDone: (codes: string[] | null) => void }) {
  const [name, setName] = useState("");
  const [password, setPassword] = useState("");
  const act = useAction();
  const submit = async (e: FormEvent) => {
    e.preventDefault();
    const r = await act.run(async () => {
      const begin = await api.post<{ options: unknown }>("/auth/mfa/passkeys/begin", { password });
      const credential = await createPasskey(begin.options);
      return api.post<{ recovery_codes: string[] | null }>("/auth/mfa/passkeys/finish", { name: name.trim(), credential });
    });
    if (r) onDone(r.recovery_codes);
  };
  return (
    <form className="form inline-form" onSubmit={submit}>
      <ErrorBox error={act.error} title="Could not add the passkey" />
      <div className="field">
        <label htmlFor="pk-new-name">Name</label>
        <input
          id="pk-new-name"
          required
          maxLength={64}
          autoFocus
          placeholder="MacBook Touch ID, YubiKey 5"
          value={name}
          onChange={(e) => setName(e.target.value)}
        />
        <p className="hint">So you can tell your passkeys apart.</p>
      </div>
      <div className="field">
        <label htmlFor="pk-pw">Your password</label>
        <input id="pk-pw" type="password" autoComplete="current-password" required value={password} onChange={(e) => setPassword(e.target.value)} />
        <p className="hint">Your browser then asks where to save the passkey. Your other sessions are signed out.</p>
      </div>
      <div className="form-actions">
        <button type="submit" className="btn btn-primary" disabled={act.pending}>
          {act.pending ? "Waiting for your passkey…" : "Continue"}
        </button>
        <button type="button" className="btn" onClick={onCancel}>
          Cancel
        </button>
      </div>
    </form>
  );
}

function AppSection({ st, reload, onAdded, onCodes }: { st: MfaStatus; reload: () => void; onAdded: () => void; onCodes: (c: string[]) => void }) {
  const [mode, setMode] = useState<"idle" | "enrol" | "off">("idle");
  const { refresh } = useAuth();
  return (
    <section className="mfa-method" aria-labelledby="mfa-app">
      <h3 id="mfa-app">Authenticator app</h3>
      {mode === "enrol" ? (
        <Enrol
          onCancel={() => setMode("idle")}
          onDone={(codes) => {
            setMode("idle");
            if (codes) onCodes(codes);
            else onAdded();
          }}
        />
      ) : mode === "off" ? (
        <PasswordConfirm
          label="Remove the authenticator app"
          danger
          hint="Codes from the app stop working. Your other sessions are signed out."
          run={(password) => api.del("/auth/mfa/totp", { password }).then(() => true)}
          onDone={() => (setMode("idle"), reload(), void refresh())}
          onCancel={() => setMode("idle")}
        />
      ) : st.totp ? (
        <>
          <p>
            <strong>On</strong>
            {st.enabled_at && (
              <span className="muted small">
                {" "}
                · set up <RelativeTime iso={st.enabled_at} />
              </span>
            )}
          </p>
          <button type="button" className="btn btn-sm btn-link-danger" onClick={() => setMode("off")}>
            Remove
          </button>
        </>
      ) : (
        <>
          <p className="hint">A six-digit code from an app such as 1Password, Google Authenticator or Microsoft Authenticator, after your password.</p>
          {!st.available ? (
            <Notice kind="warn">This server cannot store authenticator-app secrets yet: an administrator must set STACKURITY_SECRET_KEY.</Notice>
          ) : (
            <button type="button" className={st.enabled ? "btn" : "btn btn-primary"} onClick={() => setMode("enrol")}>
              Set up an authenticator app
            </button>
          )}
        </>
      )}
    </section>
  );
}

function RecoveryCodesSection({ st, onCodes }: { st: MfaStatus; onCodes: (c: string[]) => void }) {
  const [making, setMaking] = useState(false);
  return (
    <section className="mfa-method" aria-labelledby="mfa-recovery">
      <h3 id="mfa-recovery">Recovery codes</h3>
      <p>
        {st.recovery_codes_left} of 10 left. Each signs you in once if you lose your passkeys and phone.
        {st.recovery_codes_left <= 3 && " Make new ones before you run out."}
      </p>
      {making ? (
        <PasswordConfirm
          label="Make new recovery codes"
          hint="Your current recovery codes stop working."
          run={(password) => api.post<{ recovery_codes: string[] }>("/auth/mfa/recovery-codes", { password })}
          onDone={(r) => (setMaking(false), onCodes(r.recovery_codes))}
          onCancel={() => setMaking(false)}
        />
      ) : (
        <button type="button" className="btn btn-sm" onClick={() => setMaking(true)}>
          New recovery codes
        </button>
      )}
    </section>
  );
}

/** API tokens and assistants are not asked for a second factor (as on GitHub). */
function BypassNote({ st }: { st: MfaStatus }) {
  if (st.tokens === 0 && st.assistants === 0) {
    return <p className="hint">API tokens and connected AI assistants are not asked for a second factor: treat them like passwords.</p>;
  }
  return (
    <Notice kind="info">
      You have {st.tokens} API token{st.tokens === 1 ? "" : "s"} and {st.assistants} connected AI assistant{st.assistants === 1 ? "" : "s"}. They keep
      working without a second factor: review them under <Link to="/settings/tokens">API tokens</Link> and{" "}
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
function Enrol({ onCancel, onDone }: { onCancel: () => void; onDone: (codes: string[] | null) => void }) {
  const [start, setStart] = useState<TotpStart | null>(null);
  const [code, setCode] = useState("");
  const act = useAction();
  const { refresh } = useAuth();

  if (!start) {
    return (
      <PasswordConfirm
        label="Continue"
        hint="To set up an authenticator app, enter your password again."
        run={(password) => api.post<TotpStart>("/auth/mfa/totp", { password })}
        onDone={setStart}
        onCancel={onCancel}
      />
    );
  }
  const confirm = async (e: FormEvent) => {
    e.preventDefault();
    const r = await act.run(() => api.post<{ recovery_codes: string[] | null }>("/auth/mfa/totp/confirm", { code: code.trim() }));
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
      <ErrorBox error={act.error} title="Could not turn on the authenticator app" />
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
        <strong>Save these recovery codes</strong> somewhere safe, such as your password manager. Each one signs you in once if you lose your passkeys and
        phone. They are shown only now.
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

// --- what an organisation's policy asks of this session

/**
 * Shown instead of the dashboard when the organisation requires a second
 * factor this account does not have: passkeys are offered first.
 */
export function MfaEnrolmentPage() {
  const { me, logout, refresh } = useAuth();
  const [codes, setCodes] = useState<string[] | null>(null);
  const [app, setApp] = useState(false);
  const res = useLoad(() => api.get<MfaStatus>("/auth/mfa"), []);
  const accepted = me?.mfa_accepted ?? ["passkey", "totp"];
  const canPasskey = accepted.includes("passkey") && res.data?.passkeys_available !== false && passkeysSupported();
  const canApp = accepted.includes("totp");
  const done = (c: string[] | null) => (c ? setCodes(c) : void refresh());
  return (
    <div className="center-screen">
      <div className="auth-card auth-card-wide">
        <h1 className="auth-title">Set up two-factor sign-in</h1>
        {codes ? (
          <RecoveryCodes codes={codes} onDone={() => void refresh()} />
        ) : (
          <>
            <p>
              {me?.workspace?.name ?? "Your organisation"} requires {methodList(accepted)} to sign in. Set one up to continue; it takes a minute.
            </p>
            {canPasskey && !app && (
              <>
                <h2>A passkey (recommended)</h2>
                <p className="hint">Your fingerprint, face, device PIN or a security key. It cannot be phished.</p>
                <AddPasskey onCancel={() => void logout()} onDone={done} />
              </>
            )}
            {canApp &&
              (app || !canPasskey ? (
                <>
                  <h2>An authenticator app</h2>
                  <Enrol onCancel={() => (canPasskey ? setApp(false) : void logout())} onDone={done} />
                </>
              ) : (
                <p className="small">
                  <button type="button" className="btn btn-link" onClick={() => setApp(true)}>
                    Use an authenticator app instead
                  </button>
                </p>
              ))}
            {!canPasskey && !canApp && (
              <Notice kind="warn">
                {res.data?.passkeys_unavailable ?? "None of the methods your organisation accepts can be set up here."} Ask an administrator.
              </Notice>
            )}
          </>
        )}
      </div>
    </div>
  );
}

/**
 * Shown instead of the dashboard when the organisation requires a second
 * factor the account has but this session was not signed in with (a
 * passkey where admins must use one, say).
 */
export function MfaStepUpPage() {
  const { me, logout, refresh } = useAuth();
  const accepted = me?.mfa_accepted ?? [];
  const passkey = accepted.includes("passkey") && passkeysSupported();
  const app = accepted.includes("totp");
  const [code, setCode] = useState("");
  const act = useAction();
  const withPasskey = async () => {
    const ok = await act.run(async () => {
      const begin = await api.post<{ options: unknown }>("/auth/mfa/step-up/passkey/begin");
      const credential = await getPasskey(begin.options);
      return api.post("/auth/mfa/step-up/passkey/finish", { credential });
    });
    if (ok !== undefined) await refresh();
  };
  const withCode = async (e: FormEvent) => {
    e.preventDefault();
    const ok = await act.run(() => api.post("/auth/mfa/step-up", { code: code.trim() }));
    if (ok !== undefined) await refresh();
    else setCode("");
  };
  return (
    <div className="center-screen">
      <div className="auth-card form">
        <h1 className="auth-title">Confirm it is you</h1>
        <p>
          {me?.workspace?.name ?? "Your organisation"} requires {methodList(accepted)} to sign in, and this session used something else.
        </p>
        <ErrorBox error={act.error} title="That did not work" />
        {passkey && (
          <button type="button" className="btn btn-primary btn-block" disabled={act.pending} onClick={() => void withPasskey()}>
            {act.pending ? "Waiting for your passkey…" : "Use a passkey"}
          </button>
        )}
        <form onSubmit={withCode} className="form">
          <div className="field">
            <label htmlFor="stepup-code">{app ? "Or a code from your authenticator app, or a recovery code" : "Lost your passkey? A recovery code"}</label>
            <input
              id="stepup-code"
              autoComplete="one-time-code"
              className="mono"
              maxLength={24}
              required
              value={code}
              onChange={(e) => setCode(e.target.value)}
            />
            {!app && <p className="hint">You can then set up a new passkey.</p>}
          </div>
          <button type="submit" className="btn btn-block" disabled={act.pending}>
            Verify
          </button>
        </form>
        <p className="small" style={{ textAlign: "center" }}>
          <button type="button" className="btn btn-link" onClick={() => void logout()}>
            Sign out
          </button>
        </p>
      </div>
    </div>
  );
}

// --- Settings → Users: the organisation's policy (admins)

interface SecuritySettings {
  policy: "optional" | "everyone" | "admins";
  methods: MfaMethod[];
  phishing_resistant_admins: boolean;
  require_mfa: boolean;
  members_without_mfa: number;
  members_needing_setup: number;
  admins_without_passkey: number;
  email_available: boolean;
  phishing_resistant_available: boolean;
  passkeys_available: boolean;
  passkeys_unavailable?: string;
}

const POLICIES: [SecuritySettings["policy"], string, string][] = [
  ["optional", "Optional", "Each person decides."],
  ["everyone", "Required for everyone", "Members who sign in with a password or passkey must use a second factor."],
  ["admins", "Required for admins and security", "Members with the admin or security role, organisation-wide or on a project."],
];

/** Settings → Users: who must use two-factor sign-in, and which methods count. */
export function RequireMfaCard() {
  const res = useLoad(() => api.get<SecuritySettings>("/settings/security"), []);
  const act = useAction();
  const [draft, setDraft] = useState<Pick<SecuritySettings, "policy" | "methods" | "phishing_resistant_admins"> | null>(null);
  const { me, refresh } = useAuth();
  const { pathname } = useLocation();
  if (!res.data) return <ErrorBox error={res.error} title="Could not load security settings" />;
  const d = res.data;
  // Requiring it without a second factor of your own would lock you out:
  // the server refuses (409), so the choices wait until you have one.
  const ownMissing = mustSetUpOwnFirst(me?.user, d.require_mfa);
  const f = draft ?? { policy: d.policy, methods: d.methods, phishing_resistant_admins: d.phishing_resistant_admins };
  const changed = draft !== null;
  const toggle = (m: MfaMethod, on: boolean) =>
    setDraft({ ...f, methods: on ? [...f.methods.filter((x) => x !== m), m] : f.methods.filter((x) => x !== m) });
  const save = async (e: FormEvent) => {
    e.preventDefault();
    const ok = await act.run(() => api.put("/settings/security", f));
    if (ok) {
      setDraft(null);
      res.reload();
      void refresh();
    }
  };
  return (
    <Card title="Two-factor sign-in">
      <form className="form" onSubmit={save}>
        <ErrorBox error={act.error} title="Could not change the setting" />
        <p className="small">Methods: {MFA_METHODS}.</p>
        {ownMissing && (
          <div className="mfa-own-first" id="mfa-own-first">
            <p className="small">Set up two-factor for your own account first. Requiring it now would lock you out.</p>
            <Link className="btn btn-primary btn-sm" to={`/account?return=${encodeURIComponent(pathname)}#mfa`}>
              Set up now
            </Link>
          </div>
        )}
        <fieldset className="field">
          <legend>Who must use it</legend>
          <ul className="choice-list">
            {POLICIES.map(([v, label, hint]) => (
              <li key={v}>
                <label className="choice">
                  <input
                    type="radio"
                    name="mfa-policy"
                    checked={f.policy === v}
                    disabled={ownMissing && v !== "optional"}
                    aria-describedby={ownMissing && v !== "optional" ? "mfa-own-first" : undefined}
                    onChange={() => setDraft({ ...f, policy: v })}
                  />
                  <span>
                    {label}
                    <span className="hint"> {hint}</span>
                  </span>
                </label>
              </li>
            ))}
          </ul>
        </fieldset>
        <fieldset className="field">
          <legend>Methods that count</legend>
          <div className="checks">
            <label className="check">
              <input type="checkbox" checked={f.methods.includes("passkey")} onChange={(e) => toggle("passkey", e.target.checked)} />
              Passkey or security key
            </label>
            <label className="check">
              <input type="checkbox" checked={f.methods.includes("totp")} onChange={(e) => toggle("totp", e.target.checked)} />
              Authenticator app
            </label>
          </div>
          <p className="hint">Recovery codes count wherever a passkey or the app does.</p>
          {!d.passkeys_available && d.passkeys_unavailable && <p className="hint">{d.passkeys_unavailable}</p>}
        </fieldset>
        <div className="field">
          <label className="check">
            <input
              type="checkbox"
              checked={f.phishing_resistant_admins}
              disabled={(ownMissing || !d.phishing_resistant_available) && !f.phishing_resistant_admins}
              onChange={(e) => setDraft({ ...f, phishing_resistant_admins: e.target.checked })}
            />
            Require phishing-resistant sign-in (passkeys only) for admins
          </label>
          <p className="hint">
            {d.admins_without_passkey === 0
              ? "Every admin has a passkey."
              : `${d.admins_without_passkey} admin${d.admins_without_passkey === 1 ? " has" : "s have"} no passkey yet.`}
          </p>
          {!d.phishing_resistant_available && !f.phishing_resistant_admins && <ProNotice feature="phishing_resistant_mfa" />}
        </div>
        <p className="hint">
          {d.members_needing_setup === 0
            ? "Every member meets this policy."
            : `${d.members_needing_setup} member${d.members_needing_setup === 1 ? "" : "s"} will be asked to set up a second factor at their next sign-in.`}{" "}
          People who sign in with single sign-on use their identity provider&apos;s second factor instead. API tokens are not affected.
        </p>
        <div className="form-actions">
          <button type="submit" className="btn btn-primary" disabled={!changed || act.pending}>
            Save
          </button>
          {changed && (
            <button type="button" className="btn" onClick={() => (setDraft(null), act.clear())}>
              Cancel
            </button>
          )}
        </div>
      </form>
    </Card>
  );
}
