import { useEffect, useState, type FormEvent, type ReactNode } from "react";
import { Link } from "react-router";
import { api, ApiError, type MfaMethod, type Project, type UserRole } from "../api";
import { useAuth } from "../auth";
import { useAction } from "../hooks";
import { ErrorBox, GoodToKnow, Loading, Notice } from "../components/ui";
import { DEVICE_PATH, DEVICE_RESUME, deviceResumeValue, formatUserCode, normalizeUserCode, userCodeFromQuery } from "../deviceLogin";
import { LoginPage } from "./Login";
import { ConfirmFactor } from "./TwoFactor";

/** POST /device/preview: what a code asks for. */
interface DevicePreview {
  user_code: string;
  client: { id: string; name: string };
  host: string;
  request_ip: string;
  /** False when the request came from another network than this browser. */
  same_network?: boolean;
  requested_at: string;
  expires_at: string;
  signed_in_as: string;
  workspace: { id: number; name: string } | null;
  your_role: UserRole | "";
  can_approve: boolean;
  cannot_approve?: string;
  projects: Project[];
  token_name: string;
  token_days: number;
  /** The organisation requires two-factor sign-in and this session last confirmed it more than confirm_minutes ago. */
  confirm_first?: boolean;
  confirm_methods?: MfaMethod[];
  confirm_minutes?: number;
}

/**
 * /device signed out: sign in (the address and its code stay), or sign up,
 * after which the sign-up pages come back here (deviceResumePath).
 */
export function DeviceSignIn() {
  useEffect(() => {
    try {
      localStorage.setItem(DEVICE_RESUME, deviceResumeValue(window.location.search, Date.now()));
    } catch {
      // Not kept: after signing up, open the address from the terminal again.
    }
  }, []);
  return <LoginPage />;
}

function Shell({ children }: { children: ReactNode }) {
  return (
    <div className="center-screen">
      <div className="auth-card auth-card-wide accept-invite">
        <div className="auth-logo">
          <img src="/logo-login.png" alt="Stackurity" width={120} height={120} />
        </div>
        <h1 className="auth-title">Sign in a terminal</h1>
        {children}
      </div>
    </div>
  );
}

/**
 * /device signed in: a command-line tool (stackurity-scan --upload) showed a
 * code and this address. The person enters or confirms the code, checks what
 * is asking and what the token could do, and approves or denies. Approving
 * makes an upload-only API token; the tool collects it by itself.
 */
export function DeviceLoginPage() {
  const { me, logout } = useAuth();
  const [code, setCode] = useState(() => userCodeFromQuery(window.location.search));
  const [typed, setTyped] = useState(() => (code ? formatUserCode(code) : ""));
  const [typedErr, setTypedErr] = useState<string | null>(null);
  const [pv, setPv] = useState<DevicePreview | null>(null);
  // Bumped after confirming a second factor, to read the request again.
  const [confirmed, setConfirmed] = useState(0);
  const [error, setError] = useState<ApiError | null>(null);
  const [project, setProject] = useState(0);
  const [done, setDone] = useState<"approved" | "denied" | null>(null);
  const act = useAction();

  useEffect(() => {
    try {
      localStorage.removeItem(DEVICE_RESUME);
    } catch {
      // nothing kept
    }
  }, []);

  useEffect(() => {
    if (!code) return;
    setPv(null);
    setError(null);
    api
      .post<DevicePreview>("/device/preview", { user_code: code })
      .then(setPv)
      .catch((e) => setError(e instanceof ApiError ? e : new ApiError(0, "client", String(e))));
  }, [code, confirmed]);

  const enter = (e: FormEvent) => {
    e.preventDefault();
    const c = normalizeUserCode(typed);
    if (!c) return setTypedErr("A code is eight letters, like BCDF-GHJK. Copy it from your terminal.");
    setTypedErr(null);
    window.history.replaceState(null, "", `${DEVICE_PATH}?user_code=${formatUserCode(c)}`);
    setCode(c);
  };

  const decide = async (decision: "approve" | "deny") => {
    if (!pv?.workspace) return;
    const r = await act.run(() =>
      api.post<{ status: "approved" | "denied" }>("/device/decision", {
        user_code: code,
        decision,
        workspace_id: pv.workspace?.id ?? 0,
        project_id: project,
      }),
    );
    if (r) setDone(r.status);
  };

  const switchTo = async (id: number) => {
    const ok = await act.run(() => api.post(`/workspaces/${id}/activate`).then(() => true));
    if (ok) window.location.reload();
  };

  const startAgain = () => {
    window.history.replaceState(null, "", DEVICE_PATH);
    setCode("");
    setTyped("");
    setPv(null);
    setError(null);
  };

  if (done) {
    return (
      <Shell>
        {done === "approved" ? (
          <>
            <Notice kind="success">
              Approved. Go back to your terminal: {pv?.client.name ?? "the tool"} finishes signing in by itself within a few seconds.
            </Notice>
            <p className="small">
              The token is called <strong>{pv?.token_name}</strong>. You can revoke it any time in{" "}
              <Link to="/integrations/tokens">API tokens</Link>.
            </p>
          </>
        ) : (
          <Notice kind="info">Denied. The terminal is told that sign-in was refused, and no token was made. You can close this page.</Notice>
        )}
        <p className="small">
          <Link to="/">Go to Stackurity</Link>
        </p>
      </Shell>
    );
  }

  if (!code) {
    return (
      <Shell>
        <p>
          Your terminal shows a code of eight letters, like <strong>BCDF-GHJK</strong>. Type it here to let that tool upload scans to your
          organisation.
        </p>
        <form className="form" onSubmit={enter}>
          <div className="field">
            <label htmlFor="device-code">Code from your terminal</label>
            <input
              id="device-code"
              value={typed}
              onChange={(e) => setTyped(e.target.value)}
              autoComplete="off"
              autoCapitalize="characters"
              spellCheck={false}
              maxLength={12}
              placeholder="XXXX-XXXX"
              autoFocus
              aria-describedby={typedErr ? "device-code-err" : undefined}
            />
            {typedErr && (
              <p className="hint" id="device-code-err" role="alert">
                {typedErr}
              </p>
            )}
          </div>
          <button type="submit" className="btn btn-primary btn-block">
            Continue
          </button>
        </form>
        <p className="small muted">
          Signed in as {me?.user?.email}. Not you?{" "}
          <button type="button" className="btn-link" onClick={() => void logout()}>
            Sign out
          </button>
        </p>
      </Shell>
    );
  }

  if (error) {
    return (
      <Shell>
        <ErrorBox error={error} title={error.status === 410 ? "This code cannot be used any more" : "This code was not found"} />
        <p className="hint">Codes work once and for 10 minutes. Run the sign-in again in your terminal to get a new one.</p>
        <button type="button" className="btn btn-block" onClick={startAgain}>
          Enter another code
        </button>
      </Shell>
    );
  }

  if (!pv) {
    return (
      <Shell>
        <Loading label="Checking the code…" />
      </Shell>
    );
  }

  const others = (me?.workspaces ?? []).filter((m) => m.workspace_id !== pv.workspace?.id);
  const chosen = pv.projects.find((p) => p.id === project);
  return (
    <Shell>
      <p>
        <strong>{pv.client.name}</strong> wants to upload scans to <strong>{pv.workspace?.name ?? "your organisation"}</strong> as{" "}
        <strong>{pv.signed_in_as}</strong>.
      </p>
      <Notice kind="warn">
        Check that your terminal shows <strong>{pv.user_code}</strong>. Approve only if you started this sign-in yourself, just now. Never
        approve a code someone sent you.
      </Notice>
      {pv.same_network === false && (
        <Notice kind="warn">
          <strong>This request came from a different network than you</strong> ({pv.request_ip}). That is expected only if you started it
          on another computer, such as a server over SSH. If you didn't, deny it.
        </Notice>
      )}
      <dl className="kv" aria-label="The sign-in request">
        <div className="kv-row">
          <dt>Code</dt>
          <dd>
            <strong>{pv.user_code}</strong>
          </dd>
        </div>
        <div className="kv-row">
          <dt>Tool</dt>
          <dd>{pv.client.name}</dd>
        </div>
        <div className="kv-row">
          <dt>Computer</dt>
          <dd>{pv.host ? <>{pv.host} (as the tool reported it)</> : <span className="muted">not given</span>}</dd>
        </div>
        <div className="kv-row">
          <dt>Requested from</dt>
          <dd>
            {pv.request_ip || <span className="muted">unknown address</span>}, {new Date(pv.requested_at).toLocaleTimeString()}
          </dd>
        </div>
      </dl>

      {others.length > 0 && (
        <div className="field">
          <label htmlFor="device-org">Organisation</label>
          <select id="device-org" value={pv.workspace?.id ?? 0} onChange={(e) => void switchTo(Number(e.target.value))} disabled={act.pending}>
            <option value={pv.workspace?.id ?? 0}>{pv.workspace?.name ?? "None"}</option>
            {others.map((m) => (
              <option key={m.workspace_id} value={m.workspace_id}>
                {m.name}
              </option>
            ))}
          </select>
          <p className="hint">The scans go to this organisation. Switching reloads the page.</p>
        </div>
      )}

      {pv.can_approve && pv.projects.length > 0 && (
        <div className="field">
          <label htmlFor="device-project">Project for new assets</label>
          <select id="device-project" value={project} onChange={(e) => setProject(Number(e.target.value))}>
            <option value={0}>No project</option>
            {pv.projects.map((p) => (
              <option key={p.id} value={p.id}>
                {p.name}
              </option>
            ))}
          </select>
          <p className="hint">Assets the tool uploads for the first time are added to this project. Assets that already exist stay where they are.</p>
        </div>
      )}

      <section aria-labelledby="device-can">
        <h2 className="section-title" id="device-can">
          What approving allows
        </h2>
        <ul className="small">
          <li>Upload scans from this tool to {pv.workspace?.name ?? "your organisation"}{chosen ? <>, adding new assets to the project {chosen.name}</> : null}.</li>
          <li>See the results of its own uploads.</li>
          <li>Nothing else: it cannot read your other assets, issues or settings, and cannot change anything.</li>
        </ul>
      </section>

      {!pv.can_approve && <Notice kind="warn">{pv.cannot_approve}</Notice>}
      {pv.can_approve && pv.confirm_first && (
        <section className="section" aria-labelledby="device-confirm">
          <h2 className="section-title" id="device-confirm">
            Confirm it is you first
          </h2>
          <p className="small">
            {pv.workspace?.name ?? "Your organisation"} requires two-factor sign-in, and approving creates a credential, so confirm again before
            you approve. A confirmation counts for {pv.confirm_minutes ?? 15} minutes.
          </p>
          <ConfirmFactor methods={pv.confirm_methods ?? []} recovery={false} onDone={() => setConfirmed((n) => n + 1)} />
        </section>
      )}
      <ErrorBox error={act.error} title="Could not record your answer" />
      <div className="slack-link-actions">
        {pv.can_approve && !pv.confirm_first && (
          <button type="button" className="btn btn-primary btn-block" onClick={() => void decide("approve")} disabled={act.pending}>
            {act.pending ? "Approving…" : "Approve"}
          </button>
        )}
        <button type="button" className="btn btn-block" onClick={() => void decide("deny")} disabled={act.pending || !pv.workspace}>
          Deny
        </button>
      </div>
      <GoodToKnow>
        Approving makes an API token called <strong>{pv.token_name}</strong>, listed under <Link to="/integrations/tokens">API tokens</Link>{" "}
        where you can revoke it. It lasts {pv.token_days} days, and stops working sooner if you leave the organisation or no longer have the
        Engineer role.
      </GoodToKnow>
      <p className="small muted">
        Not you?{" "}
        <button type="button" className="btn-link" onClick={() => void logout()}>
          Sign out
        </button>
      </p>
    </Shell>
  );
}
