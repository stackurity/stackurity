import { useEffect, useState, type FormEvent } from "react";
import { api, ApiError, type InvitationAccepted, type InvitationGrant, type InvitationPreview } from "../api";
import { useAuth } from "../auth";
import { useAction } from "../hooks";
import { absTime } from "../format";
import { ErrorBox, Loading, Notice } from "../components/ui";
import { ROLE_HELP } from "../components/Invite";
import { permissionLabel } from "../roles";
import { LoginPage } from "./Login";

/**
 * /invite#<token>: someone following an invitation link. The token stays in
 * the address's fragment, which browsers never send to a server, and goes to
 * the API in a request body only.
 */
export function AcceptInvitePage() {
  const { state, logout } = useAuth();
  const [token] = useState(() => window.location.hash.replace(/^#/, "").trim());
  const [pv, setPv] = useState<{ invitation: InvitationPreview; signed_in_as: string } | null>(null);
  const [error, setError] = useState<ApiError | null>(null);
  const [signIn, setSignIn] = useState(false);
  const [name, setName] = useState("");
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [localErr, setLocalErr] = useState<string | null>(null);
  // Set when accepting skipped some of what the invitation named.
  const [joined, setJoined] = useState<InvitationAccepted | null>(null);
  const act = useAction();
  const signedIn = state.phase === "ready";

  useEffect(() => {
    if (!token) return;
    api
      .post<{ invitation: InvitationPreview; signed_in_as: string }>("/invitations/preview", { token })
      .then((r) => {
        setPv(r);
        setName(r.invitation.name);
        setError(null);
      })
      .catch((e) => setError(e as ApiError));
  }, [token, signedIn]);

  if (signIn && !signedIn) return <LoginPage />;

  const accept = async (e?: FormEvent) => {
    e?.preventDefault();
    setLocalErr(null);
    if (pv && !pv.invitation.account_exists) {
      if (password.length < 12) return setLocalErr("Use at least 12 characters for your password.");
      if (password !== confirm) return setLocalErr("The passwords do not match.");
    }
    const r = await act.run(() =>
      api.post<InvitationAccepted>("/invitations/accept", pv?.invitation.account_exists ? { token } : { token, name: name.trim(), password }),
    );
    if (r) {
      if (r.dropped?.length) {
        // Say what was skipped before going on.
        window.history.replaceState(null, "", "/invite");
        setJoined(r);
        return;
      }
      go(r);
    }
  };
  // Open the project with the new session; replace() also drops the link
  // from the browser's history.
  const go = (r: InvitationAccepted) => window.location.replace(r.project_id ? `/?project=${r.project_id}` : "/");

  let body;
  if (joined) {
    body = (
      <>
        <Notice kind="success">You joined. You have access to {joined.grants === 1 ? "1 project or asset" : `${joined.grants} projects and assets`}.</Notice>
        <Notice kind="warn">
          Some of what the invitation named was not given, because it changed after you were invited:
          <ul>
            {joined.dropped.map((g) => (
              <li key={`${g.kind}-${g.project_id ?? g.asset_id}-${g.name}`}>{droppedLine(g)}</li>
            ))}
          </ul>
          Ask the person who invited you if you need it.
        </Notice>
        <button type="button" className="btn btn-primary btn-block" onClick={() => go(joined)}>
          Continue
        </button>
      </>
    );
  } else if (!token) {
    body = <Notice kind="warn">This page needs the whole invitation link. Open it again from the email or message you got.</Notice>;
  } else if (error) {
    body =
      error.status === 410 ? (
        <Notice kind="warn">
          This invitation link does not work any more. It was used, it expired after 7 days, or it was withdrawn. Ask the person who invited you for a new one.
        </Notice>
      ) : (
        <ErrorBox error={error} title="Could not open the invitation" />
      );
  } else if (!pv) {
    body = <Loading />;
  } else {
    const inv = pv.invitation;
    const where = inv.project ? (
      <>
        the project <strong>{inv.project}</strong> in <strong>{inv.workspace}</strong>
      </>
    ) : (
      <strong>{inv.workspace}</strong>
    );
    const wrong = pv.signed_in_as !== "" && pv.signed_in_as.toLowerCase() !== inv.email.toLowerCase();
    body = (
      <>
        {inv.scope === "specific" && !(inv.grants.length === 1 && inv.grants[0].kind === "project") ? (
          <>
            <p>
              {inv.invited_by} invited <strong>{inv.email}</strong> to <strong>{inv.workspace}</strong>, to see:
            </p>
            <ul className="invite-grants">
              {inv.grants.map((g) => (
                <li key={`${g.kind}-${g.project_id ?? g.asset_id}-${g.name}`} className={g.available ? undefined : "muted"}>
                  {g.kind === "project" ? "Project" : "Asset"} <strong>{g.name}</strong> — {permissionLabel(g.role)}
                  {!g.available && <> (not any more: {UNAVAILABLE[g.unavailable ?? "deleted"]})</>}
                </li>
              ))}
            </ul>
            <p className="hint">The link works until {absTime(inv.expires_at)}.</p>
          </>
        ) : (
          <>
            <p>
              {inv.invited_by} invited <strong>{inv.email}</strong> to {where}
              {inv.scope === "organisation" && <> (all projects and assets)</>}, as <strong>{permissionLabel(inv.role)}</strong>.
            </p>
            <p className="hint">
              {inv.role ? ROLE_HELP[inv.role] : ""} The link works until {absTime(inv.expires_at)}.
            </p>
          </>
        )}
        {!inv.usable && (
          <Notice kind="warn">
            Everything this invitation gave access to has been archived or deleted since it was sent, so it cannot be accepted. Ask {inv.invited_by} for a new one.
          </Notice>
        )}
        <ErrorBox error={act.error} title="Could not accept" />
        {localErr && (
          <div className="alert alert-error" role="alert">
            {localErr}
          </div>
        )}
        {!inv.usable ? null : wrong ? (
          <>
            <Notice kind="warn">
              You are signed in as {pv.signed_in_as}. This invitation is for {inv.email}. Sign out, then open the link again.
            </Notice>
            <button type="button" className="btn btn-block" onClick={() => void logout()}>
              Sign out
            </button>
          </>
        ) : inv.account_exists && !pv.signed_in_as ? (
          <>
            <p>You already have an account. Sign in as {inv.email} to accept.</p>
            <button type="button" className="btn btn-primary btn-block" onClick={() => setSignIn(true)}>
              Sign in
            </button>
          </>
        ) : inv.account_exists ? (
          <button type="button" className="btn btn-primary btn-block" onClick={() => void accept()} disabled={act.pending}>
            {act.pending ? "Joining…" : `Join ${inv.workspace}`}
          </button>
        ) : (
          <form className="form" onSubmit={accept}>
            <p className="small">Create your account to accept.</p>
            <div className="field">
              <label htmlFor="ai-email">Email</label>
              <input id="ai-email" type="email" value={inv.email} readOnly autoComplete="username" />
            </div>
            <div className="field">
              <label htmlFor="ai-name">Your name</label>
              <input id="ai-name" autoComplete="name" maxLength={200} value={name} onChange={(e) => setName(e.target.value)} />
            </div>
            <div className="field">
              <label htmlFor="ai-pass">Password</label>
              <input id="ai-pass" type="password" required minLength={12} autoComplete="new-password" value={password} onChange={(e) => setPassword(e.target.value)} />
              <p className="hint">At least 12 characters.</p>
            </div>
            <div className="field">
              <label htmlFor="ai-confirm">Password again</label>
              <input id="ai-confirm" type="password" required autoComplete="new-password" value={confirm} onChange={(e) => setConfirm(e.target.value)} />
            </div>
            <button type="submit" className="btn btn-primary btn-block" disabled={act.pending}>
              {act.pending ? "Creating your account…" : "Create account and join"}
            </button>
          </form>
        )}
      </>
    );
  }

  return (
    <div className="center-screen">
      <div className="auth-card auth-card-wide accept-invite">
        <div className="auth-logo">
          <img src="/logo-login.png" alt="Stackurity" width={120} height={120} />
        </div>
        <h1 className="auth-title">You are invited</h1>
        {body}
      </div>
    </div>
  );
}

const UNAVAILABLE: Record<NonNullable<InvitationGrant["unavailable"]>, string> = {
  archived: "the project was archived",
  merged: "the asset was merged into another",
  deleted: "it was deleted",
  changed: "it changed while you were joining",
};

function droppedLine(g: InvitationGrant): string {
  return `${g.kind === "project" ? "Project" : "Asset"} ${g.name}: ${UNAVAILABLE[g.unavailable ?? "deleted"]}.`;
}
