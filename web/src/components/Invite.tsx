import { useMemo, useReducer, useState, type FormEvent } from "react";
import { api, type Invitation, type InvitationCreated, type List, type Project } from "../api";
import { useAction, useLoad } from "../hooks";
import { absTime } from "../format";
import { confirmAction } from "./ConfirmDialog";
import { CopyBox, ErrorBox, Notice } from "./ui";
import { PERMISSIONS, ROLE_HELP, invitationSummary } from "../roles";
import { EMPTY, forProject, preview, problems, reduce, toInvitation } from "../userAccess";
import { AccessPicker } from "./AccessPicker";
import { PermissionsDisclosure } from "./Permissions";

export { ROLE_HELP };

const LABELS: Record<string, string> = Object.fromEntries(PERMISSIONS.map((p) => [p.role, p.label]));

/**
 * Invite someone by email, saying what they will see: all projects and
 * assets, or specific projects and assets (the same required choice as Add
 * user, with no default). On a project's page (projectId) it starts with
 * Specific and that project, with no permission chosen. The link is emailed
 * when the organisation has an email channel; otherwise it is shown once to
 * copy.
 */
export function InviteForm({ projectId = 0, onInvited, onCancel }: { projectId?: number; projectName?: string; onInvited?: () => void; onCancel?: () => void }) {
  const [f, dispatch] = useReducer(reduce, projectId, (id: number) => (id > 0 ? forProject(id) : EMPTY));
  const [tried, setTried] = useState(false);
  const [done, setDone] = useState<(InvitationCreated & { to: string }) | null>(null);
  const [sent, setSent] = useState(0);
  const projects = useLoad(() => api.getAll<List<Project>>("/projects"), []);
  const open = useLoad(() => api.getAll<List<Invitation>>("/invitations"), [sent]);
  const names = useMemo(() => Object.fromEntries((projects.data?.items ?? []).map((p) => [p.id, p.name])), [projects.data]);
  const act = useAction();
  const missing = problems(f, names);
  const summary = preview(f, LABELS);
  const email = f.email.trim().toLowerCase();
  const earlier = (open.data?.items ?? []).find((i) => i.status === "pending" && i.email === email);

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setTried(true);
    if (missing.length) return;
    const to = f.email.trim();
    const r = await act.run(() => api.post<InvitationCreated>("/invitations", toInvitation(f)));
    if (r) {
      setDone({ ...r, to });
      setTried(false);
      setSent((n) => n + 1);
      // Ready for the next person, with the same access.
      dispatch({ type: "field", field: "email", value: "" });
      dispatch({ type: "field", field: "name", value: "" });
      onInvited?.();
    }
  };

  return (
    <div className="invite">
      <form className="form invite-form" onSubmit={submit} aria-label="Invite someone" noValidate>
        <ErrorBox error={act.error} title="Could not invite" />
        <div className="form-grid">
          <div className="field">
            <label htmlFor="inv-email">Email</label>
            <input id="inv-email" type="email" required autoComplete="off" placeholder="name@example.com" value={f.email}
              onChange={(e) => dispatch({ type: "field", field: "email", value: e.target.value })} />
          </div>
          <div className="field">
            <label htmlFor="inv-name">Name (optional)</label>
            <input id="inv-name" autoComplete="off" maxLength={200} value={f.name} onChange={(e) => dispatch({ type: "field", field: "name", value: e.target.value })} />
          </div>
        </div>
        {earlier && (
          <Notice kind="info">
            {earlier.email} already has an open invitation ({invitationSummary(earlier)}). Sending this one replaces it, and its link stops working.
          </Notice>
        )}

        <AccessPicker idp="inv" f={f} dispatch={dispatch} projects={projects} />

        <PermissionsDisclosure />

        {tried && missing.length > 0 && (
          <div className="alert alert-warn" role="alert" id="inv-problems">
            <strong>Before inviting them:</strong>
            <ul>
              {missing.map((m) => (
                <li key={m}>{m}</li>
              ))}
            </ul>
          </div>
        )}
        {summary && (
          <p className="hint" aria-live="polite">
            They will see: {summary}
          </p>
        )}
        <div className="form-actions">
          <button type="submit" className="btn btn-primary" disabled={act.pending || (tried && missing.length > 0)} aria-describedby={tried && missing.length ? "inv-problems" : undefined}>
            {act.pending ? "Inviting…" : "Invite"}
          </button>
          {onCancel && (
            <button type="button" className="btn" onClick={onCancel}>
              Cancel
            </button>
          )}
        </div>
      </form>
      {done && <InviteResult r={done} />}
    </div>
  );
}

function InviteResult({ r }: { r: InvitationCreated & { to: string } }) {
  if (r.granted) {
    const n = r.grants?.length ?? 1;
    return (
      <Notice kind="success">
        {r.to} is already in your organisation. They now have the access you chose ({n} project{n === 1 ? "" : "s"} or asset{n === 1 ? "" : "s"}).
      </Notice>
    );
  }
  const replaced = r.replaced?.length ? " It replaces their earlier invitation." : "";
  if (r.emailed) {
    return (
      <Notice kind="success">
        We emailed an invitation to {r.to}. The link works once, for 7 days.{replaced}
      </Notice>
    );
  }
  return (
    <div className="invite-link" role="status">
      <Notice kind="info">
        <strong>Send this link to {r.to}.</strong> It works once, for 7 days, and is shown only now.{replaced}
        {r.email_problem && <span className="hint"> Not emailed: {r.email_problem}.</span>}
      </Notice>
      {r.link && <CopyBox value={r.link} label={`Invitation link for ${r.to}`} />}
    </div>
  );
}

const INVITE_STATUS: Record<Invitation["status"], string> = {
  pending: "invited",
  accepted: "joined",
  revoked: "withdrawn",
  expired: "expired",
};

/**
 * Invitations of the organisation (or those naming projectId): who was
 * invited, to what, and whether they joined. Pending ones can be withdrawn.
 */
export function InvitationList({ projectId = 0, reloadKey }: { projectId?: number; reloadKey: number }) {
  const res = useLoad(() => api.getAll<List<Invitation>>("/invitations", projectId ? { project_id: projectId } : {}), [projectId, reloadKey]);
  const act = useAction();
  const list = res.data?.items ?? [];
  const revoke = async (i: Invitation) => {
    if (!(await confirmAction({ title: `Withdraw the invitation for ${i.email}?`, consequence: "Its link stops working.", action: "Withdraw invitation" }))) return;
    const ok = await act.run(() => api.del(`/invitations/${i.id}`).then(() => true));
    if (ok) res.reload();
  };
  if (list.length === 0) return <ErrorBox error={res.error} title="Could not load the invitations" />;
  return (
    <section className="invitations" aria-label="Invitations">
      <h3>Invitations</h3>
      <ErrorBox error={act.error ?? res.error} title="That did not work" />
      <ul className="project-list">
        {list.map((i) => {
          const stale = i.status === "pending" && i.grants.some((g) => !g.available);
          return (
            <li key={i.id}>
              <span className="grow">
                {i.email}{" "}
                <span className="small muted">
                  {invitationSummary(i)} · {INVITE_STATUS[i.status]}
                  {i.status === "pending" && <> · until {absTime(i.expires_at)}</>}
                </span>
                {stale && (
                  <span className="small hint-error">
                    {" "}
                    · {i.grants.filter((g) => !g.available).map((g) => `${g.name} was ${g.unavailable}`).join(", ")}; accepting skips {i.grants.every((g) => !g.available) ? "everything, so it is refused" : "it"}.
                  </span>
                )}
              </span>
              {i.status === "pending" && (
                <button type="button" className="btn btn-sm btn-link-danger" disabled={act.pending} onClick={() => void revoke(i)}>
                  Withdraw
                </button>
              )}
            </li>
          );
        })}
      </ul>
    </section>
  );
}
