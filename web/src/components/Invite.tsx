import { useState, type FormEvent } from "react";
import { api, type InvitationCreated, type UserRole } from "../api";
import { useAction } from "../hooks";
import { CopyBox, ErrorBox, Notice } from "./ui";
import { PERMISSIONS, ROLE_HELP, SPECIFIC_ROLES } from "../roles";
import { PermissionsDisclosure } from "./Permissions";

export { ROLE_HELP };

/**
 * Invite someone by email with a role on a project (or on the whole
 * organisation when projectId is 0). The link is emailed when the
 * organisation has an email channel; otherwise it is shown once to copy.
 */
export function InviteForm({ projectId, projectName, onInvited }: { projectId: number; projectName?: string; onInvited?: () => void }) {
  const [email, setEmail] = useState("");
  const [role, setRole] = useState<UserRole>("engineer");
  const [done, setDone] = useState<(InvitationCreated & { to: string }) | null>(null);
  const act = useAction();

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    const to = email.trim();
    const r = await act.run(() => api.post<InvitationCreated>("/invitations", { email: to, role, project_id: projectId }));
    if (r) {
      setDone({ ...r, to });
      setEmail("");
      onInvited?.();
    }
  };

  return (
    <div className="invite">
      <form className="form invite-form" onSubmit={submit} aria-label="Invite someone">
        <ErrorBox error={act.error} title="Could not invite" />
        <div className="field">
          <label htmlFor="inv-email">Email</label>
          <input id="inv-email" type="email" required autoComplete="off" value={email} onChange={(e) => setEmail(e.target.value)} placeholder="name@example.com" />
        </div>
        <fieldset className="field">
          <legend>Role{projectName ? ` on ${projectName}` : ""}</legend>
          <ul className="choice-list">
            {PERMISSIONS.filter((p) => projectId === 0 || SPECIFIC_ROLES.includes(p.role)).map(({ role: r, label }) => (
              <li key={r}>
                <label className="choice">
                  <input type="radio" name="inv-role" value={r} checked={role === r} onChange={() => setRole(r)} />
                  <span>
                    <strong>{label}</strong>
                    <span className="hint"> {ROLE_HELP[r]}</span>
                  </span>
                </label>
              </li>
            ))}
          </ul>
        </fieldset>
        <PermissionsDisclosure />
        <div className="form-actions">
          <button type="submit" className="btn btn-primary" disabled={act.pending || !email.trim()}>
            {act.pending ? "Inviting…" : "Invite"}
          </button>
        </div>
      </form>
      {done && <InviteResult r={done} />}
    </div>
  );
}

function InviteResult({ r }: { r: InvitationCreated & { to: string } }) {
  if (r.granted) {
    return (
      <Notice kind="success">
        {r.to} is already in your organisation. They now have the {r.grant?.role} role on this project.
      </Notice>
    );
  }
  if (r.emailed) {
    return (
      <Notice kind="success">
        We emailed an invitation to {r.to}. The link works once, for 7 days.
      </Notice>
    );
  }
  return (
    <div className="invite-link" role="status">
      <Notice kind="info">
        <strong>Send this link to {r.to}.</strong> It works once, for 7 days, and is shown only now.
        {r.email_problem && <span className="hint"> Not emailed: {r.email_problem}.</span>}
      </Notice>
      {r.link && <CopyBox value={r.link} label={`Invitation link for ${r.to}`} />}
    </div>
  );
}
