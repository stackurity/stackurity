import { api, type GitLabConnection, type GitLabStatus } from "../../api";
import { startGitLab } from "../../integrationStart";
import { useAction } from "../../hooks";
import { Badge } from "../../components/Badge";
import { confirmAction } from "../../components/ConfirmDialog";
import { ErrorBox, RelativeTime } from "../../components/ui";
import { useProject } from "../../project";

/*
 * Connect GitLab (docs/gitlab.md): the button on the Git repository card,
 * and the connected GitLab groups under Integrations.
 */

/** Sends the browser to GitLab's consent page for an authorisation Stackurity started (integrationStart.ts). */
const goToGitLab = (path: string, body: Record<string, unknown>) => startGitLab(path, body);

/** Starts Connect GitLab. */
export function ConnectGitLabButton({ className = "btn btn-sm btn-primary" }: { className?: string }) {
  const act = useAction();
  return (
    <>
      <button type="button" className={className} onClick={() => void act.run(() => goToGitLab("/integrations/gitlab/connect", {}))} disabled={act.pending}>
        {act.pending ? "Opening GitLab…" : "Connect GitLab"}
      </button>
      <ErrorBox error={act.error} title="Could not start Connect GitLab" />
    </>
  );
}

/** Starts the read-only authorisation of a connection without a group access token. */
export function AuthoriseReadOnlyButton({ id, className = "btn btn-sm btn-primary" }: { id: number; className?: string }) {
  const act = useAction();
  return (
    <>
      <button
        type="button"
        className={className}
        onClick={() => void act.run(() => goToGitLab(`/integrations/gitlab/connections/${id}/authorize`, { purpose: "readonly" }))}
        disabled={act.pending}
      >
        {act.pending ? "Opening GitLab…" : "Authorise read-only access"}
      </button>
      <ErrorBox error={act.error} title="Could not start the authorisation" />
    </>
  );
}

const STATUS_LABEL: Record<string, string> = { active: "connected", needs_credential: "needs read-only access", expired: "connect again" };

function credentialText(c: GitLabConnection): string {
  if (c.credential_kind === "group_token") {
    return c.credential_expires ? `group access token until ${new Date(c.credential_expires).toLocaleDateString()}` : "group access token";
  }
  if (c.credential_kind === "oauth") return "read-only authorisation";
  return "no credential yet";
}

export function GitLabConnections({ status, admin, onChange }: { status: GitLabStatus; admin: boolean; onChange: () => void }) {
  const act = useAction();
  const { projects } = useProject();
  if (status.connections.length === 0) return null;
  const projectName = (id: number | null) => (id ? (projects.find((p) => p.id === id)?.name ?? `project ${id}`) : "");
  const chooseProject = async (c: GitLabConnection, id: number) => {
    if (await act.run(() => api.patch(`/integrations/gitlab/connections/${c.id}`, { project_id: id }))) onChange();
  };
  const sync = async (c: GitLabConnection) => {
    if (await act.run(() => api.post(`/integrations/gitlab/connections/${c.id}/sync`, {}))) onChange();
  };
  const cleanUp = async (c: GitLabConnection) => {
    const ok = await confirmAction({
      title: `Disconnect ${c.group_path} and clean up on GitLab?`,
      consequence:
        "GitLab asks you to authorise once more; Stackurity then deletes its webhook and group access token there. Its projects stop being scanned; assets, issues and history are kept.",
      action: "Continue on GitLab",
      destructive: true,
      typeToConfirm: c.group_path,
    });
    if (ok) await act.run(() => goToGitLab(`/integrations/gitlab/connections/${c.id}/authorize`, { purpose: "cleanup" }));
  };
  const removeHere = async (c: GitLabConnection) => {
    const ok = await confirmAction({
      title: `Remove ${c.group_path} from Stackurity only?`,
      consequence:
        c.webhook === "active"
          ? "Its projects stop being scanned and Stackurity's credential is revoked. The webhook stays on GitLab until a group Owner deletes it (Settings ▸ Webhooks); its deliveries are refused. Assets, issues and history are kept."
          : "Its projects stop being scanned and Stackurity's credential is revoked. Assets, issues and history are kept.",
      action: "Remove",
      destructive: true,
      typeToConfirm: c.group_path,
    });
    if (ok && (await act.run(() => api.del(`/integrations/gitlab/connections/${c.id}`)))) onChange();
  };
  return (
    <section className="card" aria-label="GitLab groups">
      <div className="card-head">
        <h2>GitLab</h2>
      </div>
      <ErrorBox error={act.error} title="Could not change the GitLab connection" />
      <ul className="plain-list">
        {status.connections.map((c) => (
          <li key={c.id} className="int-gl-row">
            <div>
              <strong>{c.group_path}</strong> <Badge status={c.status === "active" ? "ok" : "disabled"} label={STATUS_LABEL[c.status] ?? c.status} />
              <div className="muted small">
                {c.projects} {c.projects === 1 ? "project" : "projects"} · {credentialText(c)} ·{" "}
                {c.webhook === "active" ? "rescanned on push" : "scanned on the schedule only (no webhook)"} · listed <RelativeTime iso={c.last_sync} />
              </div>
              {c.note && <div className="small text-warn-strong">{c.note}</div>}
              {projects.length > 0 &&
                (admin ? (
                  <label className="small">
                    Assets go into{" "}
                    <select
                      aria-label={`Stackurity project for ${c.group_path}`}
                      value={c.project_id ?? 0}
                      onChange={(e) => void chooseProject(c, Number(e.target.value))}
                      disabled={act.pending}
                    >
                      <option value={0}>no project</option>
                      {projects.map((p) => (
                        <option key={p.id} value={p.id}>
                          {p.name}
                        </option>
                      ))}
                    </select>{" "}
                    <span className="muted">(choosing one also adds this group&apos;s assets that are in no project)</span>
                  </label>
                ) : (
                  <div className="muted small">{c.project_id ? `Assets go into ${projectName(c.project_id)}` : "Assets go into no project"}</div>
                ))}
            </div>
            {admin && (
              <div className="form-actions">
                {c.status === "needs_credential" && <AuthoriseReadOnlyButton id={c.id} />}
                {c.status === "expired" && <ConnectGitLabButton className="btn btn-sm" />}
                {c.status === "active" && (
                  <button type="button" className="btn btn-sm" onClick={() => void sync(c)} disabled={act.pending}>
                    Sync
                  </button>
                )}
                <button type="button" className="btn btn-sm btn-link-danger" onClick={() => void cleanUp(c)} disabled={act.pending}>
                  Disconnect
                </button>
                <button type="button" className="btn btn-sm" onClick={() => void removeHere(c)} disabled={act.pending}>
                  Remove here only
                </button>
              </div>
            )}
          </li>
        ))}
      </ul>
    </section>
  );
}
