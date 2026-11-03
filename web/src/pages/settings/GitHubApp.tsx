import { api, type GitHubAppStatus, type GitHubInstallation } from "../../api";
import { useAction } from "../../hooks";
import { Badge } from "../../components/Badge";
import { confirmAction } from "../../components/ConfirmDialog";
import { ErrorBox, RelativeTime } from "../../components/ui";

/*
 * The Stackurity GitHub App ("Install on GitHub", docs/github-app.md):
 * the button on the Git repository card, and the connected GitHub accounts
 * under Integrations.
 */

/** Starts Install on GitHub: GitHub's install page, with a state bound to this person. */
export function InstallOnGitHubButton({ className = "btn btn-sm btn-primary" }: { className?: string }) {
  const act = useAction();
  const start = async () => {
    const r = await act.run(() => api.post<{ url: string }>("/integrations/github/install", { return_to: "/integrations" }));
    if (r?.url) window.location.assign(r.url);
  };
  return (
    <>
      <button type="button" className={className} onClick={() => void start()} disabled={act.pending}>
        {act.pending ? "Opening GitHub…" : "Install on GitHub"}
      </button>
      <ErrorBox error={act.error} title="Could not start Install on GitHub" />
    </>
  );
}

/** GitHub's settings page for one installation (where repositories are added or removed). */
export function installationSettingsURL(status: GitHubAppStatus, inst: GitHubInstallation): string | null {
  if (!status.app_url) return null;
  let origin: string;
  try {
    origin = new URL(status.app_url).origin;
  } catch {
    return null;
  }
  const login = encodeURIComponent(inst.account_login);
  return inst.account_type === "Organization"
    ? `${origin}/organizations/${login}/settings/installations/${inst.installation_id}`
    : `${origin}/settings/installations/${inst.installation_id}`;
}

const STATUS_LABEL: Record<string, string> = { active: "connected", suspended: "suspended on GitHub", deleted: "uninstalled on GitHub" };

export function GitHubInstallations({ status, admin, onChange }: { status: GitHubAppStatus; admin: boolean; onChange: () => void }) {
  const act = useAction();
  if (status.installations.length === 0) return null;
  const sync = async (i: GitHubInstallation) => {
    if (await act.run(() => api.post(`/integrations/github/installations/${i.installation_id}/sync`, {}))) onChange();
  };
  const disconnect = async (i: GitHubInstallation) => {
    const ok = await confirmAction({
      title: `Disconnect ${i.account_login} from GitHub?`,
      consequence:
        "Its repositories stop being scanned and the Stackurity app is uninstalled from that GitHub account. Assets, issues and history are kept. Install on GitHub again to resume.",
      action: "Disconnect",
      destructive: true,
      typeToConfirm: i.account_login,
    });
    if (!ok) return;
    if (await act.run(() => api.del(`/integrations/github/installations/${i.installation_id}`))) onChange();
  };
  return (
    <section className="card" aria-label="GitHub accounts">
      <div className="card-head">
        <h2>GitHub</h2>
      </div>
      <ErrorBox error={act.error} title="Could not change the GitHub connection" />
      <ul className="plain-list">
        {status.installations.map((i) => {
          const manage = installationSettingsURL(status, i);
          return (
            <li key={i.installation_id} className="int-gh-row">
              <div>
                <strong>{i.account_login || `Installation ${i.installation_id}`}</strong>{" "}
                <Badge status={i.status === "active" ? "ok" : "disabled"} label={STATUS_LABEL[i.status] ?? i.status} />
                <div className="muted small">
                  {i.repositories} {i.repositories === 1 ? "repository" : "repositories"}
                  {i.repository_selection === "all" ? " (all repositories)" : ""} · listed <RelativeTime iso={i.last_sync} />
                </div>
                {i.note && <div className="small text-warn-strong">{i.note}</div>}
              </div>
              {admin && (
                <div className="form-actions">
                  {manage && i.status !== "deleted" && (
                    <a className="btn btn-sm" href={manage} target="_blank" rel="noopener noreferrer">
                      Add or remove repositories
                    </a>
                  )}
                  {i.status === "active" && (
                    <button type="button" className="btn btn-sm" onClick={() => void sync(i)} disabled={act.pending}>
                      Sync
                    </button>
                  )}
                  <button type="button" className="btn btn-sm btn-danger" onClick={() => void disconnect(i)} disabled={act.pending}>
                    Disconnect
                  </button>
                </div>
              )}
            </li>
          );
        })}
      </ul>
    </section>
  );
}
