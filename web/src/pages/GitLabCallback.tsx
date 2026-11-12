import { useEffect, useState, type ReactNode } from "react";
import { Link } from "react-router";
import { api, ApiError, type GitLabConnectResult, type GitLabOAuthResult } from "../api";
import { useAuth } from "../auth";
import { useAction } from "../hooks";
import { ErrorBox, Loading, Notice } from "../components/ui";
import { errorView } from "../errors";
import { AuthoriseReadOnlyButton, ConnectGitLabButton } from "./settings/GitLab";

/*
 * /integrations/gitlab/callback?code=…&state=…: GitLab sends the browser
 * here after every authorisation Stackurity starts (Connect GitLab, the
 * read-only authorisation, the cleanup). The state works once, so the
 * request runs once per state even when React runs effects twice
 * (StrictMode). For Connect GitLab the page then lists the person's groups
 * to pick from; the server checks the membership again with GitLab.
 */

const exchanges = new Map<string, Promise<GitLabOAuthResult>>();

const asApiError = (e: unknown) => (e instanceof ApiError ? e : new ApiError(0, "client", String(e)));

export function GitLabCallbackPage() {
  const { can, me } = useAuth();
  const projects = me?.projects ?? [];
  const [q] = useState(() => new URLSearchParams(window.location.search));
  const code = q.get("code") ?? "";
  const state = q.get("state") ?? "";
  const denied = q.get("error");
  const admin = can("admin");
  const [error, setError] = useState<ApiError | null>(null);
  const [result, setResult] = useState<GitLabOAuthResult | null>(null);
  const [group, setGroup] = useState<number | null>(null);
  // The Stackurity project the group's assets go into: the one last chosen
  // in the switcher, if any. Each connected group can have its own.
  const [project, setProject] = useState<number>(() => {
    const def = me?.default_project_id ?? 0;
    return (me?.projects ?? []).some((p) => p.id === def) ? def : 0;
  });
  const [connected, setConnected] = useState<GitLabConnectResult | null>(null);
  const pick = useAction();

  useEffect(() => {
    if (denied || !state || !admin) return;
    let p = exchanges.get(state);
    if (!p) {
      p = api.post<GitLabOAuthResult>("/integrations/gitlab/oauth", { state, code });
      exchanges.set(state, p);
    }
    let live = true;
    p.then((r) => live && setResult(r)).catch((e) => live && setError(asApiError(e)));
    return () => {
      live = false;
    };
  }, [state, code, denied, admin]);

  const connect = async () => {
    if (!result?.pick || group === null) return;
    const r = await pick.run(() => api.post<GitLabConnectResult>("/integrations/gitlab/connections", { pick: result.pick, group_id: group, project_id: project }));
    if (r) setConnected(r);
  };

  const back = (label: string) => (
    <div className="slack-link-actions">
      {admin ? <ConnectGitLabButton className="btn btn-primary btn-block" /> : null}
      <Link className="btn btn-block" to="/integrations">
        {label}
      </Link>
    </div>
  );
  const done = (
    <div className="form-actions">
      <Link className="btn btn-primary" to="/integrations">
        Back to integrations
      </Link>
    </div>
  );

  let title = "Connect GitLab";
  let body: ReactNode;
  if (!admin) {
    body = <Notice kind="warn">Only administrators can connect GitLab. Ask one to do it.</Notice>;
  } else if (denied) {
    body = (
      <>
        <Notice kind="info">
          {denied === "access_denied" ? "You cancelled on GitLab, so nothing changed." : `GitLab did not finish (${denied}). Nothing changed.`}
        </Notice>
        {back("Back to integrations")}
      </>
    );
  } else if (!state) {
    body = (
      <>
        <Notice kind="warn">GitLab came back without Stackurity&apos;s request, so nothing changed.</Notice>
        {back("Back to integrations")}
      </>
    );
  } else if (error) {
    body = (
      <>
        {error.code === "gitlab_state" ? (
          <Notice kind="warn">
            This GitLab request cannot be used: it was started by someone else or in another organisation, it was already used, or it is more than 10 minutes
            old. Nothing changed.
          </Notice>
        ) : error.status === 400 || error.status === 403 || error.status === 404 || error.status === 409 || error.status === 502 ? (
          <Notice kind="warn">{errorView(error).text}</Notice>
        ) : (
          <ErrorBox error={error} title="Could not finish at GitLab" />
        )}
        {back("Back to integrations")}
      </>
    );
  } else if (connected) {
    const c = connected.connection;
    body = (
      <>
        <Notice kind={connected.needs_readonly ? "info" : "success"}>
          {connected.needs_readonly
            ? `${c.group_path} is connected, but GitLab did not let Stackurity create a group access token. Authorise read-only access to finish: GitLab asks for read_api and read_repository only.`
            : `GitLab is connected: ${c.group_path}. Its projects are listed and scanned in the next few minutes.`}
        </Notice>
        {connected.notes
          .filter((n) => !connected.needs_readonly || !n.startsWith("GitLab did not allow a group access token"))
          .map((n) => (
            <p key={n} className="muted small">
              {n}
            </p>
          ))}
        {connected.needs_readonly ? (
          <div className="form-actions">
            <AuthoriseReadOnlyButton id={c.id} className="btn btn-primary" />
          </div>
        ) : (
          done
        )}
      </>
    );
  } else if (result?.pick && result.groups) {
    title = "Pick a GitLab group";
    body = (
      <>
        <p>
          Every project in the group you pick, subgroups included, is scanned. As the group&apos;s Owner, Stackurity creates a read-only group access token and
          a webhook there; otherwise it asks for read-only access next.
        </p>
        <fieldset className="plain-list">
          <legend className="sr-only">Group</legend>
          {result.groups.map((g) => (
            <label key={g.id} className="radio-row">
              <input type="radio" name="gitlab-group" value={g.id} checked={group === g.id} onChange={() => setGroup(g.id)} /> <strong>{g.full_path}</strong>
              {g.name && g.name !== g.full_path ? <span className="muted"> · {g.name}</span> : null}
              <span className="muted small"> · {g.owner ? "Owner" : "member"}</span>
            </label>
          ))}
        </fieldset>
        {projects.length > 0 && (
          <div className="field">
            <label htmlFor="gitlab-project">Add its assets to the Stackurity project</label>
            <select id="gitlab-project" value={project} onChange={(e) => setProject(Number(e.target.value))}>
              <option value={0}>No project</option>
              {projects.map((p) => (
                <option key={p.id} value={p.id}>
                  {p.name}
                </option>
              ))}
            </select>
            <p className="muted small">
              Connect each group with its own project. Assets in no project are seen only by people with an organisation-wide role; you can choose a project
              later under Integrations.
            </p>
          </div>
        )}
        <ErrorBox error={pick.error} title="Could not connect the group" />
        <div className="form-actions">
          <button type="button" className="btn btn-primary" onClick={() => void connect()} disabled={group === null || pick.pending}>
            {pick.pending ? "Connecting…" : "Connect this group"}
          </button>
          <Link className="btn" to="/integrations">
            Cancel
          </Link>
        </div>
      </>
    );
  } else if (result?.disconnected) {
    title = "GitLab disconnected";
    body = (
      <>
        <Notice kind={result.webhook_deleted && result.token_revoked ? "success" : "warn"}>
          {result.webhook_deleted && result.token_revoked
            ? "The group is disconnected, and Stackurity's webhook and token were deleted on GitLab."
            : "The group is disconnected here, but GitLab did not let Stackurity delete everything there. A group Owner can delete the Stackurity webhook (Settings ▸ Webhooks) and access token (Settings ▸ Access tokens)."}
        </Notice>
        {done}
      </>
    );
  } else if (result?.connection) {
    body = (
      <>
        <Notice kind="success">Read-only access is set up for {result.connection.group_path}. Its projects are listed and scanned in the next few minutes.</Notice>
        {done}
      </>
    );
  } else {
    body = <Loading label="Finishing at GitLab…" />;
  }

  return (
    <div className="center-screen">
      <div className="auth-card auth-card-wide">
        <div className="auth-logo">
          <img src="/logo-login.png" alt="Stackurity" width={120} height={120} />
        </div>
        <h1 className="auth-title">{title}</h1>
        {body}
      </div>
    </div>
  );
}
