import { useEffect, useMemo, useState } from "react";
import { Link } from "react-router";
import { api, ApiError, type AssistantConnection, type AssistantConsent, type List, type UserRole } from "../api";
import { useAuth } from "../auth";
import { useAction, useLoad } from "../hooks";
import { EmptyState, ErrorBox, Loading, Notice, PageHeader, RelativeTime } from "../components/ui";

const ROLE_ABOUT: Record<UserRole, string> = {
  viewer: "read only: inventory, issues, fixes and reports",
  engineer: "also assign issues, check fixes again and ask to ignore issues",
  security: "also snooze and ignore issues",
  admin: "also create projects, invite people and add servers",
};

/** The authorization request's parameters, as the assistant sent them. */
function requestParams(): Record<string, string> {
  const q = new URLSearchParams(window.location.search);
  const out: Record<string, string> = {};
  for (const k of ["response_type", "client_id", "redirect_uri", "code_challenge", "code_challenge_method", "state", "scope", "resource"]) {
    const v = q.get(k);
    if (v !== null) out[k] = v;
  }
  return out;
}

/**
 * /oauth/authorize: an AI assistant (Claude, ChatGPT, an IDE...) asks to
 * connect. The signed-in person sees who is asking and where the answer
 * goes, and chooses the organisation (the active one), optionally one
 * project, and a role no higher than their own. The server checks it all
 * again; the browser then goes back to the assistant.
 */
export function ConnectAssistantPage() {
  const { me, logout } = useAuth();
  const params = useMemo(requestParams, []);
  const [pv, setPv] = useState<AssistantConsent | null>(null);
  const [error, setError] = useState<ApiError | null>(null);
  const [project, setProject] = useState(0);
  const [role, setRole] = useState<UserRole>("viewer");
  const [leaving, setLeaving] = useState(false);
  const act = useAction();

  useEffect(() => {
    api
      .post<AssistantConsent>("/oauth/authorize/preview", params)
      .then((r) => {
        setPv(r);
        setError(null);
      })
      .catch((e) => setError(e as ApiError));
  }, [params]);

  const decide = async (decision: "allow" | "deny") => {
    const r = await act.run(() => api.post<{ redirect: string }>("/oauth/authorize", { ...params, decision, project_id: project, role }));
    if (r?.redirect) {
      setLeaving(true);
      window.location.assign(r.redirect);
    }
  };

  const switchTo = async (id: number) => {
    const ok = await act.run(() => api.post(`/workspaces/${id}/activate`).then(() => true));
    if (ok) window.location.reload();
  };

  let body;
  if (error) {
    // An error the assistant should hear about comes with its redirect.
    const redirect = typeof error.data?.redirect === "string" ? error.data.redirect : "";
    body = (
      <>
        <ErrorBox error={error} title="This connection request cannot be used" />
        <p className="hint">Start connecting again from your assistant. If it keeps failing, remove Stackurity from the assistant and add it again.</p>
        {redirect && (
          <a className="btn btn-block" href={redirect}>
            Back to the assistant
          </a>
        )}
      </>
    );
  } else if (!pv) {
    body = <Loading />;
  } else if (leaving) {
    body = <Notice kind="info">Returning to {pv.client.name || "the assistant"}…</Notice>;
  } else {
    const others = (me?.workspaces ?? []).filter((m) => m.workspace_id !== pv.workspace.id);
    body = (
      <>
        <p>
          <strong>{pv.client.name || "An assistant"}</strong> wants to use Stackurity as <strong>{pv.signed_in_as}</strong> in{" "}
          <strong>{pv.workspace.name}</strong>.
        </p>
        <p className="hint">
          It returns to <code>{pv.client.redirect_host}</code>
          {pv.client.metadata_document ? <> (identified by {pv.client.id})</> : null}. Only allow assistants you set up yourself.
        </p>
        {others.length > 0 && (
          <div className="field">
            <label htmlFor="assistant-org">Organisation</label>
            <select id="assistant-org" value={pv.workspace.id} onChange={(e) => void switchTo(Number(e.target.value))} disabled={act.pending}>
              <option value={pv.workspace.id}>{pv.workspace.name}</option>
              {others.map((m) => (
                <option key={m.workspace_id} value={m.workspace_id}>
                  {m.name}
                </option>
              ))}
            </select>
          </div>
        )}
        <div className="field">
          <label htmlFor="assistant-project">What it can see</label>
          <select id="assistant-project" value={project} onChange={(e) => setProject(Number(e.target.value))}>
            <option value={0}>{pv.access === "projects" ? "All my projects" : "The whole organisation"}</option>
            {pv.projects.map((p) => (
              <option key={p.id} value={p.id}>
                Project {p.name} only
              </option>
            ))}
          </select>
        </div>
        <div className="field">
          <label htmlFor="assistant-role">What it can do</label>
          <select id="assistant-role" value={role} onChange={(e) => setRole(e.target.value as UserRole)}>
            {pv.roles.map((r) => (
              <option key={r} value={r}>
                {r[0].toUpperCase() + r.slice(1)}: {ROLE_ABOUT[r]}
              </option>
            ))}
          </select>
          <p className="hint">
            Never more than you can do yourself ({pv.your_role || "no role"}), now or later. Before it changes anything it shows you what it will do and
            waits for you to agree. Everything it does is in the activity log under your name.
          </p>
        </div>
        <ErrorBox error={act.error} title="Could not connect" />
        <div className="slack-link-actions">
          <button type="button" className="btn btn-primary btn-block" onClick={() => void decide("allow")} disabled={act.pending} autoFocus>
            {act.pending ? "Connecting…" : "Allow"}
          </button>
          <button type="button" className="btn btn-block" onClick={() => void decide("deny")} disabled={act.pending}>
            Deny
          </button>
        </div>
        <p className="small muted">
          It stays connected until you disconnect it in <Link to="/settings/assistants">Connected assistants</Link>, or it is unused for{" "}
          {pv.idle_days} days. Not you?{" "}
          <button type="button" className="btn-link" onClick={() => void logout()}>
            Sign out
          </button>
        </p>
      </>
    );
  }

  return (
    <div className="center-screen">
      <div className="auth-card auth-card-wide accept-invite">
        <div className="auth-logo">
          <img src="/logo-login.png" alt="Stackurity" width={120} height={120} />
        </div>
        <h1 className="auth-title">Connect an assistant</h1>
        {body}
      </div>
    </div>
  );
}

/** Settings, Connected assistants: the signed-in person's own connections, in every organisation. */
export function AssistantsPage() {
  const res = useLoad(() => api.getAll<List<AssistantConnection>>("/assistants"), []);
  const act = useAction();
  const disconnect = async (c: AssistantConnection) => {
    if (!window.confirm(`Disconnect ${c.client_name || "this assistant"}? It stops working at once; connect it again from the assistant to use it.`)) return;
    const ok = await act.run(() => api.del(`/assistants/${c.id}`).then(() => true));
    if (ok) res.reload();
  };
  const items = res.data?.items ?? [];
  const mcpURL = `${window.location.origin}/mcp`;
  return (
    <>
      <PageHeader title="Connected assistants" sub="AI assistants you allowed to use Stackurity as you, in any of your organisations." />
      <ErrorBox error={res.error ?? act.error} title="Could not load or change the connections" />
      {!res.data && !res.error ? (
        <Loading />
      ) : items.length === 0 ? (
        <EmptyState title="No connected assistants">
          <p>
            To connect Claude, ChatGPT or another assistant, add <code>{mcpURL}</code> as a custom connector (MCP server) in the assistant and sign in when it asks.
          </p>
        </EmptyState>
      ) : (
        <ul className="card slack-links">
          {items.map((c) => (
            <li key={c.id} className="slack-link-row">
              <div className="slack-link-who">
                <div className="break">
                  <strong>{c.client_name || "Assistant"}</strong> <span className="muted">({c.redirect_host})</span> in <strong>{c.workspace_name}</strong>
                  {c.project_name ? <>, project {c.project_name} only</> : null}, as {c.role}
                </div>
                <div className="small muted">
                  Connected <RelativeTime iso={c.created_at} />, last used <RelativeTime iso={c.last_used_at} />
                </div>
              </div>
              <button type="button" className="btn btn-sm btn-link-danger" onClick={() => void disconnect(c)} disabled={act.pending}>
                Disconnect
              </button>
            </li>
          ))}
        </ul>
      )}
      <p className="hint">
        The address to add in an assistant is <code>{mcpURL}</code>. See <Link to="/help">Help</Link> or docs/ai-assistants.md.
      </p>
    </>
  );
}
