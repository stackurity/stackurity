import { useEffect, useMemo, useState, type ReactNode } from "react";
import { Link, useLocation } from "react-router";
import { api, ApiError, type AssistantConnection, type AssistantConsent, type List, type UserRole } from "../api";
import { useAuth } from "../auth";
import { useAction, useLoad } from "../hooks";
import { Card, CodeBlock, CopyBox, ErrorBox, Loading, Notice, PageHeader, RelativeTime, Tabs } from "../components/ui";

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
  // "Allow changes" is off until the person ticks it: the connection then
  // only reads, whatever the role.
  const [allowChanges, setAllowChanges] = useState(false);
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
    const r = await act.run(() => api.post<{ redirect: string }>("/oauth/authorize", {
        ...params,
        decision,
        workspace_id: pv?.workspace.id ?? 0,
        project_id: project,
        role,
        allow_changes: allowChanges,
      }),);
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
          <p className="hint">Never more than you can do yourself ({pv.your_role || "no role"}), now or later.</p>
        </div>
        <div className="field">
          <label>
            <input type="checkbox" checked={allowChanges} onChange={(e) => setAllowChanges(e.target.checked)} /> Allow changes
          </label>
          <p className="hint">
            {allowChanges
              ? "It may make changes your role allows, such as assigning or snoozing issues, creating projects or install codes. It previews each change first so it can check with you, but that preview is a safeguard against its mistakes, not a lock: you decide here, and you can turn this off any time in Connected assistants."
              : "Off: it can only read. Tick this only if you want it to make changes for you; you can change it later in Connected assistants."}{" "}
            Everything it does is in the activity log under your name.
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
          It stays connected until you disconnect it in <Link to="/settings/ai-assistants#connected">Connected assistants</Link>, or it is unused for{" "}
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

/** GET /assistants: the connections, and the address to add in an assistant ("" while assistants are off). */
interface AssistantList extends List<AssistantConnection> {
  mcp_url?: string;
}

type Client = "claude" | "chatgpt" | "cursor" | "vscode" | "claude-code" | "other";

const CLIENTS: { id: Client; label: string }[] = [
  { id: "claude", label: "Claude" },
  { id: "chatgpt", label: "ChatGPT" },
  { id: "cursor", label: "Cursor" },
  { id: "vscode", label: "VS Code" },
  { id: "claude-code", label: "Claude Code" },
  { id: "other", label: "Other" },
];

const SIGN_IN = "Sign in to Stackurity in the page that opens. Choose the organisation and what it can see (everything, or one project). Tick Allow changes only if it should make changes for you. Click Allow.";

function Steps({ children }: { children: ReactNode }) {
  return <ol className="assistant-steps">{children}</ol>;
}

/*
 * How each client adds a remote MCP server, checked against the vendors'
 * documentation on 2026-10-27:
 * - Claude: https://claude.com/docs/connectors/custom/remote-mcp and
 *   https://support.claude.com/en/articles/11175166-getting-started-with-custom-connectors-using-remote-mcp
 *   (Customize > Connectors > Add custom connector; Team and Enterprise
 *   owners add it under Organization settings > Connectors first).
 * - ChatGPT: https://developers.openai.com/api/docs/guides/custom-mcp-server and
 *   https://developers.openai.com/plugins/deploy/connect-chatgpt (Plugins >
 *   + > Add custom MCP server; OAuth with dynamic client registration when
 *   no client ID is given). The help centre article could not be read and
 *   menu names have changed often, so the steps say what to look for.
 * - Cursor: https://cursor.com/docs/context/mcp (mcpServers with "url";
 *   OAuth with dynamic client registration). How sign-in starts for a
 *   server added by hand is not documented, hence "If Cursor asks".
 * - VS Code: https://code.visualstudio.com/docs/copilot/reference/mcp-configuration and
 *   https://code.visualstudio.com/docs/copilot/chat/mcp-servers ("servers",
 *   "type": "http"; MCP: Add Server; a browser sign-in on first use).
 * - Claude Code: https://code.claude.com/docs/en/mcp (claude mcp add
 *   --transport http, then /mcp to sign in).
 */
function ClientSteps({ client, url }: { client: Client; url: string }) {
  switch (client) {
    case "claude":
      return (
        <>
          <p className="small muted">claude.ai and Claude Desktop</p>
          <Steps>
            <li>
              In Claude, open <strong>Customize</strong>, then <strong>Connectors</strong> (older versions: <strong>Settings</strong>,{" "}
              <strong>Connectors</strong>).
            </li>
            <li>
              Click <strong>Add custom connector</strong>. You may need to click <strong>+</strong> first.
            </li>
            <li>
              Name it Stackurity and paste the address above as the server URL. If Claude asks how to sign in, choose{" "}
              <strong>Register automatically</strong>, or leave the client ID and secret empty.
            </li>
            <li>
              Click <strong>Add</strong>, then <strong>Connect</strong>.
            </li>
            <li>{SIGN_IN}</li>
            <li>
              In a chat, click <strong>+</strong>, then <strong>Connectors</strong>, and turn Stackurity on.
            </li>
          </Steps>
          <p className="hint">
            On a Team or Enterprise plan, an owner adds it first under <strong>Organization settings</strong>, <strong>Connectors</strong>. Then
            everyone clicks <strong>Connect</strong> under Customize, Connectors. Claude connects from the internet, so this server must be
            reachable from it.
          </p>
        </>
      );
    case "chatgpt":
      return (
        <>
          <Steps>
            <li>
              In ChatGPT on the web, open <strong>Plugins</strong>, click <strong>+</strong>, then <strong>Add custom MCP server</strong>. If your
              ChatGPT has no Plugins page, go to <strong>Settings</strong>, <strong>Apps &amp; Connectors</strong>, turn on{" "}
              <strong>Developer mode</strong> under Advanced settings, and click <strong>Create</strong>.
            </li>
            <li>Name it Stackurity and paste the address above as the server URL.</li>
            <li>
              For authentication, choose <strong>OAuth</strong>. Leave the client ID and secret empty: Stackurity registers ChatGPT by itself.
            </li>
            <li>Accept the warning about custom servers, then create it.</li>
            <li>{SIGN_IN}</li>
          </Steps>
          <p className="hint">
            If your assistant asks for a transport, choose Streamable HTTP. Your plan, or your workspace admin, decides whether custom servers
            are allowed.
          </p>
        </>
      );
    case "cursor":
      return (
        <>
          <Steps>
            <li>
              Open <code>~/.cursor/mcp.json</code> (for all your projects) or <code>.cursor/mcp.json</code> in one project. Create it if it is
              not there.
            </li>
            <li>Add Stackurity to it and save:</li>
          </Steps>
          <CodeBlock label="Cursor mcp.json" text={JSON.stringify({ mcpServers: { stackurity: { url } } }, null, 2)} />
          <p className="hint">If Cursor asks you to sign in to Stackurity, do it, then click Allow. {SIGN_IN.split(". ").slice(1, 3).join(". ")}.</p>
        </>
      );
    case "vscode":
      return (
        <>
          <Steps>
            <li>
              Open the Command Palette and run <strong>MCP: Add Server</strong>. Choose <strong>HTTP</strong>, paste the address above and name it
              stackurity.
            </li>
            <li>
              Or add it to <code>.vscode/mcp.json</code> in your project:
            </li>
          </Steps>
          <CodeBlock label="VS Code mcp.json" text={JSON.stringify({ servers: { stackurity: { type: "http", url } } }, null, 2)} />
          <p className="hint">The first time Copilot uses it, VS Code opens Stackurity in your browser. {SIGN_IN.split(". ").slice(1).join(". ")}</p>
        </>
      );
    case "claude-code":
      return (
        <>
          <Steps>
            <li>Run this in a terminal:</li>
          </Steps>
          <CodeBlock label="Claude Code command" text={`claude mcp add --transport http stackurity ${url}`} />
          <Steps>
            <li>
              In Claude Code, type <code>/mcp</code>, choose stackurity and sign in.
            </li>
            <li>{SIGN_IN}</li>
          </Steps>
        </>
      );
    case "other":
      return <OtherClient url={url} />;
  }
}

/** Assistants that start a local program (stdio), or that use a token instead of signing in. */
function OtherClient({ url }: { url: string }) {
  const server = window.location.origin;
  const config = {
    mcpServers: {
      stackurity: {
        command: "stackurity",
        args: ["mcp"],
        env: { STACKURITY_SERVER: server, STACKURITY_TOKEN_FILE: "/home/me/.config/stackurity/token" },
      },
    },
  };
  return (
    <>
      {url && (
        <p>
          Most assistants that support remote MCP servers work like the others: add the address above and sign in when asked. If your assistant asks
          for a client ID, leave it empty.
        </p>
      )}
      <p>
        <strong>Assistants that start a program on your computer</strong> run <code>stackurity mcp</code>. It needs the{" "}
        <code>stackurity</code> program and a personal token:
      </p>
      <Steps>
        <li>
          Create a token under <Link to="/settings/tokens">Settings, API tokens</Link>, with the role the assistant should have (viewer for
          read only). Save it in a file only you can read.
        </li>
        <li>Add this to the assistant&apos;s MCP settings, with your token file:</li>
      </Steps>
      <CodeBlock label="MCP settings for stackurity mcp" text={JSON.stringify(config, null, 2)} />
      <p className="hint">
        It only reads unless you add <code>--allow-writes</code> to <code>args</code>. Add <code>&quot;--project&quot;, &quot;Shop&quot;</code> to limit it
        to one project.
      </p>
    </>
  );
}

/**
 * Settings, AI assistants: how to connect Claude, ChatGPT or an editor
 * (the MCP address and steps per client), and the signed-in person's
 * connected assistants in every organisation, with Allow changes and
 * Disconnect.
 */
export function AssistantsPage() {
  const res = useLoad(() => api.getAll<AssistantList>("/assistants"), []);
  const act = useAction();
  const [client, setClient] = useState<Client>("claude");
  const { hash } = useLocation();
  const disconnect = async (c: AssistantConnection) => {
    if (!window.confirm(`Disconnect ${c.client_name || "this assistant"}? It stops working at once; connect it again from the assistant to use it.`)) return;
    const ok = await act.run(() => api.del(`/assistants/${c.id}`).then(() => true));
    if (ok) res.reload();
  };
  const setChanges = async (c: AssistantConnection, allow: boolean) => {
    const ok = await act.run(() => api.patch(`/assistants/${c.id}`, { allow_changes: allow }).then(() => true));
    if (ok) res.reload();
  };
  useEffect(() => {
    if (hash === "#connected" && res.data) document.getElementById("connected")?.scrollIntoView();
  }, [hash, res.data]);
  const items = res.data?.items ?? [];
  const url = res.data?.mcp_url ?? "";
  const off = Boolean(res.data) && !url;
  const shown = off ? "other" : client;

  return (
    <>
      <PageHeader
        title="AI assistants"
        sub="Ask Claude, ChatGPT or your code editor what is installed, what is vulnerable and what to upgrade. It sees only what you allow."
      />
      <ErrorBox error={res.error ?? act.error} title="Could not load or change the connections" />
      {!res.data && !res.error && <Loading />}
      {res.data && (
        <Card title="Connect an assistant">
          {off ? (
            <Notice kind="warn">
              <strong>Assistants cannot sign in to this server yet.</strong> Whoever runs it has to set <code>STACKURITY_BASE_URL</code> to its
              public https:// address (for example <code>https://stackurity.example.com</code>) and restart it. The address to add in an assistant
              is then that address followed by <code>/mcp</code>. Until then, assistants that start a program on your computer work, as below.
            </Notice>
          ) : (
            <div className="field">
              <p className="assistant-url-label">
                <strong>The address to add in your assistant</strong>
              </p>
              <CopyBox value={url} label="MCP server address" />
              <p className="hint">Paste it where your assistant adds a custom connector or MCP server. Then sign in when it asks.</p>
            </div>
          )}
          {!off && <Tabs label="Assistant" tabs={CLIENTS} value={client} onChange={setClient} />}
          <div role={off ? undefined : "tabpanel"} id={`panel-${shown}`} aria-labelledby={off ? undefined : `tab-${shown}`} className="assistant-panel">
            <ClientSteps client={shown} url={url} />
          </div>
          <p className="small muted">
            Every change an assistant makes is checked against your role and recorded in the activity log under your name. More in{" "}
            <Link to="/help/ai-assistants">Help</Link>.
          </p>
        </Card>
      )}

      <h2 className="section-title" id="connected">
        Connected assistants
      </h2>
      <p className="small muted">Assistants you allowed to use Stackurity as you, in any of your organisations.</p>
      {res.data && items.length === 0 && <p className="muted">None yet. They appear here once you click Allow in Stackurity.</p>}
      {items.length > 0 && (
        <ul className="card slack-links">
          {items.map((c) => (
            <li key={c.id} className="slack-link-row">
              <div className="slack-link-who">
                <div className="break">
                  <strong>{c.client_name || "Assistant"}</strong> <span className="muted">({c.redirect_host})</span> in <strong>{c.workspace_name}</strong>
                  {c.project_name ? <>, project {c.project_name} only</> : null}, as {c.role}, {c.allow_changes ? "may make changes" : "read only"}
                </div>
                <div className="small muted">
                  Connected <RelativeTime iso={c.created_at} />, last used <RelativeTime iso={c.last_used_at} />
                </div>
              </div>
              <div>
                <label className="small">
                  <input type="checkbox" checked={c.allow_changes} onChange={(e) => void setChanges(c, e.target.checked)} disabled={act.pending} /> Allow
                  changes
                </label>{" "}
                <button type="button" className="btn btn-sm btn-link-danger" onClick={() => void disconnect(c)} disabled={act.pending}>
                  Disconnect
                </button>
              </div>
            </li>
          ))}
        </ul>
      )}
    </>
  );
}
