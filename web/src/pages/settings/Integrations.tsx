import { useEffect, useState, type ReactNode } from "react";
import { Link, useNavigate, useSearchParams } from "react-router";
import { api, loadNotificationOptions, NO_NOTIFICATION_OPTIONS, type Asset, type Channel, type Integration, type List } from "../../api";
import { useAuth } from "../../auth";
import { useLoad } from "../../hooks";
import { Badge } from "../../components/Badge";
import { Table, type Column } from "../../components/Table";
import { CodeBlock, ErrorBox, Loading, PageHeader, RelativeTime, Tabs } from "../../components/ui";
import { channelTarget, DeliveriesTab, KIND_LABEL } from "./Notifications";

/*
 * Settings, Integrations: everything Stackurity connects to. Notification
 * integrations (channels, with their trigger settings) open their own page;
 * sources and AI assistants link to their existing screens.
 */

/** Small line icons for integration kinds. */
export function IntegrationIcon({ kind }: { kind: string }) {
  const paths: Record<string, ReactNode> = {
    email: (
      <>
        <rect x="3" y="5" width="18" height="14" rx="2" />
        <path d="m3 7 9 6 9-6" />
      </>
    ),
    slack: <path d="M9 3 7 21M17 3l-2 18M4 9h17M3 15h17" />,
    teams: (
      <>
        <circle cx="9" cy="8" r="3" />
        <circle cx="17" cy="9" r="2" />
        <path d="M3 20c0-3.3 2.7-6 6-6s6 2.7 6 6M15 14.5c.6-.3 1.3-.5 2-.5 2.2 0 4 1.8 4 4" />
      </>
    ),
    webhook: <path d="M10 14a4 4 0 0 0 5.7 0l3-3a4 4 0 0 0-5.7-5.7l-1 1M14 10a4 4 0 0 0-5.7 0l-3 3a4 4 0 0 0 5.7 5.7l1-1" />,
    jira: <path d="M12 3 21 12l-9 9-9-9zM12 8l4 4-4 4-4-4z" />,
    git: (
      <>
        <circle cx="6" cy="5" r="2" />
        <circle cx="6" cy="19" r="2" />
        <circle cx="18" cy="8" r="2" />
        <path d="M6 7v10M18 10c0 4-6 3-11.5 7.5" />
      </>
    ),
    container: <path d="M12 3 20 7.5v9L12 21l-8-4.5v-9zM4 7.5l8 4.5 8-4.5M12 12v9" />,
    cloud: <path d="M7 18h10a4 4 0 0 0 .5-8A6 6 0 0 0 6 9a4.5 4.5 0 0 0 1 9z" />,
    kubernetes: (
      <>
        <path d="M12 2.5 20.5 7v10L12 21.5 3.5 17V7z" />
        <circle cx="12" cy="12" r="3" />
        <path d="M12 5.5V9M12 15v3.5M6.3 8.7 9.4 10.5M14.6 13.5l3.1 1.8M6.3 15.3l3.1-1.8M14.6 10.5l3.1-1.8" />
      </>
    ),
    plugin: <path d="M9 3v4M15 3v4M6 7h12v4a6 6 0 0 1-12 0zM12 17v4" />,
    server: (
      <>
        <rect x="3" y="4" width="18" height="7" rx="1.5" />
        <rect x="3" y="13" width="18" height="7" rx="1.5" />
        <path d="M7 7.5h.01M7 16.5h.01" />
      </>
    ),
    windows: <path d="M3 5.5 10.5 4.5v7H3zM12.5 4.2 21 3v8.5h-8.5zM3 12.5h7.5v7L3 18.5zM12.5 12.5H21V21l-8.5-1.2z" />,
    ci: <path d="M4 12a8 8 0 0 1 13.7-5.6L20 9M20 4v5h-5M20 12a8 8 0 0 1-13.7 5.6L4 15M4 20v-5h5" />,
    sbom: <path d="M7 3h7l5 5v13H7zM14 3v5h5M10 12h6M10 15.5h6M10 19h3" />,
    ai: <path d="M12 3l1.8 5.2L19 10l-5.2 1.8L12 17l-1.8-5.2L5 10l5.2-1.8zM19 16l.8 2.2L22 19l-2.2.8L19 22l-.8-2.2L16 19l2.2-.8z" />,
  };
  const key = kind === "stackurity_email" ? "email" : kind === "git_repository" ? "git" : kind === "container_image" ? "container" : kind;
  return (
    <span className="int-icon" aria-hidden="true">
      <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round">
        {paths[key] ?? paths.plugin}
      </svg>
    </span>
  );
}

interface Active {
  key: string;
  kind: string;
  name: string;
  kindLabel: string;
  target: string;
  enabled: boolean;
  ok: string | null;
  error: string;
  to: string;
}

const SOURCE_LABEL: Record<string, string> = { git_repository: "Git repository", container_image: "Container image", plugin: "Plugin" };

function fromChannel(c: Channel): Active {
  return {
    key: `ch${c.id}`,
    kind: c.kind,
    name: c.name,
    kindLabel: KIND_LABEL[c.kind] ?? c.kind,
    target: channelTarget(c, undefined),
    enabled: c.enabled,
    ok: c.last_ok_at,
    error: c.last_error,
    to: `/settings/integrations/channels/${c.id}`,
  };
}

function fromSource(i: Integration): Active {
  const plugin = i.kind === "plugin" ? String(i.config?.plugin ?? "") : "";
  return {
    key: `in${i.id}`,
    kind: plugin.startsWith("aws") ? "cloud" : plugin.includes("kube") ? "kubernetes" : i.kind,
    name: i.name,
    kindLabel: plugin ? `Plugin: ${plugin}` : SOURCE_LABEL[i.kind] ?? i.kind,
    target: "",
    enabled: i.enabled,
    ok: i.last_success,
    error: i.last_error,
    to: "/integrations",
  };
}

interface AddCard {
  kind: string;
  title: string;
  text: string;
  to: string;
  admin?: boolean;
  /** Short instructions shown on this page instead of a link. */
  panel?: "ci" | "sbom";
}

const HOST_PAGE = 500;

/** "Servers with the agent" rows from GET /assets?kind=host; Windows apart when every host was read. */
function serverRows(res: List<Asset> | null | undefined): Active[] {
  if (!res || res.total === 0) return [];
  const newest = (xs: Asset[]) => xs.reduce<string | null>((m, a) => (a.last_seen && (!m || a.last_seen > m) ? a.last_seen : m), null);
  const row = (key: string, kind: string, name: string, n: number, xs: Asset[]): Active => ({
    key,
    kind,
    name,
    kindLabel: `${n} ${n === 1 ? "server" : "servers"}`,
    target: "",
    enabled: true,
    ok: newest(xs),
    error: "",
    to: "/assets?kind=host",
  });
  const all = res.items;
  if (res.total > all.length) return [row("hosts", "server", "Servers with the agent", res.total, all)];
  const win = all.filter((a) => a.attributes?.os === "windows");
  const other = all.filter((a) => a.attributes?.os !== "windows");
  const rows: Active[] = [];
  if (other.length) rows.push(row("hosts", "server", win.length ? "Linux servers with the agent" : "Servers with the agent", other.length, other));
  if (win.length) rows.push(row("hosts-win", "windows", "Windows servers with the agent", win.length, win));
  return rows;
}

function CiPanel() {
  const origin = window.location.origin;
  const action = `- uses: stackurity/scan-action@v1
  with:
    server: ${origin}
    token: \${{ secrets.STACKURITY_TOKEN }}`;
  const cli = `STACKURITY_SERVER=${origin} STACKURITY_TOKEN=<token> \\
  stackurity scan . --git-url "$CI_REPOSITORY_URL" --environment production`;
  const gate = `stackurity scan . --git-url "$CI_REPOSITORY_URL" --fail-on critical --only-fixable`;
  return (
    <div className="int-panel">
      <p>
        <strong>1.</strong> Create a collector token under <Link to="/settings/tokens">Settings → API tokens</Link> and save it as the CI secret{" "}
        <span className="mono">STACKURITY_TOKEN</span>. It can only send scans.
      </p>
      <p>
        <strong>2. GitHub Actions:</strong> add this step after the checkout.
      </p>
      <CodeBlock text={action} label="GitHub Actions step" />
      <p>
        <strong>Other CI:</strong> run the scan in the repository.
      </p>
      <CodeBlock text={cli} label="Scan command" />
      <p>
        <strong>Fail the pipeline</strong> on findings: it waits for the result and exits with status 3 when findings meet the threshold (4 when the result
        was not ready in time). <span className="mono">--fail-on-priority P1</span> and <span className="mono">--fail-on-kev</span> also work.
      </p>
      <CodeBlock text={gate} label="Scan with a gate" />
      <p className="small">
        <Link to="/help/repositories">More about repositories and CI</Link>
      </p>
    </div>
  );
}

function SbomPanel({ admin }: { admin: boolean }) {
  const origin = window.location.origin;
  const cli = `STACKURITY_SERVER=${origin} STACKURITY_TOKEN=<token> \\
  stackurity sbom import image.cdx.json`;
  const curl = `curl -X POST -H "Authorization: Bearer <token>" -H "Content-Type: application/json" \\
  --data-binary @image.cdx.json \\
  "${origin}/api/v1/sbom/import?asset_name=shop-api&asset_kind=application"`;
  return (
    <div className="int-panel">
      <p>A CycloneDX or SPDX JSON file from your build tool. Each upload replaces that asset's inventory.</p>
      {admin && (
        <p>
          <Link className="btn btn-sm" to="/get-started?step=asset">
            Upload a file in the browser
          </Link>
        </p>
      )}
      <p>
        From a script or CI, with a collector token from <Link to="/settings/tokens">Settings → API tokens</Link>:
      </p>
      <CodeBlock text={cli} label="SBOM import command" />
      <p>Or with the API:</p>
      <CodeBlock text={curl} label="SBOM upload with curl" />
      <p className="small">
        Add <span className="mono">--project &lt;id&gt;</span> (or <span className="mono">project_id=</span>) to file it in a project. <Link to="/help/sbom">More about SBOMs</Link>
      </p>
    </div>
  );
}

export function IntegrationsHubPage() {
  const { can } = useAuth();
  const admin = can("admin");
  const security = can("security");
  const engineer = can("engineer");
  const navigate = useNavigate();
  const [params, setParams] = useSearchParams();
  const tab = params.get("tab") === "deliveries" && security ? "deliveries" : "all";
  const back = Number(params.get("channel")) || 0;
  const channels = useLoad(() => (security ? api.get<List<Channel>>("/channels") : Promise.resolve(null)), [security]);
  const sources = useLoad(() => (engineer ? api.get<List<Integration>>("/integrations") : Promise.resolve(null)), [engineer]);
  const hosts = useLoad(() => api.get<List<Asset>>("/assets", { kind: "host", limit: HOST_PAGE }), []);
  const [panel, setPanel] = useState<"ci" | "sbom" | null>(null);
  const optionsRes = useLoad(loadNotificationOptions, []);
  const options = optionsRes.data ?? NO_NOTIFICATION_OPTIONS;

  // Back from "Add to Slack": open the new integration.
  useEffect(() => {
    if (back) navigate(`/settings/integrations/channels/${back}?added=1`, { replace: true });
  }, [back, navigate]);

  const rows: Active[] = [
    ...serverRows(hosts.data),
    ...(sources.data?.items ?? []).map(fromSource),
    ...(channels.data?.items ?? []).map(fromChannel),
  ];
  const cols: Column<Active>[] = [
    {
      key: "name",
      header: "Integration",
      cell: (a) => (
        <div className="int-name">
          <IntegrationIcon kind={a.kind} />
          <div>
            <Link to={a.to}>
              <strong>{a.name}</strong>
            </Link>
            <div className="muted small">{a.kindLabel}</div>
            {a.target && <div className="mono small muted break">{a.target}</div>}
          </div>
        </div>
      ),
    },
    {
      key: "status",
      header: "Status",
      cell: (a) =>
        !a.enabled ? (
          <Badge status="disabled" />
        ) : a.error ? (
          <Badge status="failed" label="error" />
        ) : a.ok ? (
          <Badge status="ok" />
        ) : (
          <Badge status="untested" tone="warn" label="not used yet" />
        ),
    },
    { key: "ok", header: "Last success / report", cell: (a) => <RelativeTime iso={a.ok} /> },
    { key: "err", header: "Last error", cell: (a) => (a.error ? <span className="text-bad small break">{a.error}</span> : <span className="muted">—</span>) },
    {
      key: "gear",
      header: <span className="sr-only">Settings</span>,
      cell: (a) => (
        <Link className="btn btn-sm" to={a.to} aria-label={`Settings for ${a.name}`} title="Settings">
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" aria-hidden="true">
            <circle cx="12" cy="12" r="3" />
            <path d="M19.4 15a1.7 1.7 0 0 0 .3 1.8l.1.1a2 2 0 1 1-2.8 2.8l-.1-.1a1.7 1.7 0 0 0-1.8-.3 1.7 1.7 0 0 0-1 1.5V21a2 2 0 1 1-4 0v-.1a1.7 1.7 0 0 0-1.1-1.5 1.7 1.7 0 0 0-1.8.3l-.1.1a2 2 0 1 1-2.8-2.8l.1-.1a1.7 1.7 0 0 0 .3-1.8 1.7 1.7 0 0 0-1.5-1H3a2 2 0 1 1 0-4h.1a1.7 1.7 0 0 0 1.5-1.1 1.7 1.7 0 0 0-.3-1.8l-.1-.1a2 2 0 1 1 2.8-2.8l.1.1a1.7 1.7 0 0 0 1.8.3H9a1.7 1.7 0 0 0 1-1.5V3a2 2 0 1 1 4 0v.1a1.7 1.7 0 0 0 1 1.5 1.7 1.7 0 0 0 1.8-.3l.1-.1a2 2 0 1 1 2.8 2.8l-.1.1a1.7 1.7 0 0 0-.3 1.8V9a1.7 1.7 0 0 0 1.5 1H21a2 2 0 1 1 0 4h-.1a1.7 1.7 0 0 0-1.5 1z" />
          </svg>
        </Link>
      ),
    },
  ];

  const groups: { title: string; cards: AddCard[] }[] = [];
  if (security) {
    const n: AddCard[] = [];
    if (options.platform_email.enabled)
      n.push({ kind: "stackurity_email", title: "Email (sent by Stackurity)", text: "Email to members and other addresses. Nothing to set up.", to: "/settings/integrations/new/stackurity_email", admin: true });
    n.push(
      { kind: "email", title: "Email (your mail server)", text: "Send through your own SMTP server: SES, SendGrid, Postmark, Gmail and more.", to: "/settings/integrations/new/email", admin: true },
      {
        kind: "slack",
        title: "Slack",
        text: options.slack_app ? "Add to Slack in two clicks. Assign and snooze from inside Slack." : "Post to a Slack channel through an incoming webhook.",
        to: "/settings/integrations/new/slack",
        admin: true,
      },
      { kind: "teams", title: "Microsoft Teams", text: "Post to a Teams channel through a Workflows webhook.", to: "/settings/integrations/new/teams", admin: true },
      { kind: "jira", title: "Jira", text: "Keep one Jira issue per incident, updated until it is fixed.", to: "/settings/integrations/new/jira", admin: true },
      { kind: "webhook", title: "Webhook", text: "Send each message as JSON to your own HTTPS endpoint.", to: "/settings/integrations/new/webhook", admin: true },
    );
    groups.push({ title: "Notifications", cards: n });
  }
  groups.push({
    title: "Sources",
    cards: [
      { kind: "server", title: "Linux server", text: "A small read-only agent, installed with one command. First results in about 2 minutes.", to: "/assets/add", admin: true },
      { kind: "windows", title: "Windows server", text: "The same agent on Windows, run as a scheduled task. Reads installed programs.", to: "/assets/add", admin: true },
      { kind: "git", title: "Git repository", text: "Clone over HTTPS and read lockfiles on a schedule.", to: "/integrations", admin: true },
      { kind: "ci", title: "CI pipeline", text: "Run stackurity scan or the GitHub Action in CI, and fail the build on findings.", to: "", panel: "ci" },
      { kind: "container", title: "Container image / registry", text: "Pull images and list their OS and application packages.", to: "/integrations", admin: true },
      { kind: "kubernetes", title: "Kubernetes cluster", text: "Workloads and the images they run, through the Kubernetes plugin.", to: "/integrations", admin: true },
      { kind: "cloud", title: "AWS", text: "Managed services (RDS, EKS, Lambda and more), through the AWS plugin.", to: "/integrations", admin: true },
      { kind: "sbom", title: "SBOM upload", text: "Upload a CycloneDX or SPDX file from your build tool.", to: "", panel: "sbom" },
      { kind: "plugin", title: "Other plugins", text: "Collectors installed on this server.", to: "/settings/plugins", admin: true },
    ],
  });
  groups.push({
    title: "AI assistants",
    cards: [{ kind: "ai", title: "AI assistants", text: "Ask about your issues and fixes from Claude, ChatGPT or your IDE.", to: "/settings/ai-assistants" }],
  });

  return (
    <>
      <PageHeader help="notifications" title="Integrations" sub="Everything Stackurity connects to: where messages go, what it collects from, and AI assistants." />
      {security && (
        <Tabs<"all" | "deliveries">
          label="Integrations"
          value={tab}
          onChange={(x) => setParams(x === "all" ? {} : { tab: x }, { replace: true })}
          tabs={[
            { id: "all", label: "Integrations" },
            { id: "deliveries", label: "Delivery log" },
          ]}
        />
      )}
      <div role="tabpanel" id={`panel-${tab}`} aria-labelledby={security ? `tab-${tab}` : undefined} className="tabpanel">
        {tab === "deliveries" ? (
          <DeliveriesTab channels={channels.data?.items ?? []} admin={admin} />
        ) : (
          <>
            <h2 className="h-sm">Active integrations</h2>
            <ErrorBox error={channels.error} title="Could not load notification integrations" />
            <ErrorBox error={sources.error} title="Could not load sources" />
            <ErrorBox error={hosts.error} title="Could not load servers" />
            {(channels.loading || sources.loading) && rows.length === 0 ? (
              <Loading />
            ) : rows.length === 0 ? (
              <p className="muted">Nothing connected yet. Add an integration below.</p>
            ) : (
              <Table caption="Active integrations" columns={cols} rows={rows} rowKey={(a) => a.key} rowClassName={(a) => (!a.enabled ? "row-removed" : a.error ? "row-stale" : undefined)} />
            )}
            <h2 className="h-sm">Add an integration</h2>
            {groups.map((g) => (
              <section key={g.title} aria-label={g.title}>
                <h3 className="int-group">{g.title}</h3>
                <ul className="int-cards">
                  {g.cards.map((c) => (
                    <li key={c.title} className="int-card">
                      <div className="int-card-head">
                        <IntegrationIcon kind={c.kind} />
                        <strong>{c.title}</strong>
                      </div>
                      <p className="small muted">{c.text}</p>
                      {c.panel ? (
                        <button
                          type="button"
                          className="btn btn-sm"
                          aria-expanded={panel === c.panel}
                          aria-controls={`int-panel-${c.panel}`}
                          onClick={() => setPanel(panel === c.panel ? null : c.panel!)}
                        >
                          {panel === c.panel ? "Hide steps" : "Show steps"}
                        </button>
                      ) : (
                        (!c.admin || admin) && (
                          <Link className="btn btn-sm" to={c.to}>
                            {c.to.startsWith("/settings/integrations/new/") || c.to === "/assets/add" ? "Add" : "Open"}
                          </Link>
                        )
                      )}
                    </li>
                  ))}
                </ul>
                {g.title === "Sources" && panel && (
                  <section className="card" id={`int-panel-${panel}`} aria-label={panel === "ci" ? "CI pipeline" : "SBOM upload"}>
                    <div className="card-head">
                      <h2>{panel === "ci" ? "Scan in a CI pipeline" : "Upload an SBOM"}</h2>
                      <button type="button" className="btn btn-link" onClick={() => setPanel(null)}>
                        Close
                      </button>
                    </div>
                    {panel === "ci" ? <CiPanel /> : <SbomPanel admin={admin} />}
                  </section>
                )}
              </section>
            ))}
          </>
        )}
      </div>
    </>
  );
}
