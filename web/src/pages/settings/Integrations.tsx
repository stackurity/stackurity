import { useEffect, type ReactNode } from "react";
import { Link, useNavigate, useSearchParams } from "react-router";
import { api, loadNotificationOptions, NO_NOTIFICATION_OPTIONS, type Channel, type Integration, type List } from "../../api";
import { useAuth } from "../../auth";
import { useLoad } from "../../hooks";
import { Badge } from "../../components/Badge";
import { Table, type Column } from "../../components/Table";
import { ErrorBox, Loading, PageHeader, RelativeTime, Tabs } from "../../components/ui";
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
  const optionsRes = useLoad(loadNotificationOptions, []);
  const options = optionsRes.data ?? NO_NOTIFICATION_OPTIONS;

  // Back from "Add to Slack": open the new integration.
  useEffect(() => {
    if (back) navigate(`/settings/integrations/channels/${back}?added=1`, { replace: true });
  }, [back, navigate]);

  const rows: Active[] = [...(channels.data?.items ?? []).map(fromChannel), ...(sources.data?.items ?? []).map(fromSource)];
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
    { key: "ok", header: "Last success", cell: (a) => <RelativeTime iso={a.ok} /> },
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
  if (engineer)
    groups.push({
      title: "Sources",
      cards: [
        { kind: "git", title: "Git repositories", text: "Clone over HTTPS and read lockfiles on a schedule.", to: "/integrations", admin: true },
        { kind: "container", title: "Container registries", text: "Pull images and list their OS and application packages.", to: "/integrations", admin: true },
        { kind: "kubernetes", title: "Kubernetes", text: "Workloads and images of a cluster, through a plugin.", to: "/integrations", admin: true },
        { kind: "cloud", title: "AWS", text: "Managed services (RDS, EKS, Lambda and more), through a plugin.", to: "/integrations", admin: true },
        { kind: "plugin", title: "Plugins", text: "Collectors installed on this server.", to: "/settings/plugins", admin: true },
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
                      {(!c.admin || admin) && (
                        <Link className="btn btn-sm" to={c.to}>
                          {c.to.startsWith("/settings/integrations/new/") ? "Add" : "Open"}
                        </Link>
                      )}
                    </li>
                  ))}
                </ul>
              </section>
            ))}
          </>
        )}
      </div>
    </>
  );
}
