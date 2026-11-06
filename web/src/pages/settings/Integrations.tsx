import { useEffect, useState } from "react";
import { Link, Navigate, useNavigate, useParams, useSearchParams } from "react-router";
import {
  api,
  loadNotificationOptions,
  NO_GITHUB_APP,
  NO_GITLAB,
  NO_NOTIFICATION_OPTIONS,
  type Asset,
  type Channel,
  type GitHubAppStatus,
  type GitLabStatus,
  type Integration,
  type List,
  type Queued,
  type Route,
} from "../../api";
import { useAuth } from "../../auth";
import { useProject } from "../../project";
import { useAction, useJobRunner, useLoad } from "../../hooks";
import { CodeBlock, ErrorBox, JobStatus, Loading, PageHeader } from "../../components/ui";
import { confirmAction } from "../../components/ConfirmDialog";
import { channelTarget, DeliveriesTab, kindLabel } from "./Notifications";
import { CloudConnectPanel } from "./CloudConnect";
import { ConnectGitLabButton, GitLabConnections } from "./GitLab";
import { CiTrusts } from "./CiTrusts";
import { GitHubInstallations, InstallOnGitHubButton } from "./GitHubApp";
import { ProjectChatAppsCard } from "../../components/ScopeNotifications";
import { PlanLimitNote } from "../../components/PlanLimit";
import { Catalogue, HealthSummary, IntegrationGrid, IntegrationIcon, StatusFilterBar, type CatalogueEntry } from "../../components/IntegrationCards";
import {
  connectedCounts,
  filterItems,
  parseFilter,
  receivesOf,
  scopeOf,
  sortItems,
  summarise,
  type HubItem,
  type StatusFilter,
} from "../../integrationHub";

/*
 * Integrations: everything Stackurity connects to. A health summary, then a
 * card per connected integration (alert channels, data sources, servers with
 * the agent), then the catalogue to add more. Notification integrations
 * (channels, with their trigger settings) open their own page; sources and
 * AI assistants link to their existing screens. The delivery log is its own
 * tab of the Integrations section.
 */

/** Kept here for older imports; the marks live in components/IntegrationCards.tsx. */
export { IntegrationIcon };

const SOURCE_LABEL: Record<string, string> = {
  git_repository: "Git repository",
  github_app: "GitHub repository (GitHub App)",
  gitlab: "GitLab project (Connect GitLab)",
  container_image: "Container image",
  container_registry: "Container registry",
  plugin: "Plugin",
};

function fromChannel(c: Channel, routes: Route[] | null, projects: { id: number; name: string }[]): HubItem {
  return {
    key: `ch${c.id}`,
    group: "alerts",
    kind: c.kind,
    name: c.name,
    kindLabel: kindLabel(c),
    target: channelTarget(c, undefined),
    targetMono: !(c.kind === "slack" && c.config?.slack_app) && !(c.kind === "teams" && c.config?.teams_app) && c.kind !== "stackurity_email",
    enabled: c.enabled,
    ok: c.last_ok_at,
    delivered: c.last_delivery_at,
    secretSource: c.secret_source,
    error: c.last_error,
    to: `/integrations/channels/${c.id}`,
    scope: scopeOf(c, projects),
    receives: routes ? receivesOf(c.id, routes) : undefined,
    channelId: c.id,
  };
}

function fromSource(i: Integration): HubItem {
  const plugin = i.kind === "plugin" ? String(i.config?.plugin ?? "") : "";
  return {
    key: `in${i.id}`,
    group: "sources",
    kind: plugin.startsWith("aws") || plugin.startsWith("gcp") || plugin.startsWith("azure") ? "cloud" : plugin.includes("kube") ? "kubernetes" : i.kind,
    name: i.name,
    kindLabel: plugin ? `Plugin: ${plugin}` : SOURCE_LABEL[i.kind] ?? i.kind,
    target: "",
    enabled: i.enabled,
    ok: i.last_success,
    error: i.last_error,
    to: "/integrations/sources",
    scope: { label: "Organisation" },
    sourceId: i.id,
  };
}

type Steps = "ci" | "sbom" | "gcp" | "azure";

const STEPS_HELP: Record<Steps, string> = { ci: "ci-keyless", sbom: "sbom", gcp: "google-cloud", azure: "azure" };

const STEPS_TITLE: Record<Steps, string> = {
  ci: "Scan in a CI pipeline",
  sbom: "Upload an SBOM",
  gcp: "Connect Google Cloud",
  azure: "Connect Azure",
};

const HOST_PAGE = 500;

/** "Servers with the agent" cards from GET /assets?kind=host; Windows apart when every host was read. */
function serverRows(res: List<Asset> | null | undefined): { items: HubItem[]; linux: number; windows: number } {
  if (!res || res.total === 0) return { items: [], linux: 0, windows: 0 };
  const newest = (xs: Asset[]) => xs.reduce<string | null>((m, a) => (a.last_seen && (!m || a.last_seen > m) ? a.last_seen : m), null);
  const row = (key: string, kind: string, name: string, n: number, xs: Asset[]): HubItem => ({
    key,
    group: "servers",
    kind,
    name,
    kindLabel: `${n} ${n === 1 ? "server" : "servers"}`,
    target: "",
    enabled: true,
    ok: newest(xs),
    error: "",
    to: "/assets?kind=host",
    scope: { label: "Organisation" },
  });
  const all = res.items;
  if (res.total > all.length) return { items: [row("hosts", "server", "Servers with the agent", res.total, all)], linux: res.total, windows: 0 };
  const win = all.filter((a) => a.attributes?.os === "windows");
  const other = all.filter((a) => a.attributes?.os !== "windows");
  const items: HubItem[] = [];
  if (other.length) items.push(row("hosts", "server", win.length ? "Linux servers with the agent" : "Servers with the agent", other.length, other));
  if (win.length) items.push(row("hosts-win", "windows", "Windows servers with the agent", win.length, win));
  return { items, linux: other.length, windows: win.length };
}

function CiPanel({ admin }: { admin: boolean }) {
  const origin = window.location.origin;
  const action = `- uses: stackurity/scan-action@v1
  with:
    server: ${origin}
    token: \${{ secrets.STACKURITY_TOKEN }}`;
  const cli = `STACKURITY_SERVER=${origin} STACKURITY_TOKEN=<token> \\
  stackurity scan . --git-url "$CI_REPOSITORY_URL" --environment production`;
  const gate = `stackurity scan . --git-url "$CI_REPOSITORY_URL" --fail-on critical --only-fixable`;
  return (
    <>
      <CiTrusts admin={admin} />
      <div className="int-panel">
        <p>
          <strong>With a stored token.</strong> For other CI systems, or where ID tokens cannot be used: create a collector token under{" "}
          <Link to="/integrations/tokens">Integrations → API tokens</Link> and save it as the CI secret <span className="mono">STACKURITY_TOKEN</span>. It can only send
          scans.
        </p>
        <CodeBlock text={action} label="GitHub Actions step with a token" />
        <CodeBlock text={cli} label="Scan command" />
        <p>
          <strong>Fail the pipeline</strong> on findings: it waits for the result and exits with status 3 when findings meet the threshold (4 when the result
          was not ready in time). <span className="mono">--fail-on-priority P1</span> and <span className="mono">--fail-on-kev</span> also work.
        </p>
        <CodeBlock text={gate} label="Scan with a gate" />
        <p className="small">
          <Link to="/help/ci-keyless">Scans in CI without a stored secret</Link> · <Link to="/help/repositories">More about repositories and CI</Link>
        </p>
      </div>
    </>
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
        From a script or CI, with a collector token from <Link to="/integrations/tokens">Integrations → API tokens</Link>:
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
  const { projects } = useProject();
  const navigate = useNavigate();
  const [params] = useSearchParams();
  const back = Number(params.get("channel")) || 0;
  const filter = parseFilter(params.get("status"));
  const channels = useLoad(() => (security ? api.get<List<Channel>>("/channels") : Promise.resolve(null)), [security]);
  const routes = useLoad(() => (security ? api.get<List<Route>>("/routes").catch(() => null) : Promise.resolve(null)), [security]);
  const sources = useLoad(() => (engineer ? api.get<List<Integration>>("/integrations") : Promise.resolve(null)), [engineer]);
  const hosts = useLoad(() => api.get<List<Asset>>("/assets", { kind: "host", limit: HOST_PAGE }), []);
  const optionsRes = useLoad(loadNotificationOptions, []);
  const gitlab = useLoad(() => (engineer ? api.get<GitLabStatus>("/integrations/gitlab").catch(() => NO_GITLAB) : Promise.resolve(NO_GITLAB)), [engineer]);
  const gl = gitlab.data ?? NO_GITLAB;
  const github = useLoad(
    () => (engineer ? api.get<GitHubAppStatus>("/integrations/github").catch(() => NO_GITHUB_APP) : Promise.resolve(NO_GITHUB_APP)),
    [engineer],
  );
  const gh = github.data ?? NO_GITHUB_APP;
  const options = optionsRes.data ?? NO_NOTIFICATION_OPTIONS;
  const act = useAction();
  const job = useJobRunner(sources.reload);
  const [tests, setTests] = useState<Record<string, { ok: boolean; error?: string } | null>>({});

  // Back from "Add to Slack": open the new integration.
  useEffect(() => {
    if (back) navigate(`/integrations/channels/${back}?added=1`, { replace: true });
  }, [back, navigate]);

  const servers = serverRows(hosts.data);
  const items: HubItem[] = sortItems([
    ...(channels.data?.items ?? []).map((c) => fromChannel(c, routes.data?.items ?? null, projects)),
    ...(sources.data?.items ?? []).map(fromSource),
    ...servers.items,
  ]);
  const summary = summarise(items);
  const shown = filterItems(items, filter);
  const counts = connectedCounts(channels.data?.items ?? [], sources.data?.items ?? [], servers);
  const hrefFor = (f: StatusFilter) => (f === "all" ? "/integrations#active" : `/integrations?status=${f}#active`);

  const sendTest = async (i: HubItem) => {
    if (!i.channelId) return;
    setTests((t) => ({ ...t, [i.key]: null }));
    const r = await act.run(() => api.post<{ ok: boolean; error?: string }>(`/channels/${i.channelId}/test`));
    if (r) {
      setTests((t) => ({ ...t, [i.key]: r }));
      channels.reload();
    }
  };
  const toggle = async (i: HubItem) => {
    const channel = i.group === "alerts";
    if (
      i.enabled &&
      !(await confirmAction({
        title: `Pause ${i.name}?`,
        consequence: channel ? "It stops sending until you resume it. Its rules are kept." : "It stops collecting until you resume it. Its assets are kept.",
        action: "Pause",
      }))
    )
      return;
    const path = channel ? `/channels/${i.channelId}` : `/integrations/${i.sourceId}`;
    const ok = await act.run(() => api.patch(path, { enabled: !i.enabled }).then(() => true));
    if (ok) (channel ? channels : sources).reload();
  };
  const runNow = (i: HubItem) => {
    if (i.sourceId) void job.start(`Run ${i.name}`, () => api.post<Queued>(`/integrations/${i.sourceId}/run`));
  };

  const groups: { title: string; description: string; cards: CatalogueEntry[] }[] = [];
  if (security) {
    const n: CatalogueEntry[] = [];
    if (options.platform_email.enabled)
      n.push({ kind: "stackurity_email", countKey: "stackurity_email", title: "Email (sent by Stackurity)", text: "Email to members and other addresses. Nothing to set up.", to: "/integrations/new/stackurity_email", admin: true });
    n.push(
      { kind: "email", countKey: "email", title: "Email (your mail server)", text: "Send through your own SMTP server: SES, SendGrid, Postmark, Gmail and more.", to: "/integrations/new/email", admin: true },
      {
        kind: "slack",
        countKey: "slack",
        title: "Slack",
        text: options.slack_app ? "Add to Slack in two clicks. Assign and snooze from inside Slack." : "Post to a Slack channel through an incoming webhook.",
        to: "/integrations/new/slack",
        admin: true,
      },
      {
        kind: "teams",
        countKey: "teams",
        title: "Microsoft Teams",
        text: options.teams_app ? "Add to Teams: add the app to a team and send it a code. No webhook." : "Post to a Teams channel through a Workflows webhook.",
        to: "/integrations/new/teams",
        admin: true,
      },
      { kind: "jira", countKey: "jira", title: "Jira", text: options.jira_app ? "Connect Jira in one click. One issue per incident, updated until it is fixed." : "Keep one Jira issue per incident, updated until it is fixed.", to: "/integrations/new/jira", admin: true },
      { kind: "pagerduty", countKey: "pagerduty", title: "PagerDuty", text: options.pagerduty_app ? "Connect PagerDuty in one click and pick the service. One alert per incident, acknowledged and resolved with it." : "Page on-call: one alert per incident, acknowledged and resolved with it.", to: "/integrations/new/pagerduty", admin: true },
      { kind: "servicenow", countKey: "servicenow", title: "ServiceNow", text: "Keep one ServiceNow incident per incident, with your field mapping.", to: "/integrations/new/servicenow", admin: true },
      { kind: "webhook", countKey: "webhook", title: "Webhook", text: "Send each message as JSON to your own HTTPS endpoint.", to: "/integrations/new/webhook", admin: true },
    );
    groups.push({ title: "Alerts and tickets", description: "Where Stackurity sends alerts, summaries and tickets. You choose what each one receives after connecting it.", cards: n });
  }
  groups.push({
    title: "Data sources",
    description: "What Stackurity reads to list your software: servers, code, images, clusters and cloud accounts. All read-only.",
    cards: [
      { kind: "server", countKey: "server", title: "Linux server", text: "A small read-only agent, installed with one command. First results in about 2 minutes.", to: "/assets/add", admin: true },
      { kind: "windows", countKey: "windows", title: "Windows server", text: "The same agent on Windows, run as a scheduled task. Reads installed programs.", to: "/assets/add", admin: true },
      ...(gh.configured
        ? [{ kind: "git", countKey: "github", title: "GitHub", text: "Install the Stackurity app and pick repositories. No token to paste; rescanned when a lockfile changes.", to: "", admin: true, button: <InstallOnGitHubButton /> }]
        : []),
      ...(gl.configured
        ? [{ kind: "git", countKey: "gitlab", title: "GitLab", text: "Pick a group: every project in it, subgroups included. No token to paste; rescanned when a lockfile changes.", to: "", admin: true, button: <ConnectGitLabButton /> }]
        : []),
      {
        kind: "git",
        countKey: "git",
        title: gh.configured || gl.configured ? "Other Git host" : "Git repository",
        text: "Clone any Git host over HTTPS with a read-only token, and read lockfiles on a schedule.",
        to: "/integrations/sources?add=git",
        admin: true,
      },
      { kind: "ci", title: "CI pipeline", text: "Run stackurity scan or the GitHub Action in CI, without a stored secret, and fail the build on findings.", to: "/integrations/setup/ci" },
      { kind: "container", countKey: "container", title: "Container image / registry", text: "Connect a registry and scan its newest tags, or add one image.", to: "/integrations/sources?add=container", admin: true },
      { kind: "kubernetes", countKey: "kubernetes", title: "Kubernetes cluster", text: "Workloads, the images they run and their exposure. One command installs a read-only reporter in the cluster.", to: "/integrations/kubernetes/add", admin: true },
      { kind: "cloud", countKey: "aws", title: "AWS", text: "Launch one CloudFormation stack: RDS, EKS, Lambda and more, and the agent on EC2 through SSM.", to: "/integrations/aws", admin: true },
      { kind: "cloud", countKey: "gcp", title: "Google Cloud", text: "Cloud SQL, Memorystore, GKE, Cloud Run and App Engine versions. Keyless: one gcloud block, no service account key.", to: "/integrations/setup/gcp", admin: true },
      { kind: "cloud", countKey: "azure", title: "Azure", text: "Azure Database, Cache for Redis, AKS, App Service and Functions versions. One consent and one az block, no secret in your tenant.", to: "/integrations/setup/azure", admin: true },
      { kind: "sbom", title: "SBOM upload", text: "Upload a CycloneDX or SPDX file from your build tool.", to: "/integrations/setup/sbom" },
      { kind: "plugin", countKey: "plugin", title: "Other plugins", text: "Collectors installed on this server.", to: "/integrations/plugins", admin: true },
    ],
  });
  groups.push({
    title: "AI assistants",
    description: "Ask about your issues and fixes from the assistant you already use.",
    cards: [{ kind: "ai", title: "AI assistants", text: "Ask about your issues and fixes from Claude, ChatGPT or your IDE.", to: "/integrations/ai-assistants" }],
  });

  // Older addresses: the delivery log was a tab of this page, and the
  // sources page (now Integrations, Sources) lived here.
  if (params.get("tab") === "deliveries") return <Navigate replace to="/integrations/deliveries" />;
  if (params.get("add")) return <Navigate replace to={`/integrations/sources?${params}`} />;

  const loading = (channels.loading || sources.loading) && items.length === 0;
  return (
    <>
      <PageHeader
        help="notifications"
        title="Integrations"
        sub="Everything Stackurity connects to: where alerts and tickets go, what it collects from, and AI assistants."
        actions={
          admin && (
            <a className="btn" href="#add">
              Add an integration
            </a>
          )
        }
      />
      <PlanLimitNote kind="channels" />
      <PlanLimitNote kind="alert_rules" />
      <ErrorBox error={channels.error} title="Could not load notification integrations" />
      <ErrorBox error={sources.error} title="Could not load sources" />
      <ErrorBox error={hosts.error} title="Could not load servers" />
      <ErrorBox error={act.error} title="Action failed" />
      <ErrorBox error={job.error} title="Could not start run" />
      <JobStatus state={job.state} onDismiss={job.reset} />
      {!loading && items.length > 0 && <HealthSummary summary={summary} failingTo={hrefFor("failing")} />}
      <div className="ix-head" id="active">
        <h2 className="h-sm">Active integrations</h2>
        {items.length > 0 && <StatusFilterBar summary={summary} value={filter} hrefFor={hrefFor} />}
      </div>
      {loading ? (
        <Loading />
      ) : items.length === 0 ? (
        <p className="muted">Nothing connected yet. Add an integration below.</p>
      ) : shown.length === 0 ? (
        <p className="muted">
          None of them is in this state. <Link to={hrefFor("all")}>Show all</Link>
        </p>
      ) : (
        <IntegrationGrid items={shown} actions={{ admin, busy: act.pending || job.busy, onTest: sendTest, onToggle: toggle, onRun: runNow }} testOf={(i) => tests[i.key]} />
      )}
      {security && <ProjectChatAppsCard admin={admin} />}
      <GitLabConnections status={gl} admin={admin} onChange={gitlab.reload} />
      <GitHubInstallations status={gh} admin={admin} onChange={github.reload} />
      <h2 className="h-sm" id="add">
        Add an integration
      </h2>
      <Catalogue groups={groups} counts={counts} admin={admin} />
    </>
  );
}


/** Integrations, set-up steps for a source that has no form of its own (CI, SBOM, Google Cloud, Azure). */
export function IntegrationStepsPage() {
  const { can } = useAuth();
  const admin = can("admin");
  const { steps } = useParams();
  if (!steps || !(steps in STEPS_TITLE)) return <Navigate replace to="/integrations" />;
  const s = steps as Steps;
  return (
    <>
      <p className="small">
        <Link to="/integrations">← Integrations</Link>
      </p>
      <PageHeader help={STEPS_HELP[s]} title={STEPS_TITLE[s]} />
      <section className="card">
        {s === "ci" ? <CiPanel admin={admin} /> : s === "sbom" ? <SbomPanel admin={admin} /> : <CloudConnectPanel provider={s} admin={admin} />}
      </section>
    </>
  );
}

/** Integrations, Delivery log: every message sent, held or failed (security role). */
export function DeliveryLogPage() {
  const { can } = useAuth();
  const channels = useLoad(() => api.get<List<Channel>>("/channels"), []);
  return (
    <>
      <PageHeader help="notifications" title="Delivery log" sub="Every message Stackurity sent, held or could not deliver, newest first." />
      <ErrorBox error={channels.error} title="Could not load notification integrations" />
      <DeliveriesTab channels={channels.data?.items ?? []} channelsLoaded={Boolean(channels.data)} admin={can("admin")} />
    </>
  );
}
