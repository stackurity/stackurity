import { useEffect, useState, type FormEvent, type ReactNode } from "react";
import { Link } from "react-router";
import { api, type List } from "../../api";
import { useAction, useLoad } from "../../hooks";
import { Badge } from "../../components/Badge";
import { Table, type Column } from "../../components/Table";
import {
  Card,
  CardFooter,
  CheckCard,
  Code,
  CodeBlock,
  EmptyState,
  ErrorBox,
  KeyValues,
  Loading,
  Notice,
  PageHeader,
  RelativeTime,
  SettingRow,
} from "../../components/ui";
import { awsEmpty } from "../../emptyCopy";
import { confirmAction } from "../../components/ConfirmDialog";
import { GroupCrumb } from "../../components/nav";

/*
 * Integrations, AWS: connect an AWS account with the Stackurity
 * CloudFormation stack (internal/api/handlers_aws.go). Launch Stack opens
 * the console with everything filled in; the stack reports its role, or
 * the administrator pastes it. With agent installs allowed, EC2 instances
 * managed by SSM get the agent from here.
 */

export interface AwsConnection {
  id: number;
  external_id: string;
  regions: string[];
  agent_install: boolean;
  status: "pending" | "active" | "failed";
  role_arn: string;
  account_id: string;
  last_error: string;
  integration_id: number | null;
  integration_removed: boolean;
  callback_expires_at: string | null;
  callback_used_at: string | null;
  created_at: string;
  verified_at: string | null;
}

interface AwsSetup extends List<AwsConnection> {
  enabled: boolean;
  principal?: string;
  launch_stack?: boolean;
  template_download: string;
  permissions: string[];
  agent_install_permissions: string[];
}

interface AwsLaunch {
  quick_create_url: string;
  template_url: string;
  template_download: string;
  stack_name: string;
  stack_region: string;
  external_id: string;
  principal: string;
  callback: boolean;
  cli: string;
}

interface AwsInstance {
  instance_id: string;
  computer_name: string;
  platform_type: string;
  platform_name: string;
  ping_status: string;
  ip_address: string;
  eligible: boolean;
  asset_id: number | null;
  last_install: AwsInstall | null;
}

interface AwsInstall {
  id: number;
  region: string;
  instance_id: string;
  computer_name: string;
  status: "pending" | "running" | "success" | "failed" | "timed_out";
  detail: string;
  created_at: string;
  updated_at: string;
}

/** Regions offered in the pickers; any valid code can be typed too. */
export const AWS_REGIONS = [
  "us-east-1", "us-east-2", "us-west-1", "us-west-2", "ca-central-1", "sa-east-1",
  "eu-west-1", "eu-west-2", "eu-west-3", "eu-central-1", "eu-central-2", "eu-north-1", "eu-south-1", "eu-south-2",
  "ap-south-1", "ap-south-2", "ap-southeast-1", "ap-southeast-2", "ap-southeast-3", "ap-northeast-1", "ap-northeast-2", "ap-northeast-3",
  "ap-east-1", "me-central-1", "me-south-1", "af-south-1", "il-central-1",
];

const REGION_RE = /^[a-z]{2}(-gov)?-[a-z]+-\d$/;

/** Splits a typed region list ("eu-west-1, us-east-1") and reports bad codes. */
export function parseRegions(text: string): { regions: string[]; bad: string[] } {
  const parts = text
    .split(/[\s,]+/)
    .map((r) => r.trim())
    .filter(Boolean);
  const regions = [...new Set(parts.filter((r) => REGION_RE.test(r)))];
  return { regions, bad: parts.filter((r) => !REGION_RE.test(r)) };
}

const INSTALL_DONE = new Set(["success", "failed", "timed_out"]);

const STATUS_LABEL: Record<AwsConnection["status"], string> = { pending: "waiting for the stack", active: "connected", failed: "not verified" };

/**
 * Opens the console in a new tab. The tab is opened at the click, before the
 * link exists, so that a popup blocker allows it; it is closed if no link
 * comes back.
 */
async function openLaunch(make: () => Promise<AwsLaunch | undefined>) {
  const tab = window.open("", "_blank");
  const launch = await make();
  if (tab) {
    if (launch?.quick_create_url) {
      tab.opener = null;
      tab.location.href = launch.quick_create_url;
    } else tab.close();
  }
  return launch;
}

export function AwsPage() {
  const res = useLoad(() => api.get<AwsSetup>("/aws/connections"), []);
  const [launch, setLaunch] = useState<{ id: number; launch: AwsLaunch } | null>(null);
  const setup = res.data;
  const items = setup?.items ?? [];

  // Refresh while a stack is being created.
  const waiting = items.some((c) => c.status === "pending");
  useEffect(() => {
    if (!waiting) return;
    const t = setInterval(res.reload, 5000);
    return () => clearInterval(t);
  }, [waiting, res.reload]);

  return (
    <>
      <nav className="crumbs" aria-label="Breadcrumb">
        <GroupCrumb />
        <Link to="/integrations">Integrations</Link> <span aria-hidden="true">/</span> <span>AWS</span>
      </nav>
      <PageHeader
        help="cloud-plugins"
        title="AWS"
        sub="Connect an AWS account with one CloudFormation stack: a read-only role for RDS, Aurora, ElastiCache, EKS, Lambda and OpenSearch versions, and optionally agent installs on EC2 through SSM."
      />
      <ErrorBox error={res.error} title="Could not load AWS connections" />
      {!setup && !res.error && <Loading />}
      {setup && !setup.enabled && (
        <Notice kind="warn">
          Connecting AWS with a stack is not set up on this server: its operator sets <Code>STACKURITY_AWS_PRINCIPAL_ARN</Code> and AWS
          credentials (docs/install.md, "AWS managed services"). You can still add the AWS plugin with your own role or keys under{" "}
          <Link to="/integrations/sources">Integrations, Sources</Link>.
        </Notice>
      )}
      {setup?.enabled && (
        <ConnectForm
          setup={setup}
          onLaunched={(id, l) => {
            setLaunch({ id, launch: l });
            res.reload();
          }}
        />
      )}
      {launch && <LaunchDetails launch={launch.launch} onClose={() => setLaunch(null)} />}

      {setup && (
        <>
          <h2 className="section-title">Connected accounts</h2>
          {items.length === 0 ? (
            <EmptyState {...awsEmpty(setup.enabled)} />
          ) : (
            items.map((c) => (
              <ConnectionCard
                key={c.id}
                c={c}
                enabled={setup.enabled}
                onChange={res.reload}
                onLaunched={(l) => {
                  setLaunch({ id: c.id, launch: l });
                  res.reload();
                }}
              />
            ))
          )}
        </>
      )}
    </>
  );
}

function ConnectForm({ setup, onLaunched }: { setup: AwsSetup; onLaunched: (id: number, l: AwsLaunch) => void }) {
  const [regions, setRegions] = useState("eu-west-1");
  const [stackRegion, setStackRegion] = useState("");
  const [agent, setAgent] = useState(false);
  const act = useAction();
  const parsed = parseRegions(regions);
  const invalid = parsed.regions.length === 0 || parsed.bad.length > 0;

  const submit = async (ev: FormEvent) => {
    ev.preventDefault();
    if (invalid) return;
    const run = () =>
      act.run(() =>
        api.post<{ connection: AwsConnection; launch: AwsLaunch }>("/aws/connections", {
          regions: parsed.regions,
          stack_region: stackRegion || parsed.regions[0],
          agent_install: agent,
        }),
      );
    let id = 0;
    const l = setup.launch_stack
      ? await openLaunch(async () => {
          const r = await run();
          id = r?.connection.id ?? 0;
          return r?.launch;
        })
      : await run().then((r) => {
          id = r?.connection.id ?? 0;
          return r?.launch;
        });
    if (l) onLaunched(id, l);
  };

  return (
    <Card
      title="Connect an AWS account"
      description="Creates a read-only role in your AWS account with one CloudFormation stack. Stackurity then lists your managed databases, caches, clusters and functions, and their versions."
    >
      <form className="form" onSubmit={submit}>
        <ErrorBox error={act.error} title="Could not start the connection" />
        <SettingRow title="Regions to read" description="Where your resources run. Stackurity only looks in these regions.">
          <div className="field">
            <label className="sr-only" htmlFor="aws-regions">
              Regions to read
            </label>
            <input
              id="aws-regions"
              className="mono"
              list="aws-region-list"
              value={regions}
              onChange={(e) => setRegions(e.target.value)}
              aria-invalid={invalid}
              aria-describedby="aws-regions-hint"
            />
            <datalist id="aws-region-list">
              {AWS_REGIONS.map((r) => (
                <option key={r} value={r} />
              ))}
            </datalist>
            <p className="hint" id="aws-regions-hint">
              {parsed.bad.length > 0 ? `Not a region code: ${parsed.bad.join(", ")}` : "Comma-separated region codes, e.g. eu-west-1, us-east-1."}
            </p>
          </div>
        </SettingRow>
        <SettingRow title="Create the stack in" description="The role is global; the region only decides where the stack lives.">
          <div className="field">
            <label className="sr-only" htmlFor="aws-stack-region">
              Create the stack in
            </label>
            <select id="aws-stack-region" value={stackRegion} onChange={(e) => setStackRegion(e.target.value)}>
              <option value="">{parsed.regions[0] ?? "the first region"} (first region)</option>
              {AWS_REGIONS.map((r) => (
                <option key={r} value={r}>
                  {r}
                </option>
              ))}
            </select>
          </div>
        </SettingRow>
        <SettingRow title="Agent on EC2" description="Optional. Lets you install the server agent on your EC2 instances from Stackurity, without signing in to each one.">
          <CheckCard
            checked={agent}
            onChange={setAgent}
            label="Allow installing the agent on EC2 instances through SSM"
            description={
              <>
                Adds{" "}
                {setup.agent_install_permissions.map((p, i) => (
                  <span key={p}>
                    {i > 0 && ", "}
                    <Code>{p}</Code>
                  </span>
                ))}{" "}
                (Run Command with AWS-RunShellScript only). Off by default.
              </>
            }
          />
        </SettingRow>
        <details className="schema-help">
          <summary>What the role can do</summary>
          <p className="small">
            Read-only, exactly what the plugin calls:{" "}
            {setup.permissions.map((p, i) => (
              <span key={p}>
                {i > 0 && ", "}
                <Code>{p}</Code>
              </span>
            ))}
            . Only <Code>{setup.principal}</Code> can assume it, and only with this connection's external ID.{" "}
            <a href={setup.template_download} download>
              Download the template
            </a>{" "}
            to review it.
          </p>
        </details>
        <CardFooter status={setup.launch_stack ? "Next, you create the stack in AWS and come back here." : undefined}>
          <button type="submit" className="btn btn-primary" disabled={act.pending || invalid}>
            {setup.launch_stack ? "Launch Stack in AWS" : "Create the connection"}
          </button>
        </CardFooter>
      </form>
    </Card>
  );
}

function LaunchDetails({ launch, onClose }: { launch: AwsLaunch; onClose: () => void }) {
  return (
    <Card
      title="Create the stack"
      actions={
        <button type="button" className="btn btn-link" onClick={onClose}>
          Close
        </button>
      }
    >
      <div className="form">
        {launch.quick_create_url ? (
          <p>
            The AWS console opened in a new tab. Tick <em>I acknowledge that AWS CloudFormation might create IAM resources</em> and click{" "}
            <strong>Create stack</strong>.{" "}
            <a className="btn btn-sm" href={launch.quick_create_url} target="_blank" rel="noopener noreferrer">
              Open the AWS console again
            </a>
          </p>
        ) : (
          <p>
            This server has no S3-hosted template for a one-click link. <a href={launch.template_download} download>Download the template</a>{" "}
            and create the stack with the AWS CLI:
          </p>
        )}
        {!launch.quick_create_url && <CodeBlock text={launch.cli} label="AWS CLI command" />}
        <p className="small">
          {launch.callback
            ? "When the stack is created, it reports its role here and the account shows as connected below. If it does not within a few minutes, paste the role ARN from the stack's Outputs."
            : "This server cannot be reached from AWS over HTTPS, so paste the role ARN from the stack's Outputs (RoleArn) below once the stack is created."}
        </p>
        <KeyValues
          entries={[
            ["Stack name", <Code key="s">{launch.stack_name}</Code>],
            ["Stack region", launch.stack_region],
            ["External ID", <Code key="x">{launch.external_id}</Code>],
            ["Trusted principal", <Code key="p">{launch.principal}</Code>],
          ]}
        />
        {launch.quick_create_url && (
          <details className="schema-help">
            <summary>With the AWS CLI instead</summary>
            <p className="small">
              <a href={launch.template_download} download>
                Download the template
              </a>
              , then:
            </p>
            <CodeBlock text={launch.cli} label="AWS CLI command" />
          </details>
        )}
      </div>
    </Card>
  );
}

function ConnectionCard({ c, enabled, onChange, onLaunched }: { c: AwsConnection; enabled: boolean; onChange: () => void; onLaunched: (l: AwsLaunch) => void }) {
  const [arn, setArn] = useState("");
  const act = useAction();

  const verify = async (ev?: FormEvent) => {
    ev?.preventDefault();
    const r = await act.run(() => api.post<{ connection: AwsConnection }>(`/aws/connections/${c.id}/verify`, { role_arn: arn.trim() }));
    if (r) {
      setArn("");
      onChange();
    }
  };
  const relaunch = async () => {
    const l = await openLaunch(async () => {
      const r = await act.run(() =>
        api.post<{ launch: AwsLaunch }>(`/aws/connections/${c.id}/launch`, { stack_region: c.regions[0], agent_install: c.agent_install }),
      );
      return r?.launch;
    });
    if (l) onLaunched(l);
  };
  const remove = async () => {
    if (
      !(await confirmAction({
        title: `Remove the AWS connection${c.account_id ? ` to ${c.account_id}` : ""}?`,
        message: "Its integration is removed too; the assets it found stay until they are deleted.",
        consequence: "Delete the stack in the AWS console as well: Stackurity cannot remove the role.",
        action: "Remove connection",
        destructive: true,
      }))
    )
      return;
    const ok = await act.run(() => api.del(`/aws/connections/${c.id}`).then(() => true));
    if (ok) onChange();
  };

  return (
    <Card
      title={
        <>
          {c.account_id ? `AWS account ${c.account_id}` : `Connection ${c.id}`} <Badge status={c.status} label={STATUS_LABEL[c.status]} />
        </>
      }
      actions={
        <button type="button" className="btn btn-sm btn-link-danger" onClick={remove} disabled={act.pending}>
          Remove
        </button>
      }
    >
      <div className="form">
        <ErrorBox error={act.error} title="AWS connection" />
        <KeyValues
          entries={[
            ["Regions", c.regions.join(", ")],
            ["External ID", <Code key="x">{c.external_id}</Code>],
            ...(c.role_arn ? ([["Role", <Code key="r">{c.role_arn}</Code>]] as [string, ReactNode][]) : []),
            ["Agent installs", c.agent_install ? "allowed in the stack" : "not asked for"],
            [c.verified_at ? "Verified" : "Started", <RelativeTime key="t" iso={c.verified_at ?? c.created_at} />],
            ...(c.integration_id
              ? ([["Integration", <Link key="i" to="/integrations/sources">Runs every 12 hours</Link>]] as [string, ReactNode][])
              : []),
          ]}
        />
        {c.status === "pending" && !c.role_arn && (
          <p className="small muted" role="status">
            Waiting for the stack to report its role. This page refreshes by itself.
          </p>
        )}
        {c.last_error && (
          <Notice kind="warn">
            <strong>Not verified:</strong> {c.last_error}
          </Notice>
        )}
        {c.integration_removed && <Notice kind="warn">Its integration was deleted. Verify again to create it, or remove the connection.</Notice>}
        {enabled && c.status !== "active" && (
          <form className="aws-inline" onSubmit={verify}>
            <label htmlFor={`aws-arn-${c.id}`}>Paste the role ARN</label>
            <input
              id={`aws-arn-${c.id}`}
              className="mono"
              placeholder="arn:aws:iam::123456789012:role/Stackurity-…"
              value={arn}
              onChange={(e) => setArn(e.target.value)}
            />
            <button type="submit" className="btn btn-sm" disabled={act.pending || (!arn.trim() && !c.role_arn)}>
              {arn.trim() || !c.role_arn ? "Verify" : "Verify again"}
            </button>
            <button type="button" className="btn btn-sm btn-link" onClick={relaunch} disabled={act.pending}>
              New Launch Stack link
            </button>
          </form>
        )}
        {enabled && c.status === "active" && c.integration_removed && (
          <button type="button" className="btn btn-sm" onClick={() => verify()} disabled={act.pending}>
            Verify again
          </button>
        )}
        {enabled && c.status === "active" && <Instances c={c} />}
      </div>
    </Card>
  );
}

function Instances({ c }: { c: AwsConnection }) {
  const [open, setOpen] = useState(c.agent_install);
  const [region, setRegion] = useState(c.regions[0]);
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const list = useLoad(
    () => (open ? api.get<List<AwsInstance> & { truncated: boolean }>(`/aws/connections/${c.id}/instances`, { region }) : Promise.resolve(undefined)),
    [open, region, c.id],
  );
  const installs = useLoad(
    () => (open ? api.get<List<AwsInstall> & { refresh_error: string }>(`/aws/connections/${c.id}/installs`) : Promise.resolve(undefined)),
    [open, c.id],
  );
  const act = useAction();
  const running = (installs.data?.items ?? []).some((i) => !INSTALL_DONE.has(i.status));
  useEffect(() => {
    if (!running) return;
    const t = setInterval(installs.reload, 5000);
    return () => clearInterval(t);
  }, [running, installs.reload]);

  const rows = list.data?.items ?? [];
  const toggle = (id: string, on: boolean) =>
    setSelected((s) => {
      const n = new Set(s);
      if (on) n.add(id);
      else n.delete(id);
      return n;
    });
  const install = async () => {
    const chosen = rows.filter((r) => selected.has(r.instance_id));
    const r = await act.run(() =>
      api.post<List<AwsInstall>>(`/aws/connections/${c.id}/installs`, {
        region,
        instances: chosen.map((i) => ({ instance_id: i.instance_id, computer_name: i.computer_name })),
      }),
    );
    if (r) {
      setSelected(new Set());
      installs.reload();
      list.reload();
    }
  };

  const cols: Column<AwsInstance>[] = [
    {
      key: "pick",
      header: <span className="sr-only">Select</span>,
      cell: (i) => (
        <input
          type="checkbox"
          aria-label={`Install on ${i.computer_name || i.instance_id}`}
          disabled={!i.eligible}
          checked={selected.has(i.instance_id)}
          onChange={(e) => toggle(i.instance_id, e.target.checked)}
        />
      ),
    },
    {
      key: "name",
      header: "Instance",
      cell: (i) => (
        <>
          <strong>{i.computer_name || i.instance_id}</strong>
          <div className="muted small mono">{i.instance_id}</div>
        </>
      ),
    },
    { key: "os", header: "Platform", cell: (i) => i.platform_name || i.platform_type || <span className="muted">—</span> },
    { key: "ping", header: "SSM", cell: (i) => <Badge status={i.ping_status === "Online" ? "ok" : "stale"} label={i.ping_status || "unknown"} /> },
    {
      key: "agent",
      header: "Agent",
      cell: (i) =>
        i.asset_id ? (
          <Link to={`/assets/${i.asset_id}`}>reporting</Link>
        ) : i.last_install ? (
          <Badge status={i.last_install.status === "success" ? "ok" : i.last_install.status} label={i.last_install.status.replace("_", " ")} />
        ) : (
          <span className="muted">not installed</span>
        ),
    },
  ];
  const instCols: Column<AwsInstall>[] = [
    {
      key: "inst",
      header: "Instance",
      cell: (i) => (
        <>
          {i.computer_name || i.instance_id}
          <div className="muted small mono">
            {i.instance_id} · {i.region}
          </div>
        </>
      ),
    },
    { key: "status", header: "Result", cell: (i) => <Badge status={i.status === "success" ? "ok" : i.status} label={i.status.replace("_", " ")} /> },
    { key: "detail", header: "Output", cell: (i) => (i.detail ? <pre className="mono small break install-output">{i.detail}</pre> : <span className="muted">—</span>) },
    { key: "when", header: "Sent", cell: (i) => <RelativeTime iso={i.created_at} /> },
  ];

  if (!open) {
    return (
      <p className="small">
        <button type="button" className="btn btn-sm" onClick={() => setOpen(true)}>
          EC2 instances and the agent
        </button>{" "}
        <span className="muted">Needs the stack's agent install option.</span>
      </p>
    );
  }
  const notCovered = rows.filter((r) => !r.asset_id).length;
  return (
    <section aria-label="EC2 instances">
      <h3>EC2 instances managed by SSM</h3>
      <div className="aws-inline">
        <label htmlFor={`aws-ssm-region-${c.id}`}>Region</label>
        <select id={`aws-ssm-region-${c.id}`} value={region} onChange={(e) => setRegion(e.target.value)}>
          {c.regions.map((r) => (
            <option key={r}>{r}</option>
          ))}
        </select>
        <button type="button" className="btn btn-sm btn-link" onClick={list.reload} disabled={list.loading}>
          Refresh
        </button>
      </div>
      <ErrorBox error={list.error} title="Could not list instances (is agent install allowed in the stack?)" />
      {list.loading && !list.data && <Loading />}
      {list.data && rows.length === 0 && <p className="muted">SSM manages no instances in {region}.</p>}
      {rows.length > 0 && (
        <>
          <p className="small">
            {rows.length} instance{rows.length === 1 ? "" : "s"}, {notCovered} without the agent (matched by hostname).
            {list.data?.truncated && " Only the first 1,000 are shown."}
          </p>
          <Table caption={`EC2 instances in ${region}`} columns={cols} rows={rows} rowKey={(i) => i.instance_id} />
          <ErrorBox error={act.error} title="Could not send the install" />
          <div className="form-actions">
            <button type="button" className="btn btn-primary" onClick={install} disabled={act.pending || selected.size === 0 || selected.size > 25}>
              Install the agent on {selected.size} instance{selected.size === 1 ? "" : "s"}
            </button>
            <span className="hint">Each gets its own single-use install code. At most 25 at a time; Linux instances that are online.</span>
          </div>
        </>
      )}
      {(installs.data?.items.length ?? 0) > 0 && (
        <>
          <h3>Installs</h3>
          {installs.data?.refresh_error && <Notice kind="warn">Could not read results from SSM: {installs.data.refresh_error}</Notice>}
          <Table caption="Agent installs" columns={instCols} rows={installs.data?.items ?? []} rowKey={(i) => i.id} />
        </>
      )}
    </section>
  );
}
