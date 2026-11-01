import { useMemo, useState, type FormEvent, type ReactNode } from "react";
import { Link, useSearchParams } from "react-router";
import {
  api,
  ApiError,
  type InstalledPlugin,
  type Integration,
  type IntegrationKind,
  type List,
  type PluginConfigField,
  type PluginList,
  type Queued,
  type ContainerRegistryConfig,
  type RegistryDiscovery,
  type RegistryImage,
  type RegistryProvider,
} from "../api";
import { useAuth } from "../auth";
import { useAction, useJobRunner, useLoad } from "../hooks";
import { minutesLabel } from "../format";
import { Badge } from "../components/Badge";
import { Table, type Column } from "../components/Table";
import { Card, Code, EmptyState, ErrorBox, JobStatus, Loading, Notice, PageHeader, RelativeTime } from "../components/ui";
import { confirmAction } from "../components/ConfirmDialog";

function healthOf(i: Integration): { status: string; tone?: "good" | "bad" | "muted" | "warn" } {
  if (!i.enabled) return { status: "disabled", tone: "muted" };
  if (i.last_error) return { status: "failed" };
  if (!i.last_attempt) return { status: "pending" };
  return { status: "ok" };
}

const KIND_LABEL: Record<string, string> = {
  git_repository: "Git repository",
  container_image: "Container image",
  container_registry: "Container registry",
  plugin: "Plugin",
};

const PROVIDER_LABEL: Record<RegistryProvider, string> = {
  ghcr: "GitHub Container Registry",
  dockerhub: "Docker Hub",
  ecr: "Amazon ECR",
  oci: "Other registry",
};

function KindBadge({ kind }: { kind: string }) {
  return <Badge status={kind} tone="info" label={KIND_LABEL[kind] ?? kind} />;
}

function targetOf(i: Integration): ReactNode {
  const c = i.config ?? {};
  if (i.kind === "git_repository") return `${c.url ?? ""}${c.ref ? ` @ ${c.ref}` : ""}`;
  if (i.kind === "container_image") return `${c.image ?? ""}${c.platform ? ` (${c.platform})` : ""}`;
  if (i.kind === "container_registry") {
    const p = (c.provider ?? "oci") as RegistryProvider;
    const where = p === "oci" ? c.url : p === "ecr" ? `${c.account_id ? `${c.account_id} ` : ""}${c.region ?? ""}` : c.namespace;
    const repos = c.repositories?.length ? ` · ${c.repositories.length} repositories` : "";
    const tags = `${c.recent_tags ?? 1} newest${c.tag_patterns?.length ? ` + ${c.tag_patterns.join(", ")}` : ""}`;
    return `${PROVIDER_LABEL[p] ?? p}: ${where ?? ""}${repos} · ${tags}`;
  }
  if (i.kind === "plugin") {
    const pc = c.config ?? {};
    const regions = Array.isArray(pc.regions) ? ` · ${(pc.regions as unknown[]).join(", ")}` : "";
    const cluster = typeof pc.cluster_name === "string" && pc.cluster_name ? ` · ${pc.cluster_name}` : "";
    return `${c.plugin ?? "?"}${regions}${cluster}`;
  }
  return "";
}

function environmentOf(i: Integration): string {
  if (i.kind === "plugin") {
    const pc = i.config.config ?? {};
    const tag = pc.environment_tag;
    if (typeof pc.environment_label === "string" && pc.environment_label) return `from namespace label “${pc.environment_label}”`;
    if (typeof pc.environment === "string" && pc.environment) return pc.environment;
    return typeof tag === "string" && tag ? `from tag “${tag}”` : "";
  }
  return i.config.environment ?? "";
}

export function IntegrationsPage() {
  const { can } = useAuth();
  const admin = can("admin");
  const res = useLoad(() => api.get<List<Integration>>("/integrations"), []);
  const act = useAction();
  const [msg, setMsg] = useState<string | null>(null);
  const [params] = useSearchParams();
  // Settings → Integrations → Container image / registry opens the choice.
  const [creating, setCreating] = useState<IntegrationKind | "choose" | "container" | null>(() =>
    params.get("add") === "container" && admin ? "container" : null,
  );
  const [imagesOf, setImagesOf] = useState<Integration | null>(null);

  const job = useJobRunner(res.reload);
  const runNow = (i: Integration) => {
    setMsg(null);
    void job.start(`Run ${i.name}`, () => api.post<Queued>(`/integrations/${i.id}/run`));
  };
  const toggle = async (i: Integration) => {
    setMsg(null);
    const r = await act.run(() => api.patch<Integration>(`/integrations/${i.id}`, { enabled: !i.enabled }));
    if (r) res.reload();
  };
  const remove = async (i: Integration) => {
    if (
      !(await confirmAction({
        title: `Delete the integration "${i.name}"?`,
        message: "The assets and their inventory are kept.",
        consequence: "It stops collecting, and its settings are deleted.",
        action: "Delete integration",
        destructive: true,
        typeToConfirm: i.name,
      }))
    )
      return;
    setMsg(null);
    const ok = await act.run(() => api.del(`/integrations/${i.id}`).then(() => true));
    if (ok) res.reload();
  };

  const columns: Column<Integration>[] = [
    {
      key: "name",
      header: "Integration",
      cell: (i) => (
        <>
          <div className="badges">
            {i.asset_id ? <Link to={`/assets/${i.asset_id}`}>{i.name}</Link> : <span>{i.name}</span>}
            <KindBadge kind={i.kind} />
          </div>
          <div className="mono small muted break">{targetOf(i)}</div>
        </>
      ),
    },
    {
      key: "status",
      header: "Status",
      cell: (i) => {
        const h = healthOf(i);
        return <Badge status={h.status} tone={h.tone} />;
      },
    },
    { key: "env", header: "Environment", cell: (i) => environmentOf(i) || <span className="muted">—</span> },
    { key: "schedule", header: "Every", cell: (i) => minutesLabel(i.schedule_minutes) },
    { key: "secret", header: "Secret", cell: (i) => (i.secret_ref ? <span className="mono small">{i.secret_ref}</span> : <span className="muted">none</span>) },
    { key: "attempt", header: "Last attempt", cell: (i) => <RelativeTime iso={i.last_attempt} /> },
    { key: "success", header: "Last success", cell: (i) => <RelativeTime iso={i.last_success} /> },
    {
      key: "error",
      header: "Last error",
      cell: (i) => (i.last_error ? <span className="text-bad small break">{i.last_error}</span> : <span className="muted">—</span>),
    },
    {
      key: "actions",
      header: <span className="sr-only">Actions</span>,
      cell: (i) => (
        <div className="row-actions">
          <button
            type="button"
            className="btn btn-sm"
            onClick={() => runNow(i)}
            disabled={act.pending || job.busy || !i.enabled}
            title={i.enabled ? undefined : "Enable the integration to run it"}
          >
            Run now
          </button>
          {i.kind === "container_registry" && (
            <button type="button" className="btn btn-sm" onClick={() => setImagesOf(imagesOf?.id === i.id ? null : i)} aria-expanded={imagesOf?.id === i.id}>
              Images
            </button>
          )}
          {admin && (
            <>
              <button type="button" className="btn btn-sm" onClick={() => toggle(i)} disabled={act.pending}>
                {i.enabled ? "Disable" : "Enable"}
              </button>
              <button type="button" className="btn btn-sm btn-link-danger" onClick={() => remove(i)} disabled={act.pending}>
                Delete
              </button>
            </>
          )}
        </div>
      ),
    },
  ];

  const done = () => {
    setCreating(null);
    res.reload();
  };

  return (
    <>
      <PageHeader help="integrations-settings"
        title="Integrations"
        sub="Sources Stackurity collects from on a schedule: Git repositories, container images and installed plugins."
        actions={
          <>
            <button type="button" className="btn" onClick={res.reload}>
              Refresh
            </button>
            {admin && !creating && (
              <button type="button" className="btn btn-primary" onClick={() => setCreating("choose")}>
                Add integration
              </button>
            )}
          </>
        }
      />
      {msg && <Notice kind="success">{msg}</Notice>}
      <ErrorBox error={act.error} title="Action failed" />
      <ErrorBox error={job.error} title="Could not start run" />
      <JobStatus state={job.state} onDismiss={job.reset} />
      {admin && creating === "choose" && <KindChooser onPick={setCreating} onCancel={() => setCreating(null)} />}
      {admin && creating === "git_repository" && <GitForm onCancel={() => setCreating(null)} onCreated={done} />}
      {admin && creating === "container" && <ContainerChooser onPick={setCreating} onCancel={() => setCreating(null)} />}
      {admin && creating === "container_image" && <ImageForm onCancel={() => setCreating(null)} onCreated={done} />}
      {admin && creating === "container_registry" && <RegistryForm integrations={res.data?.items ?? []} onCancel={() => setCreating(null)} onCreated={done} />}
      {admin && creating === "plugin" && <PluginForm onCancel={() => setCreating(null)} onCreated={done} />}
      <ErrorBox error={res.error} title="Could not load integrations" />
      {!res.data && !res.error && <Loading />}
      {res.data && res.data.items.length === 0 && (
        <EmptyState title="No integrations" help="repositories" helpLabel="Add a repository, image or cloud account">
          <p>
            {admin
              ? "Add a Git repository, a container image or a plugin (such as AWS managed services) to collect inventory on a schedule. Servers (with the agent), CI pipelines and SBOM uploads are added from Settings → Integrations."
              : "An administrator can add Git repositories, container images and plugins here."}
          </p>
        </EmptyState>
      )}
      {res.data && res.data.items.length > 0 && (
        <Table
          caption="Integrations"
          columns={columns}
          rows={res.data.items}
          rowKey={(i) => i.id}
          rowClassName={(i) => (i.last_error && i.enabled ? "row-stale" : undefined)}
        />
      )}
      {imagesOf && <RegistryImages integration={imagesOf} onClose={() => setImagesOf(null)} />}
    </>
  );
}

function KindChooser({ onPick, onCancel }: { onPick: (k: IntegrationKind) => void; onCancel: () => void }) {
  const kinds: { kind: IntegrationKind; title: string; text: string }[] = [
    { kind: "git_repository", title: "Git repository", text: "Clone over HTTPS and read lockfiles (npm, Composer, …)." },
    { kind: "container_image", title: "Container image", text: "Pull an image from a registry and inventory its OS and application packages." },
    { kind: "container_registry", title: "Connect a registry", text: "Scan the newest tags of every repository in GHCR, Docker Hub, ECR or your own registry." },
    { kind: "plugin", title: "Plugin", text: "Run an installed plugin, e.g. AWS managed services (RDS, EKS, Lambda, …)." },
  ];
  return (
    <Card title="Add integration">
      <div className="kind-choices" role="group" aria-label="Integration kind">
        {kinds.map((k) => (
          <button key={k.kind} type="button" className="kind-choice" onClick={() => onPick(k.kind)}>
            <strong>{k.title}</strong>
            <span className="muted small">{k.text}</span>
          </button>
        ))}
      </div>
      <div className="form-actions">
        <button type="button" className="btn" onClick={onCancel}>
          Cancel
        </button>
      </div>
    </Card>
  );
}

function ContainerChooser({ onPick, onCancel }: { onPick: (k: IntegrationKind) => void; onCancel: () => void }) {
  return (
    <Card title="Container images">
      <div className="kind-choices" role="group" aria-label="How to add container images">
        <button type="button" className="kind-choice" onClick={() => onPick("container_registry")}>
          <strong>Connect a registry</strong>
          <span className="muted small">List its repositories, pick some or all, and scan their newest tags. New tags are picked up on every run.</span>
        </button>
        <button type="button" className="kind-choice" onClick={() => onPick("container_image")}>
          <strong>One image</strong>
          <span className="muted small">A single reference such as ghcr.io/acme/shop:1.4, read on every run.</span>
        </button>
      </div>
      <div className="form-actions">
        <button type="button" className="btn" onClick={onCancel}>
          Cancel
        </button>
      </div>
    </Card>
  );
}

// --- shared fields

interface CommonState {
  name: string;
  schedule: string;
  secret_ref: string;
}

function CommonFields({
  idp,
  v,
  set,
  secretHelp,
  defaultScheduleHint,
}: {
  idp: string;
  v: CommonState;
  set: (v: CommonState) => void;
  secretHelp: ReactNode;
  defaultScheduleHint?: string;
}) {
  return (
    <>
      <div className="field">
        <label htmlFor={`${idp}-name`}>Name (optional)</label>
        <input id={`${idp}-name`} value={v.name} onChange={(e) => set({ ...v, name: e.target.value })} placeholder="derived from the target" />
      </div>
      <div className="field">
        <label htmlFor={`${idp}-sched`}>Run every (minutes)</label>
        <input id={`${idp}-sched`} type="number" min={15} max={10080} step={1} required value={v.schedule} onChange={(e) => set({ ...v, schedule: e.target.value })} />
        <p className="hint">15 to 10080 (one week).{defaultScheduleHint ? ` ${defaultScheduleHint}` : ""}</p>
      </div>
      <div className="field field-span">
        <label htmlFor={`${idp}-secret`}>Secret reference (optional)</label>
        <input id={`${idp}-secret`} className="mono" value={v.secret_ref} onChange={(e) => set({ ...v, secret_ref: e.target.value })} placeholder="env:STACKURITY_SECRET_… or file:/run/secrets/…" />
        <p className="hint">{secretHelp}</p>
      </div>
    </>
  );
}

function checkCommon(v: CommonState): string | null {
  const mins = Number(v.schedule);
  if (!Number.isInteger(mins) || mins < 15 || mins > 10080) return "Schedule must be a whole number of minutes between 15 and 10080.";
  const s = v.secret_ref.trim();
  if (s && !/^(env|file|secret):.+/.test(s)) return "Secret reference must look like secret:NAME, env:NAME or file:/path.";
  return null;
}

function bodyOf(kind: IntegrationKind, v: CommonState, config: unknown): Record<string, unknown> {
  const b: Record<string, unknown> = { kind, config, schedule_minutes: Number(v.schedule) };
  if (v.name.trim()) b.name = v.name.trim();
  if (v.secret_ref.trim()) b.secret_ref = v.secret_ref.trim();
  return b;
}

/** Splits "invalid config: a; b" from plugin validation into a list. */
function problemsOf(err: ApiError | null): string[] {
  if (!err || err.status !== 400) return [];
  const m = err.message.replace(/^invalid config:\s*/i, "");
  if (m === err.message) return err.details;
  return m.split(/;\s+/).filter(Boolean);
}

function FormShell({
  title,
  onSubmit,
  onCancel,
  pending,
  localErr,
  error,
  submit,
  children,
  plugin,
}: {
  title: string;
  onSubmit: (e: FormEvent) => void;
  onCancel: () => void;
  pending: boolean;
  localErr: string | null;
  error: ApiError | null;
  submit: string;
  children: ReactNode;
  plugin?: boolean;
}) {
  const problems = plugin ? problemsOf(error) : [];
  return (
    <Card title={title}>
      <form className="form" onSubmit={onSubmit}>
        {problems.length > 0 ? (
          <div className="alert alert-error" role="alert">
            <strong>The plugin rejected this configuration:</strong>
            <ul>
              {problems.map((p, i) => (
                <li key={i}>{p}</li>
              ))}
            </ul>
          </div>
        ) : (
          <ErrorBox error={error} title="Could not create integration" />
        )}
        {localErr && (
          <div className="alert alert-error" role="alert">
            {localErr}
          </div>
        )}
        {children}
        <div className="form-actions">
          <button type="submit" className="btn btn-primary" disabled={pending}>
            {pending ? "Checking…" : submit}
          </button>
          <button type="button" className="btn" onClick={onCancel}>
            Cancel
          </button>
        </div>
      </form>
    </Card>
  );
}

// --- git

function GitForm({ onCancel, onCreated }: { onCancel: () => void; onCreated: () => void }) {
  const [c, setC] = useState<CommonState>({ name: "", schedule: "360", secret_ref: "" });
  const [f, setF] = useState({ url: "", ref: "", environment: "", username: "" });
  const [localErr, setLocalErr] = useState<string | null>(null);
  const act = useAction();
  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setLocalErr(null);
    if (!/^https:\/\//i.test(f.url.trim())) return setLocalErr("The repository URL must start with https://");
    const err = checkCommon(c);
    if (err) return setLocalErr(err);
    const config: Record<string, string> = { url: f.url.trim() };
    for (const k of ["ref", "environment", "username"] as const) if (f[k].trim()) config[k] = f[k].trim();
    const ok = await act.run(() => api.post<Integration>("/integrations", bodyOf("git_repository", c, config)));
    if (ok) onCreated();
  };
  return (
    <FormShell title="Add Git repository" onSubmit={submit} onCancel={onCancel} pending={act.pending} localErr={localErr} error={act.error} submit="Create integration">
      <div className="form-grid">
        <div className="field field-span">
          <label htmlFor="gi-url">Repository URL</label>
          <input id="gi-url" type="url" required placeholder="https://github.com/org/repo" value={f.url} onChange={(e) => setF({ ...f, url: e.target.value })} />
          <p className="hint">HTTPS only.</p>
        </div>
        <div className="field">
          <label htmlFor="gi-ref">Branch or tag (optional)</label>
          <input id="gi-ref" placeholder="default branch" value={f.ref} onChange={(e) => setF({ ...f, ref: e.target.value })} />
        </div>
        <div className="field">
          <label htmlFor="gi-env">Environment (optional)</label>
          <input id="gi-env" placeholder="e.g. production" value={f.environment} onChange={(e) => setF({ ...f, environment: e.target.value })} />
        </div>
        <div className="field">
          <label htmlFor="gi-user">Username (optional)</label>
          <input id="gi-user" placeholder="x-access-token" value={f.username} onChange={(e) => setF({ ...f, username: e.target.value })} />
          <p className="hint">GitHub: x-access-token, GitLab: oauth2, Bitbucket: x-token-auth.</p>
        </div>
        <CommonFields
          idp="gi"
          v={c}
          set={setC}
          secretHelp={
            <>
              For private repositories: a reference to the access token on the server, never the token itself, e.g.{" "}
              <Code>env:STACKURITY_SECRET_GITHUB</Code>.
            </>
          }
        />
      </div>
    </FormShell>
  );
}

// --- container image

function ImageForm({ onCancel, onCreated }: { onCancel: () => void; onCreated: () => void }) {
  const [c, setC] = useState<CommonState>({ name: "", schedule: "720", secret_ref: "" });
  const [f, setF] = useState({ image: "", platform: "", environment: "", username: "" });
  const [localErr, setLocalErr] = useState<string | null>(null);
  const act = useAction();
  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setLocalErr(null);
    const img = f.image.trim();
    if (!img || /\s/.test(img) || img.includes("://")) return setLocalErr("Enter a registry reference such as ghcr.io/acme/app:1.2 (no scheme, no spaces).");
    if (f.platform.trim() && !/^[a-z0-9]+\/[a-z0-9_]+(\/[a-z0-9]+)?$/.test(f.platform.trim())) return setLocalErr("Platform looks like linux/amd64 or linux/arm64/v8.");
    const err = checkCommon(c);
    if (err) return setLocalErr(err);
    const config: Record<string, string> = { image: img };
    for (const k of ["platform", "environment", "username"] as const) if (f[k].trim()) config[k] = f[k].trim();
    const ok = await act.run(() => api.post<Integration>("/integrations", bodyOf("container_image", c, config)));
    if (ok) onCreated();
  };
  return (
    <FormShell title="Add container image" onSubmit={submit} onCancel={onCancel} pending={act.pending} localErr={localErr} error={act.error} submit="Create integration">
      <div className="form-grid">
        <div className="field field-span">
          <label htmlFor="im-image">Image reference</label>
          <input id="im-image" className="mono" required placeholder="ghcr.io/acme/app:1.2 or nginx@sha256:…" value={f.image} onChange={(e) => setF({ ...f, image: e.target.value })} />
          <p className="hint">Pin a digest (@sha256:…) to inventory exactly what you deploy; a tag is re-resolved on every run.</p>
        </div>
        <div className="field">
          <label htmlFor="im-platform">Platform (optional)</label>
          <input id="im-platform" className="mono" placeholder="linux/amd64" value={f.platform} onChange={(e) => setF({ ...f, platform: e.target.value })} />
          <p className="hint">For multi-architecture images.</p>
        </div>
        <div className="field">
          <label htmlFor="im-env">Environment (optional)</label>
          <input id="im-env" placeholder="e.g. production" value={f.environment} onChange={(e) => setF({ ...f, environment: e.target.value })} />
        </div>
        <div className="field">
          <label htmlFor="im-user">Registry username (optional)</label>
          <input id="im-user" value={f.username} onChange={(e) => setF({ ...f, username: e.target.value })} />
          <p className="hint">Needed when the secret is a password or token for a named user.</p>
        </div>
        <CommonFields
          idp="im"
          v={c}
          set={setC}
          secretHelp={
            <>
              For private registries: a reference to the registry password or token on the server, e.g. <Code>env:STACKURITY_SECRET_GHCR</Code>.
              Public images need none.
            </>
          }
        />
      </div>
    </FormShell>
  );
}

// --- plugin

function templateFor(schema: PluginConfigField[]): Record<string, unknown> {
  const t: Record<string, unknown> = {};
  for (const f of schema) {
    if (!f.required) continue;
    t[f.name] = f.type === "string_list" ? [] : f.type === "number" ? 0 : f.type === "boolean" ? false : "";
  }
  return t;
}

const AWS_SERVICES = ["rds", "elasticache", "eks", "lambda", "opensearch"];

function AwsForm({ value, onChange }: { value: Record<string, unknown>; onChange: (v: Record<string, unknown>) => void }) {
  const regions = Array.isArray(value.regions) ? (value.regions as string[]) : [];
  const services = Array.isArray(value.services) ? (value.services as string[]) : [];
  const str = (k: string) => (typeof value[k] === "string" ? (value[k] as string) : "");
  const [regionText, setRegionText] = useState(regions.join(", "));
  const set = (k: string, v: unknown) => {
    const n = { ...value };
    if (v === "" || (Array.isArray(v) && v.length === 0 && k !== "regions")) delete n[k];
    else n[k] = v;
    onChange(n);
  };
  return (
    <div className="form-grid">
      <div className="field field-span">
        <label htmlFor="aws-regions">Regions (required)</label>
        <input
          id="aws-regions"
          className="mono"
          value={regionText}
          placeholder="eu-west-1, us-east-1"
          onChange={(e) => {
            setRegionText(e.target.value);
            set(
              "regions",
              e.target.value
                .split(/[,\s]+/)
                .map((x) => x.trim())
                .filter(Boolean),
            );
          }}
        />
        <p className="hint">Comma-separated AWS region codes.</p>
      </div>
      <fieldset className="field field-span">
        <legend>Services</legend>
        <div className="multi">
          {AWS_SERVICES.map((s) => (
            <label key={s} className="check">
              <input
                type="checkbox"
                checked={services.includes(s)}
                onChange={() => set("services", services.includes(s) ? services.filter((x) => x !== s) : [...services, s])}
              />{" "}
              {s}
            </label>
          ))}
        </div>
        <p className="hint">None ticked = all services.</p>
      </fieldset>
      <div className="field">
        <label htmlFor="aws-role">Role ARN (optional)</label>
        <input id="aws-role" className="mono" value={str("role_arn")} onChange={(e) => set("role_arn", e.target.value.trim())} placeholder="arn:aws:iam::123456789012:role/stackurity-read" />
        <p className="hint">A read-only role to assume in the target account.</p>
      </div>
      <div className="field">
        <label htmlFor="aws-ext">External ID (optional)</label>
        <input id="aws-ext" value={str("external_id")} onChange={(e) => set("external_id", e.target.value.trim())} />
      </div>
      <div className="field">
        <label htmlFor="aws-envtag">Environment tag (optional)</label>
        <input id="aws-envtag" value={str("environment_tag")} onChange={(e) => set("environment_tag", e.target.value.trim())} placeholder="e.g. Environment" />
        <p className="hint">Resource tag whose value becomes the asset's environment.</p>
      </div>
    </div>
  );
}

function credentialExample(creds: string[]): string {
  const keys = creds.map((c) => c.replace(/\s*\(.*\)\s*$/, "").trim()).filter((c) => /^[A-Za-z0-9_.-]+$/.test(c));
  if (keys.length === 0) return "{}";
  return `{${keys.map((k) => `"${k}": "…"`).join(", ")}}`;
}

function PluginForm({ onCancel, onCreated }: { onCancel: () => void; onCreated: () => void }) {
  const plugins = useLoad(() => api.get<PluginList>("/plugins"), []);
  const usable = (plugins.data?.items ?? []).filter((p) => p.metadata && !p.error);
  const [name, setName] = useState("");
  const selected: InstalledPlugin | undefined = usable.find((p) => p.name === name);
  const schema = useMemo(() => selected?.metadata?.config_schema ?? [], [selected]);
  const [json, setJson] = useState("{}");
  const [mode, setMode] = useState<"form" | "json">("form");
  const [c, setC] = useState<CommonState>({ name: "", schedule: "720", secret_ref: "" });
  const [localErr, setLocalErr] = useState<string | null>(null);
  const [imageScans, setImageScans] = useState("25");
  const act = useAction();
  const isAws = name === "aws-managed";
  // Plugins that report images (Kubernetes) have them read by the image scanner.
  const reportsImages = (selected?.metadata?.capabilities ?? []).includes("inventory:image");

  let parsed: Record<string, unknown> | null = null;
  let jsonErr: string | null = null;
  try {
    const v = JSON.parse(json);
    if (v === null || typeof v !== "object" || Array.isArray(v)) jsonErr = "The configuration must be a JSON object.";
    else parsed = v as Record<string, unknown>;
  } catch (e) {
    jsonErr = `Invalid JSON: ${(e as Error).message}`;
  }

  const choose = (n: string) => {
    setName(n);
    act.clear();
    setLocalErr(null);
    const p = usable.find((x) => x.name === n);
    setJson(JSON.stringify(templateFor(p?.metadata?.config_schema ?? []), null, 2));
    setMode(n === "aws-managed" ? "form" : "json");
  };

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setLocalErr(null);
    if (!selected) return setLocalErr("Choose a plugin.");
    if (!parsed) return setLocalErr(jsonErr);
    const missing = schema.filter((f) => f.required && (parsed![f.name] === undefined || parsed![f.name] === "" || (Array.isArray(parsed![f.name]) && (parsed![f.name] as unknown[]).length === 0)));
    if (missing.length) return setLocalErr(`Required: ${missing.map((f) => f.name).join(", ")}.`);
    const err = checkCommon(c);
    if (err) return setLocalErr(err);
    const wrapper: Record<string, unknown> = { plugin: selected.name, config: parsed };
    if (reportsImages) {
      const n = Number(imageScans);
      if (!Number.isInteger(n) || n < 0 || n > 500) return setLocalErr("Image scans per run must be a whole number from 0 to 500.");
      wrapper.image_scans = n;
    }
    const ok = await act.run(() => api.post<Integration>("/integrations", bodyOf("plugin", c, wrapper)));
    if (ok) onCreated();
  };

  if (plugins.data && !plugins.data.enabled)
    return (
      <Card title="Add plugin integration">
        <Notice kind="warn">
          Plugins are not enabled on this server. Set <Code>STACKURITY_PLUGIN_DIR</Code> and install plugins there; see Settings → Plugins.
        </Notice>
        <button type="button" className="btn" onClick={onCancel}>
          Cancel
        </button>
      </Card>
    );

  return (
    <FormShell title="Add plugin integration" onSubmit={submit} onCancel={onCancel} pending={act.pending} localErr={localErr} error={act.error} submit="Validate and create" plugin>
      <ErrorBox error={plugins.error} title="Could not load plugins" />
      <div className="form-grid">
        <div className="field">
          <label htmlFor="pl-plugin">Plugin</label>
          <select id="pl-plugin" required value={name} onChange={(e) => choose(e.target.value)}>
            <option value="">Choose…</option>
            {usable.map((p) => (
              <option key={p.name} value={p.name}>
                {p.metadata!.name} ({p.name} {p.metadata!.version})
              </option>
            ))}
          </select>
          <p className="hint">
            Review what a plugin may access under <Link to="/settings/plugins">Settings → Plugins</Link> first.
          </p>
        </div>
      </div>
      {selected && (
        <>
          {schema.length > 0 && (
            <details className="schema-help" open={!isAws}>
              <summary>Configuration fields</summary>
              <ul className="banner-list small">
                {schema.map((f) => (
                  <li key={f.name}>
                    <span className="mono">{f.name}</span> <span className="muted">({f.type}{f.required ? ", required" : ""})</span> — {f.description}
                  </li>
                ))}
              </ul>
            </details>
          )}
          {isAws && (
            <div className="btn-group" role="group" aria-label="Editor">
              <button type="button" className={`btn btn-sm${mode === "form" ? " btn-primary" : ""}`} aria-pressed={mode === "form"} onClick={() => setMode("form")}>
                Form
              </button>
              <button type="button" className={`btn btn-sm${mode === "json" ? " btn-primary" : ""}`} aria-pressed={mode === "json"} onClick={() => setMode("json")}>
                JSON
              </button>
            </div>
          )}
          {isAws && mode === "form" && parsed && <AwsForm value={parsed} onChange={(v) => setJson(JSON.stringify(v, null, 2))} />}
          {isAws && mode === "form" && !parsed && <p className="text-bad">The JSON is invalid; switch to JSON to fix it.</p>}
          {(!isAws || mode === "json") && (
            <div className="field">
              <label htmlFor="pl-json">Configuration (JSON)</label>
              <textarea
                id="pl-json"
                className="mono json-editor"
                rows={10}
                spellCheck={false}
                value={json}
                onChange={(e) => setJson(e.target.value)}
                aria-invalid={Boolean(jsonErr)}
                aria-describedby="pl-json-status"
              />
              <p id="pl-json-status" className={jsonErr ? "hint text-bad" : "hint"}>
                {jsonErr ?? "Valid JSON. The plugin checks it again when you create the integration."}
              </p>
            </div>
          )}
          {reportsImages && (
            <div className="field">
              <label htmlFor="pl-image-scans">Image scans per run</label>
              <input id="pl-image-scans" type="number" min={0} max={500} value={imageScans} onChange={(e) => setImageScans(e.target.value)} />
              <p className="hint">
                Images this plugin finds running are read by the built-in image scanner, most exposed first. Each digest is scanned once a week at
                most. 0 turns scanning off.
              </p>
            </div>
          )}
          <div className="form-grid">
            <CommonFields
              idp="pl"
              v={c}
              set={setC}
              defaultScheduleHint={selected.metadata?.default_frequency ? `Plugin suggests every ${selected.metadata.default_frequency}.` : undefined}
              secretHelp={
                <>
                  Must resolve to a JSON object with the credentials the plugin lists
                  {selected.metadata?.credentials?.length ? (
                    <>
                      {" "}
                      (<span className="mono">{selected.metadata.credentials.join(", ")}</span>)
                    </>
                  ) : null}
                  , e.g. <Code>file:/run/secrets/{selected.name}.json</Code> containing <Code>{credentialExample(selected.metadata?.credentials ?? [])}</Code>.
                </>
              }
            />
          </div>
        </>
      )}
    </FormShell>
  );
}

// --- container registry

const listOf = (v: string) =>
  v
    .split(/[,\s]+/)
    .map((x) => x.trim())
    .filter(Boolean);

/** A secret name for a pasted credential: registry-<what>-<random>. */
function secretNameFor(what: string): string {
  const base = `registry-${what}`.toLowerCase().replace(/[^a-z0-9._-]+/g, "-").replace(/-+/g, "-").slice(0, 52);
  return `${base}-${Math.random().toString(36).slice(2, 8)}`;
}

type Cred = "paste" | "ref" | "aws" | "none";

function RegistryForm({ integrations, onCancel, onCreated }: { integrations: Integration[]; onCancel: () => void; onCreated: () => void }) {
  const [c, setC] = useState<CommonState>({ name: "", schedule: "360", secret_ref: "" });
  const [provider, setProvider] = useState<RegistryProvider>("ghcr");
  const [f, setF] = useState({ namespace: "", url: "", username: "", auth_host: "", region: "", account_id: "", role_arn: "", external_id: "", environment: "", platform: "" });
  const [cred, setCred] = useState<Cred>("paste");
  const [token, setToken] = useState("");
  const [keys, setKeys] = useState({ id: "", secret: "" });
  const [awsId, setAwsId] = useState("");
  const [storedRef, setStoredRef] = useState<string | null>(null);
  const [all, setAll] = useState(true);
  const [picked, setPicked] = useState<Set<string>>(new Set());
  const [include, setInclude] = useState("");
  const [exclude, setExclude] = useState("");
  const [recent, setRecent] = useState("1");
  const [patterns, setPatterns] = useState("latest");
  const [scans, setScans] = useState("25");
  const [found, setFound] = useState<RegistryDiscovery | null>(null);
  const [localErr, setLocalErr] = useState<string | null>(null);
  const act = useAction();
  const discover = useAction();
  const awsIntegrations = integrations.filter((i) => i.kind === "plugin" && i.config?.plugin === "aws-managed");
  const set = (k: keyof typeof f, v: string) => {
    setF({ ...f, [k]: v });
    setFound(null);
  };

  const config = (): ContainerRegistryConfig => {
    const cfg: ContainerRegistryConfig = { provider };
    if (provider === "oci") {
      cfg.url = f.url.trim();
      if (f.auth_host.trim()) cfg.auth_host = f.auth_host.trim();
    }
    if (provider === "ecr") {
      cfg.region = f.region.trim();
      for (const k of ["account_id", "role_arn", "external_id"] as const) if (f[k].trim()) cfg[k] = f[k].trim();
      if (cred === "aws" && awsId) cfg.aws_integration_id = Number(awsId);
    } else {
      if (f.namespace.trim()) cfg.namespace = f.namespace.trim();
      if (f.username.trim() && provider !== "ghcr") cfg.username = f.username.trim();
    }
    if (!all && picked.size) cfg.repositories = [...picked].sort();
    if (listOf(include).length) cfg.include = listOf(include);
    if (listOf(exclude).length) cfg.exclude = listOf(exclude);
    cfg.recent_tags = Number(recent);
    if (listOf(patterns).length) cfg.tag_patterns = listOf(patterns);
    cfg.image_scans = Number(scans);
    if (f.environment.trim()) cfg.environment = f.environment.trim();
    if (f.platform.trim()) cfg.platform = f.platform.trim();
    return cfg;
  };

  const check = (): string | null => {
    if (provider === "oci" && !/^https:\/\/[^/\s]+\/?$/.test(f.url.trim())) return "Enter the registry's https address, such as https://registry.example.com.";
    if ((provider === "ghcr" || provider === "dockerhub") && !f.namespace.trim()) return "Enter the organisation, user or namespace.";
    if (provider === "ecr" && !/^[a-z]{2}(-[a-z]+)+-\d$/.test(f.region.trim())) return "Enter the AWS region, such as eu-west-1.";
    if (cred === "paste" && provider === "ecr" && !storedRef && (!keys.id.trim() || !keys.secret.trim())) return "Enter the access key id and secret access key.";
    if (cred === "paste" && provider !== "ecr" && !storedRef && !token) return "Paste the token or password, or choose another kind of credentials.";
    if (cred === "paste" && provider === "dockerhub" && !f.username.trim()) return "Docker Hub needs the user name that goes with the token.";
    if (cred === "ref" && !/^secret:.+/.test(c.secret_ref.trim()) && !/^(env|file):.+/.test(c.secret_ref.trim())) return "The secret reference looks like secret:NAME.";
    if (cred === "aws" && !awsId) return "Choose the AWS integration whose keys to use.";
    const n = Number(scans);
    if (!Number.isInteger(n) || n < 0 || n > 500) return "Image scans per run must be a whole number from 0 to 500.";
    return checkCommon({ ...c, secret_ref: "" });
  };

  /** Stores a pasted credential once as a workspace secret and returns the reference to use. */
  const secretRef = async (): Promise<string> => {
    if (cred === "ref") return c.secret_ref.trim();
    if (cred !== "paste") return "";
    if (storedRef) return storedRef;
    const value = provider === "ecr" ? JSON.stringify({ aws_access_key_id: keys.id.trim(), aws_secret_access_key: keys.secret.trim() }) : token;
    const what = provider === "oci" ? f.url.replace(/^https:\/\//, "") : provider === "ecr" ? f.region : f.namespace;
    const name = secretNameFor(`${provider}-${what}`);
    await api.put(`/secrets/${encodeURIComponent(name)}`, { value });
    const ref = `secret:${name}`;
    setStoredRef(ref);
    setToken("");
    setKeys({ id: "", secret: "" });
    return ref;
  };

  const listRepos = async () => {
    setLocalErr(null);
    const err = check();
    if (err) return setLocalErr(err);
    const r = await discover.run(async () => {
      const ref = await secretRef();
      return api.post<RegistryDiscovery>("/integrations/registry/discover", { config: { ...config(), repositories: undefined }, secret_ref: ref });
    });
    if (r) {
      setFound(r);
      setPicked(new Set(r.repositories.filter((x) => x.included).map((x) => x.name)));
    }
  };

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setLocalErr(null);
    const err = check();
    if (err) return setLocalErr(err);
    if (!all && picked.size === 0) return setLocalErr("List the repositories and tick at least one, or choose All repositories.");
    const ok = await act.run(async () => {
      const ref = await secretRef();
      return api.post<Integration>("/integrations", bodyOf("container_registry", { ...c, secret_ref: ref }, config()));
    });
    if (ok) onCreated();
  };

  const togglePick = (n: string) => {
    const next = new Set(picked);
    if (next.has(n)) next.delete(n);
    else next.add(n);
    setPicked(next);
  };

  const credChoice = (value: Cred, label: string) => (
    <label className="check">
      <input
        type="radio"
        name="rg-cred"
        checked={cred === value}
        onChange={() => {
          setCred(value);
          setFound(null);
        }}
      />{" "}
      {label}
    </label>
  );

  return (
    <FormShell title="Connect a container registry" onSubmit={submit} onCancel={onCancel} pending={act.pending} localErr={localErr} error={act.error} submit="Connect registry">
      <div className="form-grid">
        <div className="field">
          <label htmlFor="rg-provider">Registry</label>
          <select
            id="rg-provider"
            value={provider}
            onChange={(e) => {
              const p = e.target.value as RegistryProvider;
              setProvider(p);
              setFound(null);
              setStoredRef(null);
              setCred(p === "dockerhub" || p === "oci" ? "none" : "paste");
            }}
          >
            {(Object.keys(PROVIDER_LABEL) as RegistryProvider[]).map((p) => (
              <option key={p} value={p}>
                {PROVIDER_LABEL[p]}
              </option>
            ))}
          </select>
        </div>
        {provider === "oci" && (
          <div className="field">
            <label htmlFor="rg-url">Registry address</label>
            <input id="rg-url" className="mono" required placeholder="https://registry.example.com" value={f.url} onChange={(e) => set("url", e.target.value)} />
            <p className="hint">Harbor, GitLab, Quay, Artifactory, Azure, Google Artifact Registry and others. https only.</p>
          </div>
        )}
        {provider !== "ecr" && (
          <div className="field">
            <label htmlFor="rg-ns">{provider === "ghcr" ? "Organisation or user" : provider === "dockerhub" ? "Namespace" : "Repository prefix (optional)"}</label>
            <input id="rg-ns" className="mono" required={provider !== "oci"} placeholder={provider === "oci" ? "team/apps" : "acme"} value={f.namespace} onChange={(e) => set("namespace", e.target.value)} />
          </div>
        )}
        {provider === "ecr" && (
          <>
            <div className="field">
              <label htmlFor="rg-region">Region</label>
              <input id="rg-region" className="mono" required placeholder="eu-west-1" value={f.region} onChange={(e) => set("region", e.target.value)} />
            </div>
            <div className="field">
              <label htmlFor="rg-account">Account id (optional)</label>
              <input id="rg-account" className="mono" placeholder="the account of the keys" value={f.account_id} onChange={(e) => set("account_id", e.target.value)} />
            </div>
            <div className="field">
              <label htmlFor="rg-role">Role ARN (optional)</label>
              <input id="rg-role" className="mono" placeholder="arn:aws:iam::123456789012:role/stackurity-ecr" value={f.role_arn} onChange={(e) => set("role_arn", e.target.value)} />
              <p className="hint">
                Read-only: <span className="mono">ecr:GetAuthorizationToken</span>, <span className="mono">ecr:DescribeRepositories</span>,{" "}
                <span className="mono">ecr:DescribeImages</span>, and for the scans <span className="mono">ecr:BatchGetImage</span> and{" "}
                <span className="mono">ecr:GetDownloadUrlForLayer</span>.
              </p>
            </div>
            <div className="field">
              <label htmlFor="rg-ext">External ID (optional)</label>
              <input id="rg-ext" value={f.external_id} onChange={(e) => set("external_id", e.target.value)} />
            </div>
          </>
        )}
        <fieldset className="field field-span">
          <legend>Credentials</legend>
          <div className="multi">
            {provider === "ecr" ? credChoice("paste", "Access keys") : credChoice("paste", "Paste a token or password")}
            {provider === "ecr" && awsIntegrations.length > 0 && credChoice("aws", "Those of an AWS integration")}
            {credChoice("ref", "A stored secret")}
            {(provider === "dockerhub" || provider === "oci") && credChoice("none", "None (public)")}
          </div>
          {cred === "paste" && provider !== "ecr" && (
            <div className="form-grid">
              <div className="field">
                <label htmlFor="rg-token">{provider === "ghcr" ? "Token (read:packages)" : "Token or password"}</label>
                <input
                  id="rg-token"
                  type="password"
                  autoComplete="off"
                  value={token}
                  placeholder={storedRef ? `stored as ${storedRef}` : ""}
                  onChange={(e) => {
                    setToken(e.target.value);
                    setStoredRef(null);
                  }}
                />
                <p className="hint">Stored as a workspace secret, sent only to this registry, never shown again. Use a read-only token.</p>
              </div>
              {provider !== "ghcr" && (
                <div className="field">
                  <label htmlFor="rg-user">User name</label>
                  <input id="rg-user" value={f.username} onChange={(e) => set("username", e.target.value)} />
                </div>
              )}
            </div>
          )}
          {cred === "paste" && provider === "ecr" && (
            <div className="form-grid">
              <div className="field">
                <label htmlFor="rg-akid">Access key id</label>
                <input
                  id="rg-akid"
                  className="mono"
                  autoComplete="off"
                  value={keys.id}
                  placeholder={storedRef ? `stored as ${storedRef}` : ""}
                  onChange={(e) => {
                    setKeys({ ...keys, id: e.target.value });
                    setStoredRef(null);
                  }}
                />
              </div>
              <div className="field">
                <label htmlFor="rg-sak">Secret access key</label>
                <input
                  id="rg-sak"
                  type="password"
                  autoComplete="off"
                  value={keys.secret}
                  onChange={(e) => {
                    setKeys({ ...keys, secret: e.target.value });
                    setStoredRef(null);
                  }}
                />
              </div>
            </div>
          )}
          {cred === "aws" && (
            <div className="field">
              <label htmlFor="rg-aws">AWS integration</label>
              <select id="rg-aws" value={awsId} onChange={(e) => setAwsId(e.target.value)}>
                <option value="">Choose…</option>
                {awsIntegrations.map((i) => (
                  <option key={i.id} value={i.id}>
                    {i.name}
                  </option>
                ))}
              </select>
              <p className="hint">Its stored keys, and its role unless you set one here.</p>
            </div>
          )}
          {cred === "ref" && (
            <div className="form-grid">
              <div className="field">
                <label htmlFor="rg-ref">Secret reference</label>
                <input id="rg-ref" className="mono" placeholder="secret:NAME" value={c.secret_ref} onChange={(e) => setC({ ...c, secret_ref: e.target.value })} />
                <p className="hint">
                  From <Link to="/settings/secrets">Settings → Secrets</Link>.
                  {provider === "ecr" ? <> It holds <Code>{'{"aws_access_key_id": "…", "aws_secret_access_key": "…"}'}</Code>.</> : null}
                </p>
              </div>
              {(provider === "dockerhub" || provider === "oci") && (
                <div className="field">
                  <label htmlFor="rg-user2">User name</label>
                  <input id="rg-user2" value={f.username} onChange={(e) => set("username", e.target.value)} />
                </div>
              )}
            </div>
          )}
        </fieldset>
        {provider === "oci" && (
          <div className="field">
            <label htmlFor="rg-auth">Token service host (optional)</label>
            <input id="rg-auth" className="mono" placeholder="gitlab.com" value={f.auth_host} onChange={(e) => set("auth_host", e.target.value)} />
            <p className="hint">Only when the registry signs in on another host (GitLab). Credentials go to no other host.</p>
          </div>
        )}
      </div>

      <fieldset className="field field-span">
        <legend>Repositories</legend>
        <div className="multi">
          <label className="check">
            <input type="radio" name="rg-all" checked={all} onChange={() => setAll(true)} /> All repositories, including new ones
          </label>
          <label className="check">
            <input type="radio" name="rg-all" checked={!all} onChange={() => setAll(false)} /> Only the ones I tick
          </label>
        </div>
        <div className="form-grid">
          <div className="field">
            <label htmlFor="rg-inc">Include (optional)</label>
            <input id="rg-inc" className="mono" placeholder="shop*, api-*" value={include} onChange={(e) => setInclude(e.target.value)} />
          </div>
          <div className="field">
            <label htmlFor="rg-exc">Exclude (optional)</label>
            <input id="rg-exc" className="mono" placeholder="*-sandbox" value={exclude} onChange={(e) => setExclude(e.target.value)} />
          </div>
        </div>
        <p className="hint">Comma-separated patterns: * matches anything, ? one character.</p>
        <div className="form-actions">
          <button type="button" className="btn" onClick={listRepos} disabled={discover.pending}>
            {discover.pending ? "Listing…" : "List repositories"}
          </button>
        </div>
        <ErrorBox error={discover.error} title="Could not list the registry" />
        {found && (
          <div>
            <p className="small muted">
              {found.registry}: {found.repositories.length} repositories{found.complete ? "" : " (the first 10,000)"}.{" "}
              {all ? "Those the patterns leave out are greyed." : "Tick the ones to scan."}
            </p>
            <ul className="banner-list small">
              {found.repositories.map((r) => (
                <li key={r.name} className={all && !r.included ? "muted" : undefined}>
                  {all ? (
                    <span className="mono">{r.name}</span>
                  ) : (
                    <label className="check">
                      <input type="checkbox" checked={picked.has(r.name)} onChange={() => togglePick(r.name)} /> <span className="mono">{r.name}</span>
                    </label>
                  )}
                </li>
              ))}
            </ul>
          </div>
        )}
      </fieldset>

      <div className="form-grid">
        <div className="field">
          <label htmlFor="rg-recent">Newest images per repository</label>
          <select id="rg-recent" value={recent} onChange={(e) => setRecent(e.target.value)}>
            <option value="1">1</option>
            <option value="2">2</option>
            <option value="3">3</option>
          </select>
          <p className="hint">By push time. Tags on the same image count once.</p>
        </div>
        <div className="field">
          <label htmlFor="rg-patterns">Also scan tags (optional)</label>
          <input id="rg-patterns" className="mono" placeholder="latest, semver, release-*" value={patterns} onChange={(e) => setPatterns(e.target.value)} />
          <p className="hint">semver matches 1.4.2 and v2.0.0-rc.1. At most 10 images per repository from patterns.</p>
        </div>
        <div className="field">
          <label htmlFor="rg-scans">Image scans per run</label>
          <input id="rg-scans" type="number" min={0} max={500} value={scans} onChange={(e) => setScans(e.target.value)} />
          <p className="hint">Newest first; the rest on later runs. Each digest is scanned once a week at most.</p>
        </div>
        <div className="field">
          <label htmlFor="rg-env">Environment (optional)</label>
          <input id="rg-env" placeholder="e.g. production" value={f.environment} onChange={(e) => set("environment", e.target.value)} />
        </div>
        <div className="field">
          <label htmlFor="rg-platform">Platform (optional)</label>
          <input id="rg-platform" className="mono" placeholder="linux/amd64" value={f.platform} onChange={(e) => set("platform", e.target.value)} />
        </div>
        <div className="field">
          <label htmlFor="rg-name">Name (optional)</label>
          <input id="rg-name" value={c.name} onChange={(e) => setC({ ...c, name: e.target.value })} placeholder="derived from the registry" />
        </div>
        <div className="field">
          <label htmlFor="rg-sched">Run every (minutes)</label>
          <input id="rg-sched" type="number" min={15} max={10080} required value={c.schedule} onChange={(e) => setC({ ...c, schedule: e.target.value })} />
          <p className="hint">New repositories and tags are found on each run.</p>
        </div>
      </div>
    </FormShell>
  );
}

function RegistryImages({ integration, onClose }: { integration: Integration; onClose: () => void }) {
  const res = useLoad(() => api.get<List<RegistryImage>>(`/integrations/${integration.id}/images`), [integration.id]);
  const columns: Column<RegistryImage>[] = [
    { key: "repo", header: "Repository", cell: (r) => <span className="mono small">{r.repository}</span> },
    { key: "tags", header: "Tags", cell: (r) => <span className="mono small">{r.tags.join(", ")}</span> },
    {
      key: "digest",
      header: "Digest",
      cell: (r) => (
        <span className="mono small" title={r.digest}>
          {r.digest.slice(7, 19)}
        </span>
      ),
    },
    { key: "pushed", header: "Pushed", cell: (r) => <RelativeTime iso={r.pushed_at} /> },
    {
      key: "state",
      header: "State",
      cell: (r) =>
        r.removed_at ? <Badge status="removed" tone="muted" label="Removed from the registry" /> : r.tracked ? <Badge status="tracked" tone="good" label="Scanned" /> : <Badge status="untracked" tone="muted" label="No longer tracked" />,
    },
    { key: "asset", header: "Asset", cell: (r) => (r.asset_id ? <Link to={`/assets/${r.asset_id}`}>Open</Link> : <span className="muted">not added yet</span>) },
  ];
  return (
    <Card title={`Images of ${integration.name}`}>
      <ErrorBox error={res.error} title="Could not load the images" />
      {!res.data && !res.error && <Loading />}
      {res.data && res.data.items.length === 0 && <p className="muted">No images yet. Run the integration to read the registry.</p>}
      {res.data && res.data.items.length > 0 && <Table caption="Registry images" columns={columns} rows={res.data.items} rowKey={(r) => r.id} />}
      <div className="form-actions">
        <button type="button" className="btn" onClick={onClose}>
          Close
        </button>
      </div>
    </Card>
  );
}
