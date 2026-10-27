import { useMemo, useState, type FormEvent, type ReactNode } from "react";
import { Link } from "react-router";
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
} from "../api";
import { useAuth } from "../auth";
import { useAction, useJobRunner, useLoad } from "../hooks";
import { minutesLabel } from "../format";
import { Badge } from "../components/Badge";
import { Table, type Column } from "../components/Table";
import { Card, Code, EmptyState, ErrorBox, JobStatus, Loading, Notice, PageHeader, RelativeTime } from "../components/ui";

function healthOf(i: Integration): { status: string; tone?: "good" | "bad" | "muted" | "warn" } {
  if (!i.enabled) return { status: "disabled", tone: "muted" };
  if (i.last_error) return { status: "failed" };
  if (!i.last_attempt) return { status: "pending" };
  return { status: "ok" };
}

const KIND_LABEL: Record<string, string> = {
  git_repository: "Git repository",
  container_image: "Container image",
  plugin: "Plugin",
};

function KindBadge({ kind }: { kind: string }) {
  return <Badge status={kind} tone="info" label={KIND_LABEL[kind] ?? kind} />;
}

function targetOf(i: Integration): ReactNode {
  const c = i.config ?? {};
  if (i.kind === "git_repository") return `${c.url ?? ""}${c.ref ? ` @ ${c.ref}` : ""}`;
  if (i.kind === "container_image") return `${c.image ?? ""}${c.platform ? ` (${c.platform})` : ""}`;
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
  const [creating, setCreating] = useState<IntegrationKind | "choose" | null>(null);

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
    if (!window.confirm(`Delete the integration "${i.name}"? The assets and their inventory are kept.`)) return;
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
      {admin && creating === "container_image" && <ImageForm onCancel={() => setCreating(null)} onCreated={done} />}
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
    </>
  );
}

function KindChooser({ onPick, onCancel }: { onPick: (k: IntegrationKind) => void; onCancel: () => void }) {
  const kinds: { kind: IntegrationKind; title: string; text: string }[] = [
    { kind: "git_repository", title: "Git repository", text: "Clone over HTTPS and read lockfiles (npm, Composer, …)." },
    { kind: "container_image", title: "Container image", text: "Pull an image from a registry and inventory its OS and application packages." },
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
  if (s && !/^(env|file):.+/.test(s)) return "Secret reference must look like env:NAME or file:/path.";
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
