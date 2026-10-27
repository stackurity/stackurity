import { useEffect, useRef, useState, type FormEvent, type ReactNode } from "react";
import { Link, useNavigate, useSearchParams } from "react-router";
import {
  api,
  ApiError,
  type EnrollmentCreated,
  type FirstResult,
  type List,
  type Onboarding,
  type Project,
  type Token,
} from "../api";
import { useAuth } from "../auth";
import { useProject } from "../project";
import { useAction, useLoad } from "../hooks";
import { plural } from "../format";
import { installCommand } from "./AddServer";
import { InviteForm } from "../components/Invite";
import { CodeBlock, ErrorBox, Loading, Notice } from "../components/ui";

/*
 * The first-run flow (0.9): a new organisation's first ten minutes.
 * 1 name a project, 2 add an asset, 3 wait for it to report, 4 the first
 * result in plain words, 5 notifications, 6 invite people. Each step can be
 * skipped; Home keeps a checklist until every step is done.
 */

type Step = "project" | "asset" | "waiting" | "result" | "notify" | "invite";
type Source = "server" | "repo" | "sbom";

const STEPS: { key: Step; label: string }[] = [
  { key: "project", label: "Project" },
  { key: "asset", label: "Add" },
  { key: "waiting", label: "Check" },
  { key: "result", label: "Result" },
  { key: "notify", label: "Alerts" },
  { key: "invite", label: "People" },
];

/** Where to resume: the first step not done yet. */
function firstStep(o: Onboarding): Step {
  if (!o.steps.project || !o.project_id) return "project";
  if (!o.steps.asset) return "asset";
  if (!o.steps.notifications) return "notify";
  return "invite";
}

export function OnboardingPage() {
  const { can } = useAuth();
  const [params] = useSearchParams();
  const ob = useLoad(() => api.getAll<Onboarding>("/onboarding"), []);
  const [step, setStep] = useState<Step | null>(null);
  const [project, setProject] = useState<Project | null>(null);
  const [source, setSource] = useState<Source>("server");
  const [assetName, setAssetName] = useState("");
  // Results are counted from when the flow asked for an asset.
  const [since, setSince] = useState(() => new Date(Date.now() - 10 * 60_000).toISOString());
  const navigate = useNavigate();
  const { choose } = useProject();
  const act = useAction();

  useEffect(() => {
    if (!ob.data || step) return;
    const want = params.get("step") as Step | null;
    setProject(ob.data.project);
    setStep(want && STEPS.some((s) => s.key === want) && (want === "project" || ob.data.project) ? want : firstStep(ob.data));
  }, [ob.data, step, params]);

  if (!can("admin")) {
    return (
      <div className="alert alert-warn" role="alert">
        Setting up is for administrators. Ask one to add your first project.
      </div>
    );
  }
  if (ob.error) return <ErrorBox error={ob.error} title="Could not load the setup" />;
  if (!ob.data || !step) return <Loading />;

  const skip = async () => {
    const ok = await act.run(() => api.put("/onboarding", { state: "skipped" }));
    if (ok !== undefined) navigate(project ? `/?project=${project.id}` : "/");
  };
  const finish = async () => {
    await act.run(() => api.put("/onboarding", { state: "done" }));
    if (project) choose(project.id);
    navigate(project ? `/?project=${project.id}` : "/");
  };
  const index = STEPS.findIndex((s) => s.key === step);

  return (
    <div className="onboard">
      <header className="onboard-head">
        <div>
          <p className="onboard-kicker">Set up Stackurity</p>
          <h1>{TITLES[step]}</h1>
        </div>
        <button type="button" className="btn btn-link onboard-skip" onClick={skip} disabled={act.pending}>
          Skip for now
        </button>
      </header>
      <ol className="onboard-steps" aria-label={`Step ${index + 1} of ${STEPS.length}`}>
        {STEPS.map((s, i) => (
          <li key={s.key} className={i < index ? "done" : i === index ? "current" : undefined} aria-current={i === index ? "step" : undefined}>
            <span className="onboard-dot" aria-hidden="true">
              {i < index ? "✓" : i + 1}
            </span>
            <span className="onboard-step-label">{s.label}</span>
          </li>
        ))}
      </ol>
      <ErrorBox error={act.error} title="Could not save" />

      {step === "project" && (
        <ProjectStep
          onDone={(p) => {
            setProject(p);
            setStep("asset");
          }}
        />
      )}
      {step === "asset" && project && (
        <AssetStep
          project={project}
          source={source}
          setSource={setSource}
          onWaiting={(name) => {
            setAssetName(name);
            setSince(new Date(Date.now() - 2 * 60_000).toISOString());
            setStep("waiting");
          }}
          onLater={() => setStep("notify")}
        />
      )}
      {step === "waiting" && project && (
        <WaitingStep project={project} source={source} name={assetName} since={since} onBack={() => setStep("asset")} onResult={() => setStep("result")} />
      )}
      {step === "result" && project && <ResultStep project={project} since={since} onNext={() => setStep("notify")} />}
      {step === "notify" && project && <NotifyStep project={project} onNext={() => setStep("invite")} />}
      {step === "invite" && project && <InviteStep project={project} onFinish={finish} pending={act.pending} />}
    </div>
  );
}

const TITLES: Record<Step, string> = {
  project: "Create your first project",
  asset: "Add something to check",
  waiting: "Checking",
  result: "Your first result",
  notify: "Turn on notifications",
  invite: "Invite people",
};

function StepCard({ children }: { children: ReactNode }) {
  return <section className="card onboard-card">{children}</section>;
}

// --- 1. project

function ProjectStep({ onDone }: { onDone: (p: Project) => void }) {
  const existing = useLoad(() => api.getAll<{ items: Project[] }>("/projects"), []);
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const act = useAction();

  const create = async (e: FormEvent) => {
    e.preventDefault();
    const p = await act.run(async () => {
      const created = await api.post<Project>("/projects", { name: name.trim(), description: description.trim() });
      await api.put("/onboarding", { project_id: created.id });
      return created;
    });
    if (p) onDone(p);
  };
  const use = async (p: Project) => {
    const ok = await act.run(() => api.put("/onboarding", { project_id: p.id }));
    if (ok !== undefined) onDone(p);
  };
  const projects = existing.data?.items ?? [];

  return (
    <StepCard>
      <p>A project groups what belongs together: a site, a product or a client. You can add more later.</p>
      <form className="form" onSubmit={create}>
        <ErrorBox error={act.error} title="Could not create the project" />
        <div className="field">
          <label htmlFor="ob-name">Project name</label>
          <input id="ob-name" required maxLength={100} value={name} onChange={(e) => setName(e.target.value)} placeholder="e.g. Online shop" autoFocus />
        </div>
        <div className="field">
          <label htmlFor="ob-desc">Description (optional)</label>
          <input id="ob-desc" maxLength={500} value={description} onChange={(e) => setDescription(e.target.value)} placeholder="What it is, who looks after it" />
        </div>
        <div className="form-actions">
          <button type="submit" className="btn btn-primary" disabled={act.pending || !name.trim()}>
            Create project
          </button>
        </div>
      </form>
      {projects.length > 0 && (
        <div className="onboard-existing">
          <p className="small muted">Or continue with a project you already have:</p>
          <ul className="onboard-pills">
            {projects.map((p) => (
              <li key={p.id}>
                <button type="button" className="btn" onClick={() => use(p)} disabled={act.pending}>
                  {p.name}
                </button>
              </li>
            ))}
          </ul>
        </div>
      )}
    </StepCard>
  );
}

// --- 2. asset

const SOURCES: { key: Source; title: string; time: string; text: string }[] = [
  { key: "server", title: "A Linux server", time: "First results in about 2 minutes", text: "Copy one command to the server. It installs a small read-only agent." },
  { key: "repo", title: "A code repository", time: "First results on your next CI run", text: "Add a GitHub Action, or run the stackurity scan command in any CI." },
  { key: "sbom", title: "Upload an SBOM", time: "First results in under a minute", text: "A CycloneDX or SPDX file from your build tool." },
];

function AssetStep({
  project,
  source,
  setSource,
  onWaiting,
  onLater,
}: {
  project: Project;
  source: Source;
  setSource: (s: Source) => void;
  onWaiting: (name: string) => void;
  onLater: () => void;
}) {
  return (
    <>
      <div className="onboard-sources" role="radiogroup" aria-label="What to add">
        {SOURCES.map((s) => (
          <button
            key={s.key}
            type="button"
            role="radio"
            aria-checked={source === s.key}
            className={`onboard-source${source === s.key ? " selected" : ""}`}
            onClick={() => setSource(s.key)}
          >
            <strong>{s.title}</strong>
            <span className="onboard-time">{s.time}</span>
            <span className="small muted">{s.text}</span>
          </button>
        ))}
      </div>
      <StepCard>
        {source === "server" && <ServerSource project={project} onWaiting={onWaiting} />}
        {source === "repo" && <RepoSource project={project} onWaiting={onWaiting} />}
        {source === "sbom" && <SbomSource project={project} onWaiting={onWaiting} />}
      </StepCard>
      <p className="small">
        <button type="button" className="btn btn-link" onClick={onLater}>
          I will add one later
        </button>
      </p>
    </>
  );
}

function ServerSource({ project, onWaiting }: { project: Project; onWaiting: (name: string) => void }) {
  const [created, setCreated] = useState<EnrollmentCreated | null>(null);
  const act = useAction();
  const make = async () => {
    const c = await act.run(() =>
      api.post<EnrollmentCreated>("/enrollments", { label: project.name, project_id: project.id, uses: 5, ttl_hours: 24 }),
    );
    if (c) setCreated(c);
  };
  if (!created) {
    return (
      <div className="form">
        <p>Linux with systemd, root or sudo, and outbound HTTPS from the server to this dashboard.</p>
        <ErrorBox error={act.error} title="Could not create the install command" />
        <div className="form-actions">
          <button type="button" className="btn btn-primary" onClick={make} disabled={act.pending}>
            Show the install command
          </button>
        </div>
      </div>
    );
  }
  const { command, insecure } = installCommand(created.code);
  return (
    <div className="form">
      <p>
        <strong>Run this on the server.</strong> It works for up to 5 servers for 24 hours, and the servers land in {project.name}.
      </p>
      {insecure && (
        <Notice kind="warn">
          This dashboard is open over plain HTTP, so the code would cross the network unencrypted. Use HTTPS if you can.
        </Notice>
      )}
      <CodeBlock text={command} label="Install command" />
      <p className="hint">The code is shown only now. The agent only reads what is installed; it never changes anything.</p>
      <div className="form-actions">
        <button type="button" className="btn btn-primary" onClick={() => onWaiting("")}>
          I ran it
        </button>
      </div>
    </div>
  );
}

function RepoSource({ project, onWaiting }: { project: Project; onWaiting: (name: string) => void }) {
  const [secret, setSecret] = useState<string | null>(null);
  const act = useAction();
  const make = async () => {
    const t = await act.run(() =>
      api.post<{ token: Token; secret: string }>("/tokens", { name: `CI for ${project.name}`, role: "collector", project_id: project.id }),
    );
    if (t) setSecret(t.secret);
  };
  const origin = window.location.origin;
  if (!secret) {
    return (
      <div className="form">
        <p>Your CI reads the lockfiles and sends them here. No code leaves your CI, only the list of packages.</p>
        <ErrorBox error={act.error} title="Could not create a token" />
        <div className="form-actions">
          <button type="button" className="btn btn-primary" onClick={make} disabled={act.pending}>
            Create a token for CI
          </button>
        </div>
      </div>
    );
  }
  const action = `- uses: stackurity/scan-action@v1
  with:
    server: ${origin}
    token: \${{ secrets.STACKURITY_TOKEN }}`;
  const cli = `STACKURITY_SERVER=${origin} STACKURITY_TOKEN=<token> stackurity scan .`;
  return (
    <div className="form">
      <p>
        <strong>1. Save this token as a CI secret named STACKURITY_TOKEN.</strong> It is shown only now, and can only send scans.
      </p>
      <CodeBlock text={secret} label="Collector token" />
      <p>
        <strong>2. GitHub Actions:</strong> add this step after the checkout.
      </p>
      <CodeBlock text={action} label="GitHub Actions step" />
      <p>
        <strong>Other CI:</strong> run the scan command with the token in the environment.
      </p>
      <CodeBlock text={cli} label="Scan command" />
      <div className="form-actions">
        <button type="button" className="btn btn-primary" onClick={() => onWaiting("")}>
          I added it
        </button>
      </div>
    </div>
  );
}

function SbomSource({ project, onWaiting }: { project: Project; onWaiting: (name: string) => void }) {
  const [file, setFile] = useState<File | null>(null);
  const [name, setName] = useState("");
  const act = useAction();
  const upload = async (e: FormEvent) => {
    e.preventDefault();
    if (!file) return;
    const asset = name.trim() || file.name.replace(/\.(json|xml|spdx|cdx)+$/i, "");
    const ok = await act.run(() => uploadSbom(file, asset, project.id));
    if (ok) onWaiting(asset);
  };
  return (
    <form className="form" onSubmit={upload}>
      <ErrorBox error={act.error} title="Could not upload" />
      <div className="field">
        <label htmlFor="ob-sbom">SBOM file (CycloneDX or SPDX JSON)</label>
        <input id="ob-sbom" type="file" accept=".json,application/json" required onChange={(e) => setFile(e.target.files?.[0] ?? null)} />
      </div>
      <div className="field">
        <label htmlFor="ob-sbom-name">Name (optional)</label>
        <input id="ob-sbom-name" maxLength={200} value={name} onChange={(e) => setName(e.target.value)} placeholder="e.g. shop-api" />
        <p className="hint">What the application is called. The file name is used otherwise.</p>
      </div>
      <div className="form-actions">
        <button type="submit" className="btn btn-primary" disabled={act.pending || !file}>
          {act.pending ? "Uploading…" : "Upload"}
        </button>
      </div>
    </form>
  );
}

async function uploadSbom(file: File, assetName: string, projectId: number): Promise<boolean> {
  const q = new URLSearchParams({ asset_name: assetName, asset_kind: "application", project_id: String(projectId) });
  const res = await fetch(`/api/v1/sbom/import?${q}`, {
    method: "POST",
    credentials: "same-origin",
    headers: { "X-Stackurity-CSRF": "1", "Content-Type": "application/json", Accept: "application/json" },
    body: await file.text(),
  });
  if (!res.ok) {
    let msg = `Upload failed (${res.status})`;
    let code = "http_" + res.status;
    try {
      const d = (await res.json()) as { error?: { message?: string; code?: string } };
      msg = d.error?.message ?? msg;
      code = d.error?.code ?? code;
    } catch {
      /* not JSON */
    }
    throw new ApiError(res.status, code, msg);
  }
  return true;
}

// --- 3. waiting

const POLL_MS = 3000;

function useResults(project: Project, since: string, live: boolean) {
  const [data, setData] = useState<FirstResult[] | null>(null);
  const [error, setError] = useState<ApiError | null>(null);
  const timer = useRef<number>();
  useEffect(() => {
    let stop = false;
    const tick = async () => {
      try {
        const r = await api.getAll<List<FirstResult>>("/onboarding/results", { since, project_id: project.id });
        if (stop) return;
        setData(r.items);
        setError(null);
      } catch (e) {
        if (!stop) setError(e as ApiError);
      }
      if (!stop && live) timer.current = window.setTimeout(tick, POLL_MS);
    };
    void tick();
    return () => {
      stop = true;
      window.clearTimeout(timer.current);
    };
  }, [project.id, since, live]);
  return { data, error };
}

function WaitingStep({
  project,
  source,
  name,
  since,
  onBack,
  onResult,
}: {
  project: Project;
  source: Source;
  name: string;
  since: string;
  onBack: () => void;
  onResult: () => void;
}) {
  const { data, error } = useResults(project, since, true);
  const [elapsed, setElapsed] = useState(0);
  useEffect(() => {
    const t = window.setInterval(() => setElapsed((s) => s + 1), 1000);
    return () => window.clearInterval(t);
  }, []);
  const assets = data ?? [];
  const done = assets.length > 0 && assets.every((a) => a.checked);
  useEffect(() => {
    if (done) {
      const t = window.setTimeout(onResult, 1200);
      return () => window.clearTimeout(t);
    }
  }, [done, onResult]);

  const what = name || (source === "server" ? "your server" : source === "repo" ? "your repository" : "your SBOM");
  const usually = source === "repo" ? "It reports on the next CI run." : source === "sbom" ? "This usually takes under a minute." : "This usually takes under 2 minutes.";
  const slow = elapsed > (source === "repo" ? 600 : 300);

  return (
    <StepCard>
      <ErrorBox error={error} title="Could not check progress" />
      {assets.length === 0 ? (
        <div className="onboard-wait" role="status" aria-live="polite">
          <span className="onboard-spinner" aria-hidden="true" />
          <div>
            <p className="onboard-big">Waiting for {what} to report...</p>
            <p className="muted">
              {usually} Waiting for {formatElapsed(elapsed)}.
            </p>
          </div>
        </div>
      ) : (
        <ul className="onboard-live" aria-live="polite">
          {assets.map((a) => (
            <li key={a.id}>
              {!a.checked && <span className="onboard-spinner" aria-hidden="true" />}
              {a.checked && (
                <span className="onboard-check" aria-hidden="true">
                  ✓
                </span>
              )}
              <div>
                <p className="onboard-big">
                  {a.name}: {plural(a.packages, "package")} found
                </p>
                <p className="muted">
                  {a.checked
                    ? `Checked. ${plural(a.issues, "issue")} found.`
                    : `Checking them against vulnerability and end-of-life data${a.issues > 0 ? `: ${plural(a.issues, "issue")} so far` : ""}...`}
                </p>
              </div>
            </li>
          ))}
        </ul>
      )}
      {slow && assets.length === 0 && (
        <Notice kind="info">
          Taking longer than usual?{" "}
          {source === "server" ? (
            <>
              Check that the command finished without errors, and that the server can reach this dashboard over HTTPS. See{" "}
              <Link to="/help/add-linux-server">Add a Linux server</Link>.
            </>
          ) : source === "repo" ? (
            <>
              Push a commit, or run the pipeline by hand. See <Link to="/help/repositories">Add a repository</Link>.
            </>
          ) : (
            <>Upload the file again. See <Link to="/help/sbom">Import an SBOM</Link>.</>
          )}
        </Notice>
      )}
      <div className="form-actions">
        <button type="button" className="btn" onClick={onBack}>
          Back
        </button>
        {assets.length > 0 && (
          <button type="button" className="btn btn-primary" onClick={onResult}>
            {done ? "See the result" : "Continue while it checks"}
          </button>
        )}
      </div>
    </StepCard>
  );
}

function formatElapsed(s: number): string {
  if (s < 60) return `${s} s`;
  return `${Math.floor(s / 60)} min ${s % 60} s`;
}

// --- 4. result

function ResultStep({ project, since, onNext }: { project: Project; since: string; onNext: () => void }) {
  const { data, error } = useResults(project, since, true);
  if (error) return <ErrorBox error={error} title="Could not load the result" />;
  if (!data) return <Loading />;
  const checked = data.filter((a) => a.checked);
  const q = `project=${project.id}`;
  return (
    <StepCard>
      {data.length === 0 && <p>Nothing has reported yet. You can come back to this from Home.</p>}
      {checked.map((a) => (
        <div key={a.id} className="onboard-result">
          <p className="onboard-headline">
            We found {plural(a.packages, "package")} on {a.name}.{" "}
            {a.fixes_now === 0 ? "Nothing needs fixing right now." : `${plural(a.fixes_now, "fix", "fixes")} ${a.fixes_now === 1 ? "matters" : "matter"} now.`}
          </p>
          <p className="muted">
            {a.issues === 0
              ? "No known vulnerabilities or end-of-life software."
              : `${plural(a.issues, "issue")} in all. Fixes group them into jobs, most urgent first.`}
          </p>
          <p className="onboard-links">
            {a.fixes_now > 0 && (
              <Link className="btn btn-primary" to={`/?${q}`}>
                See what matters now
              </Link>
            )}
            <Link className="btn" to={`/fixes?asset_id=${a.id}&${q}`}>
              All fixes for {a.name}
            </Link>
          </p>
        </div>
      ))}
      {data.length > checked.length && (
        <p className="muted">
          Still checking {plural(data.length - checked.length, "asset")}. The result appears on Home when it is ready.
        </p>
      )}
      <Notice kind="info">
        Connecting an asset does not set off alerts for what it already had. You get one message that it connected, then alerts for new issues only.
      </Notice>
      <div className="form-actions">
        <button type="button" className="btn btn-primary" onClick={onNext}>
          Next: notifications
        </button>
      </div>
    </StepCard>
  );
}

// --- 5. notifications

type Kind = "slack" | "email";
type Mode = "urgent_summary" | "urgent_only" | "weekly";

const MODE_ROUTE_NAME: Record<Mode, string> = {
  urgent_summary: "urgent and daily summary",
  urgent_only: "urgent only",
  weekly: "weekly summary",
};

const MODE_DONE: Record<Mode, string> = {
  urgent_summary: "Urgent issues arrive right away, with a summary each day at 09:00.",
  urgent_only: "Urgent issues arrive right away, with no summary.",
  weekly: "A summary arrives on Mondays at 09:00.",
};

function secretName(project: Project, kind: Kind): string {
  const slug = project.name.toUpperCase().replace(/[^A-Z0-9]+/g, "_").replace(/^_+|_+$/g, "").slice(0, 30) || "PROJECT";
  return `${kind.toUpperCase()}_${slug}_${project.id}`;
}

function NotifyStep({ project, onNext }: { project: Project; onNext: () => void }) {
  const [kind, setKind] = useState<Kind>("slack");
  const [mode, setMode] = useState<Mode>("urgent_summary");
  const [webhook, setWebhook] = useState("");
  const [to, setTo] = useState("");
  const [host, setHost] = useState("");
  const [port, setPort] = useState("587");
  const [from, setFrom] = useState("");
  const [user, setUser] = useState("");
  const [password, setPassword] = useState("");
  const [saved, setSaved] = useState<{ channel: number } | null>(null);
  const [tested, setTested] = useState<string | null>(null);
  const act = useAction();

  const save = async (e: FormEvent) => {
    e.preventDefault();
    const r = await act.run(async () => {
      let ref = "";
      if (kind === "slack" || password) {
        ref = secretName(project, kind);
        await api.put(`/secrets/${ref}`, { value: kind === "slack" ? webhook.trim() : password });
        ref = `secret:${ref}`;
      }
      const config =
        kind === "slack"
          ? {}
          : { host: host.trim(), port: Number(port) || 587, from: from.trim(), to: [to.trim()], username: user.trim() || undefined };
      const ch = await api.post<{ id: number }>("/channels", { kind, name: `${project.name} (${kind === "slack" ? "Slack" : "email"})`, config, secret_ref: ref });
      const tz = Intl.DateTimeFormat().resolvedOptions().timeZone || "UTC";
      await api.post("/routes", {
        name: `${project.name}: ${MODE_ROUTE_NAME[mode]}`,
        channel_id: ch.id,
        enabled: true,
        project_ids: [project.id],
        mode,
        min_priority: "P1",
        summary_time: "09:00",
        summary_day: "monday",
        timezone: tz,
        max_per_hour: 10,
        send_resolved: true,
      });
      return { channel: ch.id };
    });
    if (r) setSaved(r);
  };
  const test = async () => {
    if (!saved) return;
    const r = await act.run(() => api.post<{ ok: boolean; error?: string }>(`/channels/${saved.channel}/test`));
    if (r) setTested(r.ok ? "Test message sent. Check that it arrived." : `The test failed: ${r.error ?? "unknown error"}`);
  };
  const noKey = act.error?.message.includes("STACKURITY_SECRET_KEY");

  if (saved) {
    return (
      <StepCard>
        <Notice kind="success">
          Notifications are on for {project.name}. {MODE_DONE[mode]}
        </Notice>
        {tested && <Notice kind={tested.startsWith("Test message") ? "success" : "warn"}>{tested}</Notice>}
        <ErrorBox error={act.error} title="Could not send a test" />
        <p className="small">Each fix in a message has Assign to me, Snooze and Open buttons that open it here.</p>
        <div className="form-actions">
          <button type="button" className="btn" onClick={test} disabled={act.pending}>
            Send a test message
          </button>
          <button type="button" className="btn btn-primary" onClick={onNext}>
            Next: invite people
          </button>
        </div>
      </StepCard>
    );
  }

  return (
    <StepCard>
      <form className="form" onSubmit={save}>
        <fieldset className="field">
          <legend>Where</legend>
          <div className="onboard-toggle">
            <label className="choice">
              <input type="radio" name="ob-kind" checked={kind === "slack"} onChange={() => setKind("slack")} /> <span>Slack</span>
            </label>
            <label className="choice">
              <input type="radio" name="ob-kind" checked={kind === "email"} onChange={() => setKind("email")} /> <span>Email</span>
            </label>
          </div>
        </fieldset>
        {kind === "slack" ? (
          <div className="field">
            <label htmlFor="ob-webhook">Slack incoming webhook URL</label>
            <input id="ob-webhook" type="url" required pattern="https://.*" value={webhook} onChange={(e) => setWebhook(e.target.value)} placeholder="https://hooks.slack.com/services/..." autoComplete="off" />
            <p className="hint">
              In Slack: Apps, Incoming Webhooks, Add to Slack, pick the channel. It is stored encrypted, as a secret.
            </p>
          </div>
        ) : (
          <div className="form-grid">
            <div className="field field-span">
              <label htmlFor="ob-to">Send to</label>
              <input id="ob-to" type="email" required value={to} onChange={(e) => setTo(e.target.value)} placeholder="security@example.com" />
            </div>
            <div className="field">
              <label htmlFor="ob-host">Mail server (SMTP)</label>
              <input id="ob-host" required value={host} onChange={(e) => setHost(e.target.value)} placeholder="smtp.example.com" />
            </div>
            <div className="field">
              <label htmlFor="ob-port">Port</label>
              <input id="ob-port" type="number" min={1} max={65535} required value={port} onChange={(e) => setPort(e.target.value)} />
            </div>
            <div className="field">
              <label htmlFor="ob-from">From</label>
              <input id="ob-from" type="email" required value={from} onChange={(e) => setFrom(e.target.value)} placeholder="stackurity@example.com" />
            </div>
            <div className="field">
              <label htmlFor="ob-user">Username (optional)</label>
              <input id="ob-user" value={user} onChange={(e) => setUser(e.target.value)} autoComplete="off" />
            </div>
            <div className="field field-span">
              <label htmlFor="ob-pass">Password (optional)</label>
              <input id="ob-pass" type="password" value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="new-password" />
              <p className="hint">Stored encrypted, as a secret. This mail server also sends your invitations.</p>
            </div>
          </div>
        )}
        <fieldset className="field">
          <legend>What</legend>
          <ul className="choice-list">
            <li>
              <label className="choice">
                <input type="radio" name="ob-mode" checked={mode === "urgent_summary"} onChange={() => setMode("urgent_summary")} />
                <span>
                  <strong>Urgent issues right away</strong>
                  <span className="hint"> P1, SOS and known exploited, with a short summary each day.</span>
                </span>
              </label>
            </li>
            <li>
              <label className="choice">
                <input type="radio" name="ob-mode" checked={mode === "urgent_only"} onChange={() => setMode("urgent_only")} />
                <span>
                  <strong>Urgent issues only</strong>
                  <span className="hint"> P1, SOS, known exploited and issues that came back, right away. No summaries.</span>
                </span>
              </label>
            </li>
            <li>
              <label className="choice">
                <input type="radio" name="ob-mode" checked={mode === "weekly"} onChange={() => setMode("weekly")} />
                <span>
                  <strong>A weekly summary</strong>
                  <span className="hint"> On Mondays: what is new, what was fixed, the top fixes.</span>
                </span>
              </label>
            </li>
          </ul>
        </fieldset>
        {noKey ? (
          <Notice kind="warn">
            This server cannot store secrets yet. Ask whoever runs it to set STACKURITY_SECRET_KEY, or set notifications up later under{" "}
            <Link to="/settings/notifications">Settings, Notifications</Link>.
          </Notice>
        ) : (
          <ErrorBox error={act.error} title="Could not turn on notifications" />
        )}
        <div className="form-actions">
          <button type="submit" className="btn btn-primary" disabled={act.pending}>
            Turn on
          </button>
          <button type="button" className="btn" onClick={onNext}>
            Not now
          </button>
        </div>
      </form>
    </StepCard>
  );
}

// --- 6. invite

function InviteStep({ project, onFinish, pending }: { project: Project; onFinish: () => void; pending: boolean }) {
  return (
    <StepCard>
      <p>People you invite see {project.name} only, with the role you choose. You can invite more people later from the project's page.</p>
      <InviteForm projectId={project.id} projectName={project.name} />
      <div className="form-actions onboard-finish">
        <button type="button" className="btn btn-primary" onClick={onFinish} disabled={pending}>
          Finish
        </button>
      </div>
    </StepCard>
  );
}

/**
 * Home's checklist while setup is not done: what is left, each a link back
 * into the flow. Admins only.
 */
export function SetupChecklist({ o, onChange }: { o: Onboarding; onChange: () => void }) {
  const act = useAction();
  const items: { done: boolean; text: string; step: Step }[] = [
    { done: o.steps.project, text: "Create a project", step: "project" },
    { done: o.steps.asset, text: "Add a server, repository or SBOM", step: "asset" },
    { done: o.steps.notifications, text: "Turn on notifications", step: "notify" },
    { done: o.steps.invite, text: "Invite people", step: "invite" },
  ];
  const left = items.filter((i) => !i.done).length;
  const hide = async () => {
    const ok = await act.run(() => api.put("/onboarding", { state: "done" }));
    if (ok !== undefined) onChange();
  };
  return (
    <section className="card setup-checklist" aria-labelledby="setup-h">
      <div className="card-head">
        <h2 id="setup-h">Finish setting up ({plural(left, "step")} left)</h2>
        <button type="button" className="btn btn-link" onClick={hide} disabled={act.pending}>
          Hide
        </button>
      </div>
      <ErrorBox error={act.error} title="Could not hide the checklist" />
      <ul className="setup-list">
        {items.map((i) => (
          <li key={i.step} className={i.done ? "done" : undefined}>
            <span className="onboard-dot" aria-hidden="true">
              {i.done ? "✓" : ""}
            </span>
            {i.done ? (
              <span>
                {i.text}
                <span className="sr-only"> (done)</span>
              </span>
            ) : (
              <Link to={`/get-started?step=${i.step}`}>{i.text}</Link>
            )}
          </li>
        ))}
      </ul>
    </section>
  );
}
