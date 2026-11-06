import { useState, type FormEvent } from "react";
import { api, type CITrust, type CITrustList, type List, type Project } from "../../api";
import { useAction, useLoad } from "../../hooks";
import { confirmAction } from "../../components/ConfirmDialog";
import { CodeBlock, ErrorBox, FieldGroup, Notice, RelativeTime } from "../../components/ui";
import { PlanLimitNote } from "../../components/PlanLimit";

/*
 * Keyless CI scans (Integrations → CI pipeline): CI trusts, and
 * the workflow snippets that use them. A trust lets a CI provider's ID token
 * for one repository (or, chosen explicitly, every repository of an owner)
 * be exchanged for a collector token that lives 15 minutes and can report
 * only that repository.
 */

export const GITHUB_ISSUER = "https://token.actions.githubusercontent.com";
export const GITLAB_ISSUER = "https://gitlab.com";

/**
 * The workflow snippets for keyless scans, filled in with this server's URL
 * and audience, and the trust to use when one is chosen (a server that hosts
 * several organisations needs it).
 */
export function keylessSnippets(server: string, audience: string, trust?: number) {
  const github = `permissions:
  contents: read
  id-token: write   # lets the job prove which repository it runs for
steps:
  - uses: actions/checkout@v4
  - uses: stackurity/scan-action@v1
    with:
      server: ${server}${trust ? `\n      ci-trust: "${trust}"` : ""}`;
  const gitlab = `stackurity:
  image:
    name: ghcr.io/stackurity/stackurity:latest
    entrypoint: [""]
  id_tokens:
    STACKURITY_ID_TOKEN:
      aud: ${audience}
  variables:
    STACKURITY_SERVER: ${server}${trust ? `\n    STACKURITY_CI_TRUST: "${trust}"` : ""}
  script:
    - stackurity scan .
  rules:
    - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH`;
  return { github, gitlab };
}

function describe(t: CITrust): string {
  const parts = [t.owner_wildcard ? `every repository of ${t.repository.replace(/\/\*$/, "")}` : t.repository];
  if (t.ref) parts.push(t.ref.replace(/^refs\/heads\//, "branch "));
  if (t.environment) parts.push(`environment ${t.environment}`);
  if (t.workflow_ref) parts.push(`workflow ${t.workflow_ref}`);
  return parts.join(", ");
}

/** The trusts and, for an admin, adding and deleting them. */
export function CiTrusts({ admin }: { admin: boolean }) {
  const list = useLoad(() => (admin ? api.get<CITrustList>("/ci-trusts") : Promise.resolve(null)), [admin]);
  const meta = useLoad(() => api.meta(), []);
  const [adding, setAdding] = useState(false);
  const act = useAction();
  const server = window.location.origin;
  const audience = list.data?.audience || meta.data?.ci_audience || "";
  const [chosen, setChosen] = useState(0);
  const items = list.data?.items ?? [];
  const trust = items.find((t) => t.id === chosen) ?? items[0];
  const { github, gitlab } = keylessSnippets(server, audience || server, trust?.id);

  const remove = async (t: CITrust) => {
    if (
      !(await confirmAction({
        title: `Delete the CI trust for ${t.repository}?`,
        consequence: "Pipelines of this repository can no longer scan without a token, and tokens issued to running jobs stop working.",
        action: "Delete trust",
        destructive: true,
      }))
    )
      return;
    if ((await act.run(() => api.del(`/ci-trusts/${t.id}`).then(() => true))) === true) list.reload();
  };

  return (
    <div className="int-panel">
      <p>
        <strong>Without a stored secret (recommended).</strong> The pipeline proves which repository it runs for with the CI provider's signed ID token,
        and gets a token that lasts 15 minutes and can only report that repository. Nothing to store or rotate.
      </p>
      {!audience && (
        <Notice kind="warn">
          This server has no public URL, so it cannot accept CI ID tokens. The administrator of the installation sets{" "}
          <span className="mono">STACKURITY_BASE_URL</span> (or <span className="mono">STACKURITY_CI_AUDIENCE</span>).
        </Notice>
      )}
      <p>
        <strong>1.</strong> Trust the repository here{admin ? "" : " (an administrator does this)"}.
      </p>
      {admin && <PlanLimitNote kind="ci_trusts" />}
      {admin && (
        <>
          <ErrorBox error={list.error} title="Could not load CI trusts" />
          <ErrorBox error={act.error} title="Could not delete the trust" />
          {list.data && list.data.items.length > 0 && (
            <ul className="ci-trusts">
              {list.data.items.map((t) => (
                <li key={t.id}>
                  <span className="mono small">#{t.id}</span> <strong>{t.provider === "github" ? "GitHub Actions" : "GitLab"}</strong>: {describe(t)}
                  {t.provider === "gitlab" && t.issuer !== GITLAB_ISSUER && <span className="muted small"> ({t.issuer})</span>}
                  {t.project_id && <span className="muted small"> → project {t.project_id}</span>}
                  <span className="muted small">
                    {" "}
                    · last used <RelativeTime iso={t.last_used_at} />
                  </span>{" "}
                  <button type="button" className="btn btn-link btn-sm" onClick={() => remove(t)} disabled={act.pending}>
                    Delete
                  </button>
                </li>
              ))}
            </ul>
          )}
          {adding ? (
            <TrustForm
              onCancel={() => setAdding(false)}
              onSaved={() => {
                setAdding(false);
                list.reload();
              }}
            />
          ) : (
            <p>
              <button type="button" className="btn btn-sm" onClick={() => setAdding(true)}>
                Trust a repository
              </button>
            </p>
          )}
        </>
      )}
      {items.length > 1 && (
        <div className="field">
          <label htmlFor="ci-snippet-trust">Snippets for</label>
          <select id="ci-snippet-trust" value={trust?.id ?? 0} onChange={(e) => setChosen(Number(e.target.value))}>
            {items.map((t) => (
              <option key={t.id} value={t.id}>
                #{t.id} {t.repository}
              </option>
            ))}
          </select>
        </div>
      )}
      <p>
        <strong>2. GitHub Actions:</strong> give the job permission to request an ID token. Without a <span className="mono">token</span> input the action
        exchanges it.
      </p>
      <CodeBlock text={github} label="GitHub Actions job (keyless)" />
      <p>
        <strong>GitLab CI:</strong> request an ID token for this server in <span className="mono">id_tokens</span>.
      </p>
      <CodeBlock text={gitlab} label="GitLab CI job (keyless)" />
    </div>
  );
}

function TrustForm({ onCancel, onSaved }: { onCancel: () => void; onSaved: () => void }) {
  const [provider, setProvider] = useState<"github" | "gitlab">("github");
  const [issuer, setIssuer] = useState(GITLAB_ISSUER);
  const [repository, setRepository] = useState("");
  const [wildcard, setWildcard] = useState(false);
  const [ref, setRef] = useState("");
  const [environment, setEnvironment] = useState("");
  const [workflowRef, setWorkflowRef] = useState("");
  const [project, setProject] = useState(0);
  const projects = useLoad(() => api.getAll<List<Project>>("/projects"), []);
  const act = useAction();
  const repoOk = wildcard ? /^[A-Za-z0-9_.-]+(\/[A-Za-z0-9_.-]+)*(\/\*)?$/.test(repository.trim()) : /^[A-Za-z0-9_.-]+(\/[A-Za-z0-9_.-]+)+$/.test(repository.trim());
  const submit = async (e: FormEvent) => {
    e.preventDefault();
    const ok = await act.run(() =>
      api
        .post<CITrust>("/ci-trusts", {
          provider,
          issuer: provider === "gitlab" ? issuer.trim() : "",
          repository: repository.trim(),
          owner_wildcard: wildcard,
          ref: ref.trim(),
          environment: environment.trim(),
          workflow_ref: workflowRef.trim(),
          project_id: project,
        })
        .then(() => true),
    );
    if (ok) onSaved();
  };
  const owner = provider === "github" ? "owner" : "group";
  return (
    <form className="form card" onSubmit={submit} aria-label="Trust a repository">
      <ErrorBox error={act.error} title="Could not add the trust" />
      <FieldGroup title="Which pipeline" description="The CI system and the repository allowed to send scans. It proves who it is with a short-lived token from the CI system, so no secret is stored.">
      <div className="form-grid">
        <div className="field">
          <label htmlFor="ci-provider">CI provider</label>
          <select id="ci-provider" value={provider} onChange={(e) => setProvider(e.target.value as "github" | "gitlab")}>
            <option value="github">GitHub Actions</option>
            <option value="gitlab">GitLab CI</option>
          </select>
        </div>
        {provider === "gitlab" && (
          <div className="field">
            <label htmlFor="ci-issuer">GitLab URL</label>
            <input id="ci-issuer" type="url" required value={issuer} onChange={(e) => setIssuer(e.target.value)} />
            <p className="hint">https://gitlab.com, or your self-managed instance's https URL.</p>
          </div>
        )}
        <div className="field">
          <label htmlFor="ci-repo">{wildcard ? (provider === "github" ? "Owner" : "Group") : provider === "github" ? "Repository" : "Project path"}</label>
          <input
            id="ci-repo"
            required
            autoComplete="off"
            placeholder={wildcard ? (provider === "github" ? "acme" : "acme/backend") : provider === "github" ? "acme/shop" : "acme/backend/shop"}
            value={repository}
            onChange={(e) => setRepository(e.target.value)}
          />
          <label className="check">
            <input type="checkbox" checked={wildcard} onChange={(e) => setWildcard(e.target.checked)} /> Every repository of this {owner}
          </label>
          {wildcard && <p className="hint">Any repository under the {owner} can then scan, each as its own asset. Prefer one trust per repository.</p>}
        </div>
      </div>
      </FieldGroup>
      <FieldGroup title="Narrow it down (optional)" description="Accept scans only from a branch, deployment environment or workflow. Empty fields accept any.">
      <div className="form-grid">
        <div className="field">
          <label htmlFor="ci-ref">Branch or ref (optional)</label>
          <input id="ci-ref" autoComplete="off" placeholder="main" value={ref} onChange={(e) => setRef(e.target.value)} />
          <p className="hint">Only scans from this branch (or full ref, such as refs/tags/v1.0). Empty: any branch.</p>
        </div>
        <div className="field">
          <label htmlFor="ci-env">Deployment environment (optional)</label>
          <input id="ci-env" autoComplete="off" value={environment} onChange={(e) => setEnvironment(e.target.value)} />
        </div>
        <div className="field">
          <label htmlFor="ci-wf">{provider === "github" ? "Workflow (job_workflow_ref, optional)" : "CI configuration (ci_config_ref_uri, optional)"}</label>
          <input
            id="ci-wf"
            autoComplete="off"
            placeholder={provider === "github" ? "acme/shop/.github/workflows/scan.yml@refs/heads/main" : ""}
            value={workflowRef}
            onChange={(e) => setWorkflowRef(e.target.value)}
          />
        </div>
      </div>
      </FieldGroup>
      <FieldGroup title="Where results go" description="Optional. Put the repository these scans create into a project.">
      <div className="form-grid">
        <div className="field">
          <label htmlFor="ci-project">Project (optional)</label>
          <select id="ci-project" value={project} onChange={(e) => setProject(Number(e.target.value))}>
            <option value={0}>None</option>
            {(projects.data?.items ?? []).map((p) => (
              <option key={p.id} value={p.id}>
                {p.name}
              </option>
            ))}
          </select>
          <p className="hint">A repository these scans create is added to it.</p>
        </div>
      </div>
      </FieldGroup>
      <div className="form-actions">
        <button type="submit" className="btn btn-primary btn-sm" disabled={act.pending || !repoOk}>
          Trust
        </button>
        <button type="button" className="btn btn-sm" onClick={onCancel}>
          Cancel
        </button>
      </div>
    </form>
  );
}
