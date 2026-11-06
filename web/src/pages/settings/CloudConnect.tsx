import { useState, type FormEvent } from "react";
import { Link } from "react-router";
import { api, type Integration, type PluginList } from "../../api";
import { useAction, useLoad } from "../../hooks";
import { CodeBlock, ErrorBox, Notice } from "../../components/ui";

/*
 * Connect a Google Cloud project or an Azure subscription. The server
 * generates the commands (GET /cloud-setup/{gcp,azure}), so the role they
 * create grants exactly the calls the plugin makes; this page fills in the
 * ids, shows them and creates the plugin integration.
 */

interface CloudSetup {
  provider: "gcp" | "azure";
  keyless: boolean;
  keyless_unavailable?: string;
  commands?: string;
  config?: Record<string, unknown>;
  consent_url?: string;
  fallback_commands: string;
  fallback_config: Record<string, unknown>;
  fallback_secret: string;
  permissions: string[];
  plugin: string;
}

const TEXT = {
  gcp: {
    name: "Google Cloud",
    ids: [
      { key: "project_id", label: "Project id", placeholder: "acme-prod", hint: "Lowercase letters, digits and hyphens." },
      { key: "project_number", label: "Project number", placeholder: "123456789012", hint: "Digits, shown next to the project id on the Google Cloud console's Welcome page." },
    ],
    shell: { name: "Cloud Shell", url: "https://shell.cloud.google.com/" },
    run: "Run these commands in Cloud Shell, or wherever gcloud is signed in as a project owner.",
    help: "/help/google-cloud",
    fallbackTitle: "Use a service account key instead",
  },
  azure: {
    name: "Azure",
    ids: [
      { key: "tenant_id", label: "Directory (tenant) id", placeholder: "00000000-0000-0000-0000-000000000000", hint: "Microsoft Entra ID ▸ Overview." },
      { key: "subscription_id", label: "Subscription id", placeholder: "00000000-0000-0000-0000-000000000000", hint: "Subscriptions ▸ your subscription." },
    ],
    shell: { name: "Azure Cloud Shell", url: "https://shell.azure.com/" },
    run: "Run these commands in Azure Cloud Shell, or wherever az is signed in as an Owner or User Access Administrator of the subscription.",
    help: "/help/azure",
    fallbackTitle: "Use a service principal with a client secret instead",
  },
} as const;

export function CloudConnectPanel({ provider, admin }: { provider: "gcp" | "azure"; admin: boolean }) {
  const t = TEXT[provider];
  const [ids, setIds] = useState<Record<string, string>>({});
  const [setup, setSetup] = useState<CloudSetup | null>(null);
  const [secretName, setSecretName] = useState("");
  const [created, setCreated] = useState<Integration | null>(null);
  const load = useAction();
  const create = useAction();
  const plugins = useLoad(() => (admin ? api.get<PluginList>("/plugins") : Promise.resolve(null)), [admin]);
  const pluginName = provider === "gcp" ? "gcp-managed" : "azure-managed";
  const installed = (plugins.data?.items ?? []).some((p) => p.name === pluginName && p.metadata && !p.error);

  if (!admin) return <p className="muted">An administrator can connect {t.name}.</p>;

  const show = async (e: FormEvent) => {
    e.preventDefault();
    setCreated(null);
    const q: Record<string, string> = {};
    for (const f of t.ids) q[f.key] = (ids[f.key] ?? "").trim();
    const r = await load.run(() => api.get<CloudSetup>(`/cloud-setup/${provider}`, q));
    if (r) setSetup(r);
  };

  const add = async (config: Record<string, unknown>, secretRef?: string) => {
    const body: Record<string, unknown> = { kind: "plugin", config: { plugin: pluginName, config }, schedule_minutes: 720 };
    if (secretRef) body.secret_ref = secretRef;
    const r = await create.run(() => api.post<Integration>("/integrations", body));
    if (r) setCreated(r);
  };

  return (
    <div className="int-panel">
      {plugins.data && !installed && (
        <Notice kind="warn">
          The <span className="mono">{pluginName}</span> plugin is not installed on this server. It ships in the Stackurity image; see{" "}
          <Link to="/integrations/plugins">Integrations → Plugins</Link>.
        </Notice>
      )}
      <p>
        How it works: enter the {provider === "gcp" ? "project" : "subscription"} below, run the commands Stackurity writes for it in{" "}
        <a href={t.shell.url} target="_blank" rel="noopener noreferrer">
          {t.shell.name}
        </a>
        , then create the integration. Access is read-only and no key is needed.
      </p>
      <form className="form" onSubmit={show}>
        <p>
          <strong>1.</strong> Your {provider === "gcp" ? "Google Cloud project" : "Azure subscription"}
        </p>
        <div className="form-grid">
          {t.ids.map((f) => (
            <div className="field" key={f.key}>
              <label htmlFor={`cc-${provider}-${f.key}`}>{f.label}</label>
              <input
                id={`cc-${provider}-${f.key}`}
                className="mono"
                required
                placeholder={f.placeholder}
                value={ids[f.key] ?? ""}
                onChange={(e) => setIds({ ...ids, [f.key]: e.target.value })}
              />
              <p className="hint">{f.hint}</p>
            </div>
          ))}
        </div>
        <div className="form-actions">
          <button type="submit" className="btn btn-primary" disabled={load.pending}>
            {load.pending ? "Generating…" : "Next: get the commands"}
          </button>
        </div>
      </form>
      <ErrorBox error={load.error} title="Could not generate the commands" />
      {setup && (
        <>
          {setup.keyless ? (
            <>
              {setup.consent_url && (
                <p>
                  <strong>2.</strong> Add Stackurity's app to your tenant:{" "}
                  <a className="btn btn-sm" href={setup.consent_url} target="_blank" rel="noopener noreferrer">
                    Open admin consent
                  </a>{" "}
                  <span className="muted small">(or let the commands below do it). It asks for no API permissions.</span>
                </p>
              )}
              <p>
                <strong>{setup.consent_url ? "3." : "2."}</strong> {t.run} No key or secret is created.
              </p>
              <CodeBlock text={setup.commands ?? ""} label={`${t.name} setup commands`} />
              <p>
                <strong>{setup.consent_url ? "4." : "3."}</strong> Create the integration, then run it from{" "}
                <Link to="/integrations">Integrations</Link>.
              </p>
              <div className="form-actions">
                <button type="button" className="btn btn-primary" disabled={create.pending || !installed} onClick={() => void add(setup.config ?? {})}>
                  Create integration
                </button>
              </div>
            </>
          ) : (
            <Notice kind="info">Keyless access is not available on this server: {setup.keyless_unavailable}</Notice>
          )}
          <details className="schema-help" open={!setup.keyless}>
            <summary>The read-only permissions the role grants ({setup.permissions.length})</summary>
            <ul className="banner-list small mono">
              {setup.permissions.map((p) => (
                <li key={p}>{p}</li>
              ))}
            </ul>
          </details>
          <details className="schema-help" open={!setup.keyless}>
            <summary>{t.fallbackTitle}</summary>
            <CodeBlock text={setup.fallback_commands} label={`${t.name} fallback commands`} />
            <p className="small">
              Store {setup.fallback_secret} as a workspace secret under <Link to="/integrations/secrets">Integrations → Stored credentials</Link>, then enter its name.
              Stored secrets are encrypted and never shown again.
            </p>
            <div className="field">
              <label htmlFor={`cc-${provider}-secret`}>Secret name</label>
              <input id={`cc-${provider}-secret`} className="mono" value={secretName} onChange={(e) => setSecretName(e.target.value)} placeholder="e.g. GCP_KEY" />
            </div>
            <div className="form-actions">
              <button
                type="button"
                className="btn"
                disabled={create.pending || !installed || !/^[A-Za-z0-9_.-]{1,64}$/.test(secretName.trim())}
                onClick={() => void add(setup.fallback_config, `secret:${secretName.trim()}`)}
              >
                Create integration with the secret
              </button>
            </div>
          </details>
          <ErrorBox error={create.error} title="Could not create the integration" />
          {created && (
            <Notice kind="success">
              Created <strong>{created.name}</strong>. Run it from <Link to="/integrations">Integrations</Link>.
            </Notice>
          )}
        </>
      )}
      <p className="small">
        <Link to={t.help}>More about {t.name}</Link>
      </p>
    </div>
  );
}
