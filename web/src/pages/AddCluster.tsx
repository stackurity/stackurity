import { useState, type FormEvent } from "react";
import { Link } from "react-router";
import { api, type EnrollmentCreated } from "../api";
import { useAction, useLoad } from "../hooks";
import { absTime } from "../format";
import { Card, Code, CodeBlock, ErrorBox, KeyValues, Notice, PageHeader, RelativeTime, Tabs } from "../components/ui";
import { clusterCommands, parseNamespaces, validClusterName } from "../kubernetesInstall";

/**
 * Connect a Kubernetes cluster: a one-time code and the one-line install of
 * the in-cluster reporter (Helm, or kubectl with the server's manifest).
 */
export function AddClusterPage() {
  const [created, setCreated] = useState<{ enrollment: EnrollmentCreated; cluster: string; namespaces: string[] } | null>(null);
  return (
    <>
      <nav className="crumbs" aria-label="Breadcrumb">
        <Link to="/integrations">Integrations</Link> <span aria-hidden="true">/</span> <span>Kubernetes cluster</span>
      </nav>
      <PageHeader
        help="kubernetes"
        title="Connect a Kubernetes cluster"
        sub="Run one command with kubectl access to the cluster. It installs a small read-only reporter that sends the cluster's workloads and images to Stackurity over HTTPS. Nothing connects into the cluster."
      />
      {created ? (
        <ClusterCommands {...created} onDone={() => setCreated(null)} />
      ) : (
        <CreateClusterCode onCreated={(enrollment, cluster, namespaces) => setCreated({ enrollment, cluster, namespaces })} />
      )}
      <p className="small muted">
        Stackurity can also pull from the cluster's API server, if it can reach it, with the Kubernetes plugin:{" "}
        <Link to="/integrations/sources">add a Plugin integration</Link>. See <Link to="/help/kubernetes">Kubernetes clusters</Link>.
      </p>
    </>
  );
}

function ClusterCommands({
  enrollment,
  cluster,
  namespaces,
  onDone,
}: {
  enrollment: EnrollmentCreated;
  cluster: string;
  namespaces: string[];
  onDone: () => void;
}) {
  const meta = useLoad(() => api.meta(), []);
  const [tab, setTab] = useState<"helm" | "kubectl">("helm");
  const { helm, kubectl, insecure } = clusterCommands({
    origin: window.location.origin,
    code: enrollment.code,
    cluster,
    namespaces,
    version: meta.data?.version,
  });
  const e = enrollment.enrollment;
  return (
    <Card title="Install command">
      <div className="form">
        <Notice kind="warn">
          <strong>Copy a command now.</strong> The code in it is shown only once and can be used once. If it is lost, revoke it under{" "}
          <Link to="/assets/add">Pending install codes</Link> and create another.
        </Notice>
        {insecure && (
          <Notice kind="warn">
            This dashboard is open over plain HTTP, so the reporter is allowed to use HTTP and the code and its token would cross the network
            unencrypted. Reach the server over HTTPS and create the command from there instead.
          </Notice>
        )}
        <Tabs<"helm" | "kubectl">
          label="Install with"
          value={tab}
          onChange={setTab}
          tabs={[
            { id: "helm", label: "Helm" },
            { id: "kubectl", label: "kubectl" },
          ]}
        />
        <div role="tabpanel" id={`panel-${tab}`} aria-labelledby={`tab-${tab}`} className="install-command">
          {tab === "helm" ? <CodeBlock text={helm} label="Helm install command" /> : <CodeBlock text={kubectl} label="kubectl install command" />}
        </div>
        <KeyValues
          entries={[
            ["Cluster", cluster],
            ["Namespaces", namespaces.length ? namespaces.join(", ") : "All"],
            ...(e.environment ? ([["Environment", e.environment]] as [string, string][]) : []),
            [
              "Code expires",
              <>
                {absTime(e.expires_at)} (<RelativeTime iso={e.expires_at} />)
              </>,
            ],
          ]}
        />
        <div className="grid-2 tight">
          <div>
            <h3>What the command does</h3>
            <ul className="banner-list small">
              <li>
                Creates the <Code>stackurity</Code> namespace, a service account with read-only access
                {namespaces.length ? " to these namespaces" : ""} (list workloads, pods, Services, Ingresses{namespaces.length ? "" : ", nodes"}; never Secrets or
                ConfigMaps), and one reporter pod running this server's image.
              </li>
              <li>Puts the code in the Secret <Code>stackurity-reporter</Code>. On first start the reporter exchanges it for its own token, keeps the token there and removes the code.</li>
              <li>Reports every hour. Running images are then scanned by Stackurity from their registries.</li>
            </ul>
          </div>
          <div>
            <h3>Requirements</h3>
            <ul className="banner-list small">
              <li>kubectl (and Helm, for the Helm command) with rights to create a namespace, RBAC and a Deployment</li>
              <li>Outbound HTTPS from the cluster to this dashboard</li>
            </ul>
          </div>
        </div>
        <p className="small">
          <strong>Next:</strong> the cluster appears under <Link to="/assets?kind=cluster">Assets</Link> a minute or two after the pod starts, with its workloads and
          images. If it does not, see the pod's log: <Code>kubectl -n stackurity logs deploy/stackurity-reporter</Code>.
        </p>
        <div className="form-actions">
          <button type="button" className="btn" onClick={onDone}>
            I have copied it
          </button>
        </div>
      </div>
    </Card>
  );
}

function CreateClusterCode({ onCreated }: { onCreated: (e: EnrollmentCreated, cluster: string, namespaces: string[]) => void }) {
  const [cluster, setCluster] = useState("");
  const [environment, setEnvironment] = useState("");
  const [scope, setScope] = useState<"all" | "some">("all");
  const [nsText, setNsText] = useState("");
  const [problem, setProblem] = useState("");
  const act = useAction();

  const submit = async (ev: FormEvent) => {
    ev.preventDefault();
    const name = cluster.trim();
    if (!validClusterName(name)) {
      setProblem("The cluster name may contain letters, digits, dots, underscores and hyphens.");
      return;
    }
    const namespaces = scope === "some" ? parseNamespaces(nsText) : [];
    if (namespaces === null || (scope === "some" && namespaces.length === 0)) {
      setProblem("List one or more namespaces: lowercase letters, digits and hyphens.");
      return;
    }
    setProblem("");
    const c = await act.run(() =>
      api.post<EnrollmentCreated>("/enrollments", { label: `Kubernetes cluster ${name}`, environment: environment.trim(), uses: 1, ttl_hours: 24 }),
    );
    if (c) onCreated(c, name, namespaces);
  };

  return (
    <Card title="New cluster">
      <form className="form" onSubmit={submit}>
        <ErrorBox error={act.error} title="Could not create the install command" />
        {problem && <Notice kind="warn">{problem}</Notice>}
        <div className="form-grid">
          <div className="field">
            <label htmlFor="k8s-name">Cluster name</label>
            <input
              id="k8s-name"
              required
              maxLength={100}
              pattern="[A-Za-z0-9][A-Za-z0-9._\-]*"
              title="Letters, digits, dots, underscores and hyphens"
              placeholder="e.g. prod-eu"
              value={cluster}
              onChange={(e) => setCluster(e.target.value)}
            />
            <p className="hint">The cluster asset's name, and the prefix of its workloads' names.</p>
          </div>
          <div className="field">
            <label htmlFor="k8s-env">Environment</label>
            <input
              id="k8s-env"
              maxLength={64}
              pattern="[A-Za-z0-9._\-]*"
              title="Letters, digits, dots, underscores and hyphens"
              placeholder="e.g. production"
              value={environment}
              onChange={(e) => setEnvironment(e.target.value)}
            />
            <p className="hint">Optional. Production counts towards priority.</p>
          </div>
          <fieldset className="field field-span">
            <legend>Read</legend>
            <label className="check">
              <input type="radio" name="k8s-scope" checked={scope === "all"} onChange={() => setScope("all")} /> The whole cluster (read-only)
            </label>
            <label className="check">
              <input type="radio" name="k8s-scope" checked={scope === "some"} onChange={() => setScope("some")} /> Only some namespaces
            </label>
            {scope === "some" && (
              <>
                <label htmlFor="k8s-ns" className="sr-only">
                  Namespaces
                </label>
                <input id="k8s-ns" className="mono" placeholder="shop, payments" value={nsText} onChange={(e) => setNsText(e.target.value)} />
                <p className="hint">
                  For teams that cannot grant cluster-wide read. Nodes and other namespaces are then shown as not assessed.
                </p>
              </>
            )}
          </fieldset>
        </div>
        <div className="form-actions">
          <button type="submit" className="btn btn-primary" disabled={act.pending}>
            Create install command
          </button>
        </div>
      </form>
    </Card>
  );
}
