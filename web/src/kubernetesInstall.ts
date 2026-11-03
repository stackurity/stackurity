/**
 * The install commands for the Kubernetes reporter (docs/kubernetes.md):
 * the Helm chart, or the server's manifest and a Secret with kubectl.
 *
 * The enrollment code is never put in a URL: the manifest the server serves
 * holds no secret, and the code goes straight into the reporter's Secret.
 */

export interface ClusterInstall {
  /** The dashboard's origin, e.g. https://stackurity.example.com. */
  origin: string;
  code: string;
  cluster: string;
  /** Only these namespaces, with Roles instead of the ClusterRole. */
  namespaces: string[];
  /** The server's release ("0.14.0"); the chart is pinned to it. */
  version?: string;
}

const LOCAL_HOSTS = ["localhost", "127.0.0.1", "[::1]"];
const CLUSTER_NAME = /^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$/;
const NAMESPACE = /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/;
const RELEASE = /^v?(\d+\.\d+\.\d+)$/;

export function validClusterName(name: string): boolean {
  return CLUSTER_NAME.test(name);
}

/** Parses a comma, space or newline separated list of namespaces; null when one is invalid. */
export function parseNamespaces(text: string): string[] | null {
  const out: string[] = [];
  for (const ns of text.split(/[\s,]+/).filter(Boolean)) {
    if (!NAMESPACE.test(ns)) return null;
    if (!out.includes(ns)) out.push(ns);
  }
  return out;
}

export function clusterCommands(c: ClusterInstall): {
  helm: string;
  kubectl: string;
  insecure: boolean;
  /** Removing the reporter installed by each command: everything it created, the namespace too. */
  uninstall: { helm: string; kubectl: string };
} {
  const url = new URL(c.origin);
  const insecure = url.protocol === "http:";
  const pin = RELEASE.exec(c.version ?? "");
  const helm = [
    `helm install stackurity-reporter oci://ghcr.io/stackurity/charts/stackurity-reporter${pin ? ` --version ${pin[1]}` : ""} \\`,
    `  --namespace stackurity --create-namespace \\`,
    `  --set server=${c.origin} --set clusterName=${c.cluster} --set enrollCode=${c.code}` +
      (insecure ? " --set allowHTTP=true" : "") +
      (c.namespaces.length ? ` \\\n  --set rbac.clusterWide=false --set 'namespaces={${c.namespaces.join(",")}}'` : ""),
  ].join("\n");
  const q = new URLSearchParams({ cluster: c.cluster });
  if (c.namespaces.length) q.set("namespaces", c.namespaces.join(","));
  const manifest = `${c.origin}/install/kubernetes.yaml?${q.toString().replace(/%2C/g, ",")}`;
  const kubectl = `kubectl apply -f '${manifest}' && \\\n  kubectl -n stackurity create secret generic stackurity-reporter --from-literal=enroll-code=${c.code}`;
  // helm install --create-namespace leaves the namespace to delete; the
  // manifest has it, and deleting it removes the Secret made beside it.
  const uninstall = {
    helm: "helm uninstall stackurity-reporter --namespace stackurity && kubectl delete namespace stackurity",
    kubectl: `kubectl delete -f '${manifest}'`,
  };
  return { helm, kubectl, insecure: insecure && !LOCAL_HOSTS.includes(url.hostname), uninstall };
}
