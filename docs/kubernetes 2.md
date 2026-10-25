# Kubernetes

The `kubernetes` plugin answers four questions about a cluster:

- which workloads run which container images,
- which workloads can be reached from outside the cluster,
- which of those images are vulnerable or end-of-life, and
- what could not be assessed, and why.

It is read-only. It uses `get` and `list` on a fixed set of objects, never reads Secrets or ConfigMaps, and never runs anything in the cluster. It talks plain HTTPS to the API server (no client-go), with TLS verified against the cluster CA.

## What it reports

| Asset | Kind | Identity | What it carries |
|---|---|---|---|
| The cluster | `cluster` | `k8s-cluster`: UID of the `kube-system` namespace | Control plane version, and kubelet, container runtime and node OS versions grouped across nodes, with the nodes that run each (evidence `nodes`). Lifecycle comes from endoflife.date: `kubernetes`, or `amazon-eks`, `google-kubernetes-engine` and `azure-kubernetes-service` for managed clusters, plus `containerd`, `cri-o` and the node OS (Debian, Ubuntu, Amazon Linux, RHEL and others) |
| Each workload | `workload` | `k8s-workload`: cluster UID / namespace / kind / name | Deployment, StatefulSet, DaemonSet, CronJob, Job (not started by a CronJob) or bare Pod. Attributes: `namespace`, `workload_kind`, `replicas`, `ready`, `exposure`, `exposed_via`, `services`, `images`, `service_account`, `host_network`, `privileged`, `image_pull_secrets` |
| Each running image | `image` | `image-ref`: `repository@sha256:digest` | The digest the node actually pulled (from pod status), so a moving tag is never mistaken for what runs. Packages come from the built-in image scanner (Syft); see below |

Relations: a workload `runs_on` its cluster and is `deployed_as` each image it runs. The asset page of an image lists the workloads running it; a cluster's **Stack** tab shows its workloads, their images and every open finding by layer.

Pods are grouped under the controller that owns them (a ReplicaSet's pods under their Deployment, a Job's pods under their CronJob). Controllers with no running pods are still reported, with their images taken by tag from the pod template.

### Exposure

A workload is `exposure: external` when any of these reaches it:

- a Service of type `LoadBalancer` (one with a cloud "internal" annotation is still listed, marked `internal`) or `NodePort`, or a Service with `externalIPs`,
- an Ingress whose backend is a Service that selects the workload,
- `hostNetwork: true`, or a container `hostPort`.

Otherwise it is `internal`. If Services or Ingresses in its namespace could not be read, it is `unknown`, never `internal`. `exposed_via` says what made it external, e.g. `Service web (NodePort 30080)`.

Risk scoring uses this as the asset's internet exposure, and an image takes it from the workloads running it: an image is exposed when any current workload running it is. A value set by hand on the asset (**Internet exposed**) always wins. The asset list can be filtered by exposure.

### Image scanning

Images the plugin reports are queued for the server's image scanner, which reads them straight from the registry with Syft (nothing in the image runs, and no container runtime is used):

- Images behind exposed workloads, then the most used, are scanned first.
- At most `image_scans` images are queued per run (25 by default, set on the integration; 0 turns scanning off). The rest wait for later runs.
- A digest that was scanned successfully in the last 7 days is not scanned again, however many workloads or runs report it.
- Until an image has been scanned it shows a `skipped` coverage item (queued, or waiting for a later run) and its status is partial. If the registry refuses (a private registry behind an image pull secret), the reason is kept as `failed` coverage. Neither is ever shown as clean.

Images are read without credentials. To inventory a private image, add a **Container image** integration for it with a registry secret.

### Coverage

The cluster asset's coverage lists every API and namespace: `checked`, or `failed`/`partial` with the reason. A namespace whose pods the credentials may not list is reported as `namespace:<name>` `failed`: its workloads and images are not inventoried. A workload records per container whether the running digest is known (`image:<container>`), whether pods were readable, and whether exposure could be decided. Lists are read cluster-wide; when that is forbidden (namespace-scoped RBAC) the plugin reads namespace by namespace.

## Setup

### 1. A read-only service account

[`deploy/kubernetes/stackurity-reader.yaml`](../deploy/kubernetes/stackurity-reader.yaml) creates a `stackurity` namespace, a `stackurity-reader` service account, a ClusterRole with only these rules, and a long-lived token for it:

| API group | Resources | Verbs |
|---|---|---|
| core | pods, services, namespaces, nodes | get, list, watch |
| apps | deployments, statefulsets, daemonsets | get, list, watch |
| batch | jobs, cronjobs | get, list, watch |
| networking.k8s.io | ingresses | get, list, watch |

```sh
kubectl apply -f deploy/kubernetes/stackurity-reader.yaml
```

To limit it to some namespaces, bind the ClusterRole with a RoleBinding in each namespace instead of the ClusterRoleBinding, and keep cluster-wide `list` on `namespaces` and `nodes`. The other namespaces then show as not assessed.

### 2. Credentials

**Kubeconfig (Stackurity outside the cluster).** Build a kubeconfig for the token:

```sh
TOKEN=$(kubectl -n stackurity get secret stackurity-reader-token -o jsonpath='{.data.token}' | base64 -d)
SERVER=$(kubectl config view --minify -o jsonpath='{.clusters[0].cluster.server}')
CA=$(kubectl config view --minify --raw -o jsonpath='{.clusters[0].cluster.certificate-authority-data}')
cat > stackurity.kubeconfig <<EOF
apiVersion: v1
kind: Config
current-context: stackurity
clusters: [{name: prod-eu, cluster: {server: "$SERVER", certificate-authority-data: "$CA"}}]
users: [{name: stackurity-reader, user: {token: "$TOKEN"}}]
contexts: [{name: stackurity, context: {cluster: prod-eu, user: stackurity-reader}}]
EOF
```

Store it as a workspace secret (**Settings → Secrets**) whose value is the JSON object `{"kubeconfig": "<the file's contents>"}`, for example:

```sh
jq -n --rawfile k stackurity.kubeconfig '{value: ({kubeconfig: $k} | tojson)}' |
  curl -X PUT -H "Authorization: Bearer $STACKURITY_TOKEN" -H 'Content-Type: application/json' \
       --data @- https://stackurity.example.com/api/v1/secrets/prod-eu-kubeconfig
```

Only embedded credentials are used: a bearer token or a client certificate (`client-certificate-data`, `client-key-data`), and `certificate-authority-data`. Exec credential plugins (`aws eks get-token`, `gke-gcloud-auth-plugin`), auth providers, basic authentication and file paths are refused, because the plugin never runs commands or reads files the kubeconfig points to. `insecure-skip-tls-verify` is refused too. For EKS, GKE and AKS, use a service account token as above.

Instead of a kubeconfig, the secret can hold `{"token": "...", "ca_cert": "-----BEGIN CERTIFICATE-----..."}` with `server` in the plugin config. Without `ca_cert` the system roots are used.

**In-cluster.** When Stackurity runs in the cluster under a service account bound to the ClusterRole (with its token mounted), set `"in_cluster": true` and no secret. The plugin reads the pod's token and CA and calls `https://kubernetes.default.svc`. That token is the server's own identity, so only workspaces allowed to reach internal networks (the operator's, by default) may use it. The Helm chart does not mount a service account token (`automountServiceAccountToken: false`), so with the chart use a kubeconfig secret, or run the server under the `stackurity-reader` service account with the token mounted.

### 3. The integration

**Integrations → Add → Plugin → Kubernetes**, or through the API:

```json
{"kind": "plugin", "name": "prod-eu",
 "config": {"plugin": "kubernetes", "image_scans": 25,
            "config": {"cluster_name": "prod-eu", "environment_label": "environment", "exclude_namespaces": ["kube-node-lease"]}},
 "secret_ref": "secret:prod-eu-kubeconfig", "schedule_minutes": 60}
```

| Field | Meaning |
|---|---|
| `cluster_name` | Name of the cluster asset and prefix of workload names (default: the kubeconfig cluster name) |
| `context` | Kubeconfig context (default: `current-context`) |
| `server` | API server URL, with a `token` secret |
| `in_cluster` | Use the pod's service account |
| `namespaces`, `exclude_namespaces` | Only these namespaces; or all but these |
| `environment` | Environment for the cluster and its workloads |
| `environment_label` | Namespace label whose value is a workload's environment (e.g. `environment=production`), falling back to `environment` |
| `max_images` | Most images reported per run (default 300, up to 2000) |

`image_scans` sits next to `plugin`, not inside `config`: it is the server's limit, not the plugin's.

## Network

The plugin connects only to the API server in the kubeconfig, `server`, or `https://kubernetes.default.svc`. The server passes the workspace's network policy to the plugin, which refuses to connect to an internal address the workspace may not reach (`STACKURITY_PRIVATE_TARGETS`, `STACKURITY_PRIVATE_CIDRS`; see [network.md](network.md)). API servers usually have private addresses, so a workspace other than the operator's needs its API server's range in `STACKURITY_PRIVATE_CIDRS`.

Image scans contact the registries in the image references (`docker.io`, `registry.k8s.io`, `ghcr.io`, your own), checked against the same policy.

## Limitations

- Gateway API routes and service meshes are not read; exposure covers Services, Ingresses and host networking.
- Workloads of custom controllers (Argo Rollouts, operators) appear as the owner kind and name of their pods.
- Images preloaded on nodes (for example with `kind load`) report no registry digest; they are recorded by tag, with `partial` coverage.
- Kubernetes CVEs are not matched; control plane, kubelet and runtime versions are tracked for lifecycle and listed as evaluation gaps for vulnerabilities.
- Objects are listed once per run; there is no watch.
