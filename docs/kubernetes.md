# Kubernetes

Stackurity answers four questions about a cluster:

- which workloads run which container images,
- which workloads can be reached from outside the cluster,
- which of those images are vulnerable or end-of-life, and
- what could not be assessed, and why.

It is read-only. It uses `get` and `list` on a fixed set of objects, never reads Secrets or ConfigMaps (the reporter reads and updates one Secret of its own, below), and never runs anything in your workloads. It talks plain HTTPS to the API server (no client-go), with TLS verified against the cluster CA.

There are two ways to connect a cluster. Both run the same collection code (`plugins/kubernetes/kube`) and report the same assets under the same collector, so a cluster can move from one to the other and keep its history.

| | **Reporter** (push, recommended) | **Plugin** (pull) |
|---|---|---|
| Runs | `stackurity kubernetes-reporter`, a small Deployment in the cluster | The `kubernetes` plugin, on the Stackurity server |
| Connects | Out of the cluster, to Stackurity over HTTPS | Into the cluster: the server must reach the API server |
| Credentials | The pod's service account; no kubeconfig leaves the cluster | A kubeconfig or token stored in Stackurity |
| Setup | One command (Helm or `kubectl`) | RBAC, a kubeconfig, a secret and an integration |
| Use for | Stackurity Cloud, and any cluster whose API server Stackurity cannot reach | A self-hosted Stackurity next to a cluster whose API it can reach, without running anything in the cluster |

Use the reporter unless you cannot run a pod in the cluster: Stackurity Cloud can almost never reach a cluster's API server, and the reporter needs no inbound access at all.

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

Risk scoring uses this as the asset's internet exposure, and an image takes it from the workloads running it: an image is exposed when any current workload running it is, internal only when every one of them is internal, and unknown otherwise (one workload with unknown exposure keeps the image unknown, never internal). A value set by hand on the asset (**Internet exposed**) always wins. The asset list can be filtered by exposure.

### Image scanning

Images the reporter or the plugin reports are queued for the server's image scanner, which reads them straight from the registry with Syft (nothing in the image runs, and no container runtime is used):

- Images behind exposed workloads, then the most used, are scanned first.
- At most `image_scans` images are queued per run (25 by default; 0 turns scanning off): the reporter's `imageScans` value, or set on the plugin's integration. The rest wait for later runs.
- A digest that was scanned successfully in the last 7 days is not scanned again, however many workloads or runs report it.
- Until an image has been scanned it shows a `skipped` coverage item (queued, or waiting for a later run) and its status is partial. If the registry refuses (a private registry behind an image pull secret), the reason is kept as `failed` coverage. Neither is ever shown as clean.

Images are read without credentials. To inventory a private image, add a **Container image** integration for it with a registry secret.

### Coverage

The cluster asset's coverage lists every API and namespace: `checked`, or `failed`/`partial` with the reason. A namespace whose pods the credentials may not list is reported as `namespace:<name>` `failed`: its workloads and images are not inventoried. A workload records per container whether the running digest is known (`image:<container>`), whether pods were readable, and whether exposure could be decided. Lists are read cluster-wide; when that is forbidden (namespace-scoped RBAC) the plugin reads namespace by namespace.

## Connect with the reporter

**Integrations → Kubernetes cluster** (or **Add**) asks for the cluster's name, an optional environment and, optionally, the namespaces to read, and shows two equivalent commands with a one-time enrollment code. Run either one with `kubectl` access to the cluster.

Helm:

```sh
helm install stackurity-reporter oci://ghcr.io/stackurity/charts/stackurity-reporter \
  --namespace stackurity --create-namespace \
  --set server=https://stackurity.example.com --set clusterName=prod-eu --set enrollCode=enr_...
```

`kubectl` (no Helm):

```sh
kubectl apply -f 'https://stackurity.example.com/install/kubernetes.yaml?cluster=prod-eu' && \
  kubectl -n stackurity create secret generic stackurity-reporter --from-literal=enroll-code=enr_...
```

The cluster appears under **Assets** a minute or two later (once the pod has pulled its image), with its workloads and images; image scans follow. The reporter reports again every hour.

### What it does

The chart and the manifest create, in the `stackurity` namespace: a service account, the read-only RBAC below, a Role on one Secret, and a Deployment of one pod running the server's own image (`ghcr.io/stackurity/stackurity`) with `stackurity kubernetes-reporter`. The pod runs as a non-root user with a read-only root filesystem, no privilege escalation and every capability dropped, and requests 20m CPU and 64 MiB of memory.

On each run it reads the cluster with its service account, then sends the whole collection to `POST /api/v1/kubernetes/report` with its own collector token. The server stores it exactly as a plugin run (the cluster first, then images, then workloads) and queues the running images for the image scanner. The cluster and its workloads report as an agent does, so if the reporter stops they go stale after `STACKURITY_STALE_AFTER` (48 hours by default) and the dashboard says so.

### The enrollment code and the token

The code is single-use and expires (24 hours by default), like the Linux installer's. It never goes in a URL: `/install/kubernetes.yaml` holds no secret and refuses any parameter but `cluster` and `namespaces`, so the code cannot end up in the server's or a proxy's access log or a cached response. It is put straight into a Secret, `stackurity-reporter`:

- With Helm, by the chart from `enrollCode`. Helm keeps a release's values, so the used code stays in the release record; it cannot be used again.
- With `kubectl`, by `kubectl create secret` after the manifest is applied. The reporter waits for the Secret and looks at it again every 15 seconds.

On its first start the reporter exchanges the code for a collector token (`POST /api/v1/enroll`, the same exchange as `stackurity enroll`), writes the token into the same Secret (key `token`, with the code's environment under `environment`) and removes the code. Before using the code it checks that it may update the Secret, so a code is never used up by a pod that could not keep the token. Its Role allows `get` and `update` on that one Secret by name, and nothing else: it cannot list, create or read any other Secret. Upgrading the chart keeps the token (it is not part of the chart); uninstalling the release deletes it. The token is listed under **Integrations → API tokens** as `agent on Kubernetes cluster <name>`, where it can be revoked.

If the server refuses the token (revoked), the reporter logs it and waits for a new code, looking at the Secret every 15 seconds: put one in it and it enrolls again. A code the server refuses is not sent again.

```sh
kubectl -n stackurity patch secret stackurity-reporter --type merge -p '{"stringData":{"enroll-code":"enr_..."}}'
```

An enrollment code made for a project adds the cluster, its workloads and images to that project when they are first reported.

### RBAC

The ClusterRole grants exactly what the collection reads, and `plugins/kubernetes/kube/rbac_test.go` fails if the code reads something it does not grant, or it grants something the code does not use:

| API group | Resources | Verbs |
|---|---|---|
| core | namespaces, nodes, pods, services | list |
| apps | daemonsets, deployments, statefulsets | list |
| batch | cronjobs, jobs | list |
| networking.k8s.io | ingresses | list |
| core | namespaces, `kube-system` only | get |
| non-resource | `/version` | get |

No `watch`, no Secrets or ConfigMaps, no logs, exec or write verbs. The `get` on `kube-system` is used only when namespaces cannot be listed: its UID identifies the cluster.

**Some namespaces only.** For teams that cannot grant cluster-wide read, the reporter reads only the namespaces you name, with a Role in each (the namespaced rows above). Cluster-wide it then has only `get` on the `kube-system` namespace object (for the cluster's identity) and `/version`. Nodes are not read, so kubelet, runtime and node OS versions show as not assessed, as do the namespace list and every other namespace.

With Helm:

```sh
helm install stackurity-reporter oci://ghcr.io/stackurity/charts/stackurity-reporter --namespace stackurity --create-namespace \
  --set server=https://stackurity.example.com --set clusterName=prod-eu --set enrollCode=enr_... \
  --set rbac.clusterWide=false --set 'namespaces={shop,payments}'
```

With `kubectl`, add `namespaces` to the manifest's address (then create the Secret as above):

```sh
kubectl apply -f 'https://stackurity.example.com/install/kubernetes.yaml?cluster=prod-eu&namespaces=shop,payments'
```

### Chart values

| Value | Default | Meaning |
|---|---|---|
| `server` | (required) | The Stackurity server's URL; `https://` unless `allowHTTP` |
| `enrollCode` | | The one-time code; without it the Secret is created empty for you to patch the code in |
| `clusterName` | `kubernetes` | Name of the cluster asset and prefix of workload names |
| `environment`, `environmentLabel` | the code's environment | As the plugin's `environment` and `environment_label` |
| `namespaces`, `excludeNamespaces` | all | Only these namespaces; or all but these |
| `rbac.clusterWide` | `true` | `false`: Roles in `namespaces` only (above) |
| `maxImages` | 300 | Most images reported per run (up to 2000) |
| `imageScans` | 25 | Most image scans one report asks for (0 to 500; 0 turns scanning off) |
| `interval` | `1h` | Time between reports (at least `1m`) |
| `secret.create`, `secret.name` | `true`, the release name | `false` to create the Secret yourself (for example with your secrets tooling), with the code under `enroll-code` |
| `allowHTTP` | `false` | Allow an `http://` server URL (a local evaluation only: the code and token cross the network unencrypted) |
| `image.*`, `resources`, `nodeSelector`, `tolerations`, `affinity`, `priorityClassName`, `podAnnotations`, `imagePullSecrets`, `extraEnv` | | The usual; `extraEnv` for `HTTPS_PROXY` |

### `stackurity kubernetes-reporter`

The Deployment runs `stackurity kubernetes-reporter` in the pod; you do not normally run it yourself. Its flags, each with an environment variable the chart and manifest set:

| Flag | Environment | Default |
|---|---|---|
| `--server` | `STACKURITY_SERVER` | (required) |
| `--secret` | `STACKURITY_REPORTER_SECRET` | `stackurity-reporter`, in the pod's namespace |
| `--cluster-name` | `STACKURITY_CLUSTER_NAME` | `kubernetes` |
| `--environment` | `STACKURITY_ENVIRONMENT` | the enrollment code's |
| `--environment-label` | `STACKURITY_ENVIRONMENT_LABEL` | |
| `--namespaces`, `--exclude-namespaces` | `STACKURITY_NAMESPACES`, `STACKURITY_EXCLUDE_NAMESPACES` (comma separated) | all |
| `--max-images` | `STACKURITY_MAX_IMAGES` | 300 |
| `--image-scans` | `STACKURITY_IMAGE_SCANS` | 25 |
| `--interval` | `STACKURITY_INTERVAL` | `1h` |
| `--once` | | report once and exit |
| `--output`, `-o` | | write the collection to a file (`-` for standard output) instead of sending it; needs no server or token |

It refuses an `http://` server unless `STACKURITY_ALLOW_HTTP=1`. Against a server older than this feature (no `kubernetes_report` in `GET /api/v1/meta`), it sends the batches one by one to `POST /api/v1/ingest` and the images are not scanned; upgrade the server.

To see what it would send, run it once in the cluster with `--output`:

```sh
kubectl -n stackurity exec deploy/stackurity-reporter -- stackurity kubernetes-reporter --output - | head
```

## Connect with the plugin (pull)

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

Store it as a workspace secret (**Integrations → Secrets**) whose value is the JSON object `{"kubeconfig": "<the file's contents>"}`, for example:

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

The reporter connects only to the cluster's API server (`https://kubernetes.default.svc`, with the pod's service account) and to the Stackurity server in `server`, over HTTPS. Nothing connects into the cluster. Give it outbound HTTPS to Stackurity (`extraEnv` takes `HTTPS_PROXY` for a proxy); a NetworkPolicy that allows only that and the API server is enough. The Stackurity server makes no new connection for it: the image scans are the same registry pulls as for the plugin, below.

The plugin connects only to the API server in the kubeconfig, `server`, or `https://kubernetes.default.svc`. The server passes the workspace's network policy to the plugin, which refuses to connect to an internal address the workspace may not reach (`STACKURITY_PRIVATE_TARGETS`, `STACKURITY_PRIVATE_CIDRS`; see [network.md](network.md)). API servers usually have private addresses, so a workspace other than the operator's needs its API server's range in `STACKURITY_PRIVATE_CIDRS`.

Image scans contact the registries in the image references (`docker.io`, `registry.k8s.io`, `ghcr.io`, your own), checked against the same policy.

## Limitations

- Gateway API routes and service meshes are not read; exposure covers Services, Ingresses and host networking.
- Workloads of custom controllers (Argo Rollouts, operators) appear as the owner kind and name of their pods.
- Images preloaded on nodes (for example with `kind load`) report no registry digest; they are recorded by tag, with `partial` coverage.
- Kubernetes CVEs are not matched; control plane, kubelet and runtime versions are tracked for lifecycle and listed as evaluation gaps for vulnerabilities.
- Objects are listed once per run; there is no watch.
- The reporter reports on its interval; **Check again** in the dashboard does not reach it. Restart the pod (`kubectl -n stackurity rollout restart deploy/stackurity-reporter`) for a report now.
- The reporter trusts the system CA roots for the Stackurity server; a server with a private CA needs `SSL_CERT_FILE` and a mounted CA bundle (through `extraEnv` and your own volume).
