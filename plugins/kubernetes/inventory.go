package main

import (
	"context"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/package-url/packageurl-go"

	"github.com/stackurity/stackurity/pkg/plugin"
)

// resource is one namespaced collection the plugin lists.
type resource struct {
	name   string // pods, deployments, ...
	prefix string // API group path
}

var (
	resPods         = resource{"pods", "/api/v1"}
	resDeployments  = resource{"deployments", "/apis/apps/v1"}
	resStatefulSets = resource{"statefulsets", "/apis/apps/v1"}
	resDaemonSets   = resource{"daemonsets", "/apis/apps/v1"}
	resJobs         = resource{"jobs", "/apis/batch/v1"}
	resCronJobs     = resource{"cronjobs", "/apis/batch/v1"}
	resServices     = resource{"services", "/api/v1"}
	resIngresses    = resource{"ingresses", "/apis/networking.k8s.io/v1"}
)

// access records how far one resource could be read.
type access struct {
	forbidden   map[string]bool // namespaces the credentials may not list
	all         bool            // forbidden cluster-wide and namespaces unknown
	unsupported bool            // the API is not served by this cluster
	err         error           // any other failure
	tried       int             // namespaces read one by one
}

// readable reports whether the resource was read in namespace ns.
func (a *access) readable(ns string) bool {
	return a.unsupported || (!a.all && a.err == nil && !a.forbidden[ns])
}

func (a *access) coverage(scope string) plugin.CoverageItem {
	switch {
	case a.err != nil:
		return plugin.CoverageItem{Scope: scope, Status: "failed", Reason: trim(a.err.Error(), 300)}
	case a.all:
		return plugin.CoverageItem{Scope: scope, Status: "failed", Reason: "forbidden cluster-wide, and the namespaces could not be listed"}
	case a.unsupported:
		return plugin.CoverageItem{Scope: scope, Status: "unsupported", Reason: "this API is not served by the cluster"}
	case len(a.forbidden) > 0 && len(a.forbidden) == a.tried:
		return plugin.CoverageItem{Scope: scope, Status: "failed", Reason: "forbidden in every namespace"}
	case len(a.forbidden) > 0:
		return plugin.CoverageItem{Scope: scope, Status: "partial", Reason: "forbidden in namespaces: " + trim(strings.Join(sortedKeys(a.forbidden), ", "), 1500)}
	}
	return plugin.CoverageItem{Scope: scope, Status: "checked"}
}

// fetch lists a resource cluster-wide, or namespace by namespace when the
// config names namespaces or the cluster-wide list is forbidden.
func fetch[T any](ctx context.Context, c *client, r resource, scoped bool, namespaces []string) ([]T, *access) {
	acc := &access{forbidden: map[string]bool{}}
	if !scoped {
		items, err := list[T](ctx, c, r.prefix+"/"+r.name)
		switch {
		case err == nil:
			return items, acc
		case isStatus(err, 404):
			acc.unsupported = true
			return nil, acc
		case !isStatus(err, 403):
			acc.err = err
			return nil, acc
		case namespaces == nil:
			acc.all = true
			return nil, acc
		}
	}
	var out []T
	for _, ns := range namespaces {
		acc.tried++
		items, err := list[T](ctx, c, r.prefix+"/namespaces/"+ns+"/"+r.name)
		switch {
		case err == nil:
			out = append(out, items...)
		case isStatus(err, 403):
			acc.forbidden[ns] = true
		case isStatus(err, 404) && !scoped:
			acc.unsupported = true
			return nil, acc
		case isStatus(err, 404):
			// A configured namespace that does not exist has nothing in it.
		default:
			acc.err = err
			return out, acc
		}
	}
	return out, acc
}

// snapshot is everything read from one cluster.
type snapshot struct {
	settings   settings
	name       string
	version    versionInfo
	clusterUID string
	namespaces map[string]namespace // nil when they could not be listed
	scope      []string             // namespaces in scope, when known
	nsErr      error
	nodes      []node
	nodesAcc   *access
	pods       []pod
	ctrls      map[string][]controller // by kind
	services   []service
	ingresses  []ingress
	acc        map[string]*access // by resource name
}

func read(ctx context.Context, c *client, s settings) (*snapshot, error) {
	snap := &snapshot{settings: s, ctrls: map[string][]controller{}, acc: map[string]*access{}}
	if err := c.get(ctx, "/version", nil, &snap.version); err != nil {
		return nil, fmt.Errorf("reading the API server version: %w", err)
	}
	nss, err := list[namespace](ctx, c, "/api/v1/namespaces")
	if err == nil {
		snap.namespaces = map[string]namespace{}
		for _, ns := range nss {
			snap.namespaces[ns.Metadata.Name] = ns
		}
	} else {
		snap.nsErr = err
		var ks namespace
		if c.get(ctx, "/api/v1/namespaces/kube-system", nil, &ks) == nil {
			snap.clusterUID = ks.Metadata.UID
		}
	}
	if ks, ok := snap.namespaces["kube-system"]; ok {
		snap.clusterUID = ks.Metadata.UID
	}
	// Namespaces to read one by one when needed.
	scoped := len(s.Namespaces) > 0
	var names []string
	if scoped {
		names = s.Namespaces
	} else if snap.namespaces != nil {
		names = sortedKeys(snap.namespaces)
	}
	names = filterOut(names, s.ExcludeNamespaces)
	snap.scope = names

	var nacc access
	snap.nodes, err = list[node](ctx, c, "/api/v1/nodes")
	if err != nil {
		if isStatus(err, 403) {
			nacc.all = true
		} else {
			nacc.err = err
		}
	}
	snap.nodesAcc = &nacc

	var a *access
	snap.pods, a = fetch[pod](ctx, c, resPods, scoped, names)
	snap.acc["pods"] = a
	for _, r := range []struct {
		res  resource
		kind string
	}{{resDeployments, "Deployment"}, {resStatefulSets, "StatefulSet"}, {resDaemonSets, "DaemonSet"}, {resJobs, "Job"}, {resCronJobs, "CronJob"}} {
		snap.ctrls[r.kind], a = fetch[controller](ctx, c, r.res, scoped, names)
		snap.acc[r.res.name] = a
	}
	snap.services, a = fetch[service](ctx, c, resServices, scoped, names)
	snap.acc["services"] = a
	snap.ingresses, a = fetch[ingress](ctx, c, resIngresses, scoped, names)
	snap.acc["ingresses"] = a
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	snap.name = s.ClusterName
	if snap.name == "" {
		snap.name = c.cluster
	}
	if snap.name == "" {
		snap.name = "kubernetes"
	}
	return snap, nil
}

// inScope reports whether objects in namespace ns are inventoried.
func (s *snapshot) inScope(ns string) bool {
	if contains(s.settings.ExcludeNamespaces, ns) {
		return false
	}
	return len(s.settings.Namespaces) == 0 || contains(s.settings.Namespaces, ns)
}

// --- workloads

type workload struct {
	ns, kind, name string
	spec           podSpec
	labels         map[string]string // pod template labels, for Service selectors
	desired, ready int32
	counted        bool // desired/ready are known
	schedule       string
	pods           []*pod
}

func (w *workload) key() string { return w.ns + "/" + w.kind + "/" + w.name }

// workloads groups pods under the controller that owns them. Controllers
// without running pods are included too, with their images from the pod
// template.
func (s *snapshot) workloads() []*workload {
	byKey := map[string]*workload{}
	var order []*workload
	add := func(w *workload) *workload {
		if cur, ok := byKey[w.key()]; ok {
			return cur
		}
		byKey[w.key()] = w
		order = append(order, w)
		return w
	}
	cronJobOf := map[string]string{} // ns/job -> cronjob
	for _, kind := range []string{"Deployment", "StatefulSet", "DaemonSet", "CronJob", "Job"} {
		for i := range s.ctrls[kind] {
			c := &s.ctrls[kind][i]
			if !s.inScope(c.Metadata.Namespace) {
				continue
			}
			if kind == "Job" {
				if owner := controllerOf(c.Metadata); owner != nil && owner.Kind == "CronJob" {
					cronJobOf[c.Metadata.Namespace+"/"+c.Metadata.Name] = owner.Name
					continue
				}
			}
			tmpl := c.Spec.Template
			if kind == "CronJob" {
				tmpl = c.Spec.JobTemplate.Spec.Template
			}
			w := &workload{ns: c.Metadata.Namespace, kind: kind, name: c.Metadata.Name, spec: tmpl.Spec, labels: tmpl.Metadata.Labels, schedule: c.Spec.Schedule}
			switch kind {
			case "Deployment", "StatefulSet":
				w.desired, w.ready, w.counted = 1, c.Status.ReadyReplicas, true
				if c.Spec.Replicas != nil {
					w.desired = *c.Spec.Replicas
				}
			case "DaemonSet":
				w.desired, w.ready, w.counted = c.Status.DesiredNumberScheduled, c.Status.NumberReady, true
			}
			add(w)
		}
	}
	deployments := map[string]bool{}
	for _, d := range s.ctrls["Deployment"] {
		deployments[d.Metadata.Namespace+"/"+d.Metadata.Name] = true
	}
	for i := range s.pods {
		p := &s.pods[i]
		ns := p.Metadata.Namespace
		if !s.inScope(ns) {
			continue
		}
		kind, name := "Pod", p.Metadata.Name
		if owner := controllerOf(p.Metadata); owner != nil {
			kind, name = owner.Kind, owner.Name
			switch owner.Kind {
			case "ReplicaSet":
				// ReplicaSets are named <deployment>-<pod-template-hash>.
				if h := p.Metadata.Labels["pod-template-hash"]; h != "" && strings.HasSuffix(owner.Name, "-"+h) {
					if d := strings.TrimSuffix(owner.Name, "-"+h); deployments[ns+"/"+d] || s.acc["deployments"] != nil && !s.acc["deployments"].readable(ns) {
						kind, name = "Deployment", d
					}
				}
			case "Job":
				if cj, ok := cronJobOf[ns+"/"+owner.Name]; ok {
					kind, name = "CronJob", cj
				}
			case "Node":
				kind, name = "Pod", p.Metadata.Name // static (mirror) pod
			}
		}
		w := add(&workload{ns: ns, kind: kind, name: name, spec: p.Spec, labels: p.Metadata.Labels})
		w.pods = append(w.pods, p)
		if kind == "Pod" {
			w.desired, w.counted = 1, true
			if p.Status.Phase == "Running" {
				w.ready = 1
			}
		}
	}
	sort.SliceStable(order, func(i, j int) bool { return order[i].key() < order[j].key() })
	return order
}

func controllerOf(m objectMeta) *ownerRef {
	for i, o := range m.OwnerReferences {
		if o.Controller != nil && *o.Controller {
			return &m.OwnerReferences[i]
		}
	}
	return nil
}

// --- images

// Image references the server will accept: registry/path[:tag][@sha256:...].
// Mirrors the server's own check (internal/collect/image).
var refRE = regexp.MustCompile(`^[a-z0-9]+([._-][a-z0-9]+)*(:[0-9]+)?(/[a-z0-9]+([._-][a-z0-9]+)*)+(:[A-Za-z0-9_][A-Za-z0-9_.-]{0,127})?(@sha256:[a-f0-9]{64})?$`)

// splitRef splits an image reference into repository, tag and digest.
func splitRef(ref string) (repo, tag, digest string) {
	if i := strings.Index(ref, "@"); i >= 0 {
		ref, digest = ref[:i], ref[i+1:]
	}
	if i := strings.LastIndex(ref, ":"); i > strings.LastIndex(ref, "/") {
		ref, tag = ref[:i], ref[i+1:]
	}
	return ref, tag, digest
}

// canonicalRepo spells out Docker Hub names (nginx -> docker.io/library/nginx)
// so the same image is one asset however a manifest names it.
func canonicalRepo(repo string) string {
	first, rest, found := strings.Cut(repo, "/")
	switch {
	case !found:
		return "docker.io/library/" + repo
	case first == "index.docker.io" || first == "registry-1.docker.io":
		if !strings.Contains(rest, "/") {
			rest = "library/" + rest
		}
		return "docker.io/" + rest
	case !strings.ContainsAny(first, ".:") && first != "localhost":
		return "docker.io/" + repo
	}
	return repo
}

// resolveRef returns the reference to inventory for a container: the
// digest the node actually pulled when the pod status reports it, else the
// digest or tag from the spec. pinned is true when it names a digest.
func resolveRef(spec, imageID string) (ref string, pinned bool) {
	id := strings.TrimPrefix(strings.TrimPrefix(imageID, "docker-pullable://"), "docker://")
	if repo, dig, ok := strings.Cut(id, "@"); ok && repo != "" && strings.HasPrefix(dig, "sha256:") {
		r, _, _ := splitRef(repo)
		return canonicalRepo(r) + "@" + dig, true
	}
	repo, tag, dig := splitRef(spec)
	if strings.HasPrefix(dig, "sha256:") {
		return canonicalRepo(repo) + "@" + dig, true
	}
	if tag == "" {
		tag = "latest"
	}
	return canonicalRepo(repo) + ":" + tag, false
}

// imageInfo is one image reference and the workloads that run it.
type imageInfo struct {
	ref        string
	pinned     bool
	tags       map[string]bool
	platform   string
	pullSecret bool
	exposed    bool
	env        string
	uses       int
}

// containerImages is what one container of a workload runs.
type containerImages struct {
	container string
	spec      string
	refs      []string
	note      string // why no digest is known
	invalid   bool
}

func (s *snapshot) imagesOf(w *workload) []containerImages {
	var out []containerImages
	all := append(append([]container{}, w.spec.InitContainers...), w.spec.Containers...)
	for _, c := range all {
		ci := containerImages{container: c.Name, spec: c.Image}
		seen := map[string]bool{}
		waiting := ""
		for _, p := range w.pods {
			for _, st := range append(append([]containerStatus{}, p.Status.InitContainerStatuses...), p.Status.ContainerStatuses...) {
				if st.Name != c.Name {
					continue
				}
				if st.ImageID == "" {
					if st.State.Waiting != nil && st.State.Waiting.Reason != "" {
						waiting = st.State.Waiting.Reason
					}
					continue
				}
				if ref, pinned := resolveRef(c.Image, st.ImageID); pinned && !seen[ref] {
					seen[ref] = true
					ci.refs = append(ci.refs, ref)
				}
			}
		}
		if len(ci.refs) == 0 {
			ref, pinned := resolveRef(c.Image, "")
			ci.refs = []string{ref}
			switch {
			case pinned:
			case len(w.pods) == 0:
				ci.note = "no running pods; recorded by tag from the pod template"
			case waiting != "":
				ci.note = "no pod reports the image digest (" + waiting + "); recorded by tag"
			default:
				ci.note = "no pod reports the image digest; recorded by tag"
			}
		}
		for _, r := range ci.refs {
			if !refRE.MatchString(r) {
				ci.invalid = true
			}
		}
		sort.Strings(ci.refs)
		out = append(out, ci)
	}
	return out
}

// --- exposure

// Annotations that make a LoadBalancer Service private to the cloud network.
var internalLBAnnotations = map[string]string{
	"service.beta.kubernetes.io/aws-load-balancer-internal":   "",
	"service.beta.kubernetes.io/aws-load-balancer-scheme":     "internal",
	"service.beta.kubernetes.io/azure-load-balancer-internal": "true",
	"networking.gke.io/load-balancer-type":                    "internal",
	"cloud.google.com/load-balancer-type":                     "internal",
	"service.beta.kubernetes.io/oci-load-balancer-internal":   "true",
}

func internalLB(svc *service) bool {
	for k, want := range internalLBAnnotations {
		v, ok := svc.Metadata.Annotations[k]
		if ok && (want == "" && v != "false" || strings.EqualFold(v, want)) {
			return true
		}
	}
	return false
}

func selects(sel, labels map[string]string) bool {
	if len(sel) == 0 {
		return false // a Service without a selector has hand-managed endpoints
	}
	for k, v := range sel {
		if labels[k] != v {
			return false
		}
	}
	return true
}

type exposure struct {
	level    string // external, internal, unknown
	via      []string
	services []string // in-cluster Services that select the workload
}

// exposureOf works out whether a workload can be reached from outside the
// cluster: a LoadBalancer or NodePort Service, external IPs, an Ingress, or
// host networking/ports. Unreadable Services or Ingresses make it unknown,
// never internal.
func (s *snapshot) exposureOf(w *workload) exposure {
	var e exposure
	if w.spec.HostNetwork {
		e.via = append(e.via, "hostNetwork")
	}
	for _, c := range w.spec.Containers {
		for _, p := range c.Ports {
			if p.HostPort > 0 {
				proto := p.Protocol
				if proto == "" {
					proto = "TCP"
				}
				e.via = append(e.via, fmt.Sprintf("hostPort %d/%s (container %s)", p.HostPort, proto, c.Name))
			}
		}
	}
	matched := map[string]bool{}
	for i := range s.services {
		svc := &s.services[i]
		if svc.Metadata.Namespace != w.ns || !selects(svc.Spec.Selector, w.labels) {
			continue
		}
		matched[svc.Metadata.Name] = true
		switch svc.Spec.Type {
		case "LoadBalancer":
			var addrs []string
			for _, in := range svc.Status.LoadBalancer.Ingress {
				addrs = append(addrs, in.IP+in.Hostname)
			}
			d := "Service " + svc.Metadata.Name + " (LoadBalancer"
			if internalLB(svc) {
				d += ", internal"
			}
			if len(addrs) > 0 {
				d += " " + strings.Join(addrs, ", ")
			}
			e.via = append(e.via, d+")")
		case "NodePort":
			var ports []string
			for _, p := range svc.Spec.Ports {
				if p.NodePort > 0 {
					ports = append(ports, strconv.Itoa(int(p.NodePort)))
				}
			}
			e.via = append(e.via, "Service "+svc.Metadata.Name+" (NodePort "+strings.Join(ports, ", ")+")")
		default:
			if len(svc.Spec.ExternalIPs) == 0 {
				e.services = append(e.services, svc.Metadata.Name)
			}
		}
		if len(svc.Spec.ExternalIPs) > 0 {
			e.via = append(e.via, "Service "+svc.Metadata.Name+" (externalIPs "+strings.Join(svc.Spec.ExternalIPs, ", ")+")")
		}
	}
	for _, in := range s.ingresses {
		if in.Metadata.Namespace != w.ns {
			continue
		}
		backends := []*ingressBackend{in.Spec.DefaultBackend}
		var hosts []string
		for _, r := range in.Spec.Rules {
			if r.Host != "" {
				hosts = append(hosts, r.Host)
			}
			if r.HTTP != nil {
				for i := range r.HTTP.Paths {
					backends = append(backends, &r.HTTP.Paths[i].Backend)
				}
			}
		}
		for _, b := range backends {
			if b != nil && b.Service != nil && matched[b.Service.Name] {
				d := "Ingress " + in.Metadata.Name
				if len(hosts) > 0 {
					d += " (" + strings.Join(dedupe(hosts), ", ") + ")"
				}
				e.via = append(e.via, d)
				break
			}
		}
	}
	switch {
	case len(e.via) > 0:
		e.level = "external"
	case !s.acc["services"].readable(w.ns) || !s.acc["ingresses"].readable(w.ns):
		e.level = "unknown"
	default:
		e.level = "internal"
	}
	sort.Strings(e.services)
	return e
}

// --- nodes and versions

// cleanVersion turns v1.31.2-eks-1234 or v1.30.4+k3s1 into 1.31.2.
func cleanVersion(v string) string {
	v = strings.TrimPrefix(strings.TrimSpace(v), "v")
	if i := strings.IndexAny(v, "-+"); i > 0 {
		v = v[:i]
	}
	return v
}

// distribution names the Kubernetes flavour, its endoflife.date product
// and the cloud provider, from version strings and node provider IDs.
func distribution(gitVersion string, nodes []node) (dist, product, provider string) {
	providerID := ""
	if len(nodes) > 0 {
		providerID = nodes[0].Spec.ProviderID
	}
	switch {
	case strings.Contains(gitVersion, "-eks-"):
		return "eks", "amazon-eks", "aws"
	case strings.Contains(gitVersion, "-gke."):
		return "gke", "google-kubernetes-engine", "gcp"
	case strings.HasPrefix(providerID, "azure://") && strings.Contains(providerID, "/aks-"):
		return "aks", "azure-kubernetes-service", "azure"
	case strings.Contains(gitVersion, "+k3s"):
		dist = "k3s"
	case strings.Contains(gitVersion, "+rke2"):
		dist = "rke2"
	case strings.HasPrefix(providerID, "kind://"):
		dist = "kind"
	}
	switch {
	case strings.HasPrefix(providerID, "aws://"):
		provider = "aws"
	case strings.HasPrefix(providerID, "gce://"):
		provider = "gcp"
	case strings.HasPrefix(providerID, "azure://"):
		provider = "azure"
	}
	return dist, "kubernetes", provider
}

// osPatterns map a node's osImage to the os-release id and version the
// server uses for operating-system lifecycle.
var osPatterns = []struct {
	re *regexp.Regexp
	id string
}{
	{regexp.MustCompile(`^Ubuntu (\d+\.\d+)`), "ubuntu"},
	{regexp.MustCompile(`^Debian GNU/Linux (\d+)`), "debian"},
	{regexp.MustCompile(`^Amazon Linux (\d+)`), "amzn"},
	{regexp.MustCompile(`^Red Hat Enterprise Linux.*? (\d+(?:\.\d+)?)`), "rhel"},
	{regexp.MustCompile(`^Rocky Linux (\d+\.\d+)`), "rocky"},
	{regexp.MustCompile(`^AlmaLinux (\d+\.\d+)`), "almalinux"},
	{regexp.MustCompile(`^CentOS.*? (\d+)`), "centos"},
	{regexp.MustCompile(`^Alpine Linux v?(\d+\.\d+)`), "alpine"},
	{regexp.MustCompile(`^Fedora.*? (\d+)`), "fedora"},
	{regexp.MustCompile(`^Oracle Linux Server (\d+\.\d+)`), "ol"},
}

func osOf(image string) (id, version string) {
	for _, p := range osPatterns {
		if m := p.re.FindStringSubmatch(image); m != nil {
			return p.id, m[1]
		}
	}
	if m := regexp.MustCompile(`^SUSE Linux Enterprise Server (\d+)(?: SP(\d+))?`).FindStringSubmatch(image); m != nil {
		if m[2] != "" {
			return "sles", m[1] + "." + m[2]
		}
		return "sles", m[1]
	}
	return "", ""
}

// runtimeProduct maps containerd://1.7.2 to an endoflife.date product.
func runtimeProduct(rt string) (product, version string) {
	name, v, ok := strings.Cut(rt, "://")
	if !ok {
		return "", ""
	}
	switch name {
	case "containerd":
		product = "containerd"
	case "cri-o":
		product = "cri-o"
	case "docker":
		product = "docker-engine"
	default:
		return "", ""
	}
	return product, cleanVersion(v)
}

// --- helpers

func purl(name, version string) string {
	return packageurl.NewPackageURL("generic", "", name, version, nil, "").ToString()
}

func trim(s string, n int) string {
	if len(s) > n {
		return s[:n] + "..."
	}
	return s
}

// joinLimit joins values, cutting the list (with a count of what was left
// out) before it exceeds n bytes.
func joinLimit(vals []string, n int) string {
	var b strings.Builder
	for i, v := range vals {
		sep := ""
		if i > 0 {
			sep = ", "
		}
		if b.Len()+len(sep)+len(v) > n-20 {
			fmt.Fprintf(&b, " (+%d more)", len(vals)-i)
			break
		}
		b.WriteString(sep + v)
	}
	return b.String()
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func contains(l []string, v string) bool {
	for _, x := range l {
		if x == v {
			return true
		}
	}
	return false
}

func filterOut(l, drop []string) []string {
	var out []string
	for _, v := range l {
		if !contains(drop, v) {
			out = append(out, v)
		}
	}
	return out
}

func dedupe(l []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, v := range l {
		if !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	return out
}
