// Command kubernetes is a first-party Stackurity plugin that inventories a
// Kubernetes cluster through read-only API calls (get/list only): which
// workloads run which container images, which workloads are reachable from
// outside the cluster, and the control plane, kubelet, container runtime
// and node OS versions for lifecycle (endoflife.date "kubernetes",
// "amazon-eks", ...).
//
// It reports a cluster asset, one workload asset per Deployment,
// StatefulSet, DaemonSet, CronJob, Job or bare Pod (runs_on the cluster,
// deployed_as its images), and one image asset per running image, pinned
// to the digest the node pulled. The server reads each image's packages
// with its image scanner; this plugin never pulls images itself.
//
// It speaks plain HTTPS to the API server with a small typed subset of the
// API instead of client-go, which keeps the binary small.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"github.com/stackurity/stackurity/pkg/plugin"
)

type settings struct {
	ClusterName       string   `json:"cluster_name,omitempty"` // default: the kubeconfig cluster name
	Context           string   `json:"context,omitempty"`      // kubeconfig context; default: current-context
	Server            string   `json:"server,omitempty"`       // API server URL, with a token secret
	InCluster         bool     `json:"in_cluster,omitempty"`   // use the pod's service account
	Namespaces        []string `json:"namespaces,omitempty"`   // only these; default: all
	ExcludeNamespaces []string `json:"exclude_namespaces,omitempty"`
	Environment       string   `json:"environment,omitempty"`
	EnvironmentLabel  string   `json:"environment_label,omitempty"` // namespace label holding the environment
	MaxImages         int      `json:"max_images,omitempty"`        // default 300
}

const (
	defaultMaxImages = 300
	limitMaxImages   = 2000
)

func (s settings) maxImages() int {
	if s.MaxImages <= 0 {
		return defaultMaxImages
	}
	return s.MaxImages
}

var (
	nameRE      = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$`)
	namespaceRE = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
	labelRE     = regexp.MustCompile(`^([a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?/)?[A-Za-z0-9]([A-Za-z0-9._-]{0,61}[A-Za-z0-9])?$`)
)

func parse(raw json.RawMessage) (settings, []string) {
	var s settings
	if len(raw) == 0 {
		raw = json.RawMessage(`{}`)
	}
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&s); err != nil {
		return s, []string{"config: " + err.Error()}
	}
	var p []string
	if s.ClusterName != "" && !nameRE.MatchString(s.ClusterName) {
		p = append(p, "cluster_name may contain letters, digits, '.', '_' and '-' (up to 100)")
	}
	if s.Server != "" {
		u, err := url.Parse(s.Server)
		if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" {
			p = append(p, "server must be an https:// URL such as https://10.0.0.1:6443")
		}
		if s.InCluster {
			p = append(p, "server and in_cluster cannot both be set")
		}
	}
	if len(s.Context) > 253 {
		p = append(p, "context is too long")
	}
	if len(s.Namespaces) > 500 || len(s.ExcludeNamespaces) > 500 {
		p = append(p, "namespaces and exclude_namespaces may list up to 500 namespaces")
	}
	for _, ns := range append(append([]string{}, s.Namespaces...), s.ExcludeNamespaces...) {
		if !namespaceRE.MatchString(ns) {
			p = append(p, fmt.Sprintf("invalid namespace %q", ns))
		}
	}
	if len(s.Environment) > 100 {
		p = append(p, "environment is too long")
	}
	if s.EnvironmentLabel != "" && !labelRE.MatchString(s.EnvironmentLabel) {
		p = append(p, "environment_label must be a label key such as environment or example.com/env")
	}
	if s.MaxImages < 0 || s.MaxImages > limitMaxImages {
		p = append(p, fmt.Sprintf("max_images must be between 1 and %d", limitMaxImages))
	}
	return s, p
}

type k8sPlugin struct {
	// connect is replaceable in tests.
	connect func(ctx context.Context, s settings, secrets map[string]string) (*client, error)
}

func (k8sPlugin) Metadata() plugin.Metadata {
	return plugin.Metadata{
		ID: "kubernetes", Name: "Kubernetes", Version: "0.1.0",
		Maintainer: "Stackurity contributors", License: "Apache-2.0",
		Homepage: "https://github.com/stackurity/stackurity/tree/main/plugins/kubernetes",
		Description: "Workloads and the container images they run, which workloads are exposed outside the cluster, " +
			"and control plane, kubelet, container runtime and node OS versions for lifecycle tracking.",
		Capabilities: []string{"inventory:cluster", "inventory:workload", "inventory:image"},
		Permissions: []string{
			"get, list, watch on pods, services, namespaces, nodes (core API group)",
			"get, list, watch on deployments, statefulsets, daemonsets (apps)",
			"get, list, watch on jobs, cronjobs (batch)",
			"get, list, watch on ingresses (networking.k8s.io)",
			"GET /version",
		},
		Credentials: []string{
			"kubeconfig (a kubeconfig with embedded credentials)",
			"token (instead of kubeconfig, with server in config)",
			"ca_cert (optional PEM CA, with token)",
		},
		NetworkAccess: []string{"the Kubernetes API server named by the kubeconfig, server, or https://kubernetes.default.svc"},
		ConfigSchema: []plugin.ConfigField{
			{Name: "cluster_name", Type: "string", Description: "name for the cluster asset (default: the kubeconfig cluster name)"},
			{Name: "context", Type: "string", Description: "kubeconfig context (default: current-context)"},
			{Name: "server", Type: "string", Description: "API server URL, when the secret is a token"},
			{Name: "in_cluster", Type: "boolean", Description: "use the service account of the pod Stackurity runs in"},
			{Name: "namespaces", Type: "string_list", Description: "only these namespaces (default: all)"},
			{Name: "exclude_namespaces", Type: "string_list", Description: "namespaces to leave out"},
			{Name: "environment", Type: "string", Description: "environment for the cluster and its workloads"},
			{Name: "environment_label", Type: "string", Description: "namespace label whose value is the workload environment"},
			{Name: "max_images", Type: "number", Description: fmt.Sprintf("most images reported per run (default %d)", defaultMaxImages)},
		},
		Frequency:  "1h",
		RateLimits: "one paginated list call per resource (500 objects a page), per namespace only when cluster-wide listing is forbidden",
		Limitations: []string{
			"exec and auth-provider kubeconfig credentials (aws eks get-token, gke-gcloud-auth-plugin) are not supported; use a service account token",
			"Gateway API routes and service meshes are not read; exposure covers Services, Ingresses and host networking",
			"custom controllers (Argo Rollouts, operators) appear as the owner kind of their pods",
			"images in registries that need pull secrets cannot be scanned without registry credentials; this shows as failed coverage on the image",
			"Kubernetes CVEs are not matched; control plane and node versions are tracked for lifecycle",
		},
	}
}

func (k8sPlugin) Validate(raw json.RawMessage) plugin.ValidationResult {
	_, p := parse(raw)
	return plugin.ValidationResult{OK: len(p) == 0, Problems: p}
}

func (k k8sPlugin) Collect(ctx context.Context, raw json.RawMessage, secrets map[string]string) ([]*plugin.ObservationBatch, error) {
	s, p := parse(raw)
	if len(p) > 0 {
		return nil, errors.New(strings.Join(p, "; "))
	}
	c, err := k.connect(ctx, s, secrets)
	if err != nil {
		return nil, err
	}
	snap, err := read(ctx, c, s)
	if err != nil {
		return nil, err
	}
	return snap.batches(), nil
}

func (k k8sPlugin) Health(ctx context.Context, raw json.RawMessage, secrets map[string]string) plugin.HealthStatus {
	s, p := parse(raw)
	if len(p) > 0 {
		return plugin.HealthStatus{Message: strings.Join(p, "; ")}
	}
	c, err := k.connect(ctx, s, secrets)
	if err != nil {
		return plugin.HealthStatus{Message: err.Error()}
	}
	var v versionInfo
	if err := c.get(ctx, "/version", nil, &v); err != nil {
		return plugin.HealthStatus{Message: "API server: " + err.Error()}
	}
	path := "/api/v1/pods"
	if len(s.Namespaces) > 0 {
		path = "/api/v1/namespaces/" + s.Namespaces[0] + "/pods"
	}
	var pods struct{}
	if err := c.get(ctx, path, url.Values{"limit": {"1"}}, &pods); err != nil {
		return plugin.HealthStatus{Message: fmt.Sprintf("connected to Kubernetes %s, but listing pods failed: %v", v.GitVersion, err)}
	}
	return plugin.HealthStatus{OK: true, Message: fmt.Sprintf("connected to Kubernetes %s at %s", v.GitVersion, c.base.Host)}
}

func main() {
	plugin.Serve(k8sPlugin{connect: connect})
}
