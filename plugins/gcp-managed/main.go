// Command gcp-managed is a first-party Stackurity plugin that inventories
// Google Cloud managed services through read-only APIs: Cloud SQL,
// Memorystore (Redis and Memcached), GKE control planes and node pools, and
// the language runtimes of Cloud Run functions, Cloud Run source deployments
// and App Engine. Each resource becomes a managed_service asset whose
// version is matched against endoflife.date lifecycle data where a product
// exists there (google-kubernetes-engine, postgresql, mysql, python, ...).
//
// Access is keyless by default: the server signs a short-lived token naming
// the workspace, which the customer's workload identity pool exchanges for
// a service account in their project (see internal/cloudconnect). A service
// account key is the fallback.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/package-url/packageurl-go"

	"github.com/stackurity/stackurity/internal/cloudconnect"
	"github.com/stackurity/stackurity/internal/cloudconnect/apiclient"
	"github.com/stackurity/stackurity/pkg/plugin"
)

var allServices = []string{"cloudsql", "memorystore", "gke", "functions", "cloudrun", "appengine"}

const (
	authWorkloadIdentity = "workload_identity"
	authKey              = "service_account_key"
)

// maxBatches keeps a run under the runner's limit of 1000 batches, with room
// for the project's coverage batch.
const maxBatches = 990

type settings struct {
	ProjectID                string   `json:"project_id"`
	ProjectNumber            string   `json:"project_number,omitempty"`
	Auth                     string   `json:"auth,omitempty"` // workload_identity (default) or service_account_key
	ServiceAccount           string   `json:"service_account,omitempty"`
	WorkloadIdentityPool     string   `json:"workload_identity_pool,omitempty"`
	WorkloadIdentityProvider string   `json:"workload_identity_provider,omitempty"`
	Services                 []string `json:"services,omitempty"`
	EnvironmentLabel         string   `json:"environment_label,omitempty"`
}

var (
	saRE    = regexp.MustCompile(`^[a-z][a-z0-9-]{4,28}[a-z0-9]@[a-z][a-z0-9-]{4,28}[a-z0-9]\.iam\.gserviceaccount\.com$`)
	poolRE  = regexp.MustCompile(`^[a-z0-9-]{4,32}$`)
	labelRE = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,62}$`)
)

func parse(raw json.RawMessage) (settings, []string) {
	var s settings
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&s); err != nil {
		return s, []string{"config: " + err.Error()}
	}
	var p []string
	if !cloudconnect.ValidGCPProject(s.ProjectID) {
		p = append(p, "project_id must be a Google Cloud project id")
	}
	if s.Auth == "" {
		s.Auth = authWorkloadIdentity
	}
	switch s.Auth {
	case authWorkloadIdentity:
		if !cloudconnect.ValidGCPProjectNumber(s.ProjectNumber) {
			p = append(p, "project_number (digits) is required for workload_identity")
		}
	case authKey:
		if s.ProjectNumber != "" && !cloudconnect.ValidGCPProjectNumber(s.ProjectNumber) {
			p = append(p, "project_number must be digits")
		}
	default:
		p = append(p, "auth must be workload_identity or service_account_key")
	}
	if s.ServiceAccount == "" && s.ProjectID != "" {
		s.ServiceAccount = cloudconnect.GCPServiceAccountEmail(s.ProjectID)
	}
	if !saRE.MatchString(s.ServiceAccount) {
		p = append(p, "service_account must be a service account email (name@project.iam.gserviceaccount.com)")
	}
	if s.WorkloadIdentityPool == "" {
		s.WorkloadIdentityPool = cloudconnect.GCPPoolID
	}
	if s.WorkloadIdentityProvider == "" {
		s.WorkloadIdentityProvider = cloudconnect.GCPProviderID
	}
	if !poolRE.MatchString(s.WorkloadIdentityPool) || !poolRE.MatchString(s.WorkloadIdentityProvider) {
		p = append(p, "workload_identity_pool and workload_identity_provider are ids of 4-32 lowercase letters, digits and hyphens")
	}
	if len(s.Services) == 0 {
		s.Services = allServices
	}
	for _, sv := range s.Services {
		if !contains(allServices, sv) {
			p = append(p, fmt.Sprintf("unknown service %q (supported: %s)", sv, strings.Join(allServices, ", ")))
		}
	}
	if s.EnvironmentLabel != "" && !labelRE.MatchString(s.EnvironmentLabel) {
		p = append(p, "environment_label must be a label key (lowercase letters, digits, _ and -)")
	}
	return s, p
}

func contains(l []string, v string) bool {
	for _, x := range l {
		if x == v {
			return true
		}
	}
	return false
}

type gcpPlugin struct {
	ep  endpoints
	now func() time.Time
}

func permissionsList() []string {
	var out []string
	for _, c := range cloudconnect.GCPCalls {
		out = append(out, c.Permission+" ("+c.Method+")")
	}
	return append(out,
		"roles/iam.workloadIdentityUser on the service account, for the workspace's federated principal (workload_identity only)")
}

func (gcpPlugin) Metadata() plugin.Metadata {
	return plugin.Metadata{
		ID: "gcp-managed", Name: "Google Cloud managed services", Version: "0.1.0",
		Maintainer: "Stackurity contributors", License: "Apache-2.0",
		Homepage:     "https://github.com/stackurity/stackurity/tree/main/plugins/gcp-managed",
		Description:  "Engine and runtime versions of Cloud SQL, Memorystore, GKE, Cloud Run functions, Cloud Run and App Engine, for lifecycle and upgrade tracking.",
		Capabilities: []string{"inventory:managed_service"},
		Permissions:  permissionsList(),
		Credentials: []string{
			cloudconnect.CredIdentityToken + " (provided by the server, workload_identity)",
			"client_email (service_account_key: the key file's fields)", "private_key (service_account_key)", "private_key_id (service_account_key, optional)",
		},
		NetworkAccess: []string{
			"sts.googleapis.com, iamcredentials.googleapis.com (workload_identity) or oauth2.googleapis.com (service_account_key)",
			"cloudresourcemanager, sqladmin, redis, memcache, container, cloudfunctions, run and appengine .googleapis.com",
		},
		ConfigSchema: []plugin.ConfigField{
			{Name: "project_id", Type: "string", Required: true, Description: "Google Cloud project id"},
			{Name: "project_number", Type: "string", Description: "project number (required for workload_identity)"},
			{Name: "auth", Type: "string", Description: "workload_identity (default, keyless) or service_account_key"},
			{Name: "service_account", Type: "string", Description: "service account to act as (default stackurity-reader@<project>.iam.gserviceaccount.com)"},
			{Name: "workload_identity_pool", Type: "string", Description: "pool id (default stackurity)"},
			{Name: "workload_identity_provider", Type: "string", Description: "provider id (default stackurity)"},
			{Name: "services", Type: "string_list", Description: "subset of " + strings.Join(allServices, ", ")},
			{Name: "environment_label", Type: "string", Description: "resource label whose value is used as the environment"},
		},
		Frequency:  "12h",
		RateLimits: "one paginated list call sequence per service (App Engine: one per service), all locations at once",
		Limitations: []string{
			"provider-managed operating system and engine internals are not visible",
			"Cloud Run services deployed from a container image have no runtime to report: scan the image instead",
			"Memorystore for Redis has no lifecycle product on endoflife.date; its version is shown, its end of life is not assessed",
			"Cloud SQL versions are compared with the upstream engine's lifecycle; Google's extended support may run longer",
			"App Engine: only serving versions are reported",
		},
	}
}

func (gcpPlugin) Validate(raw json.RawMessage) plugin.ValidationResult {
	_, p := parse(raw)
	return plugin.ValidationResult{OK: len(p) == 0, Problems: p}
}

// resource is one managed service instance.
type resource struct {
	ID         string // full resource name, //service.googleapis.com/...
	Name       string
	Service    string
	Location   string
	Product    string // endoflife.date product
	Version    string
	Labels     map[string]string
	Attributes map[string]string
}

// serviceResult is what one service returned: resources, and locations or
// parts that could not be read.
type serviceResult struct {
	res     []resource
	partial string
}

func (g gcpPlugin) Collect(ctx context.Context, raw json.RawMessage, secrets map[string]string) ([]*plugin.ObservationBatch, error) {
	s, p := parse(raw)
	if len(p) > 0 {
		return nil, errors.New(strings.Join(p, "; "))
	}
	c, err := g.connect(ctx, s, secrets)
	if err != nil {
		return nil, err
	}
	if _, err := c.checkProject(ctx); err != nil {
		return nil, fmt.Errorf("project check failed: %w", err)
	}
	var out []*plugin.ObservationBatch
	project := plugin.NewBatch(plugin.Collector{ID: "gcp-managed"}, plugin.AssetRef{
		Kind: plugin.AssetManagedService, Name: "gcp project " + s.ProjectID, Provider: "gcp",
		Identifiers: []plugin.Identifier{{Scheme: "gcp-project", Value: s.ProjectID}},
		Attributes:  map[string]string{"project": s.ProjectID},
	})
	gaps := false
	truncated := 0
	for _, svc := range s.Services {
		r, err := c.collect(ctx, svc)
		if err != nil {
			status, reason := classify(svc, err)
			project.Cover(svc, status, reason)
			gaps = true
			continue
		}
		if r.partial != "" {
			project.Cover(svc, "partial", r.partial)
			gaps = true
		} else {
			project.Cover(svc, "checked", "")
		}
		sort.Slice(r.res, func(i, j int) bool { return r.res[i].ID < r.res[j].ID })
		for _, res := range r.res {
			if len(out) >= maxBatches {
				truncated++
				continue
			}
			out = append(out, res.batch(s))
		}
	}
	if truncated > 0 {
		project.Cover("limit", "partial", fmt.Sprintf("%d resources over the limit of %d per run were not reported; split the project across integrations with services", truncated, maxBatches))
		gaps = true
	}
	// The project asset appears only when something could not be read, so
	// a gap is visible rather than looking like zero resources.
	if gaps {
		out = append(out, project)
	}
	return out, nil
}

// classify turns a service's error into a coverage status and reason.
func classify(svc string, err error) (string, string) {
	perms := []string{}
	for _, c := range cloudconnect.GCPCalls {
		if c.Service == svc {
			perms = append(perms, c.Permission)
		}
	}
	if e, ok := apiclient.AsError(err); ok {
		if e.Reason == "SERVICE_DISABLED" || strings.Contains(e.Message, "has not been used in project") || strings.Contains(e.Message, "is disabled") {
			return "skipped", "the API is not enabled in this project, so it has no resources of this kind: " + e.Error()
		}
		if e.Status == 403 {
			return "failed", "permission denied (needs " + strings.Join(perms, ", ") + "): " + e.Error()
		}
	}
	msg := err.Error()
	if len(msg) > 400 {
		msg = msg[:400]
	}
	return "failed", msg
}

func (r resource) batch(s settings) *plugin.ObservationBatch {
	attrs := map[string]string{"service": r.Service, "project": s.ProjectID}
	for k, v := range r.Attributes {
		if v != "" {
			attrs[k] = v
		}
	}
	env := ""
	if s.EnvironmentLabel != "" {
		env = r.Labels[s.EnvironmentLabel]
	}
	b := plugin.NewBatch(plugin.Collector{ID: "gcp-managed"}, plugin.AssetRef{
		Kind: plugin.AssetManagedService, Name: r.Name, Provider: "gcp", Region: r.Location, Environment: env,
		Identifiers: []plugin.Identifier{{Scheme: "gcp-resource", Value: r.ID}}, Attributes: attrs,
	})
	b.Complete = true
	if r.Version == "" || r.Product == "" {
		b.Cover(r.Service, "partial", "the API did not return a version")
		return b
	}
	b.Observations = append(b.Observations, plugin.Observation{
		Purl:       packageurl.NewPackageURL("generic", "", r.Product, r.Version, nil, "").ToString(),
		Version:    r.Version,
		Location:   r.ID,
		Confidence: plugin.ConfidenceConfirmed,
		Evidence:   map[string]string{"kind": "managed-service", "source": "Google Cloud " + r.Service + " API"},
	})
	b.Cover(r.Service, "checked", "")
	return b
}

func (g gcpPlugin) Health(ctx context.Context, raw json.RawMessage, secrets map[string]string) plugin.HealthStatus {
	s, p := parse(raw)
	if len(p) > 0 {
		return plugin.HealthStatus{Message: strings.Join(p, "; ")}
	}
	c, err := g.connect(ctx, s, secrets)
	if err != nil {
		return plugin.HealthStatus{Message: err.Error()}
	}
	name, err := c.checkProject(ctx)
	if err != nil {
		return plugin.HealthStatus{Message: "project check: " + err.Error()}
	}
	return plugin.HealthStatus{OK: true, Message: "authenticated as " + c.as + " to project " + name}
}

func main() {
	plugin.Serve(gcpPlugin{ep: googleEndpoints, now: time.Now})
}
