// Command azure-managed is a first-party Stackurity plugin that inventories
// Azure managed services through read-only Resource Manager APIs: Azure
// Database for MySQL and PostgreSQL flexible servers, Azure Cache for Redis,
// AKS clusters and node pools, and the runtime stacks of App Service and
// Functions apps. Each resource becomes a managed_service asset whose version
// is matched against endoflife.date lifecycle data where a product exists
// there (azure-kubernetes-service, azure-database-for-postgresql, ...).
//
// Access is through Stackurity's multi-tenant Entra app by default: the
// customer adds it to their tenant and grants it a read-only role whose
// assignment names their workspace (see internal/cloudconnect). A service
// principal with a client secret is the fallback.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/package-url/packageurl-go"

	"github.com/stackurity/stackurity/internal/cloudconnect"
	"github.com/stackurity/stackurity/internal/cloudconnect/apiclient"
	"github.com/stackurity/stackurity/pkg/plugin"
)

var allServices = []string{"mysql", "postgresql", "redis", "aks", "appservice"}

const (
	authApp    = "stackurity_app"
	authSecret = "client_secret"
)

// maxBatches keeps a run under the runner's limit of 1000 batches.
const maxBatches = 990

type settings struct {
	TenantID       string   `json:"tenant_id"`
	SubscriptionID string   `json:"subscription_id"`
	Auth           string   `json:"auth,omitempty"` // stackurity_app (default) or client_secret
	Services       []string `json:"services,omitempty"`
	EnvironmentTag string   `json:"environment_tag,omitempty"`
}

var tagRE = regexp.MustCompile(`^[^<>%&\\?/]{1,512}$`)

func parse(raw json.RawMessage) (settings, []string) {
	var s settings
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&s); err != nil {
		return s, []string{"config: " + err.Error()}
	}
	var p []string
	if !cloudconnect.ValidGUID(s.TenantID) {
		p = append(p, "tenant_id must be the directory (tenant) id, a GUID")
	}
	if !cloudconnect.ValidGUID(s.SubscriptionID) {
		p = append(p, "subscription_id must be a subscription id (a GUID)")
	}
	s.TenantID, s.SubscriptionID = strings.ToLower(s.TenantID), strings.ToLower(s.SubscriptionID)
	if s.Auth == "" {
		s.Auth = authApp
	}
	if s.Auth != authApp && s.Auth != authSecret {
		p = append(p, "auth must be stackurity_app or client_secret")
	}
	if len(s.Services) == 0 {
		s.Services = allServices
	}
	for _, sv := range s.Services {
		if !contains(allServices, sv) {
			p = append(p, fmt.Sprintf("unknown service %q (supported: %s)", sv, strings.Join(allServices, ", ")))
		}
	}
	if s.EnvironmentTag != "" && !tagRE.MatchString(s.EnvironmentTag) {
		p = append(p, "environment_tag must be a tag name")
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

type azurePlugin struct{ ep endpoints }

func permissionsList() []string {
	var out []string
	for _, c := range cloudconnect.AzureCalls {
		out = append(out, c.Action+" ("+c.Method+")")
	}
	return out
}

func (azurePlugin) Metadata() plugin.Metadata {
	return plugin.Metadata{
		ID: "azure-managed", Name: "Azure managed services", Version: "0.1.0",
		Maintainer: "Stackurity contributors", License: "Apache-2.0",
		Homepage:     "https://github.com/stackurity/stackurity/tree/main/plugins/azure-managed",
		Description:  "Engine and runtime versions of Azure Database for MySQL and PostgreSQL, Azure Cache for Redis, AKS, App Service and Functions, for lifecycle and upgrade tracking.",
		Capabilities: []string{"inventory:managed_service"},
		Permissions:  permissionsList(),
		Credentials: []string{
			cloudconnect.CredAzureAppID + " (provided by the server, stackurity_app)",
			cloudconnect.CredAzureAppSecret + " (provided by the server, stackurity_app)",
			cloudconnect.CredWorkspaceProof + " (provided by the server, stackurity_app)",
			"azure_client_id (client_secret)", "azure_client_secret (client_secret)",
		},
		NetworkAccess: []string{"login.microsoftonline.com (token)", "management.azure.com (Resource Manager)"},
		ConfigSchema: []plugin.ConfigField{
			{Name: "tenant_id", Type: "string", Required: true, Description: "directory (tenant) id"},
			{Name: "subscription_id", Type: "string", Required: true, Description: "subscription id"},
			{Name: "auth", Type: "string", Description: "stackurity_app (default, no secret in your tenant) or client_secret"},
			{Name: "services", Type: "string_list", Description: "subset of " + strings.Join(allServices, ", ")},
			{Name: "environment_tag", Type: "string", Description: "resource tag whose value is used as the environment"},
		},
		Frequency:  "12h",
		RateLimits: "one paginated list per service and subscription; App Service: one configuration read per app whose list entry has no runtime",
		Limitations: []string{
			"provider-managed operating system and engine internals are not visible",
			"Azure Cache for Redis has no lifecycle product on endoflife.date; its version is shown, its end of life is not assessed",
			"App Service: container apps are left to image scanning; Windows apps report a runtime only where the site configuration names one (app settings are never read)",
			"single servers (the retired Azure Database single-server offering) are not read",
		},
	}
}

func (azurePlugin) Validate(raw json.RawMessage) plugin.ValidationResult {
	_, p := parse(raw)
	return plugin.ValidationResult{OK: len(p) == 0, Problems: p}
}

type resource struct {
	ID         string
	Name       string
	Service    string
	Location   string
	Product    string
	Version    string
	NoVersion  string // why there is no version, when there is none
	Tags       map[string]string
	Attributes map[string]string
}

type serviceResult struct {
	res     []resource
	partial string
}

func (a azurePlugin) Collect(ctx context.Context, raw json.RawMessage, secrets map[string]string) ([]*plugin.ObservationBatch, error) {
	s, p := parse(raw)
	if len(p) > 0 {
		return nil, errors.New(strings.Join(p, "; "))
	}
	c, err := a.connect(ctx, s, secrets)
	if err != nil {
		return nil, err
	}
	sub := plugin.NewBatch(plugin.Collector{ID: "azure-managed"}, plugin.AssetRef{
		Kind: plugin.AssetManagedService, Name: "azure subscription " + c.subName, Provider: "azure",
		Identifiers: []plugin.Identifier{{Scheme: "azure-subscription", Value: s.SubscriptionID}},
		Attributes:  map[string]string{"subscription": s.SubscriptionID, "tenant": s.TenantID},
	})
	var out []*plugin.ObservationBatch
	gaps, truncated := false, 0
	for _, svc := range s.Services {
		r, err := c.collect(ctx, svc)
		if err != nil {
			status, reason := classify(svc, err)
			sub.Cover(svc, status, reason)
			gaps = true
			continue
		}
		if r.partial != "" {
			sub.Cover(svc, "partial", r.partial)
			gaps = true
		} else {
			sub.Cover(svc, "checked", "")
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
		sub.Cover("limit", "partial", fmt.Sprintf("%d resources over the limit of %d per run were not reported; split the subscription across integrations with services", truncated, maxBatches))
		gaps = true
	}
	if gaps {
		out = append(out, sub)
	}
	return out, nil
}

func classify(svc string, err error) (string, string) {
	var actions []string
	for _, c := range cloudconnect.AzureCalls {
		if c.Service == svc {
			actions = append(actions, c.Action)
		}
	}
	if e, ok := apiclient.AsError(err); ok {
		switch {
		case e.Code == "MissingSubscriptionRegistration":
			return "skipped", "the resource provider is not registered in this subscription, so it has no resources of this kind: " + e.Error()
		case e.Status == 403:
			return "failed", "permission denied (needs " + strings.Join(actions, ", ") + "): " + e.Error()
		}
	}
	msg := err.Error()
	if len(msg) > 400 {
		msg = msg[:400]
	}
	return "failed", msg
}

func (r resource) batch(s settings) *plugin.ObservationBatch {
	attrs := map[string]string{"service": r.Service, "subscription": s.SubscriptionID, "resource_group": resourceGroup(r.ID)}
	for k, v := range r.Attributes {
		if v != "" {
			attrs[k] = v
		}
	}
	env := ""
	if s.EnvironmentTag != "" {
		for k, v := range r.Tags {
			if strings.EqualFold(k, s.EnvironmentTag) {
				env = v
			}
		}
	}
	b := plugin.NewBatch(plugin.Collector{ID: "azure-managed"}, plugin.AssetRef{
		Kind: plugin.AssetManagedService, Name: r.Name, Provider: "azure", Region: r.Location, Environment: env,
		Identifiers: []plugin.Identifier{{Scheme: "azure-resource-id", Value: strings.ToLower(r.ID)}}, Attributes: attrs,
	})
	b.Complete = true
	if r.Version == "" || r.Product == "" {
		why := r.NoVersion
		if why == "" {
			why = "the API did not return a version"
		}
		b.Cover(r.Service, "partial", why)
		return b
	}
	b.Observations = append(b.Observations, plugin.Observation{
		Purl:       packageurl.NewPackageURL("generic", "", r.Product, r.Version, nil, "").ToString(),
		Version:    r.Version,
		Location:   r.ID,
		Confidence: plugin.ConfidenceConfirmed,
		Evidence:   map[string]string{"kind": "managed-service", "source": "Azure " + r.Service + " API"},
	})
	b.Cover(r.Service, "checked", "")
	return b
}

// resourceGroup reads the group from /subscriptions/s/resourceGroups/<g>/...
func resourceGroup(id string) string {
	parts := strings.Split(id, "/")
	for i := 0; i+1 < len(parts); i++ {
		if strings.EqualFold(parts[i], "resourceGroups") {
			return parts[i+1]
		}
	}
	return ""
}

func (a azurePlugin) Health(ctx context.Context, raw json.RawMessage, secrets map[string]string) plugin.HealthStatus {
	s, p := parse(raw)
	if len(p) > 0 {
		return plugin.HealthStatus{Message: strings.Join(p, "; ")}
	}
	c, err := a.connect(ctx, s, secrets)
	if err != nil {
		return plugin.HealthStatus{Message: err.Error()}
	}
	return plugin.HealthStatus{OK: true, Message: "authenticated to subscription " + c.subName}
}

func main() {
	plugin.Serve(azurePlugin{ep: azureEndpoints})
}
