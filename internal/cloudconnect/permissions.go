// Package cloudconnect holds what the gcp-managed and azure-managed plugins
// and the server share: the exact read permissions each plugin's API calls
// need, the setup commands generated from them, and the server's own
// workload identity (a signing key and issuer for Google Cloud federation,
// a proof value per workspace, and the Stackurity Entra app for Azure).
//
// The plugins list their API calls from GCPCalls and AzureCalls; the setup
// commands grant exactly GCPPermissions and AzureActions. Each plugin's tests
// fail when it makes a call the role does not grant, or the role grants
// something no call needs.
package cloudconnect

import "sort"

// GCPCall is one Google Cloud API call the gcp-managed plugin makes, with
// the IAM permission it needs.
type GCPCall struct {
	Service    string // the plugin's service name (cloudsql, gke, ...), "" for the project check
	Method     string // Google's method name, for documentation
	Permission string
}

// GCPCalls is every read call gcp-managed makes. Token exchange (STS,
// iamcredentials) is authorised by the workload identity binding, not by the
// custom role, and is not listed.
var GCPCalls = []GCPCall{
	{"", "cloudresourcemanager.projects.get", "resourcemanager.projects.get"},
	{"cloudsql", "sqladmin.instances.list", "cloudsql.instances.list"},
	{"memorystore", "redis.projects.locations.instances.list", "redis.instances.list"},
	{"memorystore", "memcache.projects.locations.instances.list", "memcache.instances.list"},
	{"gke", "container.projects.locations.clusters.list", "container.clusters.list"},
	{"functions", "cloudfunctions.projects.locations.functions.list (v2)", "cloudfunctions.functions.list"},
	{"cloudrun", "run.projects.locations.services.list (v2)", "run.services.list"},
	{"appengine", "appengine.apps.services.list", "appengine.services.list"},
	{"appengine", "appengine.apps.services.versions.list", "appengine.versions.list"},
}

// GCPPermissions is the custom role's permission list, sorted.
func GCPPermissions() []string {
	seen := map[string]bool{}
	var out []string
	for _, c := range GCPCalls {
		if !seen[c.Permission] {
			seen[c.Permission] = true
			out = append(out, c.Permission)
		}
	}
	sort.Strings(out)
	return out
}

// AzureCall is one Azure Resource Manager call azure-managed makes.
type AzureCall struct {
	Service string // the plugin's service name, "" for subscription-level checks
	Method  string // HTTP method and path shape, for documentation
	Action  string // the Azure RBAC action it needs
}

// AzureCalls is every Resource Manager call azure-managed makes. The token
// request to Entra ID is not an RBAC action and is not listed.
var AzureCalls = []AzureCall{
	{"", "GET /subscriptions/{id}", "Microsoft.Resources/subscriptions/read"},
	{"", "GET /subscriptions/{id}/providers/Microsoft.Authorization/roleAssignments", "Microsoft.Authorization/roleAssignments/read"},
	{"mysql", "GET .../providers/Microsoft.DBforMySQL/flexibleServers", "Microsoft.DBforMySQL/flexibleServers/read"},
	{"postgresql", "GET .../providers/Microsoft.DBforPostgreSQL/flexibleServers", "Microsoft.DBforPostgreSQL/flexibleServers/read"},
	{"redis", "GET .../providers/Microsoft.Cache/redis", "Microsoft.Cache/redis/read"},
	{"aks", "GET .../providers/Microsoft.ContainerService/managedClusters", "Microsoft.ContainerService/managedClusters/read"},
	{"appservice", "GET .../providers/Microsoft.Web/sites", "Microsoft.Web/sites/read"},
	{"appservice", "GET .../sites/{name}/config/web", "Microsoft.Web/sites/config/read"},
}

// AzureActions is the custom role's action list, sorted.
func AzureActions() []string {
	seen := map[string]bool{}
	var out []string
	for _, c := range AzureCalls {
		if !seen[c.Action] {
			seen[c.Action] = true
			out = append(out, c.Action)
		}
	}
	sort.Strings(out)
	return out
}
