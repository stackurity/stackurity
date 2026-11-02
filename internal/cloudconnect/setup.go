package cloudconnect

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

// Names the generated Google Cloud commands create in the customer's project.
const (
	GCPPoolID         = "stackurity"
	GCPProviderID     = "stackurity"
	GCPServiceAccount = "stackurity-reader" // @<project>.iam.gserviceaccount.com
	GCPRoleID         = "stackurityInventoryReader"
)

var (
	guidRE          = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	gcpProjectRE    = regexp.MustCompile(`^[a-z][a-z0-9-]{4,28}[a-z0-9]$`)
	gcpProjectNumRE = regexp.MustCompile(`^[1-9][0-9]{0,19}$`)
)

// ValidGUID reports whether s is a GUID (Azure tenant and subscription ids).
func ValidGUID(s string) bool { return guidRE.MatchString(s) }

// ValidGCPProject reports whether s is a Google Cloud project id.
func ValidGCPProject(s string) bool { return gcpProjectRE.MatchString(s) }

// ValidGCPProjectNumber reports whether s is a project number.
func ValidGCPProjectNumber(s string) bool { return gcpProjectNumRE.MatchString(s) }

// GCPServiceAccountEmail is the service account the commands create.
func GCPServiceAccountEmail(project string) string {
	return GCPServiceAccount + "@" + project + ".iam.gserviceaccount.com"
}

// GCPProviderName is the workload identity provider's full resource name,
// the audience of the token exchange.
func GCPProviderName(projectNumber, pool, provider string) string {
	return fmt.Sprintf("//iam.googleapis.com/projects/%s/locations/global/workloadIdentityPools/%s/providers/%s", projectNumber, pool, provider)
}

// GCPPrincipal is the federated principal for a workspace.
func GCPPrincipal(projectNumber, pool string, workspace int64) string {
	return fmt.Sprintf("principal://iam.googleapis.com/projects/%s/locations/global/workloadIdentityPools/%s/subject/%s", projectNumber, pool, Subject(workspace))
}

// Setup is what the dashboard shows to connect one project or subscription.
type Setup struct {
	Provider string `json:"provider"` // gcp, azure
	// Keyless is the recommended way: nothing secret is created in the
	// customer's cloud. When the server cannot offer it, KeylessUnavailable
	// says why and only the fallback is shown.
	Keyless            bool           `json:"keyless"`
	KeylessUnavailable string         `json:"keyless_unavailable,omitempty"`
	Commands           string         `json:"commands,omitempty"`
	Config             map[string]any `json:"config,omitempty"` // the plugin integration's config for the keyless way
	ConsentURL         string         `json:"consent_url,omitempty"`
	// The fallback: a credential the customer creates and stores as a
	// workspace secret.
	FallbackCommands string         `json:"fallback_commands"`
	FallbackConfig   map[string]any `json:"fallback_config"`
	FallbackSecret   string         `json:"fallback_secret"` // what the stored secret must contain
	Permissions      []string       `json:"permissions"`
	Plugin           string         `json:"plugin"`
}

// GCPSetup generates the gcloud commands for one project.
func (p *Platform) GCPSetup(workspace int64, project, projectNumber string) (*Setup, error) {
	if !ValidGCPProject(project) {
		return nil, errors.New("project_id must be a Google Cloud project id (6-30 lowercase letters, digits and hyphens)")
	}
	if !ValidGCPProjectNumber(projectNumber) {
		return nil, errors.New("project_number must be the project's number (digits)")
	}
	perms := GCPPermissions()
	sa := GCPServiceAccountEmail(project)
	common := fmt.Sprintf(`set -euo pipefail
PROJECT_ID=%q
SA=%q

# A custom role with exactly the read permissions Stackurity uses.
gcloud iam roles create %s --project="$PROJECT_ID" --stage=GA \
  --title="Stackurity inventory reader" \
  --description="Read-only: managed service versions for Stackurity" \
  --permissions=%q

# A service account that holds the role. No key is created.
gcloud iam service-accounts create %s --project="$PROJECT_ID" \
  --display-name="Stackurity (read-only)"
gcloud projects add-iam-policy-binding "$PROJECT_ID" --condition=None \
  --member="serviceAccount:$SA" --role="projects/$PROJECT_ID/roles/%s"
`, project, sa, GCPRoleID, strings.Join(perms, ","), GCPServiceAccount, GCPRoleID)

	s := &Setup{Provider: "gcp", Plugin: "gcp-managed", Permissions: perms, FallbackSecret: "the service account key file (JSON) as it was downloaded"}
	s.FallbackCommands = "# Only if your organisation cannot use workload identity federation.\n" + common + `
# Creates a key: store the file's contents as a workspace secret, then delete it.
gcloud iam service-accounts keys create stackurity-key.json --iam-account="$SA"
`
	s.FallbackConfig = map[string]any{"project_id": project, "auth": "service_account_key"}
	if ok, why := p.GCPStatus(); !ok {
		s.KeylessUnavailable = why
		return s, nil
	}
	s.Keyless = true
	s.Commands = "# Run in Cloud Shell, or anywhere gcloud is signed in as a project owner.\n" + common + fmt.Sprintf(`
# Trust tokens this Stackurity server signs for your workspace only.
gcloud services enable iamcredentials.googleapis.com sts.googleapis.com --project="$PROJECT_ID"
gcloud iam workload-identity-pools create %s --project="$PROJECT_ID" \
  --location=global --display-name="Stackurity"
cat > stackurity-jwks.json <<'EOF'
%s
EOF
gcloud iam workload-identity-pools providers create-oidc %s --project="$PROJECT_ID" \
  --location=global --workload-identity-pool=%s \
  --issuer-uri=%q --allowed-audiences=%q \
  --attribute-mapping="google.subject=assertion.sub" \
  --attribute-condition="assertion.sub=='%s'" \
  --jwk-json-path=stackurity-jwks.json

# Let that workspace, and nothing else, act as the service account.
gcloud iam service-accounts add-iam-policy-binding "$SA" --project="$PROJECT_ID" \
  --role=roles/iam.workloadIdentityUser \
  --member=%q
rm stackurity-jwks.json
`, GCPPoolID, p.JWKS(), GCPProviderID, GCPPoolID, p.Issuer, GCPAudience, Subject(workspace), GCPPrincipal(projectNumber, GCPPoolID, workspace))
	s.Config = map[string]any{"project_id": project, "project_number": projectNumber, "auth": "workload_identity"}
	return s, nil
}

// AzureRoleName is the custom role's name; it carries the subscription so
// two subscriptions in one tenant do not collide.
func AzureRoleName(subscription string) string {
	return "Stackurity Inventory Reader (" + strings.ToLower(subscription) + ")"
}

// AzureRoleDefinition is the custom role, as az role definition create reads it.
func AzureRoleDefinition(subscription string) string {
	b, _ := json.MarshalIndent(map[string]any{
		"Name":             AzureRoleName(subscription),
		"IsCustom":         true,
		"Description":      "Read-only: managed service versions for Stackurity",
		"Actions":          AzureActions(),
		"NotActions":       []string{},
		"DataActions":      []string{},
		"NotDataActions":   []string{},
		"AssignableScopes": []string{"/subscriptions/" + strings.ToLower(subscription)},
	}, "", "  ")
	return string(b)
}

// AzureConsentPath is where Entra ID sends the admin back after consent;
// the app registration lists base+AzureConsentPath as a redirect URI.
const AzureConsentPath = "/settings/integrations"

// AzureSetup generates the az commands for one subscription.
func (p *Platform) AzureSetup(workspace int64, tenant, subscription string) (*Setup, error) {
	if !ValidGUID(tenant) {
		return nil, errors.New("tenant_id must be the directory (tenant) id, a GUID")
	}
	if !ValidGUID(subscription) {
		return nil, errors.New("subscription_id must be a subscription id (a GUID)")
	}
	tenant, subscription = strings.ToLower(tenant), strings.ToLower(subscription)
	role := AzureRoleName(subscription)
	common := fmt.Sprintf(`set -euo pipefail
SUBSCRIPTION_ID=%q
az account set --subscription "$SUBSCRIPTION_ID"

# A custom role with exactly the read actions Stackurity uses.
cat > stackurity-role.json <<'EOF'
%s
EOF
az role definition create --role-definition @stackurity-role.json
rm stackurity-role.json
`, subscription, AzureRoleDefinition(subscription))
	s := &Setup{Provider: "azure", Plugin: "azure-managed", Permissions: AzureActions(),
		FallbackSecret: `{"azure_client_id": "<appId>", "azure_client_secret": "<password>"}`}
	s.FallbackCommands = "# Only if you cannot add Stackurity's app to your tenant.\n" + common + fmt.Sprintf(`
# Creates a service principal with a client secret in your tenant. Store
# appId and password as a workspace secret: {"azure_client_id": "<appId>", "azure_client_secret": "<password>"}
sleep 30   # a new role takes a moment to be usable
az ad sp create-for-rbac --name "stackurity-reader" --role %q \
  --scopes "/subscriptions/$SUBSCRIPTION_ID" --query "{appId: appId, password: password}"
`, role)
	s.FallbackConfig = map[string]any{"tenant_id": tenant, "subscription_id": subscription, "auth": "client_secret"}
	if ok, why := p.AzureStatus(); !ok {
		s.KeylessUnavailable = why
		return s, nil
	}
	s.Keyless = true
	q := url.Values{"client_id": {p.AzureAppID}}
	if strings.HasPrefix(p.Issuer, "https://") {
		q.Set("redirect_uri", p.Issuer+AzureConsentPath)
	}
	s.ConsentURL = "https://login.microsoftonline.com/" + tenant + "/adminconsent?" + q.Encode()
	s.Commands = "# Run in Cloud Shell, or anywhere az is signed in as an Owner or User Access Administrator\n# of the subscription (and allowed to add enterprise applications).\n" + common + fmt.Sprintf(`
# Add Stackurity's app to your tenant (the same as opening the admin consent link).
APP_ID=%q
az ad sp show --id "$APP_ID" >/dev/null 2>&1 || az ad sp create --id "$APP_ID" >/dev/null
SP_ID=$(az ad sp show --id "$APP_ID" --query id -o tsv)

# Grant the role. The description ties the grant to your Stackurity
# workspace: Stackurity refuses a subscription whose grant names another one.
for i in 1 2 3 4 5 6 7 8 9 10; do
  az role assignment create --assignee-object-id "$SP_ID" --assignee-principal-type ServicePrincipal \
    --role %q --scope "/subscriptions/$SUBSCRIPTION_ID" \
    --description %q && break
  sleep 15   # a new role or service principal takes a moment to be usable
done
az role assignment list --assignee "$SP_ID" --scope "/subscriptions/$SUBSCRIPTION_ID" --query "[0].id" -o tsv | grep -q . \
  || { echo "The role assignment was not created; run this again in a minute." >&2; exit 1; }
`, p.AzureAppID, role, ProofPrefix+p.WorkspaceProof(workspace))
	s.Config = map[string]any{"tenant_id": tenant, "subscription_id": subscription, "auth": "stackurity_app"}
	return s, nil
}
