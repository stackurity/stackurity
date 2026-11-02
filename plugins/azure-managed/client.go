package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/stackurity/stackurity/internal/cloudconnect"
	"github.com/stackurity/stackurity/internal/cloudconnect/apiclient"
)

// endpoints are fixed in the binary: a workspace's config cannot send the
// platform's app secret, or a bearer token, anywhere else. Tests replace them.
type endpoints struct {
	Login string // https://login.microsoftonline.com
	ARM   string // https://management.azure.com
}

var azureEndpoints = endpoints{Login: "https://login.microsoftonline.com", ARM: "https://management.azure.com"}

const (
	maxPages         = 200
	maxConfigReads   = 500
	apiSubscriptions = "2022-12-01"
	apiRoles         = "2022-04-01"
	apiMySQL         = "2023-12-30"
	apiPostgres      = "2024-08-01"
	apiRedis         = "2024-11-01"
	apiAKS           = "2024-09-01"
	apiWeb           = "2023-12-01"
)

type client struct {
	ep      endpoints
	http    *http.Client
	token   string
	sub     string
	subName string
}

func (a azurePlugin) connect(ctx context.Context, s settings, secrets map[string]string) (*client, error) {
	c := &client{ep: a.ep, http: apiclient.NewHTTP(ctx), sub: s.SubscriptionID}
	var id, secret string
	switch s.Auth {
	case authSecret:
		id, secret = strings.TrimSpace(secrets["azure_client_id"]), secrets["azure_client_secret"]
		if id == "" || secret == "" {
			return nil, errors.New(`client_secret needs a stored secret {"azure_client_id": "...", "azure_client_secret": "..."}`)
		}
	default:
		id, secret = secrets[cloudconnect.CredAzureAppID], secrets[cloudconnect.CredAzureAppSecret]
		if id == "" || secret == "" || secrets[cloudconnect.CredWorkspaceProof] == "" {
			return nil, errors.New("Stackurity's Azure app is not available on this server (the operator sets STACKURITY_AZURE_APP_ID and STACKURITY_AZURE_APP_SECRET, and STACKURITY_SECRET_KEY); use auth client_secret instead")
		}
	}
	form := url.Values{"client_id": {id}, "client_secret": {secret}, "grant_type": {"client_credentials"},
		"scope": {"https://management.azure.com/.default"}}
	var tok struct {
		AccessToken string `json:"access_token"`
	}
	err := apiclient.Do(ctx, c.http, http.MethodPost, c.ep.Login+"/"+url.PathEscape(s.TenantID)+"/oauth2/v2.0/token", "",
		"application/x-www-form-urlencoded", strings.NewReader(form.Encode()), &tok)
	if err != nil {
		if e, ok := apiclient.AsError(err); ok && strings.Contains(e.Message, "AADSTS700016") && s.Auth == authApp {
			return nil, fmt.Errorf("Stackurity's app is not in tenant %s yet: open the admin consent link or run the setup commands (%w)", s.TenantID, err)
		}
		return nil, fmt.Errorf("sign-in to tenant %s failed: %w", s.TenantID, err)
	}
	if tok.AccessToken == "" {
		return nil, errors.New("token endpoint returned no token")
	}
	c.token = tok.AccessToken
	if err := c.checkSubscription(ctx, s.TenantID); err != nil {
		return nil, err
	}
	if s.Auth == authApp {
		if err := c.checkProof(ctx, secrets[cloudconnect.CredWorkspaceProof]); err != nil {
			return nil, err
		}
	}
	return c, nil
}

func (c *client) arm(path, apiVersion string) string {
	return c.ep.ARM + path + "?api-version=" + apiVersion
}

func (c *client) get(ctx context.Context, u string, out any) error {
	return apiclient.Do(ctx, c.http, http.MethodGet, u, c.token, "", nil, out)
}

// list reads every page of a Resource Manager collection. nextLink must stay
// on the Resource Manager host the token is for.
func list[T any](ctx context.Context, c *client, first string) ([]T, error) {
	var out []T
	base, err := url.Parse(c.ep.ARM)
	if err != nil {
		return nil, err
	}
	u := first
	for i := 0; i < maxPages && u != ""; i++ {
		var page struct {
			Value    []T    `json:"value"`
			NextLink string `json:"nextLink"`
		}
		if err := c.get(ctx, u, &page); err != nil {
			return nil, err
		}
		out = append(out, page.Value...)
		u = page.NextLink
		if u != "" {
			n, err := url.Parse(u)
			if err != nil || n.Scheme != base.Scheme || n.Host != base.Host {
				return nil, fmt.Errorf("refusing a next page link to another host (%.100s)", u)
			}
		}
	}
	if u != "" {
		return nil, fmt.Errorf("more than %d pages", maxPages)
	}
	return out, nil
}

func (c *client) checkSubscription(ctx context.Context, tenant string) error {
	var s struct {
		SubscriptionID string `json:"subscriptionId"`
		DisplayName    string `json:"displayName"`
		TenantID       string `json:"tenantId"`
		State          string `json:"state"`
	}
	if err := c.get(ctx, c.arm("/subscriptions/"+c.sub, apiSubscriptions), &s); err != nil {
		return fmt.Errorf("subscription %s could not be read (was the role assigned on it?): %w", c.sub, err)
	}
	if s.TenantID != "" && !strings.EqualFold(s.TenantID, tenant) {
		return fmt.Errorf("subscription %s belongs to tenant %s, not %s", c.sub, s.TenantID, tenant)
	}
	c.subName = c.sub
	if s.DisplayName != "" {
		c.subName = s.DisplayName + " (" + c.sub + ")"
	}
	return nil
}

// checkProof refuses a subscription unless one of the app's role
// assignments there names this workspace. The app is shared by every
// workspace, so without this a workspace could read a subscription that
// another workspace's customer granted to it.
func (c *client) checkProof(ctx context.Context, proof string) error {
	oid := tokenClaim(c.token, "oid")
	if oid == "" || !cloudconnect.ValidGUID(oid) {
		return errors.New("the access token names no service principal (oid)")
	}
	q := url.Values{"api-version": {apiRoles}, "$filter": {"principalId eq '" + oid + "'"}}
	type assignment struct {
		Properties struct {
			Description string `json:"description"`
			Scope       string `json:"scope"`
		} `json:"properties"`
	}
	as, err := list[assignment](ctx, c, c.ep.ARM+"/subscriptions/"+c.sub+"/providers/Microsoft.Authorization/roleAssignments?"+q.Encode())
	if err != nil {
		return fmt.Errorf("could not read the app's role assignments (needs Microsoft.Authorization/roleAssignments/read): %w", err)
	}
	want := cloudconnect.ProofPrefix + proof
	for _, a := range as {
		for _, f := range strings.Fields(a.Properties.Description) {
			if f == want {
				return nil
			}
		}
	}
	return fmt.Errorf("no role assignment for Stackurity's app on subscription %s names this workspace: run the setup commands shown in this workspace (the assignment's description must be %q)", c.sub, want)
}

// tokenClaim reads a claim from a JWT payload without verifying it: the
// token came over TLS from the token endpoint, and is only used to name
// ourselves in a filter.
func tokenClaim(tok, name string) string {
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		return ""
	}
	b, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return ""
	}
	var m map[string]any
	if json.Unmarshal(b, &m) != nil {
		return ""
	}
	s, _ := m[name].(string)
	return s
}

func (c *client) collect(ctx context.Context, svc string) (serviceResult, error) {
	switch svc {
	case "mysql":
		return c.databases(ctx, "mysql", "Microsoft.DBforMySQL", apiMySQL, "azure-database-for-mysql")
	case "postgresql":
		return c.databases(ctx, "postgresql", "Microsoft.DBforPostgreSQL", apiPostgres, "azure-database-for-postgresql")
	case "redis":
		return c.redis(ctx)
	case "aks":
		return c.aks(ctx)
	case "appservice":
		return c.appService(ctx)
	}
	return serviceResult{}, fmt.Errorf("unknown service %s", svc)
}

type armResource struct {
	ID       string            `json:"id"`
	Name     string            `json:"name"`
	Kind     string            `json:"kind"`
	Location string            `json:"location"`
	Tags     map[string]string `json:"tags"`
	SKU      struct {
		Name string `json:"name"`
		Tier string `json:"tier"`
	} `json:"sku"`
}

func (c *client) databases(ctx context.Context, svc, provider, apiVersion, product string) (serviceResult, error) {
	type server struct {
		armResource
		Properties struct {
			Version      string `json:"version"`
			FullVersion  string `json:"fullVersion"`  // MySQL: 8.0.21
			MinorVersion string `json:"minorVersion"` // PostgreSQL: 16.4
			State        string `json:"state"`
		} `json:"properties"`
	}
	ss, err := list[server](ctx, c, c.arm("/subscriptions/"+c.sub+"/providers/"+provider+"/flexibleServers", apiVersion))
	if err != nil {
		return serviceResult{}, err
	}
	var r serviceResult
	for _, s := range ss {
		v := s.Properties.Version
		for _, precise := range []string{s.Properties.FullVersion, s.Properties.MinorVersion} {
			if precise != "" && (v == "" || strings.HasPrefix(precise, v)) {
				v = precise
			}
		}
		r.res = append(r.res, resource{ID: s.ID, Name: s.Name, Service: svc, Location: s.Location, Product: product, Version: v, Tags: s.Tags,
			Attributes: map[string]string{"sku": s.SKU.Name, "tier": s.SKU.Tier, "state": s.Properties.State, "major_version": s.Properties.Version}})
	}
	return r, nil
}

func (c *client) redis(ctx context.Context) (serviceResult, error) {
	type cache struct {
		armResource
		Properties struct {
			RedisVersion string `json:"redisVersion"`
			SKU          struct {
				Name string `json:"name"`
			} `json:"sku"`
		} `json:"properties"`
	}
	cs, err := list[cache](ctx, c, c.arm("/subscriptions/"+c.sub+"/providers/Microsoft.Cache/redis", apiRedis))
	if err != nil {
		return serviceResult{}, err
	}
	var r serviceResult
	for _, x := range cs {
		// No endoflife.date product: the version is kept, its lifecycle
		// shows as not assessed.
		r.res = append(r.res, resource{ID: x.ID, Name: x.Name, Service: "redis", Location: x.Location, Product: "azure-cache-for-redis",
			Version: x.Properties.RedisVersion, Tags: x.Tags, Attributes: map[string]string{"sku": x.Properties.SKU.Name}})
	}
	return r, nil
}

func (c *client) aks(ctx context.Context) (serviceResult, error) {
	type cluster struct {
		armResource
		Properties struct {
			KubernetesVersion        string `json:"kubernetesVersion"`
			CurrentKubernetesVersion string `json:"currentKubernetesVersion"`
			AgentPoolProfiles        []struct {
				Name                       string `json:"name"`
				OrchestratorVersion        string `json:"orchestratorVersion"`
				CurrentOrchestratorVersion string `json:"currentOrchestratorVersion"`
				OSType                     string `json:"osType"`
				Mode                       string `json:"mode"`
			} `json:"agentPoolProfiles"`
		} `json:"properties"`
	}
	cs, err := list[cluster](ctx, c, c.arm("/subscriptions/"+c.sub+"/providers/Microsoft.ContainerService/managedClusters", apiAKS))
	if err != nil {
		return serviceResult{}, err
	}
	var r serviceResult
	for _, cl := range cs {
		v := firstNonEmpty(cl.Properties.CurrentKubernetesVersion, cl.Properties.KubernetesVersion)
		r.res = append(r.res, resource{ID: cl.ID, Name: cl.Name, Service: "aks", Location: cl.Location, Product: "azure-kubernetes-service",
			Version: v, Tags: cl.Tags, Attributes: map[string]string{"role": "control-plane", "tier": cl.SKU.Tier}})
		for _, ap := range cl.Properties.AgentPoolProfiles {
			r.res = append(r.res, resource{ID: cl.ID + "/agentPools/" + ap.Name, Name: cl.Name + "/" + ap.Name, Service: "aks", Location: cl.Location,
				Product: "azure-kubernetes-service", Version: firstNonEmpty(ap.CurrentOrchestratorVersion, ap.OrchestratorVersion), Tags: cl.Tags,
				Attributes: map[string]string{"role": "node-pool", "cluster": cl.Name, "os_type": ap.OSType, "mode": ap.Mode}})
		}
	}
	return r, nil
}

func firstNonEmpty(v ...string) string {
	for _, s := range v {
		if s != "" {
			return s
		}
	}
	return ""
}

type siteConfig struct {
	LinuxFxVersion      string `json:"linuxFxVersion"`
	WindowsFxVersion    string `json:"windowsFxVersion"`
	NetFrameworkVersion string `json:"netFrameworkVersion"`
	PHPVersion          string `json:"phpVersion"`
	PythonVersion       string `json:"pythonVersion"`
	NodeVersion         string `json:"nodeVersion"`
	JavaVersion         string `json:"javaVersion"`
}

func (c *client) appService(ctx context.Context) (serviceResult, error) {
	type site struct {
		armResource
		Properties struct {
			State      string      `json:"state"`
			Reserved   bool        `json:"reserved"` // Linux
			SiteConfig *siteConfig `json:"siteConfig"`
		} `json:"properties"`
	}
	sites, err := list[site](ctx, c, c.arm("/subscriptions/"+c.sub+"/providers/Microsoft.Web/sites", apiWeb))
	if err != nil {
		return serviceResult{}, err
	}
	var r serviceResult
	reads, skipped := 0, 0
	for _, s := range sites {
		cfg := s.Properties.SiteConfig
		if cfg == nil || (cfg.LinuxFxVersion == "" && cfg.WindowsFxVersion == "") {
			if reads >= maxConfigReads {
				skipped++
				continue
			}
			reads++
			var full struct {
				Properties siteConfig `json:"properties"`
			}
			if err := c.get(ctx, c.arm(s.ID+"/config/web", apiWeb), &full); err != nil {
				return r, err
			}
			cfg = &full.Properties
		}
		kind := "app"
		if strings.Contains(strings.ToLower(s.Kind), "functionapp") {
			kind = "function"
		}
		product, ver, why := stackVersion(*cfg)
		if product == "" && why == "" {
			continue // a container: scan the image instead
		}
		r.res = append(r.res, resource{ID: s.ID, Name: s.Name, Service: "appservice", Location: s.Location, Product: product, Version: ver, NoVersion: why,
			Tags: s.Tags, Attributes: map[string]string{"app_kind": kind, "kind": s.Kind, "stack": firstNonEmpty(cfg.LinuxFxVersion, cfg.WindowsFxVersion), "state": s.Properties.State}})
	}
	if skipped > 0 {
		r.partial = fmt.Sprintf("%d apps over the limit of %d configuration reads per run were not reported", skipped, maxConfigReads)
	}
	return r, nil
}

var leadingVersion = regexp.MustCompile(`^v?(\d+(?:\.\d+)*)`)

func numeric(s string) string {
	m := leadingVersion.FindStringSubmatch(strings.TrimPrefix(strings.TrimSpace(s), "~"))
	if m == nil {
		return ""
	}
	return m[1]
}

// stackVersion maps an app's site configuration to an endoflife.date product
// and version. A container app returns nothing (scan the image); an app whose
// runtime is not named returns a reason.
func stackVersion(c siteConfig) (product, version, why string) {
	fx := firstNonEmpty(c.LinuxFxVersion, c.WindowsFxVersion)
	if fx != "" {
		stack, v, _ := strings.Cut(fx, "|")
		switch strings.ToUpper(stack) {
		case "DOCKER", "COMPOSE", "KUBE", "SITECONTAINERS":
			return "", "", ""
		case "PYTHON":
			return "python", numeric(v), ""
		case "NODE":
			return "nodejs", strings.SplitN(numeric(v), ".", 2)[0], ""
		case "DOTNETCORE", "DOTNET", "DOTNET-ISOLATED":
			n := numeric(v)
			if !strings.Contains(n, ".") && n != "" {
				n += ".0"
			}
			return "dotnet", n, ""
		case "PHP":
			return "php", numeric(v), ""
		case "RUBY":
			return "ruby", numeric(v), ""
		}
		return "azure-app-service-stack", strings.ToLower(fx), ""
	}
	// Windows apps without windowsFxVersion name their stack in separate
	// fields. .NET Framework (v4.0) is not a line endoflife.date tracks
	// by this number, so it is not guessed.
	switch {
	case c.PHPVersion != "" && !strings.EqualFold(c.PHPVersion, "off"):
		return "php", numeric(c.PHPVersion), ""
	case c.PythonVersion != "":
		return "python", numeric(c.PythonVersion), ""
	case c.NodeVersion != "":
		return "nodejs", strings.SplitN(numeric(c.NodeVersion), ".", 2)[0], ""
	case c.JavaVersion != "":
		return "azure-app-service-stack", "java|" + strings.ToLower(c.JavaVersion), ""
	}
	if n := numeric(c.NetFrameworkVersion); n != "" && !strings.HasPrefix(n, "4") && !strings.HasPrefix(n, "2") {
		if !strings.Contains(n, ".") {
			n += ".0"
		}
		return "dotnet", n, ""
	}
	return "", "", "the site configuration does not name the runtime (Windows apps keep it in app settings, which read-only access cannot see)"
}
