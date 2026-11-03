package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/stackurity/stackurity/internal/cloudconnect"
	"github.com/stackurity/stackurity/internal/cloudconnect/apiclient"
)

// endpoints are Google's API base URLs. They are fixed in the binary: a
// workspace's config cannot point the identity token or a key's signed
// assertion anywhere else. Tests replace them.
type endpoints struct {
	STS, IAMCredentials, OAuthToken                                  string
	ResourceManager, SQLAdmin, Redis, Memcache, Container, Functions string
	Run, AppEngine                                                   string
}

var googleEndpoints = endpoints{
	STS: "https://sts.googleapis.com", IAMCredentials: "https://iamcredentials.googleapis.com", OAuthToken: "https://oauth2.googleapis.com/token",
	ResourceManager: "https://cloudresourcemanager.googleapis.com", SQLAdmin: "https://sqladmin.googleapis.com",
	Redis: "https://redis.googleapis.com", Memcache: "https://memcache.googleapis.com", Container: "https://container.googleapis.com",
	Functions: "https://cloudfunctions.googleapis.com", Run: "https://run.googleapis.com", AppEngine: "https://appengine.googleapis.com",
}

const cloudPlatformScope = "https://www.googleapis.com/auth/cloud-platform"

// maxPages bounds a paginated list.
const maxPages = 200

type client struct {
	ep      endpoints
	http    *http.Client
	token   string
	project string
	number  string
	as      string // the service account acted as
}

func (g gcpPlugin) connect(ctx context.Context, s settings, secrets map[string]string) (*client, error) {
	now := time.Now
	if g.now != nil {
		now = g.now
	}
	c := &client{ep: g.ep, http: apiclient.NewHTTP(ctx), project: s.ProjectID, number: s.ProjectNumber}
	var err error
	switch s.Auth {
	case authKey:
		c.token, c.as, err = c.keyToken(ctx, secrets, now())
	default:
		c.token, err = c.federatedToken(ctx, s, secrets)
		c.as = s.ServiceAccount
	}
	if err != nil {
		return nil, err
	}
	return c, nil
}

// federatedToken exchanges the server's identity token for a federated
// token at Google's STS, then for an access token of the service account.
func (c *client) federatedToken(ctx context.Context, s settings, secrets map[string]string) (string, error) {
	jwt := secrets[cloudconnect.CredIdentityToken]
	if jwt == "" {
		return "", errors.New("keyless access is not available: this Stackurity server issues no identity tokens (it needs STACKURITY_SECRET_KEY and an https STACKURITY_BASE_URL); use auth service_account_key instead")
	}
	body, _ := json.Marshal(map[string]string{
		"grant_type":           "urn:ietf:params:oauth:grant-type:token-exchange",
		"audience":             cloudconnect.GCPProviderName(s.ProjectNumber, s.WorkloadIdentityPool, s.WorkloadIdentityProvider),
		"scope":                cloudPlatformScope,
		"requested_token_type": "urn:ietf:params:oauth:token-type:access_token",
		"subject_token":        jwt,
		"subject_token_type":   "urn:ietf:params:oauth:token-type:jwt",
	})
	var sts struct {
		AccessToken string `json:"access_token"`
	}
	if err := apiclient.Do(ctx, c.http, http.MethodPost, c.ep.STS+"/v1/token", "", "application/json", bytes.NewReader(body), &sts); err != nil {
		return "", fmt.Errorf("token exchange with the workload identity pool failed (was the setup run for this workspace and project number?): %w", err)
	}
	if sts.AccessToken == "" {
		return "", errors.New("token exchange returned no token")
	}
	body, _ = json.Marshal(map[string]any{"scope": []string{cloudPlatformScope}, "lifetime": "3600s"})
	var sa struct {
		AccessToken string `json:"accessToken"`
	}
	u := c.ep.IAMCredentials + "/v1/projects/-/serviceAccounts/" + url.PathEscape(s.ServiceAccount) + ":generateAccessToken"
	if err := apiclient.Do(ctx, c.http, http.MethodPost, u, sts.AccessToken, "application/json", bytes.NewReader(body), &sa); err != nil {
		return "", fmt.Errorf("acting as %s failed (does the workspace's principal have roles/iam.workloadIdentityUser on it?): %w", s.ServiceAccount, err)
	}
	if sa.AccessToken == "" {
		return "", errors.New("generateAccessToken returned no token")
	}
	return sa.AccessToken, nil
}

// keyToken signs a JWT with a service account key and exchanges it at
// Google's OAuth endpoint (the key file's own token_uri is not used).
func (c *client) keyToken(ctx context.Context, secrets map[string]string, now time.Time) (string, string, error) {
	email, pemKey := strings.TrimSpace(secrets["client_email"]), secrets["private_key"]
	if email == "" || pemKey == "" {
		return "", "", errors.New("service_account_key needs the key file stored as the integration's secret (client_email and private_key)")
	}
	block, _ := pem.Decode([]byte(pemKey))
	if block == nil {
		return "", "", errors.New("private_key is not PEM")
	}
	k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		k, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	}
	rk, ok := k.(*rsa.PrivateKey)
	if err != nil || !ok {
		return "", "", errors.New("private_key is not an RSA key")
	}
	hdr := map[string]string{"alg": "RS256", "typ": "JWT"}
	if kid := secrets["private_key_id"]; kid != "" {
		hdr["kid"] = kid
	}
	h, _ := json.Marshal(hdr)
	cl, _ := json.Marshal(map[string]any{"iss": email, "scope": cloudPlatformScope, "aud": "https://oauth2.googleapis.com/token",
		"iat": now.Unix(), "exp": now.Add(time.Hour).Unix()})
	signing := base64.RawURLEncoding.EncodeToString(h) + "." + base64.RawURLEncoding.EncodeToString(cl)
	sum := sha256.Sum256([]byte(signing))
	sig, err := rsa.SignPKCS1v15(rand.Reader, rk, crypto.SHA256, sum[:])
	if err != nil {
		return "", "", err
	}
	form := url.Values{"grant_type": {"urn:ietf:params:oauth:grant-type:jwt-bearer"}, "assertion": {signing + "." + base64.RawURLEncoding.EncodeToString(sig)}}
	var tok struct {
		AccessToken string `json:"access_token"`
	}
	if err := apiclient.Do(ctx, c.http, http.MethodPost, c.ep.OAuthToken, "", "application/x-www-form-urlencoded", strings.NewReader(form.Encode()), &tok); err != nil {
		return "", "", fmt.Errorf("service account key sign-in failed: %w", err)
	}
	if tok.AccessToken == "" {
		return "", "", errors.New("token endpoint returned no token")
	}
	return tok.AccessToken, email, nil
}

func (c *client) get(ctx context.Context, u string, out any) error {
	return apiclient.Do(ctx, c.http, http.MethodGet, u, c.token, "", nil, out)
}

// pages calls fetch with each page token until there is none.
func pages(fetch func(token string) (string, error)) error {
	tok := ""
	for i := 0; i < maxPages; i++ {
		next, err := fetch(tok)
		if err != nil {
			return err
		}
		if next == "" {
			return nil
		}
		tok = next
	}
	return fmt.Errorf("more than %d pages", maxPages)
}

func withPage(u, token string) string {
	if token == "" {
		return u
	}
	sep := "?"
	if strings.Contains(u, "?") {
		sep = "&"
	}
	return u + sep + "pageToken=" + url.QueryEscape(token)
}

// project reads the project and checks it is the configured one.
func (c *client) checkProject(ctx context.Context) (string, error) {
	var p struct {
		Name        string `json:"name"` // projects/<number>
		ProjectID   string `json:"projectId"`
		DisplayName string `json:"displayName"`
	}
	if err := c.get(ctx, c.ep.ResourceManager+"/v3/projects/"+url.PathEscape(c.project), &p); err != nil {
		return "", err
	}
	if p.ProjectID != "" && p.ProjectID != c.project {
		return "", fmt.Errorf("the API answered for project %q, not %q", p.ProjectID, c.project)
	}
	if num := strings.TrimPrefix(p.Name, "projects/"); c.number != "" && num != "" && num != c.number {
		return "", fmt.Errorf("project %s has number %s, not the configured %s", c.project, num, c.number)
	}
	if p.DisplayName != "" {
		return p.DisplayName + " (" + c.project + ")", nil
	}
	return c.project, nil
}

func (c *client) collect(ctx context.Context, svc string) (serviceResult, error) {
	switch svc {
	case "cloudsql":
		return c.cloudSQL(ctx)
	case "memorystore":
		return c.memorystore(ctx)
	case "gke":
		return c.gke(ctx)
	case "functions":
		return c.functions(ctx)
	case "cloudrun":
		return c.cloudRun(ctx)
	case "appengine":
		return c.appEngine(ctx)
	}
	return serviceResult{}, fmt.Errorf("unknown service %s", svc)
}

func (c *client) projectPath() string { return "/projects/" + url.PathEscape(c.project) }

// locationOf reads the location from projects/p/locations/<l>/...
func locationOf(name string) string {
	parts := strings.Split(name, "/")
	for i := 0; i+1 < len(parts); i++ {
		if parts[i] == "locations" {
			return parts[i+1]
		}
	}
	return ""
}

func lastPart(name string) string { return name[strings.LastIndex(name, "/")+1:] }

func unreachableNote(locs []string) string {
	if len(locs) == 0 {
		return ""
	}
	if len(locs) > 10 {
		locs = append(locs[:10:10], "...")
	}
	return "locations that did not answer: " + strings.Join(locs, ", ")
}

func (c *client) cloudSQL(ctx context.Context) (serviceResult, error) {
	var r serviceResult
	err := pages(func(tok string) (string, error) {
		var page struct {
			Items []struct {
				Name                     string `json:"name"`
				Region                   string `json:"region"`
				DatabaseVersion          string `json:"databaseVersion"`
				DatabaseInstalledVersion string `json:"databaseInstalledVersion"`
				InstanceType             string `json:"instanceType"`
				State                    string `json:"state"`
				Settings                 struct {
					Tier       string            `json:"tier"`
					UserLabels map[string]string `json:"userLabels"`
				} `json:"settings"`
			} `json:"items"`
			NextPageToken string `json:"nextPageToken"`
		}
		if err := c.get(ctx, withPage(c.ep.SQLAdmin+"/v1"+c.projectPath()+"/instances", tok), &page); err != nil {
			return "", err
		}
		for _, i := range page.Items {
			v := i.DatabaseInstalledVersion
			if v == "" {
				v = i.DatabaseVersion
			}
			product, version := cloudSQLVersion(v)
			r.res = append(r.res, resource{
				ID: "//sqladmin.googleapis.com/projects/" + c.project + "/instances/" + i.Name, Name: i.Name, Service: "cloudsql",
				Location: i.Region, Product: product, Version: version, Labels: i.Settings.UserLabels,
				Attributes: map[string]string{"database_version": i.DatabaseVersion, "tier": i.Settings.Tier, "instance_type": i.InstanceType, "state": i.State},
			})
		}
		return page.NextPageToken, nil
	})
	return r, err
}

var sqlServerMajor = map[string]string{"2017": "14.0", "2019": "15.0", "2022": "16.0", "2025": "17.0"}

// cloudSQLVersion maps POSTGRES_15_7, MYSQL_8_0_31 or SQLSERVER_2019_STANDARD
// to an endoflife.date product and version.
func cloudSQLVersion(v string) (string, string) {
	parts := strings.Split(strings.ToUpper(v), "_")
	if len(parts) < 2 {
		return "", ""
	}
	nums := []string{}
	for _, p := range parts[1:] {
		if p == "" || strings.Trim(p, "0123456789") != "" {
			break
		}
		nums = append(nums, p)
	}
	switch parts[0] {
	case "POSTGRES":
		if len(nums) > 0 {
			return "postgresql", strings.Join(nums, ".")
		}
	case "MYSQL":
		if len(nums) > 0 {
			return "mysql", strings.Join(nums, ".")
		}
	case "SQLSERVER":
		if len(nums) > 0 {
			if m, ok := sqlServerMajor[nums[0]]; ok {
				return "mssqlserver", m
			}
		}
	}
	return "", ""
}

func (c *client) memorystore(ctx context.Context) (serviceResult, error) {
	var r serviceResult
	var unreachable []string
	err := pages(func(tok string) (string, error) {
		var page struct {
			Instances []struct {
				Name         string            `json:"name"`
				LocationID   string            `json:"locationId"`
				RedisVersion string            `json:"redisVersion"`
				Tier         string            `json:"tier"`
				Labels       map[string]string `json:"labels"`
			} `json:"instances"`
			NextPageToken string   `json:"nextPageToken"`
			Unreachable   []string `json:"unreachable"`
		}
		if err := c.get(ctx, withPage(c.ep.Redis+"/v1"+c.projectPath()+"/locations/-/instances", tok), &page); err != nil {
			return "", err
		}
		unreachable = append(unreachable, page.Unreachable...)
		for _, i := range page.Instances {
			// Memorystore for Redis has no endoflife.date product; the
			// version is kept and its lifecycle shows as not assessed.
			ver := strings.ReplaceAll(strings.TrimPrefix(i.RedisVersion, "REDIS_"), "_", ".")
			r.res = append(r.res, resource{ID: "//redis.googleapis.com/" + i.Name, Name: lastPart(i.Name), Service: "memorystore",
				Location: locationOf(i.Name), Product: "google-cloud-memorystore-redis", Version: ver, Labels: i.Labels,
				Attributes: map[string]string{"engine": "redis", "tier": i.Tier, "redis_version": i.RedisVersion}})
		}
		return page.NextPageToken, nil
	})
	if err != nil {
		return r, err
	}
	err = pages(func(tok string) (string, error) {
		var page struct {
			Instances []struct {
				Name                string            `json:"name"`
				MemcacheVersion     string            `json:"memcacheVersion"`
				MemcacheFullVersion string            `json:"memcacheFullVersion"`
				Labels              map[string]string `json:"labels"`
			} `json:"instances"`
			NextPageToken string   `json:"nextPageToken"`
			Unreachable   []string `json:"unreachable"`
		}
		if err := c.get(ctx, withPage(c.ep.Memcache+"/v1"+c.projectPath()+"/locations/-/instances", tok), &page); err != nil {
			return "", err
		}
		unreachable = append(unreachable, page.Unreachable...)
		for _, i := range page.Instances {
			ver := strings.TrimPrefix(i.MemcacheFullVersion, "memcached-")
			if ver == "" {
				ver = strings.ReplaceAll(strings.TrimPrefix(i.MemcacheVersion, "MEMCACHE_"), "_", ".")
			}
			r.res = append(r.res, resource{ID: "//memcache.googleapis.com/" + i.Name, Name: lastPart(i.Name), Service: "memorystore",
				Location: locationOf(i.Name), Product: "memcached", Version: ver, Labels: i.Labels,
				Attributes: map[string]string{"engine": "memcached", "memcache_version": i.MemcacheVersion}})
		}
		return page.NextPageToken, nil
	})
	r.partial = unreachableNote(unreachable)
	return r, err
}

func (c *client) gke(ctx context.Context) (serviceResult, error) {
	var page struct {
		Clusters []struct {
			Name                 string            `json:"name"`
			Location             string            `json:"location"`
			CurrentMasterVersion string            `json:"currentMasterVersion"`
			ResourceLabels       map[string]string `json:"resourceLabels"`
			ReleaseChannel       struct {
				Channel string `json:"channel"`
			} `json:"releaseChannel"`
			Autopilot struct {
				Enabled bool `json:"enabled"`
			} `json:"autopilot"`
			NodePools []struct {
				Name    string `json:"name"`
				Version string `json:"version"`
			} `json:"nodePools"`
		} `json:"clusters"`
		MissingZones []string `json:"missingZones"`
	}
	// clusters.list is not paginated.
	if err := c.get(ctx, c.ep.Container+"/v1"+c.projectPath()+"/locations/-/clusters", &page); err != nil {
		return serviceResult{}, err
	}
	var r serviceResult
	for _, cl := range page.Clusters {
		id := "//container.googleapis.com/projects/" + c.project + "/locations/" + cl.Location + "/clusters/" + cl.Name
		attrs := map[string]string{"role": "control-plane", "release_channel": cl.ReleaseChannel.Channel}
		if cl.Autopilot.Enabled {
			attrs["autopilot"] = "true"
		}
		r.res = append(r.res, resource{ID: id, Name: cl.Name, Service: "gke", Location: cl.Location,
			Product: "google-kubernetes-engine", Version: cl.CurrentMasterVersion, Labels: cl.ResourceLabels, Attributes: attrs})
		for _, np := range cl.NodePools {
			r.res = append(r.res, resource{ID: id + "/nodePools/" + np.Name, Name: cl.Name + "/" + np.Name, Service: "gke", Location: cl.Location,
				Product: "google-kubernetes-engine", Version: np.Version, Labels: cl.ResourceLabels,
				Attributes: map[string]string{"role": "node-pool", "cluster": cl.Name}})
		}
	}
	r.partial = unreachableNote(page.MissingZones)
	return r, nil
}

var runtimeRE = regexp.MustCompile(`^(python|nodejs|go|ruby|php|java|dotnet)(\d+)$`)

// runtimeVersion maps a Google runtime id (python312, nodejs20, go122,
// dotnet8) to an endoflife.date product and release line. Runtimes without
// a matching product keep their id under google-cloud-runtime, which shows
// as not assessed.
func runtimeVersion(rt string) (string, string) {
	m := runtimeRE.FindStringSubmatch(rt)
	if m == nil {
		return "google-cloud-runtime", rt
	}
	n := m[2]
	switch m[1] {
	case "python", "ruby", "php":
		if len(n) >= 2 {
			return m[1], n[:1] + "." + n[1:]
		}
	case "go":
		if len(n) >= 2 && n[0] == '1' {
			return "go", "1." + n[1:]
		}
	case "nodejs":
		return "nodejs", n
	case "dotnet":
		switch n {
		case "3":
			return "dotnet", "3.1"
		case "1":
			return "google-cloud-runtime", rt
		}
		return "dotnet", n + ".0"
	}
	return "google-cloud-runtime", rt
}

func (c *client) functions(ctx context.Context) (serviceResult, error) {
	var r serviceResult
	var unreachable []string
	err := pages(func(tok string) (string, error) {
		var page struct {
			Functions []struct {
				Name        string            `json:"name"`
				Environment string            `json:"environment"`
				State       string            `json:"state"`
				Labels      map[string]string `json:"labels"`
				BuildConfig struct {
					Runtime string `json:"runtime"`
				} `json:"buildConfig"`
			} `json:"functions"`
			NextPageToken string   `json:"nextPageToken"`
			Unreachable   []string `json:"unreachable"`
		}
		if err := c.get(ctx, withPage(c.ep.Functions+"/v2"+c.projectPath()+"/locations/-/functions", tok), &page); err != nil {
			return "", err
		}
		unreachable = append(unreachable, page.Unreachable...)
		for _, f := range page.Functions {
			product, ver := runtimeVersion(f.BuildConfig.Runtime)
			if f.BuildConfig.Runtime == "" {
				product = ""
			}
			r.res = append(r.res, resource{ID: "//cloudfunctions.googleapis.com/" + f.Name, Name: lastPart(f.Name), Service: "functions",
				Location: locationOf(f.Name), Product: product, Version: ver, Labels: f.Labels,
				Attributes: map[string]string{"runtime": f.BuildConfig.Runtime, "generation": f.Environment, "state": f.State}})
		}
		return page.NextPageToken, nil
	})
	r.partial = unreachableNote(unreachable)
	return r, err
}

func (c *client) cloudRun(ctx context.Context) (serviceResult, error) {
	var r serviceResult
	var unreachable []string
	err := pages(func(tok string) (string, error) {
		var page struct {
			Services []struct {
				Name     string            `json:"name"`
				Labels   map[string]string `json:"labels"`
				Template struct {
					Containers []struct {
						Image        string `json:"image"`
						BaseImageURI string `json:"baseImageUri"`
					} `json:"containers"`
				} `json:"template"`
			} `json:"services"`
			NextPageToken string   `json:"nextPageToken"`
			Unreachable   []string `json:"unreachable"`
		}
		if err := c.get(ctx, withPage(c.ep.Run+"/v2"+c.projectPath()+"/locations/-/services", tok), &page); err != nil {
			return "", err
		}
		unreachable = append(unreachable, page.Unreachable...)
		for _, s := range page.Services {
			if s.Labels["goog-managed-by"] == "cloudfunctions" {
				continue // reported as a function
			}
			for _, ct := range s.Template.Containers {
				// Source deployments with automatic base image updates name
				// the runtime (.../runtimes/python312); a plain image has
				// none and is left to image scanning.
				if ct.BaseImageURI == "" {
					continue
				}
				rt := lastPart(ct.BaseImageURI)
				if i := strings.IndexAny(rt, ":@"); i >= 0 {
					rt = rt[:i]
				}
				product, ver := runtimeVersion(rt)
				r.res = append(r.res, resource{ID: "//run.googleapis.com/" + s.Name, Name: lastPart(s.Name), Service: "cloudrun",
					Location: locationOf(s.Name), Product: product, Version: ver, Labels: s.Labels,
					Attributes: map[string]string{"runtime": rt, "base_image": ct.BaseImageURI}})
				break
			}
		}
		return page.NextPageToken, nil
	})
	r.partial = unreachableNote(unreachable)
	return r, err
}

func (c *client) appEngine(ctx context.Context) (serviceResult, error) {
	var r serviceResult
	var services []string
	base := c.ep.AppEngine + "/v1/apps/" + url.PathEscape(c.project) + "/services"
	err := pages(func(tok string) (string, error) {
		var page struct {
			Services []struct {
				ID string `json:"id"`
			} `json:"services"`
			NextPageToken string `json:"nextPageToken"`
		}
		if err := c.get(ctx, withPage(base, tok), &page); err != nil {
			return "", err
		}
		for _, s := range page.Services {
			services = append(services, s.ID)
		}
		return page.NextPageToken, nil
	})
	if apiclient.StatusOf(err) == http.StatusNotFound {
		return r, nil // the project has no App Engine application
	}
	if err != nil {
		return r, err
	}
	for _, svc := range services {
		err := pages(func(tok string) (string, error) {
			var page struct {
				Versions []struct {
					ID            string `json:"id"`
					Runtime       string `json:"runtime"`
					Env           string `json:"env"`
					ServingStatus string `json:"servingStatus"`
				} `json:"versions"`
				NextPageToken string `json:"nextPageToken"`
			}
			if err := c.get(ctx, withPage(base+"/"+url.PathEscape(svc)+"/versions?view=BASIC", tok), &page); err != nil {
				return "", err
			}
			for _, v := range page.Versions {
				if v.ServingStatus != "SERVING" {
					continue
				}
				product, ver := runtimeVersion(v.Runtime)
				if v.Runtime == "python27" {
					product, ver = "python", "2.7"
				}
				r.res = append(r.res, resource{ID: "//appengine.googleapis.com/apps/" + c.project + "/services/" + svc + "/versions/" + v.ID,
					Name: c.project + "/" + svc + "/" + v.ID, Service: "appengine", Product: product, Version: ver,
					Attributes: map[string]string{"runtime": v.Runtime, "env": v.Env, "app_service": svc}})
			}
			return page.NextPageToken, nil
		})
		if err != nil {
			return r, err
		}
	}
	return r, nil
}
