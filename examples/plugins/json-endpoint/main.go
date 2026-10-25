// Command json-endpoint is an example Stackurity plugin. It reads version
// information from HTTP JSON endpoints (for example an appliance's or
// internal service's /version) and reports each as an application asset.
//
// Install: build it, copy the binary into the server's plugin directory as
// "json-endpoint" (mode 0755, not group/world-writable), then add a plugin
// integration with a config such as:
//
//	{"targets": [{"name": "billing-api", "url": "https://billing.internal/version",
//	  "version_pointer": "/build/version", "product": "billing-api", "environment": "production"}]}
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/package-url/packageurl-go"

	"github.com/stackurity/stackurity/pkg/plugin"
)

type target struct {
	Name           string `json:"name"`
	URL            string `json:"url"`
	VersionPointer string `json:"version_pointer"` // RFC 6901 JSON pointer, e.g. /version
	Product        string `json:"product"`         // component name; defaults to name
	Environment    string `json:"environment"`
	AllowHTTP      bool   `json:"allow_http"`
}

type config struct {
	Targets []target `json:"targets"`
}

type endpoint struct{ client *http.Client }

func (endpoint) Metadata() plugin.Metadata {
	return plugin.Metadata{
		ID: "json-endpoint", Name: "JSON version endpoint", Version: "0.1.0",
		Maintainer: "Stackurity contributors", License: "Apache-2.0",
		Homepage:      "https://github.com/stackurity/stackurity/tree/main/examples/plugins/json-endpoint",
		Description:   "Reads a version string from HTTP JSON endpoints of custom services and appliances.",
		Capabilities:  []string{"inventory:application"},
		Permissions:   []string{},
		Credentials:   []string{"bearer_token (optional)"},
		NetworkAccess: []string{"the target URLs listed in config"},
		ConfigSchema: []plugin.ConfigField{
			{Name: "targets", Type: "list", Required: true, Description: "name, url, version_pointer, product, environment, allow_http"},
		},
		Frequency:   "6h",
		Limitations: []string{"reports one component per endpoint", "version confidence is 'inferred' because the endpoint is self-reported"},
	}
}

func parse(raw json.RawMessage) (config, []string) {
	var c config
	var problems []string
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return c, []string{"config: " + err.Error()}
	}
	if len(c.Targets) == 0 || len(c.Targets) > 500 {
		problems = append(problems, "targets must list 1-500 endpoints")
	}
	for i, t := range c.Targets {
		u, err := url.Parse(t.URL)
		switch {
		case t.Name == "":
			problems = append(problems, fmt.Sprintf("targets[%d].name is required", i))
		case err != nil || u.Host == "":
			problems = append(problems, fmt.Sprintf("targets[%d].url is invalid", i))
		case u.Scheme != "https" && !(t.AllowHTTP && u.Scheme == "http"):
			problems = append(problems, fmt.Sprintf("targets[%d].url must be https (or set allow_http)", i))
		case !strings.HasPrefix(t.VersionPointer, "/"):
			problems = append(problems, fmt.Sprintf("targets[%d].version_pointer must be a JSON pointer like /version", i))
		}
	}
	return c, problems
}

func (endpoint) Validate(raw json.RawMessage) plugin.ValidationResult {
	_, problems := parse(raw)
	return plugin.ValidationResult{OK: len(problems) == 0, Problems: problems}
}

// pointer resolves an RFC 6901 JSON pointer.
func pointer(doc any, ptr string) (any, bool) {
	cur := doc
	for _, raw := range strings.Split(ptr, "/")[1:] {
		tok := strings.NewReplacer("~1", "/", "~0", "~").Replace(raw)
		switch v := cur.(type) {
		case map[string]any:
			next, ok := v[tok]
			if !ok {
				return nil, false
			}
			cur = next
		case []any:
			i, err := strconv.Atoi(tok)
			if err != nil || i < 0 || i >= len(v) {
				return nil, false
			}
			cur = v[i]
		default:
			return nil, false
		}
	}
	return cur, true
}

func (e endpoint) fetch(ctx context.Context, t target, token string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", t.URL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := e.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	var doc any
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&doc); err != nil {
		return "", fmt.Errorf("not JSON: %w", err)
	}
	v, ok := pointer(doc, t.VersionPointer)
	if !ok {
		return "", fmt.Errorf("%s not found in response", t.VersionPointer)
	}
	s := strings.TrimSpace(fmt.Sprint(v))
	if s == "" || len(s) > 100 {
		return "", fmt.Errorf("unusable version value")
	}
	return s, nil
}

func (e endpoint) Collect(ctx context.Context, raw json.RawMessage, secrets map[string]string) ([]*plugin.ObservationBatch, error) {
	c, _ := parse(raw)
	var out []*plugin.ObservationBatch
	for _, t := range c.Targets {
		product := t.Product
		if product == "" {
			product = t.Name
		}
		b := plugin.NewBatch(plugin.Collector{ID: "json-endpoint"}, plugin.AssetRef{
			Kind: plugin.AssetApplication, Name: t.Name, Environment: t.Environment,
			Identifiers: []plugin.Identifier{{Scheme: "url", Value: t.URL}},
		})
		b.Complete = true
		v, err := e.fetch(ctx, t, secrets["bearer_token"])
		if err != nil {
			// Report the failure as coverage, not as an empty healthy asset.
			b.Cover("endpoint:"+t.URL, "failed", err.Error())
			b.Complete = false
			out = append(out, b)
			continue
		}
		b.Observations = append(b.Observations, plugin.Observation{
			Purl:       packageurl.NewPackageURL("generic", "", strings.ToLower(product), v, nil, "").ToString(),
			Version:    v,
			Location:   t.URL + "#" + t.VersionPointer,
			Confidence: plugin.ConfidenceInferred,
			Evidence:   map[string]string{"source": "self-reported endpoint"},
		})
		b.Cover("endpoint:"+t.URL, "checked", "")
		out = append(out, b)
	}
	return out, nil
}

func (e endpoint) Health(ctx context.Context, raw json.RawMessage, secrets map[string]string) plugin.HealthStatus {
	c, problems := parse(raw)
	if len(problems) > 0 {
		return plugin.HealthStatus{OK: false, Message: strings.Join(problems, "; ")}
	}
	if _, err := e.fetch(ctx, c.Targets[0], secrets["bearer_token"]); err != nil {
		return plugin.HealthStatus{OK: false, Message: c.Targets[0].Name + ": " + err.Error()}
	}
	return plugin.HealthStatus{OK: true, Message: fmt.Sprintf("%d target(s) configured; first is reachable", len(c.Targets))}
}

func main() {
	plugin.Serve(endpoint{client: &http.Client{Timeout: 20 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}})
}
