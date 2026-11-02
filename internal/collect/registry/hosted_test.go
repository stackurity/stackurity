package registry

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// withAPI points one hosted API at a fake for the test.
func withAPI(t *testing.T, v *string, u string) {
	t.Helper()
	prev := *v
	*v = u
	t.Cleanup(func() { *v = prev })
}

const hubPassword = "dckr_pat_secretvalue"

// fakeHub is Docker Hub's API: sign-in, repositories and tags paged by
// "next" URLs.
func fakeHub(t *testing.T, rec *recorder) *httptest.Server {
	var srv *httptest.Server
	srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		rec.add(r, string(body))
		switch {
		case r.URL.Path == "/v2/users/login":
			var in map[string]string
			_ = json.Unmarshal(body, &in)
			if in["username"] != "acmebot" || in["password"] != hubPassword {
				w.WriteHeader(401)
				// A careless API that echoes what it was sent.
				_, _ = fmt.Fprintf(w, `{"message":"incorrect password %s"}`, in["password"])
				return
			}
			_, _ = w.Write([]byte(`{"token":"hub-jwt"}`))
			return
		case r.Header.Get("Authorization") != "Bearer hub-jwt":
			w.WriteHeader(401)
			return
		case r.URL.Path == "/v2/repositories/acme/":
			if r.URL.Query().Get("page") == "2" {
				_, _ = w.Write([]byte(`{"next":null,"results":[{"name":"web"}]}`))
				return
			}
			_, _ = fmt.Fprintf(w, `{"next":"%s/v2/repositories/acme/?page=2&page_size=100","results":[{"name":"shop"},{"name":"BAD NAME"}]}`, srv.URL)
		case r.URL.Path == "/v2/repositories/acme/shop/tags/":
			_, _ = fmt.Fprintf(w, `{"next":null,"results":[
				{"name":"latest","digest":"sha256:%s","tag_last_pushed":"2026-10-05T00:00:00Z"},
				{"name":"1.4","digest":"sha256:%s","tag_last_pushed":"2026-10-05T00:00:00Z"},
				{"name":"1.3","digest":"sha256:%s","tag_last_pushed":"2026-10-03T00:00:00Z"},
				{"name":"old","digest":"sha256:%s","tag_last_pushed":"2025-01-01T00:00:00Z"}]}`,
				strings.Repeat("a", 64), strings.Repeat("a", 64), strings.Repeat("b", 64), strings.Repeat("c", 64))
		case r.URL.Path == "/v2/repositories/acme/web/tags/":
			_, _ = w.Write([]byte(`{"next":null,"results":[]}`))
		default:
			w.WriteHeader(404)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestDockerHub(t *testing.T) {
	rec := &recorder{}
	srv := fakeHub(t, rec)
	withAPI(t, &dockerHubAPI, srv.URL)
	cfg := Config{Provider: DockerHub, Namespace: "acme", Username: "acmebot", RecentTags: 1}
	res, err := Discover(ws1(), cfg, Credentials{Secret: hubPassword}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !res.ListComplete || !res.Listed["acme/web"] || res.Listed["acme/BAD NAME"] || res.Host != "registry-1.docker.io" {
		t.Errorf("listing = %+v", res)
	}
	shop := repoOf(t, res, "acme/shop")
	if len(shop.Images) != 1 || strings.Join(shop.Images[0].Tags, ",") != "1.4,latest" ||
		shop.Images[0].Ref != "acme/shop@sha256:"+strings.Repeat("a", 64) || shop.Images[0].Display != "acme/shop:1.4" {
		t.Errorf("shop = %+v", shop.Images)
	}
	// The password went to the sign-in only, never anywhere else.
	for _, q := range rec.all() {
		if q.Path != "/v2/users/login" && (strings.Contains(q.Body, hubPassword) || strings.Contains(q.Auth, hubPassword)) {
			t.Errorf("password sent to %s", q.Path)
		}
	}
	// A refused sign-in whose answer echoes the password: the error does not.
	_, err = Discover(ws1(), cfg, Credentials{Secret: hubPassword + "x"}, nil)
	if err == nil || strings.Contains(err.Error(), hubPassword) || !strings.Contains(err.Error(), "[redacted]") {
		t.Errorf("err = %v", err)
	}
	if _, err := Discover(ws1(), Config{Provider: DockerHub, Namespace: "acme"}, Credentials{Secret: "x"}, nil); err == nil ||
		!strings.Contains(err.Error(), "username") {
		t.Errorf("a secret without a username: %v", err)
	}
}

func TestDockerHubNextPageOnAnotherHostRefused(t *testing.T) {
	evil := newFakeOther(t, nil)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprintf(w, `{"next":"%s/steal","results":[{"name":"shop"}]}`, on(evil.srv.URL, "evil.test"))
	}))
	defer srv.Close()
	withAPI(t, &dockerHubAPI, srv.URL)
	_, err := Discover(ws1(), Config{Provider: DockerHub, Namespace: "acme"}, Credentials{}, nil)
	if err == nil || !strings.Contains(err.Error(), "another host") || len(evil.all()) != 0 {
		t.Errorf("err = %v, evil requests = %d", err, len(evil.all()))
	}
}

const ghToken = "ghp_secrettokenvalue"

func TestGHCR(t *testing.T) {
	rec := &recorder{}
	var srv *httptest.Server
	srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec.add(r, "")
		if r.Header.Get("Authorization") != "Bearer "+ghToken {
			w.WriteHeader(401)
			return
		}
		switch r.URL.EscapedPath() {
		case "/orgs/acme/packages":
			w.WriteHeader(404) // a user, not an organisation
		case "/users/acme/packages":
			if r.URL.Query().Get("page") == "" {
				w.Header().Set("Link", fmt.Sprintf(`<%s/users/acme/packages?package_type=container&per_page=100&page=2>; rel="next"`, srv.URL))
				_, _ = w.Write([]byte(`[{"name":"shop"}]`))
				return
			}
			_, _ = w.Write([]byte(`[{"name":"tools/cli"}]`))
		case "/users/acme/packages/container/shop/versions":
			_, _ = fmt.Fprintf(w, `[
				{"name":"sha256:%s","created_at":"2026-10-04T00:00:00Z","metadata":{"container":{"tags":["2.0","latest"]}}},
				{"name":"sha256:%s","created_at":"2026-10-02T00:00:00Z","metadata":{"container":{"tags":["1.9"]}}},
				{"name":"sha256:%s","created_at":"2026-10-06T00:00:00Z","metadata":{"container":{"tags":[]}}}]`,
				strings.Repeat("1", 64), strings.Repeat("2", 64), strings.Repeat("3", 64))
		case "/users/acme/packages/container/tools%2Fcli/versions":
			_, _ = w.Write([]byte(`[]`))
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()
	withAPI(t, &githubAPI, srv.URL)
	cfg := Config{Provider: GHCR, Namespace: "Acme", TagPatterns: []string{"1.*"}}
	res, err := Discover(ws1(), cfg, Credentials{Secret: ghToken}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Listed["acme/tools/cli"] || !res.ListComplete || res.Host != "ghcr.io" {
		t.Errorf("listing = %+v", res)
	}
	shop := repoOf(t, res, "acme/shop")
	if len(shop.Images) != 2 || shop.Images[0].Ref != "ghcr.io/acme/shop@sha256:"+strings.Repeat("1", 64) ||
		strings.Join(shop.Images[0].Tags, ",") != "2.0,latest" || strings.Join(shop.Images[1].Tags, ",") != "1.9" {
		t.Errorf("shop = %+v (untagged versions are not images to scan)", shop.Images)
	}
	if _, err := Discover(ws1(), cfg, Credentials{}, nil); err == nil || !strings.Contains(err.Error(), "read:packages") {
		t.Errorf("no token: %v", err)
	}
	host, user, secret, err := ScanAuth(ws1(), cfg, Credentials{Secret: ghToken})
	if err != nil || host != "ghcr.io" || user != "Acme" || secret != ghToken {
		t.Errorf("scan auth = %s %s %s %v", host, user, secret, err)
	}
}

const awsSecretKey = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

func TestECR(t *testing.T) {
	rec := &recorder{}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		rec.add(r, string(body))
		if !strings.HasPrefix(r.Header.Get("Authorization"), "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/") ||
			!strings.Contains(r.Header.Get("Authorization"), "/eu-west-1/ecr/aws4_request") {
			w.WriteHeader(403)
			_, _ = w.Write([]byte(`{"__type":"UnrecognizedClientException","message":"bad signature"}`))
			return
		}
		var in map[string]any
		_ = json.Unmarshal(body, &in)
		switch strings.TrimPrefix(r.Header.Get("X-Amz-Target"), "AmazonEC2ContainerRegistry_V20150921.") {
		case "GetAuthorizationToken":
			_, _ = fmt.Fprintf(w, `{"authorizationData":[{"authorizationToken":"%s","proxyEndpoint":"https://123456789012.dkr.ecr.eu-west-1.amazonaws.com"}]}`,
				base64.StdEncoding.EncodeToString([]byte("AWS:ecr-password")))
		case "DescribeRepositories":
			_, _ = w.Write([]byte(`{"repositories":[{"repositoryName":"team/shop"},{"repositoryName":"gone"}]}`))
		case "DescribeImages":
			switch in["repositoryName"] {
			case "gone":
				w.WriteHeader(400)
				_, _ = w.Write([]byte(`{"__type":"RepositoryNotFoundException","message":"not found"}`))
			default:
				if in["nextToken"] == nil {
					_, _ = fmt.Fprintf(w, `{"imageDetails":[{"imageDigest":"sha256:%s","imageTags":["1.0"],"imagePushedAt":1759300000.5}],"nextToken":"p2"}`, strings.Repeat("d", 64))
					return
				}
				_, _ = fmt.Fprintf(w, `{"imageDetails":[{"imageDigest":"sha256:%s","imageTags":["1.1","latest"],"imagePushedAt":1759400000}]}`, strings.Repeat("e", 64))
			}
		default:
			w.WriteHeader(400)
		}
	}))
	defer srv.Close()
	prev := ecrEndpoint
	ecrEndpoint = func(string) string { return srv.URL }
	defer func() { ecrEndpoint = prev }()

	keys := &AWSKeys{AccessKeyID: "AKIDEXAMPLE", SecretAccessKey: awsSecretKey}
	cfg := Config{Provider: ECR, Region: "eu-west-1"}
	res, err := Discover(ws1(), cfg, Credentials{AWS: keys}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.Host != "123456789012.dkr.ecr.eu-west-1.amazonaws.com" {
		t.Errorf("host = %s", res.Host)
	}
	shop := repoOf(t, res, "team/shop")
	if !shop.TagsComplete || len(shop.Images) != 1 || shop.Images[0].Ref != res.Host+"/team/shop@sha256:"+strings.Repeat("e", 64) ||
		!shop.Images[0].Pushed.Equal(time.Unix(1759400000, 0)) {
		t.Errorf("shop = %+v (both pages read, the newest push chosen)", shop)
	}
	if !repoOf(t, res, "gone").Gone {
		t.Error("a repository ECR says does not exist is not gone")
	}
	for _, q := range rec.all() {
		if strings.Contains(q.Body, awsSecretKey) || strings.Contains(q.Auth, awsSecretKey) {
			t.Error("the secret access key was sent; requests are only signed with it")
		}
	}
	host, user, pass, err := ScanAuth(ws1(), cfg, Credentials{AWS: keys})
	if err != nil || host != res.Host || user != "AWS" || pass != "ecr-password" {
		t.Errorf("scan auth = %s %s %s %v", host, user, pass, err)
	}
	if _, err := Discover(ws1(), cfg, Credentials{}, nil); err == nil || !strings.Contains(err.Error(), "access keys") {
		t.Errorf("no keys: %v", err)
	}
}

func TestSelect(t *testing.T) {
	d := func(c string) string { return "sha256:" + strings.Repeat(c, 64) }
	tags := []Tag{
		{"latest", d("a"), t0.Add(5 * time.Hour)},
		{"3.0.0", d("a"), t0.Add(5 * time.Hour)},
		{"2.1.0", d("b"), t0.Add(4 * time.Hour)},
		{"feature-x", d("c"), t0.Add(3 * time.Hour)},
		{"2.0.0", d("d"), t0.Add(2 * time.Hour)},
		{"unknown", "", time.Time{}}, // digest not read: skipped
	}
	cases := []struct {
		cfg  Config
		want string
	}{
		{Config{}, "3.0.0,latest"},
		{Config{RecentTags: 2}, "3.0.0,latest|2.1.0"},
		{Config{RecentTags: 3}, "3.0.0,latest|2.1.0|feature-x"},
		{Config{TagPatterns: []string{"semver"}}, "3.0.0,latest|2.1.0|2.0.0"},
		{Config{TagPatterns: []string{"feature-*"}}, "3.0.0,latest|feature-x"},
		{Config{TagPatterns: []string{"latest"}}, "3.0.0,latest"},
	}
	for _, c := range cases {
		var parts []string
		for _, im := range NewSelector(c.cfg).Select(tags) {
			parts = append(parts, strings.Join(im.Tags, ","))
		}
		if got := strings.Join(parts, "|"); got != c.want {
			t.Errorf("%+v: %s, want %s", c.cfg, got, c.want)
		}
	}
	// Patterns are bounded per repository.
	var many []Tag
	for i := 0; i < 30; i++ {
		many = append(many, Tag{fmt.Sprintf("1.0.%d", i), fmt.Sprintf("sha256:%064d", i), t0.Add(time.Duration(i) * time.Minute)})
	}
	if n := len(NewSelector(Config{TagPatterns: []string{"semver"}}).Select(many)); n != MaxPatternTags {
		t.Errorf("%d images from patterns, want at most %d", n, MaxPatternTags)
	}
}

func TestRepositorySelection(t *testing.T) {
	cases := []struct {
		cfg  Config
		name string
		want bool
	}{
		{Config{Namespace: "acme"}, "acme/shop", true},
		{Config{Namespace: "acme", Include: []string{"shop*"}}, "acme/shop-api", true},
		{Config{Namespace: "acme", Include: []string{"shop*"}}, "acme/web", false},
		{Config{Namespace: "acme", Exclude: []string{"*-test", "sandbox/*"}}, "acme/shop-test", false},
		{Config{Namespace: "acme", Exclude: []string{"sandbox/*"}}, "acme/sandbox/x", false},
		{Config{Namespace: "acme", Repositories: []string{"shop"}}, "acme/shop", true},
		{Config{Namespace: "acme", Repositories: []string{"shop"}}, "acme/web", false},
		{Config{Repositories: []string{"team/shop"}, Exclude: []string{"team/*"}}, "team/shop", false},
	}
	for _, c := range cases {
		if got := NewSelector(c.cfg).Repository(c.name); got != c.want {
			t.Errorf("%+v %s: %v", c.cfg, c.name, got)
		}
	}
}

func TestCandidates(t *testing.T) {
	names := []string{"0.9", "1.10", "1.9", "latest", "dev", "1.2"}
	got := NewSelector(Config{TagPatterns: []string{"dev"}}).Candidates(names)
	if strings.Join(got, ",") != "dev,latest,1.10,1.9,1.2,0.9" {
		t.Errorf("candidates = %v", got)
	}
	var many []string
	for i := 0; i < 200; i++ {
		many = append(many, fmt.Sprintf("1.%d", i))
	}
	if got := NewSelector(Config{}).Candidates(many); len(got) != MaxInspected || got[0] != "1.199" {
		t.Errorf("%d candidates, first %s", len(got), got[0])
	}
}

func TestConfigValidate(t *testing.T) {
	n := 600
	bad := []Config{
		{Provider: "quay"},
		{Provider: GHCR},
		{Provider: GHCR, Namespace: "-bad"},
		{Provider: DockerHub, Namespace: "a/b"},
		{Provider: DockerHub, Namespace: "evil.example.com"},
		{Provider: DockerHub, Namespace: "acme", Repositories: []string{"evil.example.com/shop"}},
		{Provider: OCI, URL: "http://registry.example.com"},
		{Provider: OCI, URL: "https://user:pw@registry.example.com"},
		{Provider: OCI, URL: "https://registry.example.com/path"},
		{Provider: OCI, URL: "registry.example.com"},
		{Provider: OCI, URL: "https://r.example.com", AuthHost: "https://gitlab.com"},
		{Provider: ECR},
		{Provider: ECR, Region: "eu-west-1", RoleARN: "role"},
		{Provider: ECR, Region: "eu-west-1", AccountID: "123"},
		{Provider: GHCR, Namespace: "acme", Region: "eu-west-1"},
		{Provider: GHCR, Namespace: "acme", URL: "https://x.example.com"},
		{Provider: GHCR, Namespace: "acme", RecentTags: 4},
		{Provider: GHCR, Namespace: "acme", Include: []string{"a b"}},
		{Provider: GHCR, Namespace: "acme", TagPatterns: []string{"$(id)"}},
		{Provider: GHCR, Namespace: "acme", Repositories: []string{"UPPER"}},
		{Provider: GHCR, Namespace: "acme", Platform: "linux"},
		{Provider: GHCR, Namespace: "acme", ImageScans: &n},
		{Provider: GHCR, Namespace: "acme", Username: "a:b"},
	}
	for _, c := range bad {
		if c.Validate() == nil {
			t.Errorf("accepted %+v", c)
		}
	}
	good := []Config{
		{Provider: GHCR, Namespace: "Acme-Inc", RecentTags: 3, TagPatterns: []string{"semver", "latest"}},
		{Provider: DockerHub, Namespace: "library", Include: []string{"ngin*"}},
		{Provider: OCI, URL: "https://registry.example.com:5000/", Namespace: "team/apps", AuthHost: "gitlab.com"},
		{Provider: OCI, URL: "https://[2001:db8::1]:5000"},
		{Provider: ECR, Region: "eu-west-1", AccountID: "123456789012", RoleARN: "arn:aws:iam::123456789012:role/stackurity-ecr", ExternalID: "abc-123"},
		{Provider: ECR, Region: "cn-north-1", AWSIntegrationID: 4},
	}
	for _, c := range good {
		if err := c.Validate(); err != nil {
			t.Errorf("%+v: %v", c, err)
		}
	}
}
