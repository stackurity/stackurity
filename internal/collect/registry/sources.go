package registry

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// source is one kind of registry: how to list its repositories and the
// tags of one, with their digests and push times where it can tell.
type source interface {
	// refBase is the image reference of a repository, without tag or
	// digest: ghcr.io/acme/shop, acme/shop (Docker Hub), host/repo.
	refBase(repo string) string
	// host is the registry host image references point at, as
	// image.RegistryHost reads it: credentials for scans go only there.
	host() string
	repositories(ctx context.Context) ([]string, bool, error)
	tags(ctx context.Context, repo string, sel *Selector, known map[string]time.Time) ([]Tag, bool, error)
}

// Addresses of the hosted registries' APIs. Tests point them at fakes.
var (
	dockerHubAPI = "https://hub.docker.com"
	githubAPI    = "https://api.github.com"
	ghcrHost     = "ghcr.io"
)

// --- generic OCI Distribution registry

type ociSource struct {
	c         *client
	namespace string
	platform  string
}

func (s *ociSource) refBase(repo string) string { return s.c.base.Host + "/" + repo }
func (s *ociSource) host() string               { return s.c.base.Hostname() }

func (s *ociSource) repositories(ctx context.Context) ([]string, bool, error) {
	names, complete, err := s.c.Catalog(ctx, MaxTags)
	if err != nil {
		return nil, false, err
	}
	if s.namespace == "" {
		return names, complete, nil
	}
	var out []string
	for _, n := range names {
		if strings.HasPrefix(n, s.namespace+"/") {
			out = append(out, n)
		}
	}
	return out, complete, nil
}

// tags reads every tag name, then the digests of the candidates (at most
// MaxInspected) and, for digests not seen before, when they were built.
func (s *ociSource) tags(ctx context.Context, repo string, sel *Selector, known map[string]time.Time) ([]Tag, bool, error) {
	names, complete, err := s.c.TagNames(ctx, repo)
	if err != nil {
		return nil, false, err
	}
	inspect := map[string]bool{}
	for _, n := range sel.Candidates(names) {
		inspect[n] = true
	}
	created := map[string]time.Time{}
	out := make([]Tag, 0, len(names))
	var firstErr error
	failed := 0
	for _, n := range names {
		t := Tag{Name: n}
		if inspect[n] {
			d, err := s.c.Digest(ctx, repo, n)
			if err == nil {
				t.Digest = d
				if p, ok := known[d]; ok {
					t.Pushed = p
				} else if p, ok := created[d]; ok {
					t.Pushed = p
				} else if p, err2 := s.c.Created(ctx, repo, d, s.platform); err2 == nil {
					created[d], t.Pushed = p, p
				} else {
					err = err2
				}
			}
			if err != nil {
				if ctx.Err() != nil {
					return nil, false, ctx.Err()
				}
				failed++
				if firstErr == nil {
					firstErr = err
				}
				t.Digest = ""
			}
		}
		out = append(out, t)
	}
	if failed > 0 && failed == len(inspect) {
		return nil, false, firstErr
	}
	return out, complete, nil
}

// --- JSON APIs of hosted registries (Docker Hub, GitHub)

type apiClient struct {
	hc     *http.Client
	base   *url.URL
	header http.Header
	red    redactor
}

// do makes a request to the API's own host only and decodes its JSON
// answer into out. It returns the response headers (for Link paging).
func (a *apiClient) do(ctx context.Context, method string, u *url.URL, body any, out any) (http.Header, error) {
	if authority(u) != authority(a.base) || u.Scheme != a.base.Scheme {
		return nil, fmt.Errorf("refused a request to %s: not %s", u.Host, a.base.Host)
	}
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, u.String(), rd)
	if err != nil {
		return nil, err
	}
	for k, v := range a.header {
		req.Header[k] = v
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := a.hc.Do(req)
	if err != nil {
		return nil, errors.New(a.red.clean(err.Error()))
	}
	defer drain(resp)
	if resp.StatusCode != http.StatusOK {
		return nil, statusErr(a.red, a.base.Host, resp)
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxListBody)).Decode(out); err != nil {
		return nil, fmt.Errorf("%s sent an unreadable answer", a.base.Host)
	}
	return resp.Header, nil
}

// sameHost resolves a next-page URL from a JSON answer and refuses one on
// another host.
func (a *apiClient) sameHost(cur *url.URL, next string) (*url.URL, error) {
	if next == "" {
		return nil, nil
	}
	ref, err := url.Parse(next)
	if err != nil {
		return nil, errors.New("unreadable next page link")
	}
	u := cur.ResolveReference(ref)
	if authority(u) != authority(a.base) || u.Scheme != a.base.Scheme {
		return nil, fmt.Errorf("refused a next page on another host (%s)", u.Host)
	}
	return u, nil
}

func mustURL(s string) *url.URL {
	u, err := url.Parse(s)
	if err != nil {
		panic(err)
	}
	return u
}

// --- Docker Hub

type dockerHubSource struct {
	api       *apiClient
	namespace string
}

func newDockerHub(ctx context.Context, namespace, username, secret string) (*dockerHubSource, error) {
	a := &apiClient{hc: newHTTPClient(), base: mustURL(dockerHubAPI), header: http.Header{}, red: newRedactor(username, secret)}
	a.header.Set("Accept", "application/json")
	if secret != "" {
		if username == "" {
			return nil, errors.New("Docker Hub needs the username that goes with the access token: set username")
		}
		// The password or personal access token is exchanged for a
		// session token at hub.docker.com, the only host it is sent to.
		var t struct {
			Token string `json:"token"`
		}
		u := *a.base
		u.Path = "/v2/users/login"
		if _, err := a.do(ctx, http.MethodPost, &u, map[string]string{"username": username, "password": secret}, &t); err != nil {
			return nil, fmt.Errorf("Docker Hub sign-in: %w", err)
		}
		if t.Token == "" || strings.ContainsAny(t.Token, "\r\n") {
			return nil, errors.New("Docker Hub sign-in returned no token")
		}
		a.header.Set("Authorization", "Bearer "+t.Token)
	}
	return &dockerHubSource{api: a, namespace: namespace}, nil
}

func (s *dockerHubSource) refBase(repo string) string { return repo }
func (s *dockerHubSource) host() string               { return "registry-1.docker.io" }

func (s *dockerHubSource) repositories(ctx context.Context) ([]string, bool, error) {
	u := *s.api.base
	u.Path = "/v2/repositories/" + s.namespace + "/"
	u.RawQuery = url.Values{"page_size": {"100"}}.Encode()
	next := &u
	var out []string
	for page := 0; next != nil; page++ {
		if page >= maxPages || len(out) >= MaxTags {
			return out, false, nil
		}
		var body struct {
			Next    string `json:"next"`
			Results []struct {
				Name string `json:"name"`
			} `json:"results"`
		}
		if _, err := s.api.do(ctx, http.MethodGet, next, nil, &body); err != nil {
			return nil, false, err
		}
		for _, r := range body.Results {
			if nameRE.MatchString(r.Name) {
				out = append(out, s.namespace+"/"+r.Name)
			}
		}
		n, err := s.api.sameHost(next, body.Next)
		if err != nil {
			return nil, false, err
		}
		next = n
	}
	return out, true, nil
}

func (s *dockerHubSource) tags(ctx context.Context, repo string, _ *Selector, _ map[string]time.Time) ([]Tag, bool, error) {
	u := *s.api.base
	u.Path = "/v2/repositories/" + repo + "/tags/"
	u.RawQuery = url.Values{"page_size": {"100"}, "ordering": {"last_updated"}}.Encode()
	next := &u
	var out []Tag
	for page := 0; next != nil; page++ {
		if page >= maxPages || len(out) >= MaxTags {
			return out, false, nil
		}
		var body struct {
			Next    string `json:"next"`
			Results []struct {
				Name          string    `json:"name"`
				Digest        string    `json:"digest"`
				TagLastPushed time.Time `json:"tag_last_pushed"`
				LastUpdated   time.Time `json:"last_updated"`
			} `json:"results"`
		}
		if _, err := s.api.do(ctx, http.MethodGet, next, nil, &body); err != nil {
			return nil, false, err
		}
		for _, r := range body.Results {
			t := Tag{Name: r.Name, Pushed: r.TagLastPushed}
			if t.Pushed.IsZero() {
				t.Pushed = r.LastUpdated
			}
			if digestRE.MatchString(r.Digest) {
				t.Digest = r.Digest
			}
			out = append(out, t)
		}
		n, err := s.api.sameHost(next, body.Next)
		if err != nil {
			return nil, false, err
		}
		next = n
	}
	return out, true, nil
}

// --- GitHub Container Registry, through the GitHub packages API

type ghcrSource struct {
	api       *apiClient
	namespace string
	owner     string // "orgs" or "users", found on the first listing
}

func newGHCR(namespace, secret string) (*ghcrSource, error) {
	if secret == "" {
		return nil, errors.New("listing GitHub packages needs a token with read:packages: set a secret")
	}
	a := &apiClient{hc: newHTTPClient(), base: mustURL(githubAPI), header: http.Header{}, red: newRedactor("", secret)}
	a.header.Set("Accept", "application/vnd.github+json")
	a.header.Set("X-GitHub-Api-Version", "2022-11-28")
	a.header.Set("Authorization", "Bearer "+secret)
	return &ghcrSource{api: a, namespace: namespace}, nil
}

func (s *ghcrSource) refBase(repo string) string { return ghcrHost + "/" + repo }
func (s *ghcrSource) host() string               { return strings.Split(ghcrHost, ":")[0] }

// list reads a GitHub list across its Link-header pages, handing each
// item to add (which counts what it kept), until limit items. path is
// escaped (a package name may hold a slash).
func (s *ghcrSource) list(ctx context.Context, path string, query url.Values, limit int, add func(json.RawMessage) int) (bool, error) {
	u := *s.api.base
	u.Path = path
	if strings.Contains(path, "%") {
		u.Path, _ = url.PathUnescape(path)
		u.RawPath = path
	}
	u.RawQuery = query.Encode()
	next := &u
	n := 0
	for page := 0; next != nil; page++ {
		if page >= maxPages || n >= limit {
			return false, nil
		}
		var items []json.RawMessage
		h, err := s.api.do(ctx, http.MethodGet, next, nil, &items)
		if err != nil {
			return false, err
		}
		for _, it := range items {
			n += add(it)
		}
		nl, err := nextLink(next, h)
		if err != nil {
			return false, err
		}
		next = nl
	}
	return true, nil
}

func (s *ghcrSource) repositories(ctx context.Context) ([]string, bool, error) {
	var out []string
	add := func(raw json.RawMessage) int {
		var p struct {
			Name string `json:"name"`
		}
		if json.Unmarshal(raw, &p) == nil {
			name := strings.ToLower(p.Name)
			if nameRE.MatchString(name) {
				out = append(out, strings.ToLower(s.namespace)+"/"+name)
				return 1
			}
		}
		return 0
	}
	q := url.Values{"package_type": {"container"}, "per_page": {"100"}}
	owners := []string{"orgs", "users"}
	if s.owner != "" {
		owners = []string{s.owner}
	}
	var lastErr error
	for _, o := range owners {
		out = out[:0]
		complete, err := s.list(ctx, "/"+o+"/"+s.namespace+"/packages", q, MaxTags, add)
		if err == nil {
			s.owner = o
			return out, complete, nil
		}
		lastErr = err
		if !isNotFound(err) {
			return nil, false, err
		}
	}
	return nil, false, lastErr
}

func (s *ghcrSource) tags(ctx context.Context, repo string, _ *Selector, _ map[string]time.Time) ([]Tag, bool, error) {
	if s.owner == "" {
		if _, _, err := s.repositories(ctx); err != nil {
			return nil, false, err
		}
	}
	pkg := strings.TrimPrefix(repo, strings.ToLower(s.namespace)+"/")
	var out []Tag
	add := func(raw json.RawMessage) int {
		var v struct {
			Name      string    `json:"name"`
			CreatedAt time.Time `json:"created_at"`
			Metadata  struct {
				Container struct {
					Tags []string `json:"tags"`
				} `json:"container"`
			} `json:"metadata"`
		}
		if json.Unmarshal(raw, &v) != nil || !digestRE.MatchString(v.Name) {
			return 0
		}
		for _, t := range v.Metadata.Container.Tags {
			out = append(out, Tag{Name: t, Digest: v.Name, Pushed: v.CreatedAt})
		}
		return len(v.Metadata.Container.Tags)
	}
	complete, err := s.list(ctx, "/"+s.owner+"/"+s.namespace+"/packages/container/"+url.PathEscape(pkg)+"/versions",
		url.Values{"per_page": {"100"}}, MaxTags, add)
	if err != nil {
		return nil, false, err
	}
	return out, complete, nil
}
