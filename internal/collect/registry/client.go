package registry

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/stackurity/stackurity/internal/netguard"
)

// Response bodies read from a registry are bounded.
const (
	maxListBody     = 8 << 20
	maxManifestBody = 4 << 20
	maxTokenBody    = 64 << 10
	maxPages        = 200
)

// testTLS is the TLS configuration of the registry client in tests (which
// talk to httptest servers with their own certificate); nil otherwise.
var testTLS *tls.Config

// newHTTPClient makes a client for one workspace's registry requests:
// every connection is checked by netguard, and a redirect to another host
// never carries credentials (checkRedirect).
func newHTTPClient() *http.Client {
	t := &http.Transport{
		DialContext:           netguard.DialContext,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
		MaxIdleConns:          8,
		IdleConnTimeout:       30 * time.Second,
		TLSClientConfig:       testTLS,
	}
	return &http.Client{Timeout: 2 * time.Minute, Transport: t, CheckRedirect: checkRedirect}
}

// checkRedirect follows at most five redirects, never from https to http,
// and drops credentials when a redirect leaves the host the request was
// made to (blob downloads are redirected to storage on another host).
// net/http drops them for most other hosts already, but keeps them for a
// subdomain; here any other host loses them.
func checkRedirect(req *http.Request, via []*http.Request) error {
	if len(via) >= 5 {
		return errors.New("stopped after 5 redirects")
	}
	if via[0].URL.Scheme == "https" && req.URL.Scheme != "https" {
		return fmt.Errorf("refused a redirect from https to %s", req.URL.Scheme)
	}
	if authority(req.URL) != authority(via[0].URL) {
		req.Header.Del("Authorization")
		req.Header.Del("Cookie")
	}
	return nil
}

// authority is a URL's host and port, with the scheme's default port
// written out, in lower case.
func authority(u *url.URL) string {
	host, port := u.Hostname(), u.Port()
	if port == "" {
		port = "443"
		if u.Scheme == "http" {
			port = "80"
		}
	}
	return strings.ToLower(net.JoinHostPort(host, port))
}

// redactor removes a secret, and the forms it is sent in, from text that
// may be shown (an error from the registry that echoes a header).
type redactor []string

func newRedactor(username, secret string) redactor {
	if secret == "" {
		return nil
	}
	basic := base64.StdEncoding.EncodeToString([]byte(username + ":" + secret))
	return redactor{basic, strings.TrimRight(basic, "="), secret}
}

func (r redactor) clean(s string) string {
	for _, v := range r {
		if v != "" {
			s = strings.ReplaceAll(s, v, "[redacted]")
		}
	}
	return s
}

// client speaks the OCI Distribution API to one registry.
type client struct {
	hc       *http.Client
	base     *url.URL
	username string
	secret   string
	// realms are the authorities (host:port) a token realm may be on
	// besides the registry itself.
	realms map[string]bool
	basic  bool              // the registry asked for basic authentication
	tokens map[string]string // bearer tokens by scope
	red    redactor
}

func newClient(base *url.URL, username, secret string, realms ...string) *client {
	c := &client{hc: newHTTPClient(), base: base, username: username, secret: secret,
		realms: map[string]bool{authority(base): true}, tokens: map[string]string{}, red: newRedactor(username, secret)}
	for _, r := range realms {
		if r == "" {
			continue
		}
		u := &url.URL{Scheme: "https", Host: r}
		c.realms[authority(u)] = true
	}
	return c
}

// challenge is a parsed WWW-Authenticate header.
type challenge struct {
	scheme string
	params map[string]string
}

var challengeParamRE = regexp.MustCompile(`([A-Za-z_]+)="([^"]*)"|([A-Za-z_]+)=([^,\s"]+)`)

func parseChallenge(h string) (challenge, bool) {
	h = strings.TrimSpace(h)
	scheme, rest, _ := strings.Cut(h, " ")
	if scheme == "" {
		return challenge{}, false
	}
	c := challenge{scheme: strings.ToLower(scheme), params: map[string]string{}}
	for _, m := range challengeParamRE.FindAllStringSubmatch(rest, -1) {
		if m[1] != "" {
			c.params[strings.ToLower(m[1])] = m[2]
		} else {
			c.params[strings.ToLower(m[3])] = m[4]
		}
	}
	return c, true
}

// scopeFor is the token scope a registry path needs.
func scopeFor(path string) string {
	if path == "/v2/_catalog" {
		return "registry:catalog:*"
	}
	rest := strings.TrimPrefix(path, "/v2/")
	for _, sep := range []string{"/tags/list", "/manifests/", "/blobs/"} {
		if i := strings.Index(rest, sep); i > 0 {
			return "repository:" + rest[:i] + ":pull"
		}
	}
	return ""
}

// get makes a request to the registry, answering an authentication
// challenge once. The URL must be on the registry's own host.
func (c *client) get(ctx context.Context, method string, u *url.URL, accept ...string) (*http.Response, error) {
	if authority(u) != authority(c.base) || u.Scheme != c.base.Scheme {
		return nil, fmt.Errorf("refused a request to %s: not the registry %s", u.Host, c.base.Host)
	}
	scope := scopeFor(u.Path)
	for attempt := 0; ; attempt++ {
		req, err := http.NewRequestWithContext(ctx, method, u.String(), nil)
		if err != nil {
			return nil, err
		}
		for _, a := range accept {
			req.Header.Add("Accept", a)
		}
		switch {
		case c.tokens[scope] != "":
			req.Header.Set("Authorization", "Bearer "+c.tokens[scope])
		case c.basic && c.secret != "":
			req.SetBasicAuth(c.username, c.secret)
		case c.secret != "" && c.username == "":
			// A token issued for the registry, used as it is.
			req.Header.Set("Authorization", "Bearer "+c.secret)
		}
		resp, err := c.hc.Do(req)
		if err != nil {
			return nil, c.cleanErr(err)
		}
		if resp.StatusCode != http.StatusUnauthorized || attempt > 0 {
			return resp, nil
		}
		ch, ok := parseChallenge(resp.Header.Get("WWW-Authenticate"))
		drain(resp)
		if !ok {
			return nil, errors.New("the registry refused the request (401) without saying how to authenticate")
		}
		switch ch.scheme {
		case "basic":
			if c.secret == "" {
				return nil, errors.New("the registry needs credentials: set a secret")
			}
			if c.basic {
				return nil, errors.New("the registry refused the credentials (401)")
			}
			c.basic = true
		case "bearer":
			want := ch.params["scope"]
			if want == "" {
				want = scope
			}
			tok, err := c.token(ctx, ch, want)
			if err != nil {
				return nil, err
			}
			c.tokens[scope] = tok
		default:
			return nil, fmt.Errorf("the registry asks for %q authentication, which is not supported", ch.scheme)
		}
	}
}

// token gets a bearer token from the realm a challenge names, which must
// be the registry's own host or one this registry is known to use.
// Credentials go there, so a realm on any other host is refused without
// contacting it.
func (c *client) token(ctx context.Context, ch challenge, scope string) (string, error) {
	realm, err := url.Parse(ch.params["realm"])
	if err != nil || realm.Host == "" {
		return "", errors.New("the registry's authentication challenge has no valid realm")
	}
	if realm.Scheme != "https" || realm.User != nil {
		return "", fmt.Errorf("refused the registry's token service %s: it must be https", realm.Redacted())
	}
	if !c.realms[authority(realm)] {
		return "", fmt.Errorf("refused to authenticate at %s: it is not the registry %s or its token service "+
			"(for a registry whose token service is on another host, set auth_host)", realm.Host, c.base.Host)
	}
	q := realm.Query()
	if s := ch.params["service"]; s != "" {
		q.Set("service", s)
	}
	if scope != "" {
		q.Set("scope", scope)
	}
	realm.RawQuery = q.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, realm.String(), nil)
	if err != nil {
		return "", err
	}
	switch {
	case c.secret != "" && c.username != "":
		req.SetBasicAuth(c.username, c.secret)
	case c.secret != "":
		return "", errors.New("the registry's token service needs a username with the secret: set username")
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return "", c.cleanErr(err)
	}
	defer drain(resp)
	if resp.StatusCode != http.StatusOK {
		return "", c.statusErr("token service", resp)
	}
	var t struct {
		Token       string `json:"token"`
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxTokenBody)).Decode(&t); err != nil {
		return "", errors.New("the registry's token service sent an unreadable answer")
	}
	if t.Token == "" {
		t.Token = t.AccessToken
	}
	if t.Token == "" || strings.ContainsAny(t.Token, "\r\n") {
		return "", errors.New("the registry's token service sent no token")
	}
	return t.Token, nil
}

func drain(resp *http.Response) {
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	resp.Body.Close()
}

func (c *client) cleanErr(err error) error {
	if errors.Is(err, netguard.ErrBlocked) {
		return err
	}
	return errors.New(c.red.clean(err.Error()))
}

// statusErr describes a refusal: the status and the registry's error
// codes, never more than a few hundred characters, with the secret removed.
func (c *client) statusErr(what string, resp *http.Response) error {
	return statusErr(c.red, what, resp)
}

func statusErr(red redactor, what string, resp *http.Response) error {
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
	var e struct {
		Errors []struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"errors"`
		Message string `json:"message"`
	}
	msg := ""
	if json.Unmarshal(body, &e) == nil {
		for _, x := range e.Errors {
			msg += " " + x.Code + ": " + x.Message
		}
		if msg == "" {
			msg = " " + e.Message
		}
	}
	msg = strings.TrimSpace(red.clean(msg))
	if len(msg) > 300 {
		msg = msg[:300]
	}
	if msg != "" {
		return &StatusError{Code: resp.StatusCode, msg: fmt.Sprintf("%s answered %s: %s", what, resp.Status, msg)}
	}
	return &StatusError{Code: resp.StatusCode, msg: fmt.Sprintf("%s answered %s", what, resp.Status)}
}

// StatusError is an HTTP refusal from a registry or its API.
type StatusError struct {
	Code int
	msg  string
}

func (e *StatusError) Error() string { return e.msg }

func isNotFound(err error) bool {
	var se *StatusError
	return errors.As(err, &se) && se.Code == http.StatusNotFound
}

// nextLink is the next page from a Link header (rel="next"), resolved
// against the current page. A next page on another host is an error: a
// registry does not send its clients elsewhere with their credentials.
func nextLink(cur *url.URL, h http.Header) (*url.URL, error) {
	for _, v := range h.Values("Link") {
		for _, part := range strings.Split(v, ",") {
			part = strings.TrimSpace(part)
			if !strings.Contains(part, `rel="next"`) && !strings.Contains(part, "rel=next") {
				continue
			}
			i, j := strings.Index(part, "<"), strings.Index(part, ">")
			if i < 0 || j < i {
				continue
			}
			ref, err := url.Parse(part[i+1 : j])
			if err != nil {
				return nil, errors.New("unreadable next page link")
			}
			next := cur.ResolveReference(ref)
			if authority(next) != authority(cur) || next.Scheme != cur.Scheme {
				return nil, fmt.Errorf("refused a next page on another host (%s)", next.Host)
			}
			return next, nil
		}
	}
	return nil, nil
}

func (c *client) url(path string, query url.Values) *url.URL {
	u := *c.base
	u.Path = path
	u.RawQuery = query.Encode()
	return &u
}

// Catalog lists the registry's repositories (at most limit names). The
// list is complete unless the limit cut it short.
func (c *client) Catalog(ctx context.Context, limit int) ([]string, bool, error) {
	u := c.url("/v2/_catalog", url.Values{"n": {"1000"}})
	var out []string
	for page := 0; u != nil; page++ {
		if page >= maxPages || len(out) >= limit {
			return out, false, nil
		}
		resp, err := c.get(ctx, http.MethodGet, u, "application/json")
		if err != nil {
			return nil, false, err
		}
		if resp.StatusCode != http.StatusOK {
			err := c.statusErr("the registry's catalog", resp)
			drain(resp)
			if isNotFound(err) || resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
				return nil, false, fmt.Errorf("%w; a registry without a catalog needs its repositories listed in repositories", err)
			}
			return nil, false, err
		}
		var body struct {
			Repositories []string `json:"repositories"`
		}
		err = json.NewDecoder(io.LimitReader(resp.Body, maxListBody)).Decode(&body)
		next, lerr := nextLink(u, resp.Header)
		drain(resp)
		if err != nil {
			return nil, false, errors.New("the registry's catalog is unreadable")
		}
		if lerr != nil {
			return nil, false, lerr
		}
		out = append(out, body.Repositories...)
		u = next
	}
	if len(out) > limit {
		return out[:limit], false, nil
	}
	return out, true, nil
}

// TagNames lists a repository's tags (at most MaxTags). A repository
// that does not exist is a not-found StatusError.
func (c *client) TagNames(ctx context.Context, repo string) ([]string, bool, error) {
	u := c.url("/v2/"+repo+"/tags/list", url.Values{"n": {"1000"}})
	var out []string
	for page := 0; u != nil; page++ {
		if page >= maxPages || len(out) >= MaxTags {
			return out, false, nil
		}
		resp, err := c.get(ctx, http.MethodGet, u, "application/json")
		if err != nil {
			return nil, false, err
		}
		if resp.StatusCode != http.StatusOK {
			err := c.statusErr("tags of "+repo, resp)
			drain(resp)
			return nil, false, err
		}
		var body struct {
			Tags []string `json:"tags"`
		}
		err = json.NewDecoder(io.LimitReader(resp.Body, maxListBody)).Decode(&body)
		next, lerr := nextLink(u, resp.Header)
		drain(resp)
		if err != nil {
			return nil, false, fmt.Errorf("the tag list of %s is unreadable", repo)
		}
		if lerr != nil {
			return nil, false, lerr
		}
		out = append(out, body.Tags...)
		u = next
	}
	if len(out) > MaxTags {
		return out[:MaxTags], false, nil
	}
	return out, true, nil
}

var manifestTypes = []string{
	"application/vnd.oci.image.index.v1+json",
	"application/vnd.docker.distribution.manifest.list.v2+json",
	"application/vnd.oci.image.manifest.v1+json",
	"application/vnd.docker.distribution.manifest.v2+json",
}

var digestRE = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)

// Digest is the digest a tag points to, from a HEAD request.
func (c *client) Digest(ctx context.Context, repo, tag string) (string, error) {
	resp, err := c.get(ctx, http.MethodHead, c.url("/v2/"+repo+"/manifests/"+tag, nil), manifestTypes...)
	if err != nil {
		return "", err
	}
	defer drain(resp)
	if resp.StatusCode == http.StatusOK {
		if d := resp.Header.Get("Docker-Content-Digest"); digestRE.MatchString(d) {
			return d, nil
		}
	} else if resp.StatusCode != http.StatusMethodNotAllowed {
		return "", c.statusErr(repo+":"+tag, resp)
	}
	// No digest header (or no HEAD): the digest of the manifest itself.
	body, _, err := c.manifest(ctx, repo, tag)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(body)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

func (c *client) manifest(ctx context.Context, repo, ref string) ([]byte, string, error) {
	resp, err := c.get(ctx, http.MethodGet, c.url("/v2/"+repo+"/manifests/"+ref, nil), manifestTypes...)
	if err != nil {
		return nil, "", err
	}
	defer drain(resp)
	if resp.StatusCode != http.StatusOK {
		return nil, "", c.statusErr(repo+"@"+ref, resp)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxManifestBody+1))
	if err != nil {
		return nil, "", c.cleanErr(err)
	}
	if len(body) > maxManifestBody {
		return nil, "", fmt.Errorf("the manifest of %s is larger than %d bytes", repo, maxManifestBody)
	}
	if digestRE.MatchString(ref) {
		sum := sha256.Sum256(body)
		if "sha256:"+hex.EncodeToString(sum[:]) != ref {
			return nil, "", fmt.Errorf("the manifest of %s@%s does not match its digest", repo, ref)
		}
	}
	return body, resp.Header.Get("Content-Type"), nil
}

// Created is when the image a digest names was built, from its
// configuration (an index's entry for platform, else linux/amd64, else
// its first entry). A generic registry gives no push time; this stands in
// for it.
func (c *client) Created(ctx context.Context, repo, digest, platform string) (time.Time, error) {
	body, _, err := c.manifest(ctx, repo, digest)
	if err != nil {
		return time.Time{}, err
	}
	var m struct {
		Manifests []struct {
			Digest   string `json:"digest"`
			Platform struct {
				OS           string `json:"os"`
				Architecture string `json:"architecture"`
				Variant      string `json:"variant"`
			} `json:"platform"`
		} `json:"manifests"`
		Config struct {
			Digest string `json:"digest"`
		} `json:"config"`
	}
	if err := json.Unmarshal(body, &m); err != nil {
		return time.Time{}, fmt.Errorf("the manifest of %s is unreadable", repo)
	}
	if len(m.Manifests) > 0 {
		pick := m.Manifests[0].Digest
		want := platform
		if want == "" {
			want = "linux/amd64"
		}
		for _, e := range m.Manifests {
			p := e.Platform.OS + "/" + e.Platform.Architecture
			if p == want || p+"/"+e.Platform.Variant == want {
				pick = e.Digest
				break
			}
		}
		if !digestRE.MatchString(pick) {
			return time.Time{}, fmt.Errorf("the index of %s names no image", repo)
		}
		if body, _, err = c.manifest(ctx, repo, pick); err != nil {
			return time.Time{}, err
		}
		m.Config.Digest = ""
		if err := json.Unmarshal(body, &m); err != nil {
			return time.Time{}, fmt.Errorf("the manifest of %s is unreadable", repo)
		}
	}
	if !digestRE.MatchString(m.Config.Digest) {
		return time.Time{}, fmt.Errorf("the manifest of %s names no configuration", repo)
	}
	resp, err := c.get(ctx, http.MethodGet, c.url("/v2/"+repo+"/blobs/"+m.Config.Digest, nil), "application/json", "*/*")
	if err != nil {
		return time.Time{}, err
	}
	defer drain(resp)
	if resp.StatusCode != http.StatusOK {
		return time.Time{}, c.statusErr("the configuration of "+repo, resp)
	}
	var cfg struct {
		Created time.Time `json:"created"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxManifestBody)).Decode(&cfg); err != nil {
		return time.Time{}, fmt.Errorf("the configuration of %s is unreadable", repo)
	}
	return cfg.Created, nil
}

// SetTestTLS sets the TLS configuration of registry clients made from now
// on (tests in other packages, which talk to httptest servers) and
// returns a function that restores the previous one. Never used by the
// server.
func SetTestTLS(c *tls.Config) (restore func()) {
	prev := testTLS
	testTLS = c
	return func() { testTLS = prev }
}
