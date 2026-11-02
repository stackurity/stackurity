package api

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/stackurity/stackurity/internal/netguard"
	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/tenant"
)

// Keyless CI scans. A CI provider signs an OpenID Connect ID token for
// each job (GitHub Actions with `permissions: id-token: write`, GitLab CI
// with `id_tokens:`). POST /ci/token checks such a token against the
// issuer's published keys and the CI trusts administrators made under
// Settings → Integrations → CI pipeline, and answers with a collector token
// that:
//
//   - expires after ciTokenTTL,
//   - belongs to the trust's workspace and files new assets in its project,
//   - may report only the repository the job ran for (the git-url identity
//     https://github.com/<repository>, or <GitLab instance>/<project_path>;
//     checkRepoIngest), and is revoked with its trust.
//
// The issuer named by a token is fetched only when a trust names exactly
// that issuer, over HTTPS, through the outbound address guard of the
// trust's workspace.

const (
	// GitHubIssuer is GitHub Actions' token issuer. An enterprise with a
	// customised issuer uses GitHubIssuer + "/<enterprise slug>".
	GitHubIssuer = "https://token.actions.githubusercontent.com"
	// GitLabIssuer is gitlab.com's; a self-managed instance's issuer is its
	// own URL.
	GitLabIssuer = "https://gitlab.com"
	ciTokenTTL   = 15 * time.Minute
	// ciLeeway allows for clocks that differ a little.
	ciLeeway = time.Minute
	// maxIDToken bounds the token accepted (GitHub's are about 1.5 KB).
	maxIDToken = 16 << 10
)

// ciAlgs: asymmetric signatures only, so "none" and an HMAC signed with a
// public key are refused before any key is looked at.
var ciAlgs = []jose.SignatureAlgorithm{jose.RS256, jose.RS384, jose.RS512, jose.PS256, jose.PS384, jose.PS512, jose.ES256, jose.ES384, jose.ES512}

// limitCIToken: CI runners share addresses (a NAT in front of self-hosted
// runners, a matrix of jobs), so the limit is looser than enrollment's.
var limitCIToken = rateLimit{30, time.Minute}

// ciKeysTTL is how long an issuer's keys are used; ciKeysRefresh is how
// soon a token signed with a key not in the cached set may fetch them
// again (keys are rotated; a stream of made-up key ids must not turn into
// a stream of requests to the issuer).
var (
	ciKeysTTL     = time.Hour
	ciKeysRefresh = 30 * time.Second
)

type ciIssuerKeys struct {
	keys    jose.JSONWebKeySet
	fetched time.Time // zero when no fetch succeeded
	tried   time.Time
}

// ciKeyCache keeps each issuer's keys apart for workspaces that may reach
// private addresses and those that may not, since what a fetch reaches
// depends on that.
type ciKeyCache struct {
	mu   sync.Mutex
	sets map[string]*ciIssuerKeys
}

// ciAudience is the aud a CI token must carry: STACKURITY_CI_AUDIENCE, or
// the server's public URL (STACKURITY_BASE_URL). Empty turns keyless CI
// scans off.
func (s *Server) ciAudience() string {
	if s.CIAudience != "" {
		return s.CIAudience
	}
	return strings.TrimRight(s.BaseURL, "/")
}

func (s *Server) ciHTTP() *http.Client {
	if s.CIOIDCHTTP != nil {
		return s.CIOIDCHTTP
	}
	tr := &http.Transport{DialContext: netguard.DialContext, ResponseHeaderTimeout: 5 * time.Second, TLSHandshakeTimeout: 5 * time.Second}
	if s.CIOIDCRootCAs != nil {
		tr.TLSClientConfig = &tls.Config{RootCAs: s.CIOIDCRootCAs, MinVersion: tls.VersionTLS12}
	}
	return &http.Client{Timeout: 5 * time.Second, Transport: tr,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

// ciGetJSON fetches an HTTPS document of at most 256 KiB.
func (s *Server) ciGetJSON(ctx context.Context, raw string, out any) error {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil {
		return fmt.Errorf("%q is not an https URL", raw)
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "GET", raw, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := s.ciHTTP().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("%s answered %d", raw, resp.StatusCode)
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 256<<10)).Decode(out); err != nil {
		return fmt.Errorf("%s: not the JSON expected", raw)
	}
	return nil
}

// ciFetchKeys reads the issuer's discovery document, checks that it names
// the issuer exactly, and fetches its key set.
func (s *Server) ciFetchKeys(ctx context.Context, issuer string) (jose.JSONWebKeySet, error) {
	var set jose.JSONWebKeySet
	var disc struct {
		Issuer  string `json:"issuer"`
		JWKSURI string `json:"jwks_uri"`
	}
	if err := s.ciGetJSON(ctx, issuer+"/.well-known/openid-configuration", &disc); err != nil {
		return set, err
	}
	if disc.Issuer != issuer {
		return set, fmt.Errorf("the discovery document names issuer %q, not %q", disc.Issuer, issuer)
	}
	if err := s.ciGetJSON(ctx, disc.JWKSURI, &set); err != nil {
		return set, err
	}
	return set, nil
}

// ciKeys returns issuer's keys for ctx's workspace, from the cache unless
// they are older than ciKeysTTL or kid is not among them (then fetched
// again, at most once per ciKeysRefresh). A failed fetch falls back to the
// keys already held.
func (s *Server) ciKeys(ctx context.Context, issuer, kid string) (jose.JSONWebKeySet, error) {
	key := issuer + "\x00" + strconv.FormatBool(netguard.AllowsPrivate(ctx))
	c := s.ciKeyCache
	c.mu.Lock()
	e := c.sets[key]
	if e == nil {
		e = &ciIssuerKeys{}
		c.sets[key] = e
	}
	have := !e.fetched.IsZero()
	fresh := have && time.Since(e.fetched) < ciKeysTTL
	known := kid == "" || len(e.keys.Key(kid)) > 0
	if (fresh && known) || time.Since(e.tried) < ciKeysRefresh {
		keys := e.keys
		c.mu.Unlock()
		if !have {
			return keys, errors.New("the issuer's keys could not be fetched; try again shortly")
		}
		return keys, nil
	}
	e.tried = time.Now()
	c.mu.Unlock()

	set, err := s.ciFetchKeys(ctx, issuer)
	c.mu.Lock()
	defer c.mu.Unlock()
	if err != nil {
		s.Log.Warn("CI token issuer keys not fetched", "issuer", issuer, "err", err)
		if have {
			return e.keys, nil
		}
		return e.keys, errors.New("the issuer's keys could not be fetched: " + err.Error())
	}
	e.keys, e.fetched = set, time.Now()
	return set, nil
}

// ciClaims are what a trust is matched against, read from a verified token.
type ciClaims struct {
	Provider      string
	Issuer        string
	Repository    string // owner/repo, GitLab group/subgroup/project
	OwnerID       string // repository_owner_id, namespace_id
	OwnerPath     string // repository_owner, namespace_path
	Ref           string // full ref: refs/heads/main
	Environment   string
	WorkflowRef   string // job_workflow_ref, ci_config_ref_uri
	RepositoryURL string // the git-url identity scans must use
	JTI           string
	Detail        map[string]any // for the audit log
}

func claimString(m map[string]any, k string) string {
	switch v := m[k].(type) {
	case string:
		return v
	case float64:
		return strconv.FormatFloat(v, 'f', -1, 64)
	case json.Number:
		return v.String()
	}
	return ""
}

var repoPath = regexp.MustCompile(`^[A-Za-z0-9_.-]+(/[A-Za-z0-9_.-]+)+$`)

// readCIClaims maps a provider's claims onto ciClaims.
func readCIClaims(provider, issuer string, m map[string]any) (*ciClaims, error) {
	c := &ciClaims{Provider: provider, Issuer: issuer, JTI: claimString(m, "jti"), Environment: claimString(m, "environment")}
	keep := func(keys ...string) {
		for _, k := range keys {
			if v := claimString(m, k); v != "" {
				c.Detail[k] = v
			}
		}
	}
	c.Detail = map[string]any{}
	switch provider {
	case "github":
		c.Repository, c.OwnerID, c.Ref, c.WorkflowRef = claimString(m, "repository"), claimString(m, "repository_owner_id"),
			claimString(m, "ref"), claimString(m, "job_workflow_ref")
		c.OwnerPath = claimString(m, "repository_owner")
		c.RepositoryURL = "https://github.com/" + c.Repository
		keep("run_id", "run_attempt", "sha", "actor", "event_name", "workflow", "repository_id")
	case "gitlab":
		c.Repository, c.OwnerID, c.WorkflowRef = claimString(m, "project_path"), claimString(m, "namespace_id"), claimString(m, "ci_config_ref_uri")
		c.OwnerPath = claimString(m, "namespace_path")
		c.Ref = claimString(m, "ref_path")
		if c.Ref == "" {
			switch ref := claimString(m, "ref"); claimString(m, "ref_type") {
			case "branch":
				c.Ref = "refs/heads/" + ref
			case "tag":
				c.Ref = "refs/tags/" + ref
			}
		}
		c.RepositoryURL = issuer + "/" + c.Repository
		keep("pipeline_id", "job_id", "sha", "user_login", "pipeline_source", "project_id")
	default:
		return nil, fmt.Errorf("unknown provider %q", provider)
	}
	if !repoPath.MatchString(c.Repository) || strings.Contains(c.Repository, "..") {
		return nil, errors.New("the token does not name a repository")
	}
	return c, nil
}

// verifyCIToken checks tok's signature with issuer's keys (fetched for
// ctx's workspace) and its registered claims, and returns all its claims.
func (s *Server) verifyCIToken(ctx context.Context, tok *jwt.JSONWebToken, issuer string) (map[string]any, error) {
	h := tok.Headers[0]
	set, err := s.ciKeys(ctx, issuer, h.KeyID)
	if err != nil {
		return nil, err
	}
	keys := set.Keys
	if h.KeyID != "" {
		keys = set.Key(h.KeyID)
	}
	var reg jwt.Claims
	all := map[string]any{}
	verified := false
	for _, k := range keys {
		if !k.Valid() || !k.IsPublic() || (k.Use != "" && k.Use != "sig") || (k.Algorithm != "" && k.Algorithm != h.Algorithm) {
			continue
		}
		if tok.Claims(k.Key, &reg, &all) == nil {
			verified = true
			break
		}
	}
	if !verified {
		if h.KeyID != "" && len(keys) == 0 {
			return nil, fmt.Errorf("the token is signed with key %q, which the issuer does not publish", h.KeyID)
		}
		return nil, errors.New("the token's signature does not verify with the issuer's keys")
	}
	if reg.Issuer != issuer {
		return nil, errors.New("the token's issuer does not match")
	}
	aud := s.ciAudience()
	if len(reg.Audience) != 1 || reg.Audience[0] != aud {
		return nil, fmt.Errorf("the token's audience (aud) must be exactly %q; request the token with that audience", aud)
	}
	if reg.Expiry == nil || reg.IssuedAt == nil {
		return nil, errors.New("the token needs exp and iat")
	}
	now := time.Now()
	if err := reg.ValidateWithLeeway(jwt.Expected{Time: now}, ciLeeway); err != nil {
		switch {
		case errors.Is(err, jwt.ErrExpired):
			return nil, errors.New("the token has expired")
		case errors.Is(err, jwt.ErrNotValidYet), errors.Is(err, jwt.ErrIssuedInTheFuture):
			return nil, errors.New("the token is not valid yet (check the runner's clock)")
		}
		return nil, fmt.Errorf("the token is not valid: %w", err)
	}
	return all, nil
}

// trustMatches reports whether t accepts the job, and when it names the
// repository but another constraint differs, why not.
func trustMatches(t store.CITrust, c *ciClaims) (ok bool, why string) {
	repo := strings.ToLower(c.Repository)
	if t.OwnerWildcard {
		if !strings.HasPrefix(repo, strings.ToLower(strings.TrimSuffix(t.Repository, "*"))) {
			return false, ""
		}
	} else if !strings.EqualFold(t.Repository, c.Repository) {
		return false, ""
	}
	switch {
	case t.Ref != "" && t.Ref != c.Ref:
		return false, fmt.Sprintf("trust %d accepts ref %s, not %s", t.ID, t.Ref, orNone(c.Ref))
	case t.Environment != "" && t.Environment != c.Environment:
		return false, fmt.Sprintf("trust %d accepts environment %s, not %s", t.ID, t.Environment, orNone(c.Environment))
	case t.WorkflowRef != "" && t.WorkflowRef != c.WorkflowRef:
		return false, fmt.Sprintf("trust %d accepts workflow %s, not %s", t.ID, t.WorkflowRef, orNone(c.WorkflowRef))
	}
	return true, ""
}

func orNone(s string) string {
	if s == "" {
		return "(none)"
	}
	return s
}

// specificity orders matching trusts of one workspace and project: one
// repository before an owner's, then more constraints first.
func specificity(t store.CITrust) int {
	n := 0
	if !t.OwnerWildcard {
		n += 8
	}
	for _, v := range []string{t.Ref, t.Environment, t.WorkflowRef} {
		if v != "" {
			n++
		}
	}
	return n
}

// unverifiedIssuer reads iss without trusting it: it only picks which
// trusts, and so which issuer's keys, to check the token against.
func unverifiedIssuer(tok *jwt.JSONWebToken) string {
	var c struct {
		Issuer string `json:"iss"`
	}
	if tok.UnsafeClaimsWithoutVerification(&c) != nil {
		return ""
	}
	return c.Issuer
}

// ciToken is POST /ci/token: a CI job's ID token for a collector token.
func (s *Server) ciToken(w http.ResponseWriter, r *http.Request) {
	if s.limited(w, r, "too many attempts; wait a minute", limitHit{"ci-token", clientIP(r), limitCIToken}) {
		return
	}
	var req struct {
		Token string `json:"token"`
		// TrustID chooses among several trusts that accept the job
		// (STACKURITY_CI_TRUST).
		TrustID int64 `json:"trust_id"`
	}
	if err := decode(r, &req); err != nil {
		s.fail(w, r, err)
		return
	}
	aud := s.ciAudience()
	if aud == "" {
		writeError(w, 503, "not_configured", "keyless CI scans need the server's public URL: the administrator sets STACKURITY_BASE_URL (or STACKURITY_CI_AUDIENCE)")
		return
	}
	invalid := func(msg string) { writeError(w, 401, "invalid_token", msg) }
	raw := strings.TrimSpace(req.Token)
	if raw == "" || len(raw) > maxIDToken {
		invalid("send the CI provider's ID token as token")
		return
	}
	tok, err := jwt.ParseSigned(raw, ciAlgs)
	if err != nil {
		invalid("the token is not a JWT signed with an accepted algorithm (RS256, RS384, RS512, PS256, PS384, PS512, ES256, ES384, ES512)")
		return
	}
	if len(tok.Headers) != 1 {
		invalid("the token must have one signature")
		return
	}
	issuer := unverifiedIssuer(tok)
	if !strings.HasPrefix(issuer, "https://") {
		invalid("the token's issuer (iss) must be an https URL")
		return
	}
	trusts, err := s.Store.CITrustsForIssuer(r.Context(), issuer)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if len(trusts) == 0 {
		writeError(w, 403, "forbidden", "no CI trust on this server accepts tokens from this issuer; an administrator adds one under Settings → Integrations → CI pipeline")
		return
	}

	// On a server that hosts several organisations, any of them can trust a
	// repository by name, so the job names the trust it means: otherwise a
	// pipeline run before its own organisation trusted the repository could
	// send its inventory to another organisation that had.
	if req.TrustID == 0 {
		ws, err := s.Store.ActiveWorkspaceIDs(tenant.System(r.Context()))
		if err != nil {
			s.fail(w, r, err)
			return
		}
		if len(ws) > 1 {
			writeError(w, 400, "trust_required", "this server hosts several organisations, so a CI job names its CI trust: set STACKURITY_CI_TRUST (the scan action's ci-trust input) to the trust's id, shown under Settings → Integrations → CI pipeline")
			return
		}
	}

	// Verify once per outbound policy (workspaces that may reach private
	// addresses or not), with the keys fetched under it.
	type outcome struct {
		claims map[string]any
		err    error
	}
	verified := map[bool]*outcome{}
	var candidates []store.CITrust
	var reasons []string
	var claims *ciClaims
	var lastErr error
	for _, t := range trusts {
		ctx := tenant.WithWorkspace(r.Context(), t.WorkspaceID)
		private := netguard.AllowsPrivate(ctx)
		o := verified[private]
		if o == nil {
			m, err := s.verifyCIToken(ctx, tok, issuer)
			o = &outcome{m, err}
			verified[private] = o
		}
		if o.err != nil {
			lastErr = o.err
			continue
		}
		c, err := readCIClaims(t.Provider, issuer, o.claims)
		if err != nil {
			lastErr = err
			continue
		}
		claims = c
		if req.TrustID != 0 && t.ID != req.TrustID {
			continue
		}
		ok, why := trustMatches(t, c)
		if ok {
			candidates = append(candidates, t)
		} else if why != "" {
			reasons = append(reasons, why)
			_ = s.Store.Audit(ctx, store.Actor{Type: "ci", Name: t.Provider + ":" + c.Repository, RemoteAddr: clientIP(r)},
				"ci.token_refused", "ci_trust", itoa(t.ID), ciAuditDetail(c, map[string]any{"reason": why}))
		}
	}
	if claims == nil {
		invalid(lastErr.Error())
		return
	}
	if len(candidates) == 0 {
		msg := fmt.Sprintf("no CI trust accepts repository %s on ref %s", claims.Repository, orNone(claims.Ref))
		if req.TrustID != 0 {
			msg = fmt.Sprintf("CI trust %d does not accept repository %s on ref %s", req.TrustID, claims.Repository, orNone(claims.Ref))
		}
		if len(reasons) > 0 {
			msg += ": " + strings.Join(reasons, "; ")
		}
		writeError(w, 403, "forbidden", msg)
		return
	}
	sort.SliceStable(candidates, func(i, j int) bool { return specificity(candidates[i]) > specificity(candidates[j]) })
	t := candidates[0]
	for _, o := range candidates[1:] {
		if o.WorkspaceID != t.WorkspaceID || !sameProject(o.ProjectID, t.ProjectID) {
			writeError(w, 409, "conflict", "several CI trusts accept this repository, for different organisations or projects; set STACKURITY_CI_TRUST to the id of the trust to use (shown under Settings → Integrations → CI pipeline)")
			return
		}
	}

	name := fmt.Sprintf("CI %s %s", t.Provider, claims.Repository)
	if run := claimString(claims.Detail, "run_id") + claimString(claims.Detail, "pipeline_id"); run != "" {
		name += " run " + run
	}
	if len(name) > 200 {
		name = name[:200]
	}
	ctx := tenant.WithWorkspace(r.Context(), t.WorkspaceID)
	actor := store.Actor{Type: "ci", Name: t.Provider + ":" + claims.Repository, RemoteAddr: clientIP(r)}
	issued, secret, err := s.Store.IssueCIToken(r.Context(), t, store.CIToken{Name: name, RepositoryURL: claims.RepositoryURL,
		OwnerID: pinnedOwnerID(t, claims), TTL: ciTokenTTL})
	if errors.Is(err, store.ErrCITrustOwner) {
		_ = s.Store.Audit(ctx, actor, "ci.token_refused", "ci_trust", itoa(t.ID), ciAuditDetail(claims, map[string]any{"reason": "owner id changed", "owner_id": claims.OwnerID}))
		writeError(w, 403, "forbidden", err.Error())
		return
	}
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, 403, "forbidden", "the CI trust was deleted")
		return
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	_ = s.Store.Audit(ctx, actor, "ci.token", "ci_trust", itoa(t.ID), ciAuditDetail(claims, map[string]any{
		"token_prefix": issued.Prefix, "token_id": issued.ID, "expires_at": issued.ExpiresAt, "project_id": t.ProjectID}))
	writeJSON(w, 200, map[string]any{"token": secret, "expires_at": issued.ExpiresAt, "repository_url": claims.RepositoryURL,
		"project_id": t.ProjectID, "trust_id": t.ID})
}

// pinnedOwnerID is the owner id the trust records and then requires: that
// of the owner the trust names (the repository's owner, or the owner or
// group of a wildcard). A project in a subgroup below a GitLab group
// wildcard has its subgroup's id in the token, so it is not pinned.
func pinnedOwnerID(t store.CITrust, c *ciClaims) string {
	owner := strings.TrimSuffix(t.Repository, "/*")
	if !t.OwnerWildcard {
		owner = owner[:strings.LastIndex(owner, "/")]
	}
	if !strings.EqualFold(owner, c.OwnerPath) {
		return ""
	}
	return c.OwnerID
}

func sameProject(a, b *int64) bool {
	return (a == nil && b == nil) || (a != nil && b != nil && *a == *b)
}

func ciAuditDetail(c *ciClaims, extra map[string]any) map[string]any {
	d := map[string]any{"provider": c.Provider, "issuer": c.Issuer, "repository": c.Repository, "ref": c.Ref}
	if c.Environment != "" {
		d["environment"] = c.Environment
	}
	if c.WorkflowRef != "" {
		d["workflow_ref"] = c.WorkflowRef
	}
	if c.JTI != "" {
		d["jti"] = c.JTI
	}
	for k, v := range c.Detail {
		d[k] = v
	}
	for k, v := range extra {
		d[k] = v
	}
	return d
}

// --- trusts (Settings → Integrations → CI pipeline)

type ciTrustRequest struct {
	Name          string `json:"name"`
	Provider      string `json:"provider"`
	Issuer        string `json:"issuer"`
	Repository    string `json:"repository"`
	OwnerWildcard bool   `json:"owner_wildcard"`
	Ref           string `json:"ref"`
	Environment   string `json:"environment"`
	WorkflowRef   string `json:"workflow_ref"`
	ProjectID     int64  `json:"project_id"`
}

var (
	ownerPath   = regexp.MustCompile(`^[A-Za-z0-9_.-]+(/[A-Za-z0-9_.-]+)*$`)
	enterprise  = regexp.MustCompile(`^[A-Za-z0-9-]{1,100}$`)
	refPattern  = regexp.MustCompile(`^refs/[A-Za-z0-9_./+@-]{1,280}$`)
	printable   = regexp.MustCompile(`^[^\x00-\x1f\x7f]*$`)
	errWildcard = badRequest("repository must be owner/name; to trust every repository of an owner or group, choose that explicitly (owner_wildcard) and give owner/*")
)

// normalizeTrust checks a trust request and returns the trust to store.
func normalizeTrust(req ciTrustRequest) (store.CITrust, error) {
	t := store.CITrust{Name: strings.TrimSpace(req.Name), Provider: req.Provider, Issuer: strings.TrimRight(strings.TrimSpace(req.Issuer), "/"),
		Ref: strings.TrimSpace(req.Ref), Environment: strings.TrimSpace(req.Environment), WorkflowRef: strings.TrimSpace(req.WorkflowRef)}
	switch t.Provider {
	case "github":
		if t.Issuer == "" {
			t.Issuer = GitHubIssuer
		}
		if slug, ok := strings.CutPrefix(t.Issuer, GitHubIssuer+"/"); t.Issuer != GitHubIssuer && (!ok || !enterprise.MatchString(slug)) {
			return t, badRequest("a GitHub Actions trust uses the issuer " + GitHubIssuer + " (or " + GitHubIssuer + "/<enterprise> for a customised enterprise issuer)")
		}
	case "gitlab":
		if t.Issuer == "" {
			t.Issuer = GitLabIssuer
		}
		u, err := url.Parse(t.Issuer)
		if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || len(t.Issuer) > 500 {
			return t, badRequest("the GitLab issuer is the instance's https URL, such as https://gitlab.com or https://gitlab.example.com")
		}
		if strings.HasPrefix(t.Issuer, GitHubIssuer) {
			return t, badRequest("that is GitHub's issuer; choose GitHub Actions")
		}
	default:
		return t, badRequest("provider must be github or gitlab")
	}
	repo := strings.Trim(strings.TrimSpace(req.Repository), "/")
	if req.OwnerWildcard {
		owner := strings.TrimSuffix(repo, "/*")
		if strings.Contains(owner, "*") || !ownerPath.MatchString(owner) || strings.Contains(owner, "..") {
			return t, errWildcard
		}
		repo = owner + "/*"
	} else if strings.Contains(repo, "*") || !repoPath.MatchString(repo) || strings.Contains(repo, "..") {
		return t, errWildcard
	}
	if t.Provider == "github" && !req.OwnerWildcard && strings.Count(repo, "/") != 1 {
		return t, badRequest("a GitHub repository is owner/name")
	}
	if len(repo) > 300 {
		return t, badRequest("repository is too long")
	}
	t.Repository, t.OwnerWildcard = repo, req.OwnerWildcard
	if t.Ref != "" && !strings.HasPrefix(t.Ref, "refs/") {
		t.Ref = "refs/heads/" + t.Ref
	}
	if t.Ref != "" && (!refPattern.MatchString(t.Ref) || strings.Contains(t.Ref, "..")) {
		return t, badRequest("ref must be a branch name or a full ref such as refs/heads/main or refs/tags/v1.0")
	}
	if len(t.Name) > 200 || len(t.Environment) > 200 || len(t.WorkflowRef) > 500 ||
		!printable.MatchString(t.Name+t.Environment+t.WorkflowRef) || strings.ContainsAny(t.Environment+t.WorkflowRef, " \t") {
		return t, badRequest("name (200 characters), environment (200) and workflow_ref (500) are limited, without spaces in environment and workflow_ref")
	}
	if req.ProjectID < 0 {
		return t, badRequest("project_id must be a project")
	} else if req.ProjectID > 0 {
		t.ProjectID = &req.ProjectID
	}
	return t, nil
}

func (s *Server) listCITrusts(w http.ResponseWriter, r *http.Request) {
	items, err := s.Store.ListCITrusts(r.Context())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	base, err := s.publicURL(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, 200, map[string]any{"items": items, "audience": s.ciAudience(), "server": base})
}

func (s *Server) createCITrust(w http.ResponseWriter, r *http.Request) {
	var req ciTrustRequest
	if err := decode(r, &req); err != nil {
		s.fail(w, r, err)
		return
	}
	t, err := normalizeTrust(req)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	p := principal(r)
	if p.User != nil {
		t.CreatedBy, t.CreatedByName = &p.User.ID, p.User.Email
	}
	out, err := s.Store.CreateCITrust(r.Context(), t)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	_ = s.Store.Audit(r.Context(), p.Actor(r), "ci_trust.create", "ci_trust", itoa(out.ID), map[string]any{
		"provider": out.Provider, "issuer": out.Issuer, "repository": out.Repository, "owner_wildcard": out.OwnerWildcard,
		"ref": out.Ref, "environment": out.Environment, "workflow_ref": out.WorkflowRef, "project_id": out.ProjectID})
	writeJSON(w, 201, out)
}

func (s *Server) deleteCITrust(w http.ResponseWriter, r *http.Request) {
	id, err := idParam(r, "id")
	if err != nil {
		s.fail(w, r, err)
		return
	}
	t, err := s.Store.DeleteCITrust(r.Context(), id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	_ = s.Store.Audit(r.Context(), principal(r).Actor(r), "ci_trust.delete", "ci_trust", itoa(id),
		map[string]any{"provider": t.Provider, "repository": t.Repository})
	w.WriteHeader(204)
}
