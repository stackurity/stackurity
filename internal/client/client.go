// Package client is the HTTP client the CLI and agent use to talk to a
// Stackurity server.
package client

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/stackurity/stackurity/internal/license"
	"github.com/stackurity/stackurity/internal/model"
)

type Client struct {
	BaseURL string
	Token   string
	HTTP    *http.Client
	UA      string
	// Project, when not 0, scopes every request to this project
	// (X-Stackurity-Project), and uploads (Ingest, ImportSBOM) ask the
	// server to file their asset in it (project_id).
	Project int64
}

func New(base, token, version string) (*Client, error) {
	u, err := url.Parse(base)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return nil, fmt.Errorf("invalid server url %q", base)
	}
	return &Client{
		BaseURL: strings.TrimSuffix(base, "/"),
		Token:   token,
		HTTP:    &http.Client{Timeout: 5 * time.Minute},
		UA:      "stackurity/" + version,
	}, nil
}

type APIError struct {
	Status  int
	Code    string   `json:"code"`
	Message string   `json:"message"`
	Details []string `json:"details"`
	// RetryAfter is the server's Retry-After (seconds form), or 0.
	RetryAfter time.Duration `json:"-"`
	// Offer is plan_required's structured part (servers from 0.20.13):
	// how the organisation could get the feature it asked for.
	*license.Offer
}

func (e *APIError) Error() string {
	msg := fmt.Sprintf("server returned %d %s: %s", e.Status, e.Code, e.Message)
	if len(e.Details) > 0 {
		msg += " (" + strings.Join(e.Details, "; ") + ")"
	}
	return msg
}

func (c *Client) Do(ctx context.Context, method, path string, body io.Reader, headers map[string]string, out any) error {
	req, err := http.NewRequestWithContext(ctx, method, c.BaseURL+path, body)
	if err != nil {
		return err
	}
	if c.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.Token)
	}
	req.Header.Set("User-Agent", c.UA)
	if c.Project > 0 {
		req.Header.Set("X-Stackurity-Project", strconv.FormatInt(c.Project, 10))
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		var e struct {
			Error APIError `json:"error"`
		}
		_ = json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&e)
		e.Error.Status = resp.StatusCode
		if n, err := strconv.Atoi(strings.TrimSpace(resp.Header.Get("Retry-After"))); err == nil && n > 0 {
			e.Error.RetryAfter = time.Duration(n) * time.Second
		}
		return &e.Error
	}
	if out == nil {
		return nil
	}
	if w, ok := out.(io.Writer); ok {
		_, err = io.Copy(w, resp.Body)
		return err
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

func gz(v any) (*bytes.Buffer, error) {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if err := json.NewEncoder(zw).Encode(v); err != nil {
		return nil, err
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return &buf, nil
}

type IngestResult struct {
	AssetID      int64   `json:"asset_id"`
	CollectionID int64   `json:"collection_id"`
	Observations int     `json:"observations"`
	Removed      int64   `json:"removed"`
	NewAsset     bool    `json:"new_asset"`
	Conflict     []int64 `json:"identity_conflict"`
	// ProjectID is the project the server filed the upload under (0 when
	// none was asked for, or the server is older than 0.10); InProject
	// whether the asset is in it now.
	ProjectID int64 `json:"project_id"`
	InProject *bool `json:"in_project"`
	// VEX is what the server did with the VEX embedded in an uploaded
	// CycloneDX SBOM, and VEXNote why it did nothing (0.14).
	VEX *struct {
		Matched   int `json:"matched"`
		Unmatched int `json:"unmatched"`
		Pending   int `json:"pending"`
	} `json:"vex"`
	VEXNote string `json:"vex_note"`
}

// ErrProjectIgnored: an upload asked for a project and the server's answer
// does not name it, so the server ignored project_id.
var ErrProjectIgnored = errors.New("the server stored the upload without the project: it does not support project_id on uploads (Stackurity 0.10 or later is needed); add the asset to the project in Assets > Projects")

// projectQuery is the query string an upload adds for c.Project.
func (c *Client) projectQuery() string {
	if c.Project <= 0 {
		return ""
	}
	return "project_id=" + strconv.FormatInt(c.Project, 10)
}

// checkProject fails an upload whose answer shows the project was ignored.
func (c *Client) checkProject(res *IngestResult) error {
	if c.Project > 0 && res.ProjectID != c.Project {
		return ErrProjectIgnored
	}
	return nil
}

// Ingest submits a batch, gzip-compressed, retrying transient failures.
func (c *Client) Ingest(ctx context.Context, b *model.ObservationBatch) (*IngestResult, error) {
	var res IngestResult
	var err error
	for attempt := 0; attempt < 4; attempt++ {
		var buf *bytes.Buffer
		buf, err = gz(b)
		if err != nil {
			return nil, err
		}
		path := "/api/v1/ingest"
		if q := c.projectQuery(); q != "" {
			path += "?" + q
		}
		err = c.Do(ctx, "POST", path, buf, map[string]string{
			"Content-Type": "application/json", "Content-Encoding": "gzip",
		}, &res)
		if err == nil {
			return &res, c.checkProject(&res)
		}
		if ae, ok := err.(*APIError); ok && ae.Status < 500 && ae.Status != 429 {
			return nil, err // client errors are not retried
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(time.Duration(1<<attempt) * 2 * time.Second):
		}
	}
	return nil, err
}

func (c *Client) ImportSBOM(ctx context.Context, doc io.Reader, assetName, assetKind, env string) (*IngestResult, error) {
	q := url.Values{}
	if assetName != "" {
		q.Set("asset_name", assetName)
		q.Set("asset_kind", assetKind)
	}
	if env != "" {
		q.Set("environment", env)
	}
	if c.Project > 0 {
		q.Set("project_id", strconv.FormatInt(c.Project, 10))
	}
	var res IngestResult
	if err := c.Do(ctx, "POST", "/api/v1/sbom/import?"+q.Encode(), doc, map[string]string{"Content-Type": "application/json"}, &res); err != nil {
		return &res, err
	}
	return &res, c.checkProject(&res)
}

// FeatureUploadProject, in Meta.Features, means the server files uploads
// in the project named by project_id (0.10). Older servers ignore it.
const FeatureUploadProject = "upload_project"

// FeatureAppList, in Meta.Features, means the server takes a host batch's
// list of application directories (apps.dirs) and marks the applications
// missing from it removed (0.14). Older servers refuse the field.
const FeatureAppList = "app_list"

// FeatureHostImages, in Meta.Features, means the server scopes host-image
// identities to their host and takes a host batch's images.refs (the
// agent's --docker).
const FeatureHostImages = "host_images"

// FeatureLeaks, in Meta.Features, means the server takes a batch's leaks
// (keys and passwords found in files). Older servers refuse the field.
const FeatureLeaks = "leaks"

// FeatureGatePolicies, in Meta.Features, means the server answers
// POST /gate-policies/check (policy gates).
const FeatureGatePolicies = "gate_policies"

// FeatureLeakValueChecks, in Meta.Features, means the server takes each
// leak's value_check (model.LeakValueCheck); older servers refuse it.
const FeatureLeakValueChecks = "leak_value_checks"

// FeatureConfigFindings, in Meta.Features, means the server takes a
// batch's config_findings (risky settings: AI agent hooks, SSH access,
// GitHub Actions workflows). Older servers refuse the field.
const FeatureConfigFindings = "config_findings"

// FeatureCodeFindings, in Meta.Features, means the server takes code
// scanners' reports (POST /code-findings/import).
const FeatureCodeFindings = "code_findings"

// FeatureConfigAttackTools, in Meta.Features, means the server takes
// config findings of category attack_tool. Older servers refuse the whole
// batch over an unknown category, so collectors drop those findings
// (model.ConfigScan.WithoutCategory) for a server that does not list it.
const FeatureConfigAttackTools = "config_attack_tools"

// FeatureConfigKernel, in Meta.Features, means the server takes config
// findings of category kernel (the SCTP module). Older servers refuse the
// whole batch over an unknown category, so collectors drop them for a
// server that does not list it.
const FeatureConfigKernel = "config_kernel"

// FeatureReachability, in Meta.Features, means the server takes
// observations' reachability. Older servers refuse the field.
const FeatureReachability = "reachability"

// Meta is the server's anonymous description of itself (GET /meta).
type Meta struct {
	Version       string   `json:"version"`
	SetupRequired bool     `json:"setup_required"`
	Features      []string `json:"features"`
	// CIAudience is the aud a CI job's ID token needs for POST /ci/token;
	// empty when the server does not exchange them.
	CIAudience string `json:"ci_audience"`
}

// CIToken is a collector token a CI job exchanged its ID token for.
type CIToken struct {
	Token         string    `json:"token"`
	ExpiresAt     time.Time `json:"expires_at"`
	RepositoryURL string    `json:"repository_url"`
	ProjectID     *int64    `json:"project_id"`
	TrustID       int64     `json:"trust_id"`
}

// ExchangeCIToken trades a CI provider's OpenID Connect ID token for a
// short-lived collector token (POST /ci/token). trustID chooses among
// several trusts that accept the job; 0 lets the server choose.
func (c *Client) ExchangeCIToken(ctx context.Context, idToken string, trustID int64) (*CIToken, error) {
	body, err := json.Marshal(map[string]any{"token": idToken, "trust_id": trustID})
	if err != nil {
		return nil, err
	}
	var out CIToken
	if err := c.Do(ctx, "POST", "/api/v1/ci/token", bytes.NewReader(body), map[string]string{"Content-Type": "application/json", "X-Stackurity-CSRF": "1"}, &out); err != nil {
		return nil, err
	}
	if out.Token == "" {
		return nil, errors.New("the server answered without a token")
	}
	return &out, nil
}

func (c *Client) Meta(ctx context.Context) (*Meta, error) {
	var m Meta
	if err := c.Do(ctx, "GET", "/api/v1/meta", nil, nil, &m); err != nil {
		return nil, err
	}
	return &m, nil
}

// Has reports whether the server lists a feature.
func (m *Meta) Has(feature string) bool {
	for _, f := range m.Features {
		if f == feature {
			return true
		}
	}
	return false
}

// Project is a project as GET /projects lists it.
type Project struct {
	ID         int64      `json:"id"`
	Name       string     `json:"name"`
	ArchivedAt *time.Time `json:"archived_at"`
}

// Projects lists the active projects the caller can see.
func (c *Client) Projects(ctx context.Context) ([]Project, error) {
	var out struct {
		Items []Project `json:"items"`
	}
	err := c.Do(ctx, "GET", "/api/v1/projects", nil, nil, &out)
	return out.Items, err
}

// GetProject reads one project.
func (c *Client) GetProject(ctx context.Context, id int64) (*Project, error) {
	var out struct {
		Project Project `json:"project"`
	}
	if err := c.Do(ctx, "GET", fmt.Sprintf("/api/v1/projects/%d", id), nil, nil, &out); err != nil {
		return nil, err
	}
	return &out.Project, nil
}

// AgentAction is a remediation action dispatched to this host.
type AgentAction struct {
	ID          int64    `json:"id"`
	Kind        string   `json:"kind"`
	Package     string   `json:"package"`
	Manager     string   `json:"manager"`
	FromVersion string   `json:"from_version"`
	ToVersion   string   `json:"to_version"`
	HealthUnits []string `json:"health_units"`
}

func (c *Client) AgentActions(ctx context.Context) ([]AgentAction, error) {
	var out struct {
		Items []AgentAction `json:"items"`
	}
	err := c.Do(ctx, "GET", "/api/v1/agent/actions", nil, nil, &out)
	return out.Items, err
}

// reportRetryWait is the first pause between report attempts; it doubles.
var reportRetryWait = 2 * time.Second

// ReportAction sends the result of a remediation action. A change has
// already been made, so the result is worth retrying through a brief network
// interruption or server restart; the server accepts the same result twice
// without recording it twice. Client errors (such as a 409 because the
// server already timed the action out) are not retried. If every attempt
// fails, the inventory the agent collects next lets the server settle it.
func (c *Client) ReportAction(ctx context.Context, id int64, report any) error {
	b, err := json.Marshal(report)
	if err != nil {
		return err
	}
	wait := reportRetryWait
	for attempt := 0; ; attempt++ {
		err = c.Do(ctx, "POST", fmt.Sprintf("/api/v1/agent/actions/%d/report", id), bytes.NewReader(b),
			map[string]string{"Content-Type": "application/json"}, nil)
		if err == nil || attempt == 3 {
			return err
		}
		if ae, ok := err.(*APIError); ok && ae.Status < 500 && ae.Status != 429 {
			return err
		}
		select {
		case <-ctx.Done():
			return err
		case <-time.After(wait):
		}
		wait *= 2
	}
}

// ResultFinding is the part of a finding a CI gate needs.
type ResultFinding struct {
	ID             int64  `json:"id"`
	Kind           string `json:"kind"`
	Key            string `json:"key"`
	ComponentName  string `json:"component_name"`
	Version        string `json:"version"`
	Location       string `json:"location"`
	Verification   string `json:"verification"`
	Severity       string `json:"severity"`
	Priority       string `json:"priority"`
	State          string `json:"state"`
	FixedVersion   string `json:"fixed_version"`
	Title          string `json:"title"`
	KnownExploited bool   `json:"known_exploited"`
	// PriorityPolicy is the risk policy version that scored the finding;
	// "" until the server has prioritised it.
	PriorityPolicy string `json:"priority_policy_version"`
}

type CollectionResult struct {
	CollectionID int64           `json:"collection_id"`
	AssetID      int64           `json:"asset_id"`
	Status       string          `json:"status"` // pending, scoring, evaluated, failed
	Error        string          `json:"error"`
	Findings     []ResultFinding `json:"findings"`
	Gaps         int64           `json:"evaluation_gaps"`
}

// CollectionResult fetches the evaluation of a submitted collection.
func (c *Client) CollectionResult(ctx context.Context, id int64) (*CollectionResult, error) {
	var res CollectionResult
	if err := c.Do(ctx, "GET", fmt.Sprintf("/api/v1/collections/%d/result", id), nil, nil, &res); err != nil {
		return nil, err
	}
	return &res, nil
}

// Enrollment is what the server returns for a redeemed enrollment code.
type Enrollment struct {
	Token        string   `json:"token"`
	Environment  string   `json:"environment"`
	AppDirs      []string `json:"app_dirs"`
	DiscoverApps bool     `json:"discover_apps"`
	// ProjectID is the project the code adds hosts to (nil: none, or a
	// server older than 0.10, which does not say).
	ProjectID *int64 `json:"project_id"`
}

// Enroll exchanges a one-time enrollment code for a collector token. The
// client needs no token of its own. With project (not 0) the server first
// checks that the code adds hosts to that project, and refuses (403)
// without using the code up if not; servers before 0.10 refuse the unknown
// field (400), also without using the code.
func (c *Client) Enroll(ctx context.Context, code, hostname string, project int64) (*Enrollment, error) {
	req := map[string]any{"code": code, "hostname": hostname}
	if project > 0 {
		req["project_id"] = project
	}
	body, _ := json.Marshal(req)
	var e Enrollment
	err := c.Do(ctx, "POST", "/api/v1/enroll", bytes.NewReader(body),
		map[string]string{"Content-Type": "application/json", "X-Stackurity-CSRF": "1"}, &e)
	return &e, err
}

// EnrollWait is Enroll that keeps trying, for up to wait, while the server
// answers 429 (too many hosts enrolling at once, as in a fleet rollout from
// behind one NAT address) or 503. It waits as long as the server's
// Retry-After asks, or backs off from 5 seconds to a minute, with jitter so
// that many hosts started together spread out. Other errors (an invalid or
// used-up code) return at once. note is told about each wait; it may be nil.
func (c *Client) EnrollWait(ctx context.Context, code, hostname string, project int64, wait time.Duration, note func(d time.Duration, err error)) (*Enrollment, error) {
	deadline := time.Now().Add(wait)
	backoff := 5 * time.Second
	for {
		e, err := c.Enroll(ctx, code, hostname, project)
		var ae *APIError
		if err == nil || !errors.As(err, &ae) || (ae.Status != http.StatusTooManyRequests && ae.Status != http.StatusServiceUnavailable) {
			return e, err
		}
		d := ae.RetryAfter
		if d <= 0 {
			d = backoff
			backoff = min(backoff*2, time.Minute)
		}
		d = min(d, time.Minute) + rand.N(d/2+time.Second)
		if time.Now().Add(d).After(deadline) {
			return e, err
		}
		if note != nil {
			note(d, err)
		}
		select {
		case <-ctx.Done():
			return e, ctx.Err()
		case <-time.After(d):
		}
	}
}

// ErrNoCheckPolling means the server predates check again (0.7): it has no
// endpoint for agents to ask whether to report now.
var ErrNoCheckPolling = fmt.Errorf("server does not support check again")

// CheckDue asks the server whether someone asked for a fresh report from
// any of assetIDs (Check again in the dashboard). It is a small GET the
// agent sends about once a minute. pollEvery is the interval the server
// suggests (0 when it says nothing).
func (c *Client) CheckDue(ctx context.Context, assetIDs []int64) (due bool, pollEvery time.Duration, err error) {
	q := url.Values{}
	for _, id := range assetIDs {
		q.Add("asset_id", fmt.Sprint(id))
	}
	var out struct {
		Check       bool `json:"check"`
		PollSeconds int  `json:"poll_seconds"`
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if err := c.Do(ctx, "GET", "/api/v1/agent/check?"+q.Encode(), nil, nil, &out); err != nil {
		if ae, ok := err.(*APIError); ok && (ae.Status == 404 || ae.Status == 405) {
			return false, 0, ErrNoCheckPolling
		}
		return false, 0, err
	}
	return out.Check, time.Duration(out.PollSeconds) * time.Second, nil
}

// FeatureKubernetesReport, in Meta.Features, means the server takes a whole
// cluster's collection at POST /kubernetes/report and queues scans of the
// images it runs.
const FeatureKubernetesReport = "kubernetes_report"

// ImageScanStats is what the server queued for a report's images.
type ImageScanStats struct {
	Queued   int `json:"queued"`
	Fresh    int `json:"fresh"`
	Pending  int `json:"pending"`
	Deferred int `json:"deferred"`
}

// KubernetesReportResult is the server's answer to a cluster's report.
type KubernetesReportResult struct {
	ClusterAssetID int64          `json:"cluster_asset_id"`
	Assets         int            `json:"assets"`
	NewAssets      int            `json:"new_assets"`
	Refused        []string       `json:"refused"`
	Images         int            `json:"images"`
	ImageScans     ImageScanStats `json:"image_scans"`
}

// KubernetesReport sends one collection of a cluster (the cluster's batch
// first, then images, then workloads). imageScans is the most image scans
// the server may queue for it (0: none). Server errors are retried.
func (c *Client) KubernetesReport(ctx context.Context, batches []*model.ObservationBatch, imageScans int) (*KubernetesReportResult, error) {
	var res KubernetesReportResult
	var err error
	for attempt := 0; attempt < 4; attempt++ {
		var buf *bytes.Buffer
		buf, err = gz(map[string]any{"batches": batches, "image_scans": imageScans})
		if err != nil {
			return nil, err
		}
		err = c.Do(ctx, "POST", "/api/v1/kubernetes/report", buf, map[string]string{
			"Content-Type": "application/json", "Content-Encoding": "gzip",
		}, &res)
		if err == nil {
			return &res, nil
		}
		// 429 is not retried: the limit is per hour.
		if ae, ok := err.(*APIError); ok && ae.Status < 500 {
			return nil, err
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(time.Duration(1<<attempt) * 2 * time.Second):
		}
	}
	return nil, err
}

// PolicyCheckRequest asks whether an asset passes its policy gates. Name
// the asset by one of AssetID, RepositoryURL and ImageDigest, or by
// CollectionID (an upload) alone.
type PolicyCheckRequest struct {
	AssetID       int64  `json:"asset_id,omitempty"`
	RepositoryURL string `json:"repository_url,omitempty"`
	ImageDigest   string `json:"image_digest,omitempty"`
	CollectionID  int64  `json:"collection_id,omitempty"`
	// Source: ci, deploy or api.
	Source string `json:"source,omitempty"`
	Commit string `json:"commit,omitempty"`
	Ref    string `json:"ref,omitempty"`
	// DryRun asks only which policies apply; nothing is recorded.
	DryRun bool `json:"dry_run,omitempty"`
}

// PolicyViolation is one violation in a policy check's answer.
type PolicyViolation struct {
	PolicyID   int64  `json:"policy_id"`
	PolicyName string `json:"policy_name"`
	Mode       string `json:"mode"` // warn or enforce
	Kind       string `json:"kind"`
	Reason     string `json:"reason"`
	Component  string `json:"component"`
	Key        string `json:"key"`
	FindingID  *int64 `json:"finding_id,omitempty"`
	LeakID     *int64 `json:"leak_id,omitempty"`
	Link       string `json:"link"`
	// EnforceRequiresPlan: an enforce policy this server's edition or
	// plan does not enforce; it counted as a warning.
	EnforceRequiresPlan bool `json:"enforce_requires_plan,omitempty"`
}

// PolicyCheck is the answer of POST /gate-policies/check.
type PolicyCheck struct {
	CheckID           int64             `json:"check_id,omitempty"`
	Result            string            `json:"result"` // pass, warn or fail ("" for a dry run)
	AssetID           int64             `json:"asset_id"`
	AssetName         string            `json:"asset_name"`
	PoliciesEvaluated int               `json:"policies_evaluated"`
	PoliciesEnforced  int               `json:"policies_enforced"`
	Violations        []PolicyViolation `json:"violations"`
	DryRun            bool              `json:"dry_run,omitempty"`
	// DeployRequiresPlan: a deploy check on a server or plan without the
	// deploy gate; violations are reported but the result is never fail.
	DeployRequiresPlan bool `json:"deploy_requires_plan,omitempty"`
}

// ErrPolicyCheckUnsupported: the server has no policy gate check (older
// than policy gates: 404 or 405).
var ErrPolicyCheckUnsupported = errors.New("the server does not check policy gates: it is older than policy gates")

// CheckPolicies asks the server whether an asset passes its policy gates
// (POST /gate-policies/check). A server without the endpoint answers
// ErrPolicyCheckUnsupported.
func (c *Client) CheckPolicies(ctx context.Context, req PolicyCheckRequest) (*PolicyCheck, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	var out PolicyCheck
	err = c.Do(ctx, "POST", "/api/v1/gate-policies/check", bytes.NewReader(body),
		map[string]string{"Content-Type": "application/json", "X-Stackurity-CSRF": "1"}, &out)
	if policyCheckUnsupported(err) {
		return nil, ErrPolicyCheckUnsupported
	}
	if err != nil {
		return nil, err
	}
	if out.Violations == nil {
		out.Violations = []PolicyViolation{}
	}
	return &out, nil
}

// policyCheckUnsupported tells a server without the check from a check
// that failed: a 405 (servers with the policy routes of 0.20 but not the
// check route), or a 404 for the route itself ("no such endpoint", or
// not JSON at all) rather than for the asset.
func policyCheckUnsupported(err error) bool {
	var ae *APIError
	if !errors.As(err, &ae) {
		return false
	}
	switch ae.Status {
	case http.StatusMethodNotAllowed:
		return true
	case http.StatusNotFound:
		return ae.Code == "" || ae.Message == "no such endpoint"
	}
	return false
}
