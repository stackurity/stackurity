package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/stackurity/stackurity/internal/auth"
	"github.com/stackurity/stackurity/internal/collect/gitrepo"
	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/tenant"
)

// The policy gate check (docs/design/policy-gates.md, section 5;
// docs/policy-gates.md): POST /gate-policies/check asks whether one asset
// passes the policies that apply to it now. `stackurity scan` asks it
// after the server has evaluated the upload, and `stackurity policy check`
// asks it from deploy pipelines. Every answer is recorded in
// gate_policy_checks.
//
// Callers: anyone who may read the asset (viewer or more, on the
// organisation or on the asset's project), and collector tokens for what
// they report: a CI job's token (POST /ci/token) only its own repository,
// a token bound to a host only that host, and any collector token an asset
// it uploaded (collection_id of its own upload), as with
// GET /collections/{id}/result.

// FeatureGatePolicies, in GET /meta's features, says the server answers
// POST /gate-policies/check.
const FeatureGatePolicies = "gate_policies"

// gateEnforceAllowed reports whether a policy in enforce mode may fail a
// check for the workspace in ctx. In the Community build it never may: an
// enforce policy is reported as a warning, with enforce_requires_plan
// (docs/design/policy-gates.md, section 7). The licensed build sets it from
// the licence feature in delivery step 4.
var gateEnforceAllowed = func(ctx context.Context) bool { return false }

// gateCheckRequest names the asset by exactly one of AssetID,
// RepositoryURL and ImageDigest, or by CollectionID (an upload) alone; a
// CollectionID given with one of them must be of the same asset.
type gateCheckRequest struct {
	AssetID       int64  `json:"asset_id"`
	RepositoryURL string `json:"repository_url"`
	ImageDigest   string `json:"image_digest"`
	CollectionID  int64  `json:"collection_id"`
	// Source: ci, deploy or api (the default).
	Source string `json:"source"`
	Commit string `json:"commit"`
	Ref    string `json:"ref"`
	// DryRun answers which policies apply (policies_evaluated,
	// policies_enforced) without reading findings or recording the check:
	// the CLI asks first, so it waits for the evaluation only when a policy
	// applies.
	DryRun bool `json:"dry_run"`
}

// gateCheckViolation is one violation in a check's answer.
type gateCheckViolation struct {
	PolicyID   int64  `json:"policy_id"`
	PolicyName string `json:"policy_name"`
	// Mode is the policy's mode: warn or enforce.
	Mode   string `json:"mode"`
	Kind   string `json:"kind"`
	Reason string `json:"reason"`
	// Component is the component's name and version ("" for a leaked key).
	Component string `json:"component"`
	Key       string `json:"key"`
	FindingID *int64 `json:"finding_id,omitempty"`
	LeakID    *int64 `json:"leak_id,omitempty"`
	// Link is the finding's or leaked key's page on the dashboard,
	// absolute when the server knows its address (BaseURL).
	Link string `json:"link"`
	// EnforceRequiresPlan: the policy is in enforce mode but this edition
	// or plan does not enforce it, so it counted as a warning.
	EnforceRequiresPlan bool `json:"enforce_requires_plan,omitempty"`
}

// gateCheckResponse is the answer.
type gateCheckResponse struct {
	// CheckID is the recorded check (0 for a dry run).
	CheckID int64 `json:"check_id,omitempty"`
	// Result: pass (no violation), warn (violations, none enforced) or
	// fail (a violation of a policy that is enforced). Empty for a dry run.
	Result    string `json:"result"`
	AssetID   int64  `json:"asset_id"`
	AssetName string `json:"asset_name"`
	// PoliciesEvaluated counts the policies that apply to the asset and
	// are not off; PoliciesEnforced those of them that can fail a check.
	PoliciesEvaluated int                  `json:"policies_evaluated"`
	PoliciesEnforced  int                  `json:"policies_enforced"`
	Violations        []gateCheckViolation `json:"violations"`
	DryRun            bool                 `json:"dry_run,omitempty"`
}

// gateCheckSources are the values of source.
var gateCheckSources = []string{store.GateSourceCI, store.GateSourceDeploy, store.GateSourceAPI}

// validate checks the request and puts it in its stored form.
func (q *gateCheckRequest) validate() error {
	q.Source = strings.ToLower(strings.TrimSpace(q.Source))
	if q.Source == "" {
		q.Source = store.GateSourceAPI
	}
	ok := false
	for _, s := range gateCheckSources {
		ok = ok || q.Source == s
	}
	if !ok {
		return badRequest("source must be ci, deploy or api")
	}
	q.RepositoryURL = strings.TrimSpace(q.RepositoryURL)
	q.ImageDigest = strings.TrimSpace(q.ImageDigest)
	q.Commit = strings.TrimSpace(q.Commit)
	q.Ref = strings.TrimSpace(q.Ref)
	if q.AssetID < 0 || q.CollectionID < 0 {
		return badRequest("asset_id and collection_id must be positive")
	}
	n := 0
	for _, set := range []bool{q.AssetID > 0, q.RepositoryURL != "", q.ImageDigest != ""} {
		if set {
			n++
		}
	}
	switch {
	case n > 1:
		return badRequest("name the asset by one of asset_id, repository_url and image_digest")
	case n == 0 && q.CollectionID == 0:
		return badRequest("name the asset: asset_id, repository_url, image_digest or collection_id")
	}
	if q.ImageDigest != "" {
		d := store.NormalizeImageDigest(q.ImageDigest)
		if d == "" {
			return badRequest("image_digest must be a sha256 digest (sha256:<64 hex digits>)")
		}
		q.ImageDigest = d
	}
	if q.RepositoryURL != "" {
		q.RepositoryURL = gitrepo.NormalizeURL(q.RepositoryURL)
	}
	if len(q.Commit) > 100 || len(q.Ref) > 500 || len(q.RepositoryURL) > 2048 {
		return badRequest("commit, ref or repository_url is too long")
	}
	return nil
}

// gateCheckOutcome turns the asset's violations into the answer's
// violations and result. enforce says whether enforce-mode policies may
// fail the check; base is the dashboard's address for absolute links.
func gateCheckOutcome(vs []store.GateViolation, enforce bool, base string) (string, []gateCheckViolation) {
	base = strings.TrimRight(base, "/")
	result := store.GateResultPass
	out := make([]gateCheckViolation, 0, len(vs))
	for _, v := range vs {
		cv := gateCheckViolation{PolicyID: v.PolicyID, PolicyName: v.PolicyName, Mode: v.Mode, Kind: v.Kind, Reason: v.Reason,
			Component: v.Component, Key: v.Key, FindingID: v.FindingID, LeakID: v.LeakID, Link: v.Link}
		if base != "" && strings.HasPrefix(cv.Link, "/") {
			cv.Link = base + cv.Link
		}
		switch {
		case v.Mode == store.GateModeEnforce && enforce:
			result = store.GateResultFail
		case v.Mode == store.GateModeEnforce:
			cv.EnforceRequiresPlan = true
			fallthrough
		default:
			if result == store.GateResultPass {
				result = store.GateResultWarn
			}
		}
		out = append(out, cv)
	}
	return result, out
}

// gateCheckCaller reports whether the caller may ask for checks at all:
// readers (viewer or more, organisation-wide or on a project) and
// collector tokens.
func gateCheckCaller(p *Principal) (reader, collector bool) {
	if p == nil {
		return false, false
	}
	reader = auth.Higher(p.Role, p.ProjectRole).AtLeast(auth.RoleViewer)
	collector = p.Role == auth.RoleCollector && p.Token != nil
	return reader, collector
}

func (s *Server) checkGatePolicies(w http.ResponseWriter, r *http.Request) {
	p := principal(r)
	reader, collector := gateCheckCaller(p)
	if !reader && !collector {
		writeError(w, 403, "forbidden", "checking policy gates needs a collector token or the viewer role")
		return
	}
	var req gateCheckRequest
	if err := decode(r, &req); err != nil {
		s.fail(w, r, err)
		return
	}
	if err := req.validate(); err != nil {
		s.fail(w, r, err)
		return
	}
	ctx := r.Context()
	assetID, err := s.resolveGateCheckAsset(r, &req, reader)
	// The asset is read as the caller (row-level security: a member with
	// project access sees only their assets) ...
	var a *store.Asset
	if err == nil {
		a, err = s.Store.GetAsset(ctx, assetID)
	}
	if errors.Is(err, store.ErrNotFound) {
		// Said in words, so a client can tell it from a server without
		// this endpoint ("no such endpoint").
		writeError(w, 404, "not_found", "no asset matches, or this token cannot see it")
		return
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	// ... and, once the caller may see it, its policies are worked out
	// for the whole organisation: a policy turned off or edited in a
	// project the caller cannot see still counts as it is.
	ws, ok := tenant.Workspace(ctx)
	if !ok {
		s.fail(w, r, store.ErrNotFound)
		return
	}
	wctx := tenant.WithWorkspace(ctx, ws)
	enforce := gateEnforceAllowed(wctx)
	policies, err := s.Store.EffectiveGatePolicies(wctx, a.ID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	res := gateCheckResponse{AssetID: a.ID, AssetName: a.Name, Violations: []gateCheckViolation{}, DryRun: req.DryRun}
	evaluated := []int64{}
	for _, gp := range policies {
		if gp.Mode == store.GateModeOff {
			continue
		}
		evaluated = append(evaluated, gp.ID)
		res.PoliciesEvaluated++
		if gp.Mode == store.GateModeEnforce && enforce {
			res.PoliciesEnforced++
		}
	}
	if req.DryRun {
		writeJSON(w, 200, res)
		return
	}
	vs, err := s.Store.GateViolations(wctx, store.GateViolationFilter{AssetID: a.ID})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	res.Result, res.Violations = gateCheckOutcome(vs, enforce, s.BaseURL)

	repo := req.RepositoryURL
	if repo == "" {
		repo = ciRepository(r)
	}
	if repo == "" {
		repo = a.Attributes["git_url"]
	}
	commit := req.Commit
	if commit == "" && req.CollectionID > 0 {
		commit = a.Attributes["git_commit"]
	}
	recorded, _ := json.Marshal(res.Violations)
	actor := p.Actor(r)
	var actorID *int64
	if actor.ID > 0 {
		actorID = &actor.ID
	}
	c, err := s.Store.RecordGatePolicyCheck(wctx, store.GatePolicyCheck{AssetID: &a.ID, AssetName: a.Name, Source: req.Source,
		ActorType: actor.Type, ActorID: actorID, ActorName: actor.Name, Commit: commit, Ref: req.Ref, ImageDigest: req.ImageDigest,
		Repository: repo, Result: res.Result, Violations: recorded, PolicyIDs: evaluated})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	res.CheckID = c.ID
	writeJSON(w, 200, res)
}

// resolveGateCheckAsset finds the asset a check names, as the caller sees
// it, and refuses a collector token an asset it does not report.
func (s *Server) resolveGateCheckAsset(r *http.Request, req *gateCheckRequest, reader bool) (int64, error) {
	ctx := r.Context()
	p := principal(r)
	var asset int64
	ownUpload := false
	if req.CollectionID > 0 {
		a, submitter, err := s.Store.CollectionAsset(ctx, req.CollectionID)
		if err != nil {
			return 0, err
		}
		ownUpload = p.Token != nil && submitter != nil && *submitter == p.Token.ID
		if !reader && !ownUpload {
			// As GET /collections/{id}/result: another token's upload is
			// not found.
			return 0, store.ErrNotFound
		}
		asset = a
	}
	var named int64
	var err error
	switch {
	case req.AssetID > 0:
		named = req.AssetID
	case req.RepositoryURL != "":
		named, err = s.Store.AssetByGitURL(ctx, req.RepositoryURL)
	case req.ImageDigest != "":
		named, err = s.Store.AssetByImageDigest(ctx, req.ImageDigest)
	}
	if err != nil {
		return 0, err
	}
	if named > 0 {
		if asset > 0 && named != asset {
			return 0, badRequest("collection_id is an upload of another asset")
		}
		asset = named
	}
	if reader || ownUpload {
		return asset, nil
	}
	// A collector token naming an asset: only one it reports.
	if repo := ciRepository(r); repo != "" {
		own, err := s.Store.AssetByGitURL(ctx, repo)
		if err == store.ErrNotFound || (err == nil && own != asset) {
			return 0, forbidden("this token was issued to a CI job of " + repo + " and can check only that repository")
		}
		return asset, err
	}
	bound, err := s.boundAsset(r)
	if err != nil {
		return 0, err
	}
	if bound != nil {
		ok, err := s.Store.AssetsReportingThrough(ctx, *bound, []int64{asset})
		if err != nil {
			return 0, err
		}
		if len(ok) == 0 {
			return 0, forbidden("this token is bound to another asset")
		}
		return asset, nil
	}
	return 0, forbidden("a collector token can check only an asset it uploaded: pass the upload's collection_id, or use a token with the viewer role")
}
