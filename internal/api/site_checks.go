package api

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/stackurity/stackurity/internal/sitecheck"
	"github.com/stackurity/stackurity/internal/sitecheck/stored"
	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/tenant"
)

// Website checks (docs/website-check.md, internal/sitecheck).
//
//   - POST /api/v1/site-checks       run one for the organisation (engineer
//     or above); takes one of the plan's site_checks_per_month, given back
//     if the check fails. An API token may run one only when the plan does
//     not set no_site_check_api.
//   - GET  /api/v1/site-checks       the organisation's checks, newest first
//   - GET  /api/v1/site-checks/{id}  one, with its report
//   - POST /api/v1/public/site-check the summary only (sitecheck.Teaser),
//     for the public page on the website, which calls it server-side with
//     the key in X-Site-Check-Key (Server.SiteCheckPublicKey; 404 without
//     one) after its own Turnstile and per-visitor limit.

var (
	// limitSiteChecksPerOrg caps how fast one organisation runs checks,
	// whatever its allowance.
	limitSiteChecksPerOrg = rateLimit{10, time.Minute}
	// limitPublicSiteChecks caps the public endpoint as a whole: a stolen
	// key cannot turn the server into a crawler.
	limitPublicSiteChecks = rateLimit{3000, 24 * time.Hour}
	// siteCheckSlots is how many checks run at once on one server.
	siteCheckSlots = make(chan struct{}, 8)
)

// siteCheckBody is the request of both POST endpoints.
type siteCheckBody struct {
	URL string `json:"url"`
}

// siteCheckResult is a stored check with its report decoded.
type siteCheckResult struct {
	store.SiteCheck
	Report *sitecheck.Report `json:"report"`
}

// runSiteCheck runs one check, waiting for a free slot.
func (s *Server) runSiteCheck(ctx context.Context, target string) (*sitecheck.Report, error) {
	u, err := sitecheck.Target(target)
	if err != nil {
		return nil, err
	}
	select {
	case siteCheckSlots <- struct{}{}:
		defer func() { <-siteCheckSlots }()
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	in, err := stored.New(ctx, s.Store)
	if err != nil {
		return nil, err
	}
	c := &sitecheck.Checker{Intel: in, Client: s.siteCheckClient}
	return c.Check(ctx, u)
}

// writeSiteCheckError answers a check that could not run.
func (s *Server) writeSiteCheckError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, sitecheck.ErrTarget):
		writeError(w, 400, "bad_target", err.Error())
	case errors.Is(err, context.Canceled) && r.Context().Err() != nil:
		s.fail(w, r, err)
	default:
		// The site did not answer, or its certificate is refused: the
		// message says which, for the person who asked.
		if errors.Is(err, context.DeadlineExceeded) {
			writeError(w, 422, "site_unreachable", "the website did not answer in time")
			return
		}
		writeError(w, 422, "site_unreachable", err.Error())
	}
}

func (s *Server) createSiteCheck(w http.ResponseWriter, r *http.Request) {
	var b siteCheckBody
	if err := decode(r, &b); err != nil {
		s.fail(w, r, err)
		return
	}
	if _, err := sitecheck.Target(b.URL); err != nil {
		writeError(w, 400, "bad_target", err.Error())
		return
	}
	ctx := r.Context()
	p := principal(r)
	if p.Token != nil {
		ok, next, err := s.Store.SiteCheckAPIAllowed(ctx)
		if err != nil {
			s.fail(w, r, err)
			return
		}
		if !ok {
			s.fail(w, r, &store.PlanLimitError{Kind: store.LimitSiteCheckAPI, NextPlan: next})
			return
		}
	}
	ws, _ := tenant.Workspace(ctx)
	if s.limited(w, r, "too many website checks; wait a minute", limitHit{"site-checks", strconv.FormatInt(ws, 10), limitSiteChecksPerOrg}) {
		return
	}
	if err := s.Store.TakeSiteCheck(ctx); err != nil {
		s.fail(w, r, err)
		return
	}
	rep, err := s.runSiteCheck(ctx, b.URL)
	if err != nil {
		_ = s.Store.GiveBackSiteCheck(ctx)
		s.writeSiteCheckError(w, r, err)
		return
	}
	raw, err := json.Marshal(rep)
	if err != nil {
		_ = s.Store.GiveBackSiteCheck(ctx)
		s.fail(w, r, err)
		return
	}
	var userID, tokenID int64
	name := ""
	if p.User != nil {
		userID, name = p.User.ID, p.User.Email
	}
	if p.Token != nil {
		tokenID = p.Token.ID
		if name == "" {
			name = p.Token.Name
		}
	}
	saved, err := s.Store.AddSiteCheck(ctx, store.SiteCheck{URL: rep.URL, FinalURL: rep.FinalURL, Host: rep.Host, Report: raw,
		Issues: rep.Summary.Issues, KnownExploited: rep.Summary.KnownExploited, EndOfLife: rep.Summary.EndOfLife,
		CreatedByName: name}, userID, tokenID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	_ = s.Store.Audit(ctx, p.Actor(r), "site_check.run", "site_check", itoa(saved.ID),
		map[string]any{"host": rep.Host, "issues": rep.Summary.Issues, "via_api": p.Token != nil})
	saved.Report = nil
	writeJSON(w, 201, siteCheckResult{SiteCheck: *saved, Report: rep})
}

func (s *Server) listSiteChecks(w http.ResponseWriter, r *http.Request) {
	items, total, err := s.Store.SiteChecks(r.Context(), page(r))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	writeJSON(w, 200, paged(items, total, page(r)))
}

func (s *Server) getSiteCheck(w http.ResponseWriter, r *http.Request) {
	id, err := idParam(r, "id")
	if err != nil {
		s.fail(w, r, err)
		return
	}
	c, err := s.Store.SiteCheckByID(r.Context(), id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	var rep sitecheck.Report
	if err := json.Unmarshal(c.Report, &rep); err != nil {
		s.fail(w, r, err)
		return
	}
	c.Report = nil
	writeJSON(w, 200, siteCheckResult{SiteCheck: *c, Report: &rep})
}

// publicSiteCheck is the website's endpoint: the teaser only, nothing
// stored, no workspace.
func (s *Server) publicSiteCheck(w http.ResponseWriter, r *http.Request) {
	key := r.Header.Get("X-Site-Check-Key")
	if s.SiteChecksOff || s.SiteCheckPublicKey == "" || subtle.ConstantTimeCompare([]byte(key), []byte(s.SiteCheckPublicKey)) != 1 {
		http.NotFound(w, r)
		return
	}
	if s.limited(w, r, "the public website check is busy; try again later", limitHit{"public-site-check", "all", limitPublicSiteChecks}) {
		return
	}
	var b siteCheckBody
	if err := decode(r, &b); err != nil {
		s.fail(w, r, err)
		return
	}
	rep, err := s.runSiteCheck(tenant.System(r.Context()), b.URL)
	if err != nil {
		s.writeSiteCheckError(w, r, err)
		return
	}
	writeJSON(w, 200, rep.Teaser())
}
