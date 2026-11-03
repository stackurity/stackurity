package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/signal"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/stackurity/stackurity/internal/client"
	"github.com/stackurity/stackurity/internal/diag"
	"github.com/stackurity/stackurity/internal/model"
	"github.com/stackurity/stackurity/internal/store"
)

// selftestPrefix starts the name of every selftest asset.
const selftestPrefix = "stackurity-selftest-"

// selftestCandidate is a package with a well-known advisory that its
// ecosystem's feed has held for years.
type selftestCandidate struct {
	feed, purl, advisory string
}

// selftestCandidates, in order of preference. Only one whose feed already
// exists and has synced is used: a package of another ecosystem would make
// the server create that ecosystem's feeds, which would then stay.
var selftestCandidates = []selftestCandidate{
	{"osv:npm", "pkg:npm/lodash@4.17.20", "GHSA-35jh-r3h4-6jhm"},
	{"osv:PyPI", "pkg:pypi/pyyaml@5.3", "GHSA-8q59-q68h-6hv4"},
	{"osv:Maven", "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1", "GHSA-jfh8-c2jp-5v3q"},
	{"osv:Go", "pkg:golang/golang.org/x/text@v0.3.5", "GO-2021-0113"},
	{"osv:RubyGems", "pkg:gem/nokogiri@1.10.3", "GHSA-vr8q-g5c7-m54m"},
	{"osv:Packagist", "pkg:composer/guzzlehttp/guzzle@7.4.0", "GHSA-q559-8m2m-g699"},
}

// selftestNoMatch is submitted when no candidate's feed has synced: a
// generic package no feed covers, so the stages up to evaluation still run.
const selftestNoMatch = "pkg:generic/stackurity-selftest@0.0.0"

// selftest proves a running installation works end to end, through its
// public API: it submits a small inventory as a labelled throwaway asset,
// waits for the evaluation, reads the expected finding back and deletes
// the asset, whatever happened. The asset carries only a selftest
// identifier, so the server sends no notification about it (store.SelftestScheme).
type selftest struct {
	cl    *client.Client
	out   io.Writer
	await gate // evaluation wait and poll
	// results so far; a stage that fails stops the ones after it except
	// the cleanup.
	results []diag.Result
}

func (s *selftest) add(stage string, st diag.Status, title, detail, next string) diag.Result {
	r := diag.Result{Check: stage, Status: st, Title: title, Detail: detail, Next: next}
	s.results = append(s.results, r)
	diag.WriteResult(s.out, r, len("leftovers"))
	return r
}

func (s *selftest) failed() bool {
	for _, r := range s.results {
		if r.Status == diag.Fail {
			return true
		}
	}
	return false
}

func (s *selftest) run(ctx context.Context) {
	created := int64(0)
	defer func() {
		// Even when a stage failed or the run was interrupted.
		cctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
		defer cancel()
		s.cleanup(cctx, created)
	}()
	if !s.connect(ctx) {
		return
	}
	s.leftovers(ctx)
	cand := s.pickAdvisory(ctx)
	if s.failed() {
		return
	}
	created = s.submit(ctx, cand)
}

// connect checks the server answers and the token may delete assets.
func (s *selftest) connect(ctx context.Context) bool {
	var meta struct {
		Version string `json:"version"`
	}
	if err := s.cl.Do(ctx, "GET", "/api/v1/meta", nil, nil, &meta); err != nil {
		s.add("server", diag.Fail, "The server does not answer", err.Error(), "Check --server (STACKURITY_SERVER) and that the server is running (curl its /readyz).")
		return false
	}
	var me struct {
		Role string `json:"role"`
	}
	if err := s.cl.Do(ctx, "GET", "/api/v1/auth/me", nil, nil, &me); err != nil {
		s.add("server", diag.Fail, "The token is refused", err.Error(), "Create an API token with the admin role (Integrations → API tokens) and pass it in STACKURITY_TOKEN or --token-file.")
		return false
	}
	if me.Role != "admin" {
		s.add("server", diag.Fail, "The token's role is "+me.Role+", not admin", "The selftest deletes the asset it creates, which needs an admin.",
			"Create an API token with the admin role (Integrations → API tokens) for the selftest.")
		return false
	}
	s.add("server", diag.Pass, "Stackurity "+meta.Version+" answers; the token is an admin's", "", "")
	return true
}

// leftovers deletes selftest assets an interrupted run left behind: named
// with the prefix and identified only by a selftest identifier.
func (s *selftest) leftovers(ctx context.Context) {
	var list struct {
		Items []store.Asset `json:"items"`
	}
	if err := s.cl.Do(ctx, "GET", "/api/v1/assets?limit=100&q="+url.QueryEscape(selftestPrefix), nil, nil, &list); err != nil {
		s.add("leftovers", diag.Warn, "Could not look for assets an earlier selftest left", err.Error(), "")
		return
	}
	n := 0
	for _, a := range list.Items {
		if !strings.HasPrefix(a.Name, selftestPrefix) {
			continue
		}
		var got struct {
			Identifiers []store.Identifier `json:"identifiers"`
		}
		if err := s.cl.Do(ctx, "GET", fmt.Sprintf("/api/v1/assets/%d", a.ID), nil, nil, &got); err != nil || !onlySelftest(got.Identifiers) {
			continue
		}
		if err := s.cl.Do(ctx, "DELETE", fmt.Sprintf("/api/v1/assets/%d", a.ID), nil, nil, nil); err == nil {
			n++
		}
	}
	if n > 0 {
		s.add("leftovers", diag.Pass, fmt.Sprintf("Deleted %d asset(s) an earlier, interrupted selftest left", n), "", "")
	}
}

func onlySelftest(ids []store.Identifier) bool {
	for _, id := range ids {
		if id.Scheme != store.SelftestScheme {
			return false
		}
	}
	return len(ids) > 0
}

// pickAdvisory chooses a candidate whose feed has synced and holds its
// advisory, or nil.
func (s *selftest) pickAdvisory(ctx context.Context) *selftestCandidate {
	var feeds struct {
		Items []store.Feed `json:"items"`
	}
	if err := s.cl.Do(ctx, "GET", "/api/v1/feeds", nil, nil, &feeds); err != nil {
		s.add("advisory", diag.Fail, "Could not read the feeds", err.Error(), "")
		return nil
	}
	synced := map[string]store.Feed{}
	for _, f := range feeds.Items {
		if f.Enabled && f.LastSuccess != nil {
			synced[f.Name] = f
		}
	}
	for _, c := range selftestCandidates {
		f, ok := synced[c.feed]
		if !ok {
			continue
		}
		var advs struct {
			Items []store.Advisory `json:"items"`
		}
		if err := s.cl.Do(ctx, "GET", "/api/v1/advisories/"+url.PathEscape(c.advisory), nil, nil, &advs); err != nil {
			continue
		}
		for _, a := range advs.Items {
			if a.ID == c.advisory && a.Withdrawn == nil {
				c := c
				s.add("advisory", diag.Pass, fmt.Sprintf("%s (synced %s ago) holds %s for %s", c.feed,
					diag.Ago(time.Since(*f.LastSuccess)), c.advisory, strings.TrimPrefix(c.purl, "pkg:")), "", "")
				return &c
			}
		}
	}
	var names []string
	for _, c := range selftestCandidates {
		names = append(names, c.feed)
	}
	s.add("advisory", diag.Skip, "No synced feed holds a known advisory: the finding stage is skipped",
		"The selftest uses "+strings.Join(names, ", ")+" when the inventory already has that ecosystem and its feed has synced.",
		"Run it again after the first sync (stackurity doctor shows the feeds).")
	return nil
}

// submit uploads the asset, waits for its evaluation and reads the finding
// back. It returns the asset's id once it exists.
func (s *selftest) submit(ctx context.Context, cand *selftestCandidate) int64 {
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	tag := hex.EncodeToString(b)
	name := selftestPrefix + tag
	purl := selftestNoMatch
	if cand != nil {
		purl = cand.purl
	}
	batch := model.NewBatch(model.Collector{ID: "stackurity-selftest", Version: version, Method: "selftest"},
		model.AssetRef{Kind: model.AssetRepository, Name: name, Environment: "selftest",
			Identifiers: []model.Identifier{{Scheme: store.SelftestScheme, Value: tag}}})
	batch.Observations = []model.Observation{{Purl: purl, Confidence: model.ConfidenceConfirmed}}
	batch.Cover("selftest", "checked", "")
	batch.Complete = true
	start := time.Now()
	res, err := s.cl.Ingest(ctx, batch)
	if err != nil {
		s.add("ingest", diag.Fail, "The inventory upload was refused", err.Error(),
			"Read the error: a full disk or database shows in stackurity doctor; an asset limit in Settings → Usage.")
		return 0
	}
	s.add("ingest", diag.Pass, fmt.Sprintf("Uploaded %s as asset %d (collection %d)", name, res.AssetID, res.CollectionID), "", "")

	result, err := s.await.await(ctx, s.cl, res.CollectionID)
	if err != nil {
		s.add("evaluate", diag.Fail, "The server did not evaluate the upload", err.Error(),
			"Check that a server runs its worker: stackurity doctor shows failing jobs and background tasks.")
		return res.AssetID
	}
	s.add("evaluate", diag.Pass, fmt.Sprintf("Evaluated and prioritised in %s: %d open finding(s)", time.Since(start).Round(time.Second), len(result.Findings)), "", "")

	if cand == nil {
		s.add("finding", diag.Skip, "Skipped: no advisory to expect (see advisory)", "", "")
		return res.AssetID
	}
	// Read each vulnerability finding back through the API until the one
	// the advisory produced (findings are keyed by CVE where there is one;
	// the advisory is among their sources).
	for _, rf := range result.Findings {
		if rf.Kind != "vulnerability" {
			continue
		}
		var got struct {
			Finding store.Finding `json:"finding"`
		}
		if err := s.cl.Do(ctx, "GET", fmt.Sprintf("/api/v1/findings/%d", rf.ID), nil, nil, &got); err != nil {
			s.add("finding", diag.Fail, fmt.Sprintf("Finding %d could not be read back", rf.ID), err.Error(), "")
			return res.AssetID
		}
		f := got.Finding
		if f.AssetID == res.AssetID && (f.Key == cand.advisory || slices.Contains(f.Sources, cand.advisory)) {
			s.add("finding", diag.Pass, fmt.Sprintf("Finding %d (%s, %s, %s) read back through GET /api/v1/findings/%d", f.ID, f.Key, f.Severity, f.Priority, f.ID), "", "")
			return res.AssetID
		}
	}
	s.add("finding", diag.Fail, fmt.Sprintf("No finding for %s on %s", cand.advisory, cand.purl),
		"The feed holds the advisory and the server evaluated the asset, but matched nothing.",
		"Run stackurity support-bundle and send it to support with this output.")
	return res.AssetID
}

// cleanup deletes the asset and checks it is gone.
func (s *selftest) cleanup(ctx context.Context, id int64) {
	if id == 0 {
		return
	}
	path := fmt.Sprintf("/api/v1/assets/%d", id)
	err := s.cl.Do(ctx, "DELETE", path, nil, nil, nil)
	if err == nil {
		err = s.cl.Do(ctx, "GET", path, nil, nil, nil)
		var ae *client.APIError
		if errors.As(err, &ae) && ae.Status == 404 {
			s.add("cleanup", diag.Pass, fmt.Sprintf("Deleted asset %d and its findings", id), "", "")
			return
		}
		if err == nil {
			err = errors.New("it is still there")
		}
	}
	s.add("cleanup", diag.Fail, fmt.Sprintf("Could not delete asset %d", id), err.Error(),
		"Delete it on its page in the dashboard; the next selftest also deletes it.")
}

func selftestCmd() *cobra.Command {
	var c conn
	var wait time.Duration
	cmd := &cobra.Command{
		Use:   "selftest",
		Short: "Prove a running server works end to end: upload a throwaway asset, get its finding, delete it",
		Long: "Uploads a small inventory with a known-vulnerable package as a labelled throwaway asset, waits for the\n" +
			"evaluation, reads the finding back through the API and deletes the asset, even on failure. It sends no\n" +
			"notification. Needs an admin API token (STACKURITY_TOKEN or --token-file). Exit code 1 when a stage fails.",
		RunE: func(cmd *cobra.Command, args []string) error {
			cl, err := c.client()
			if err != nil {
				return err
			}
			ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
			defer stop()
			s := &selftest{cl: cl, out: cmd.OutOrStdout(), await: gate{wait: wait}}
			s.run(ctx)
			if s.failed() {
				return &exitError{code: 1, msg: "selftest failed"}
			}
			fmt.Fprintln(cmd.OutOrStdout(), "selftest passed")
			return nil
		},
	}
	c.flags(cmd)
	cmd.Flags().DurationVar(&wait, "wait", 5*time.Minute, "how long to wait for the server to evaluate the upload")
	return cmd
}
