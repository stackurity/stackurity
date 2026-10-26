package api_test

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/stackurity/stackurity/internal/api"
	"github.com/stackurity/stackurity/internal/auth"
	"github.com/stackurity/stackurity/internal/model"
	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/tenant"
)

// Why it matched, in one sentence, on the finding, in explain, and the
// second check where it disagreed.
func TestFindingWhyAndSecondCheck(t *testing.T) {
	l := newLoopEnv(t)
	id := l.findings["CVE-E"]
	var detail struct {
		Why struct {
			Sentence      string   `json:"sentence"`
			Type          string   `json:"type"`
			EvidenceState string   `json:"evidence_state"`
			StateText     string   `json:"evidence_state_text"`
			NeedsReview   bool     `json:"needs_review"`
			Missing       []string `json:"missing_information"`
			SecondCheck   *struct {
				Result string `json:"result"`
			} `json:"second_check"`
			SecondCheckText string `json:"second_check_text"`
		} `json:"why"`
	}
	if code := l.view.do("GET", "/api/v1/findings/"+itoa(id), nil, &detail); code != 200 {
		t.Fatalf("finding: %d", code)
	}
	if !strings.HasPrefix(detail.Why.Sentence, "Installed 4.0.0 (from ") || detail.Why.Type != "package_advisory" ||
		detail.Why.EvidenceState != "confirmed" || detail.Why.SecondCheck != nil || len(detail.Why.Missing) != 0 {
		t.Fatalf("why: %+v", detail.Why)
	}

	recordDisagreement(t, l.st, l.ctx, id)
	if code := l.view.do("GET", "/api/v1/findings/"+itoa(id), nil, &detail); code != 200 {
		t.Fatalf("finding: %d", code)
	}
	if detail.Why.EvidenceState != "confirmed" || !detail.Why.NeedsReview || detail.Why.SecondCheck == nil || detail.Why.SecondCheck.Result != "disagreed" ||
		!strings.HasPrefix(detail.Why.StateText, "Needs validation: the second check disagreed (affected") ||
		len(detail.Why.Missing) != 1 || !strings.Contains(detail.Why.Missing[0], "disagreed") {
		t.Fatalf("after a disagreement: %+v", detail.Why)
	}
	var explain struct {
		Why struct {
			Sentence string `json:"sentence"`
		} `json:"why"`
	}
	if code := l.view.do("GET", "/api/v1/findings/"+itoa(id)+"/explain", nil, &explain); code != 200 || explain.Why.Sentence == "" {
		t.Fatalf("explain: %d %+v", code, explain)
	}
	var sum store.SecondCheckSummary
	if code := l.view.do("GET", "/api/v1/second-checks", nil, &sum); code != 200 || sum.Disagreed != 1 || len(sum.Recent) != 1 {
		t.Fatalf("second checks: %d %+v", code, sum)
	}
	var list struct {
		Items []store.Finding `json:"items"`
	}
	if code := l.view.do("GET", "/api/v1/findings?second_check=disagreed", nil, &list); code != 200 || len(list.Items) != 1 || list.Items[0].ID != id ||
		list.Items[0].SecondCheck != "disagreed" {
		t.Fatalf("filter: %d %+v", code, list)
	}
	if code := l.view.do("GET", "/api/v1/findings?second_check=maybe", nil, nil); code != 400 {
		t.Errorf("bad filter: %d", code)
	}
}

// Upload limits on /ingest and /sbom/import: the wire size, the size after
// gzip (a decompression bomb), and output with NUL bytes, which used to fail
// the whole ingest in PostgreSQL. The limits are exercised at a small scale
// (64 KiB on the wire, 256 KiB after gzip: the same code path) so the test
// stays fast under -race; the production values are pinned separately.
func TestIngestLimits(t *testing.T) {
	if api.MaxIngestBody != 64<<20 || api.MaxIngestInflow != 256<<20 {
		t.Fatalf("upload limits changed: %d on the wire, %d after gzip", api.MaxIngestBody, api.MaxIngestInflow)
	}
	e := newEnvWith(t, func(s *api.Server) { s.IngestLimits = [2]int64{64 << 10, 256 << 10} })
	tok, secret, err := e.st.CreateToken(tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace), "c", auth.RoleCollector, nil, 0, 0)
	if err != nil || tok == nil {
		t.Fatal(err)
	}
	big := bytes.Repeat([]byte(" "), 65<<10)
	var gz bytes.Buffer
	w := gzip.NewWriter(&gz)
	_, _ = w.Write(bytes.Repeat([]byte(" "), 300<<10)) // 300 KiB inflates past the limit from about 1 KiB
	_ = w.Close()
	for _, path := range []string{"/api/v1/ingest", "/api/v1/sbom/import?asset_name=x"} {
		if code := bearer(e, secret, "POST", path, big, nil); code < 400 || code >= 500 {
			t.Errorf("%s: body over the wire limit: %d", path, code)
		}
		if code := bearer(e, secret, "POST", path, gz.Bytes(), map[string]string{"Content-Encoding": "gzip"}); code < 400 || code >= 500 {
			t.Errorf("%s: gzip bomb: %d", path, code)
		}
	}
	// Within the limits, a valid batch still passes.
	if code := bearer(e, secret, "POST", "/api/v1/ingest", sampleBatch(), nil); code != 201 {
		t.Fatalf("a small batch: %d", code)
	}
	b := model.NewBatch(model.Collector{ID: "t", Method: "agent"},
		model.AssetRef{Kind: model.AssetHost, Name: "h\x00ost", Identifiers: []model.Identifier{{Scheme: "machine-id", Value: "nul\x00"}},
			Attributes: map[string]string{"git_url": "javascript:alert(1)"}})
	b.Observations = []model.Observation{{Purl: "pkg:deb/debian/bash@5.2", Confidence: model.ConfidenceConfirmed,
		Evidence: map[string]string{"note": "a\x00b"}}}
	raw, _ := json.Marshal(b)
	if code := bearer(e, secret, "POST", "/api/v1/ingest", raw, nil); code != 201 {
		t.Fatalf("batch with NUL bytes: %d", code)
	}
	assets, _, err := e.st.ListAssets(tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace), store.AssetFilter{Search: "host"})
	if err != nil || len(assets) != 1 || assets[0].Name != "host" {
		t.Fatalf("assets: %+v %v", assets, err)
	}
	if strings.Contains(fmt.Sprint(assets[0]), "javascript:") {
		t.Errorf("unsafe link stored: %+v", assets[0])
	}
}
