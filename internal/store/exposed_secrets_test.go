package store_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/stackurity/stackurity/internal/model"
	"github.com/stackurity/stackurity/internal/store"
)

func fp(c byte) string { return strings.Repeat(string(c), 64) }

func repoBatch(url string, at time.Time, complete bool, fs ...model.SecretFinding) *model.ObservationBatch {
	b := model.NewBatch(model.Collector{ID: "lockfile-scanner", Version: "test", Method: "repository"}, model.AssetRef{
		Kind: model.AssetRepository, Name: url, Identifiers: []model.Identifier{{Scheme: "git-url", Value: url}}})
	b.ObservedAt = at
	b.Complete = true
	b.Observations = []model.Observation{}
	b.Secrets = &model.SecretList{Findings: fs, Complete: complete}
	return b
}

func secret(rule, loc string, fingerprint string, sev string) model.SecretFinding {
	return model.SecretFinding{Rule: rule, Title: rule, Location: loc, Line: 3, Fingerprint: fingerprint, Preview: "ghp_…abcd",
		Severity: sev, Exposure: "repository"}
}

func ingestSecrets(t *testing.T, s *store.Store, ctx context.Context, b *model.ObservationBatch) int64 {
	t.Helper()
	if err := b.Validate(); err != nil {
		t.Fatal(err)
	}
	r, err := s.Ingest(ctx, b, 0)
	if err != nil {
		t.Fatal(err)
	}
	return r.AssetID
}

func openSecrets(t *testing.T, s *store.Store, ctx context.Context, status string) map[string]store.ExposedSecret {
	t.Helper()
	list, total, err := s.ListExposedSecrets(ctx, store.ExposedSecretFilter{Status: status})
	if err != nil {
		t.Fatal(err)
	}
	if int(total) != len(list) {
		t.Fatalf("total %d, listed %d", total, len(list))
	}
	out := map[string]store.ExposedSecret{}
	for _, e := range list {
		out[e.AssetName+" "+e.Location] = e
	}
	return out
}

// A scan's secrets are stored per asset and place; the same key in two
// repositories is one secret in two places; a complete scan that no longer
// finds one resolves it, an incomplete one does not; ignoring applies to
// every place of the secret and survives later scans.
func TestExposedSecrets(t *testing.T) {
	ctx, s := loopStore(t)
	t0 := time.Now().Add(-time.Hour).UTC().Truncate(time.Second)
	shop := ingestSecrets(t, s, ctx, repoBatch("https://git.example.com/shop", t0, true,
		secret("github-token", "deploy.sh", fp('a'), "high"),
		secret("stripe-secret-key", "src/pay.js", fp('b'), "high"),
		secret("env-secret", ".env.example", fp('c'), "low")))
	ingestSecrets(t, s, ctx, repoBatch("https://git.example.com/blog", t0, true,
		secret("github-token", "ci/release.sh", fp('a'), "high")))

	got := openSecrets(t, s, ctx, "open")
	if len(got) != 4 {
		t.Fatalf("open: %v", got)
	}
	if e := got["https://git.example.com/shop deploy.sh"]; e.Places != 2 || e.Preview != "ghp_…abcd" || e.Line != 3 {
		t.Fatalf("shared key: %+v", e)
	}
	sum, err := s.SummarizeExposedSecrets(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if sum.Open != 4 || sum.Secrets != 3 || sum.Assets != 2 || sum.BySeverity["high"] != 3 || sum.BySeverity["low"] != 1 {
		t.Fatalf("summary: %+v", sum)
	}

	// Rescan of shop: the Stripe key was removed, the scan is incomplete.
	ingestSecrets(t, s, ctx, repoBatch("https://git.example.com/shop", t0.Add(time.Minute), false,
		secret("github-token", "deploy.sh", fp('a'), "high")))
	if n := len(openSecrets(t, s, ctx, "open")); n != 4 {
		t.Fatalf("an incomplete scan resolved something: %d open", n)
	}
	// Complete this time: the Stripe key and the example file are gone.
	ingestSecrets(t, s, ctx, repoBatch("https://git.example.com/shop", t0.Add(2*time.Minute), true,
		secret("github-token", "deploy.sh", fp('a'), "high")))
	got = openSecrets(t, s, ctx, "open")
	if len(got) != 2 {
		t.Fatalf("after removal: %v", got)
	}
	if r := openSecrets(t, s, ctx, "resolved"); len(r) != 2 || r["https://git.example.com/shop src/pay.js"].ResolvedAt == nil {
		t.Fatalf("resolved: %v", r)
	}

	// The Stripe key comes back: the same row opens again.
	ingestSecrets(t, s, ctx, repoBatch("https://git.example.com/shop", t0.Add(3*time.Minute), true,
		secret("github-token", "deploy.sh", fp('a'), "high"), secret("stripe-secret-key", "src/pay.js", fp('b'), "high")))
	if e, ok := openSecrets(t, s, ctx, "open")["https://git.example.com/shop src/pay.js"]; !ok || e.ResolvedAt != nil || !e.FirstSeen.Equal(t0) {
		t.Fatalf("reopened: %+v", e)
	}

	// Ignoring the GitHub token ignores both places, and a scan that still
	// finds it keeps it ignored.
	u, err := s.CreateUser(ctx, "sec@example.com", "Sec", "security", "correct horse battery")
	if err != nil {
		t.Fatal(err)
	}
	id := openSecrets(t, s, ctx, "open")["https://git.example.com/shop deploy.sh"].ID
	if n, err := s.IgnoreExposedSecret(ctx, id, u.ID, "revoked on GitHub"); err != nil || n != 2 {
		t.Fatalf("ignore: %d %v", n, err)
	}
	ingestSecrets(t, s, ctx, repoBatch("https://git.example.com/shop", t0.Add(4*time.Minute), true,
		secret("github-token", "deploy.sh", fp('a'), "high"), secret("stripe-secret-key", "src/pay.js", fp('b'), "high")))
	ign := openSecrets(t, s, ctx, "ignored")
	if len(ign) != 2 || ign["https://git.example.com/blog ci/release.sh"].IgnoreReason != "revoked on GitHub" ||
		ign["https://git.example.com/blog ci/release.sh"].IgnoredBy != "sec@example.com" {
		t.Fatalf("ignored: %v", ign)
	}
	if _, err := s.IgnoreExposedSecret(ctx, id, u.ID, "again"); err == nil {
		t.Fatal("ignoring an ignored secret must fail")
	}
	if n, err := s.ReopenExposedSecret(ctx, id); err != nil || n != 2 {
		t.Fatalf("reopen: %d %v", n, err)
	}
	if _, err := s.ReopenExposedSecret(ctx, 999999); err != store.ErrNotFound {
		t.Fatalf("missing: %v", err)
	}

	// Filters.
	list, _, err := s.ListExposedSecrets(ctx, store.ExposedSecretFilter{AssetID: shop})
	if err != nil || len(list) != 2 {
		t.Fatalf("by asset: %v %v", list, err)
	}
	if list[0].AssetID != shop {
		t.Fatal("asset filter")
	}
}
