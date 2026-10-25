package store_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/stackurity/stackurity/internal/model"
	"github.com/stackurity/stackurity/internal/osv"
	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/tenant"
	"github.com/stackurity/stackurity/internal/testdb"
)

func searchFixture(t *testing.T) (context.Context, *store.Store, int64) {
	t.Helper()
	ctx := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)
	s := store.New(testdb.New(t))
	ingest := func(kind model.AssetKind, name string, ids []model.Identifier, attrs map[string]string, purls ...string) int64 {
		t.Helper()
		b := model.NewBatch(model.Collector{ID: "test", Version: "1", Method: "agent"},
			model.AssetRef{Kind: kind, Name: name, Identifiers: ids, Attributes: attrs})
		for _, p := range purls {
			b.Observations = append(b.Observations, model.Observation{Purl: p, Confidence: model.ConfidenceConfirmed})
		}
		b.Complete = true
		if err := b.Validate(); err != nil {
			t.Fatal(err)
		}
		r, err := s.Ingest(ctx, b, 0)
		if err != nil {
			t.Fatal(err)
		}
		return r.AssetID
	}
	web := ingest(model.AssetHost, "web-1", []model.Identifier{{Scheme: "machine-id", Value: "4c4c4544-0042"}, {Scheme: "hostname", Value: "web-1.prod.example.com"}}, nil,
		"pkg:npm/lodash@4.17.20", "pkg:npm/lodash-es@4.17.21", "pkg:deb/ubuntu/openssl@3.0.2-0ubuntu1.10?distro=ubuntu-22.04",
		"pkg:npm/%40babel/core@7.0.0", "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1")
	ingest(model.AssetHost, "web-2", []model.Identifier{{Scheme: "machine-id", Value: "m2"}}, nil, "pkg:npm/lodash@4.17.21")
	ingest(model.AssetImage, "ghcr.io/acme/shop:1.4", []model.Identifier{{Scheme: "image-ref", Value: "ghcr.io/acme/shop:1.4"}},
		map[string]string{"digest": "sha256:9f86d081884c7d659a2feaa0c55ad015"}, "pkg:npm/express@4.18.2")
	ingest(model.AssetHost, "a_b-host", []model.Identifier{{Scheme: "machine-id", Value: "m3"}}, nil)
	ingest(model.AssetHost, "axb-host", []model.Identifier{{Scheme: "machine-id", Value: "m4"}}, nil)

	team, err := s.CreateTeam(ctx, "Platform", "platform@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.UpdateAsset(ctx, web, store.AssetUpdate{OwnerTeamID: store.Nullable[int64]{Set: true, Value: &team.ID}}); err != nil {
		t.Fatal(err)
	}

	// Advisories are public data: one affecting lodash here, one affecting nothing.
	if err := s.EnsureFeed(ctx, "osv:npm", "vulnerability", time.Hour, 6*time.Hour); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	if _, err := s.UpsertAdvisories(ctx, "osv:npm", []*osv.Vulnerability{
		{ID: "GHSA-35jh-r3h4-6jhm", Aliases: []string{"CVE-2021-23337"}, Summary: "Command injection in lodash", Modified: now},
		{ID: "DSA-5555-1", Aliases: []string{"CVE-2023-99999"}, Summary: "openssh security update", Modified: now},
	}); err != nil {
		t.Fatal(err)
	}
	rows, _, err := s.ListInventory(ctx, store.InventoryFilter{AssetID: web, Search: "lodash"})
	if err != nil {
		t.Fatal(err)
	}
	var lodash store.InventoryRow
	for _, r := range rows {
		if r.Name == "lodash" {
			lodash = r
		}
	}
	if _, _, err := s.SyncFindings(ctx, []string{"vulnerability"}, []int64{lodash.ID}, []store.FindingInput{{
		Kind: "vulnerability", Key: "CVE-2021-23337", InventoryID: lodash.ID, AssetID: web, ComponentID: lodash.ComponentID,
		Verification: "confirmed", Severity: "high", Title: "Command injection in lodash", Sources: []string{"GHSA-35jh-r3h4-6jhm"},
		Evidence: map[string]any{}}}); err != nil {
		t.Fatal(err)
	}
	return ctx, s, web
}

func TestSearchVulnerabilities(t *testing.T) {
	ctx, s, web := searchFixture(t)

	// The CVE, an alias of it in any case, and the GHSA id all land on the finding.
	for _, q := range []string{"CVE-2021-23337", "cve-2021-23337", "GHSA-35jh-r3h4-6jhm", "ghsa-35JH-r3h4-6jhm"} {
		res, err := s.Search(ctx, q, 10)
		if err != nil {
			t.Fatal(err)
		}
		if len(res.Vulnerabilities) != 1 {
			t.Fatalf("%s: %+v", q, res.Vulnerabilities)
		}
		v := res.Vulnerabilities[0]
		if v.Key != "CVE-2021-23337" || v.Rank != store.RankExact || v.OpenFindings != 1 || v.AffectedAssets != 1 ||
			len(v.Assets) != 1 || v.Assets[0].ID != web || len(v.Components) != 1 || v.Components[0] != "lodash" ||
			v.Severity != "high" || v.Advisory == nil || v.Advisory.IDs[0] != "GHSA-35jh-r3h4-6jhm" {
			t.Errorf("%s: %+v", q, v)
		}
	}

	// A distro advisory that affects nothing here is still found, with no assets.
	res, err := s.Search(ctx, "dsa-5555-1", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Vulnerabilities) != 1 {
		t.Fatalf("dsa: %+v", res.Vulnerabilities)
	}
	if v := res.Vulnerabilities[0]; v.Key != "CVE-2023-99999" || v.Kind != "" || v.OpenFindings != 0 || len(v.Assets) != 0 ||
		v.Advisory == nil || v.Advisory.Summary != "openssh security update" {
		t.Errorf("dsa: %+v", v)
	}

	// Part of a key finds it as a lower-ranked match.
	res, _ = s.Search(ctx, "2021-233", 10)
	if len(res.Vulnerabilities) != 1 || res.Vulnerabilities[0].Rank == store.RankExact {
		t.Errorf("partial key: %+v", res.Vulnerabilities)
	}

	// Plain words are not looked up as advisory ids.
	res, _ = s.Search(ctx, "lodash", 10)
	if len(res.Vulnerabilities) != 0 {
		t.Errorf("word matched vulnerabilities: %+v", res.Vulnerabilities)
	}
}

func TestSearchComponents(t *testing.T) {
	ctx, s, web := searchFixture(t)

	res, err := s.Search(ctx, "lodash", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Components) != 2 || res.Components[0].Name != "lodash" || res.Components[0].Rank != store.RankExact ||
		res.Components[0].AssetCount != 2 || res.Components[1].Name != "lodash-es" || res.Components[1].Rank != store.RankPrefix {
		t.Fatalf("lodash: %+v", res.Components)
	}
	if c := res.Components[0]; len(c.Versions) != 2 || c.OpenFindings != 1 || len(c.Assets) != 2 {
		t.Errorf("lodash details: %+v", c)
	}

	// A version narrows the assets: name@version, "name version" and a purl.
	for _, q := range []string{"lodash@4.17.20", "lodash 4.17.20", "pkg:npm/lodash@4.17.20"} {
		res, err := s.Search(ctx, q, 10)
		if err != nil {
			t.Fatal(err)
		}
		if len(res.Components) == 0 {
			t.Fatalf("%s: no components", q)
		}
		c := res.Components[0]
		if c.Name != "lodash" || c.Version != "4.17.20" || c.VersionAssets != 1 || len(c.Assets) != 1 || c.Assets[0].ID != web ||
			c.Assets[0].Version != "4.17.20" || c.AssetCount != 2 {
			t.Errorf("%s: %+v", q, c)
		}
	}
	// A version nobody has keeps the component but no assets.
	res, _ = s.Search(ctx, "lodash@1.0.0", 10)
	if len(res.Components) == 0 || res.Components[0].VersionAssets != 0 || len(res.Components[0].Assets) != 0 {
		t.Errorf("missing version: %+v", res.Components)
	}

	// A distro build matches the upstream version; a longer number does not.
	res, _ = s.Search(ctx, "openssl 3.0.2", 10)
	if len(res.Components) != 1 || res.Components[0].VersionAssets != 1 || res.Components[0].Assets[0].Version != "3.0.2-0ubuntu1.10" {
		t.Errorf("openssl 3.0.2: %+v", res.Components)
	}
	res, _ = s.Search(ctx, "openssl 3.0.20", 10)
	if len(res.Components) != 1 || res.Components[0].VersionAssets != 0 {
		t.Errorf("openssl 3.0.20: %+v", res.Components)
	}

	// Namespaced names: npm scopes and Maven coordinates.
	for q, want := range map[string]string{"@babel/core": "core", "org.apache.logging.log4j:log4j-core": "log4j-core",
		"pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1": "log4j-core"} {
		res, _ := s.Search(ctx, q, 10)
		if len(res.Components) != 1 || res.Components[0].Name != want || res.Components[0].Rank != store.RankExact {
			t.Errorf("%s: %+v", q, res.Components)
		}
	}
	// A purl of another type finds nothing.
	res, _ = s.Search(ctx, "pkg:pypi/lodash", 10)
	if len(res.Components) != 0 {
		t.Errorf("type filter: %+v", res.Components)
	}
}

func TestSearchAssetsAndTeams(t *testing.T) {
	ctx, s, web := searchFixture(t)

	for q, scheme := range map[string]string{"web-1": "", "web-1.prod.example.com": "hostname", "4c4c4544-0042": "machine-id"} {
		res, err := s.Search(ctx, q, 10)
		if err != nil {
			t.Fatal(err)
		}
		if len(res.Assets) == 0 || res.Assets[0].ID != web || res.Assets[0].Rank != store.RankExact ||
			(scheme != "" && res.Assets[0].MatchScheme != scheme) || res.Assets[0].OwnerTeam != "Platform" || res.Assets[0].OpenFindings != 1 {
			t.Errorf("%s: %+v", q, res.Assets)
		}
	}
	// "web" finds both hosts by prefix, in name order.
	res, _ := s.Search(ctx, "WEB", 10)
	if len(res.Assets) != 2 || res.Assets[0].Name != "web-1" || res.Assets[1].Name != "web-2" || res.Assets[0].Rank != store.RankPrefix {
		t.Errorf("web: %+v", res.Assets)
	}
	// Image references and digests.
	for _, q := range []string{"ghcr.io/acme/shop", "sha256:9f86d081884c7d659a2feaa0c55ad015", "9f86d081"} {
		res, _ := s.Search(ctx, q, 10)
		if len(res.Assets) != 1 || res.Assets[0].Kind != "image" {
			t.Errorf("%s: %+v", q, res.Assets)
		}
	}
	res, _ = s.Search(ctx, "sha256:9f86d081884c7d659a2feaa0c55ad015", 10)
	if len(res.Assets) != 1 || res.Assets[0].MatchScheme != "digest" || res.Assets[0].Rank != store.RankExact {
		t.Errorf("digest: %+v", res.Assets)
	}

	// Teams by name or email, with what they own.
	for _, q := range []string{"platform", "platform@example.com"} {
		res, _ := s.Search(ctx, q, 10)
		if len(res.Teams) != 1 || res.Teams[0].Name != "Platform" || res.Teams[0].Rank != store.RankExact ||
			res.Teams[0].AssetCount != 1 || res.Teams[0].OpenFindings != 1 {
			t.Errorf("%s: %+v", q, res.Teams)
		}
	}

	// The limit applies per group and says when there is more.
	res, _ = s.Search(ctx, "host", 1)
	if len(res.Assets) != 1 || !res.More["assets"] {
		t.Errorf("limit: %+v %v", res.Assets, res.More)
	}
}

func TestSearchEscapesWildcards(t *testing.T) {
	ctx, s, _ := searchFixture(t)
	res, err := s.Search(ctx, "a_b", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Assets) != 1 || res.Assets[0].Name != "a_b-host" {
		t.Errorf("_ matched as a wildcard: %+v", res.Assets)
	}
	for _, q := range []string{"%%", "%host", `\%`, "__"} {
		res, err := s.Search(ctx, q, 10)
		if err != nil {
			t.Fatal(err)
		}
		if len(res.Assets)+len(res.Components)+len(res.Teams)+len(res.Vulnerabilities) != 0 {
			t.Errorf("%q matched: %+v", q, res)
		}
	}
}

func TestSearchValidation(t *testing.T) {
	ctx, s, _ := searchFixture(t)
	for _, q := range []string{"", " ", "a", " a ", strings.Repeat("a", 201), "ab\x00c"} {
		if _, err := s.Search(ctx, q, 10); !errors.Is(err, store.ErrInvalid) {
			t.Errorf("%q: %v", q, err)
		}
	}
	if q, err := store.NormalizeSearch("  lodash \n"); err != nil || q != "lodash" {
		t.Errorf("normalize: %q %v", q, err)
	}
	// Outside a workspace (system scope or none) search refuses to run.
	for _, c := range []context.Context{context.Background(), tenant.System(context.Background())} {
		if _, err := s.Search(c, "web-1", 10); !errors.Is(err, store.ErrInvalid) {
			t.Errorf("search outside a workspace: %v", err)
		}
	}
}

func TestSearchFindingTitles(t *testing.T) {
	ctx, s, web := searchFixture(t)

	res, err := s.Search(ctx, "command injection", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("title: %+v", res.Findings)
	}
	if f := res.Findings[0]; f.Key != "CVE-2021-23337" || f.Title != "Command injection in lodash" || f.Rank != store.RankPrefix ||
		f.OpenFindings != 1 || f.AffectedAssets != 1 || len(f.Assets) != 1 || f.Assets[0].ID != web || f.Severity != "high" {
		t.Errorf("title: %+v", f)
	}
	// Two characters are too few for titles; resolved findings never match.
	if res, _ := s.Search(ctx, "in", 10); len(res.Findings) != 0 {
		t.Errorf("two-character title search: %+v", res.Findings)
	}
	if _, err := s.Pool.Exec(ctx, `UPDATE findings SET status = 'resolved'`); err != nil {
		t.Fatal(err)
	}
	if res, _ := s.Search(ctx, "injection", 10); len(res.Findings) != 0 {
		t.Errorf("resolved finding matched: %+v", res.Findings)
	}
}

// Members are searched only when asked, only within the workspace, with
// their role there and the open findings assigned to them.
func TestSearchMembers(t *testing.T) {
	ctx, s, _ := searchFixture(t)
	dana, err := s.CreateUser(ctx, "dana@example.com", "Dana Scully", "engineer", "correct horse battery")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Pool.Exec(ctx, `UPDATE findings SET assignee_user_id = $1`, dana.ID); err != nil {
		t.Fatal(err)
	}
	// An account in another workspace only.
	if _, _, err := s.CreateWorkspace(context.Background(), "Other", "other", "dana.other@example.com", "Dana Other", "correct horse battery"); err != nil {
		t.Fatal(err)
	}

	if res, _ := s.Search(ctx, "dana", 10); len(res.Members) != 0 || res.More["members"] {
		t.Errorf("members without asking: %+v", res.Members)
	}
	for _, q := range []string{"dana", "Scully", "DANA@EXAMPLE.COM", "example.com"} {
		res, err := s.SearchWith(ctx, q, store.SearchOptions{Members: true})
		if err != nil {
			t.Fatal(err)
		}
		if len(res.Members) != 1 {
			t.Fatalf("%s: %+v", q, res.Members)
		}
		if m := res.Members[0]; m.ID != dana.ID || m.Role != "engineer" || m.OpenAssigned != 1 || m.Disabled {
			t.Errorf("%s: %+v", q, m)
		}
	}
	if res, _ := s.SearchWith(ctx, "dana.other", store.SearchOptions{Members: true}); len(res.Members) != 0 {
		t.Errorf("a non-member was found: %+v", res.Members)
	}
}
