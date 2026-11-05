package diag

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/stackurity/stackurity/internal/auth"
	"github.com/stackurity/stackurity/internal/intel"
	"github.com/stackurity/stackurity/internal/model"
	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/tenant"
	"github.com/stackurity/stackurity/internal/testdb"
)

// The support bundle keeps what support needs and nothing else: secret
// values planted in the environment (including a variable this version
// does not know), in stored settings, in errors, and the installation's
// names, addresses, users and inventory never appear in it.
func TestBundleRedacts(t *testing.T) {
	ctx := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)
	sys := tenant.System(ctx)
	st := store.New(testdb.New(t))

	environ := []string{
		"STACKURITY_DATABASE_URL=postgres://stkadmin:Pa55w0rd-db-9f3k@db1.corp.internal:5432/stackurity",
		"STACKURITY_SECRET_KEY=AbCdEf0123456789xyzQRSbase64key",
		"STACKURITY_SMTP_PASSWORD=smtp-hunter2-8813",
		"STACKURITY_NVD_API_KEY=nvd-5f1e2d3c-4b5a-6978-8a9b-0c1d2e3f4a5b",
		"STACKURITY_SECRET_ACMEJIRA=jira-tok-ABCDEF123456",
		"STACKURITY_BRAND_NEW_WEBHOOK_TOKEN=xoxb-unknown-77777-SECRET", // a setting this version does not know
		"STACKURITY_BASE_URL=https://stackurity.acmecorp.example",
		"STACKURITY_OSV_URL=https://mirror-user:mirror-pw-4242@osvmirror.acmecorp.example/osv",
		"STACKURITY_LICENSE=garbage-licence-key-0000111122223333",
		"STACKURITY_STALE_AFTER=48h; curl evil.example", // allow-listed name, but not the shape of a duration
		"STACKURITY_LOG_LEVEL=debug",
		"GOMEMLIMIT=1100MiB",
		"HOME=/Users/secretuser",
	}
	secrets := []string{"Pa55w0rd-db-9f3k", "stkadmin", "db1.corp.internal", "AbCdEf0123456789xyzQRSbase64key", "smtp-hunter2-8813",
		"nvd-5f1e2d3c", "jira-tok-ABCDEF123456", "ACMEJIRA", "xoxb-unknown-77777-SECRET", "acmecorp", "mirror-pw-4242", "mirror-user",
		"garbage-licence-key", "evil.example", "secretuser",
		// planted in the database below
		"whsec_live_9876543210abcdef", "acme-prod-cluster", "web-01", "lodash", "alice", "10.20.30.40", "feedpw", "tok_live_ABCDEF0123456789XYZ",
		"SECRETPATH", "payload-secret-xyz", "/home/acme", "/var/lib/acmedata", "ops@", "fe80::1ff:fe23:4567:890a"}

	// An asset, a user, a channel and settings: none of them may show.
	b := model.NewBatch(model.Collector{ID: "a", Method: "agent"}, model.AssetRef{Kind: model.AssetHost, Name: "web-01.corp.acmecorp.example",
		Environment: "acme-prod-cluster", Identifiers: []model.Identifier{{Scheme: "hostname", Value: "web-01.corp.acmecorp.example"}}})
	b.Observations = []model.Observation{{Purl: "pkg:npm/lodash@4.17.20", Confidence: model.ConfidenceConfirmed}}
	if _, err := st.Ingest(ctx, b, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := st.CreateUser(ctx, "alice@acmecorp.example", "Alice", auth.RoleAdmin, "A long enough password 1!"); err != nil {
		t.Fatal(err)
	}
	cfgJSON, _ := json.Marshal(map[string]string{"url": "https://hooks.acmecorp.example/T000/SECRETPATH"})
	if _, err := st.CreateChannel(ctx, "webhook", "acme hook", cfgJSON, "env:STACKURITY_SECRET_ACMEJIRA"); err != nil {
		t.Fatal(err)
	}
	if err := st.SetFixGrouping(ctx, store.FixGroupingAsset); err != nil {
		t.Fatal(err)
	}
	for k, v := range map[string]string{"risk_policy": `{"production_environments": ["acme-prod-cluster"]}`,
		"webhook_signing": `{"secret": "whsec_live_9876543210abcdef"}`} {
		if _, err := st.Pool.Exec(ctx, `INSERT INTO settings (key, value) VALUES ($1, $2)`, k, v); err != nil {
			t.Fatal(err)
		}
	}
	// Errors that quote addresses, credentials, an email address, paths
	// and a token.
	feed(t, st, "osv:npm", "vulnerability", time.Hour, 6*time.Hour, 50*time.Hour)
	if _, err := st.Pool.Exec(sys, `UPDATE feeds SET last_error = $1 WHERE name = 'osv:npm'`,
		"GET https://feeduser:feedpw@osvmirror.acmecorp.example/osv/npm/all.zip from 10.20.30.40 and [fe80::1ff:fe23:4567:890a]: 401; "+
			"ask ops@acmecorp.example; token=tok_live_ABCDEF0123456789XYZ; wrote /home/acme/stackurity/work/x"); err != nil {
		t.Fatal(err)
	}
	if err := st.RegisterPeriodic(sys, "prune", time.Hour); err != nil {
		t.Fatal(err)
	}
	if _, err := st.ClaimPeriodic(sys, "prune", "web-01.corp.acmecorp.example:4242", time.Hour, time.Minute); err != nil {
		t.Fatal(err)
	}
	if err := st.FinishPeriodic(sys, "prune", "web-01.corp.acmecorp.example:4242",
		errors.New("open /var/lib/acmedata/x: no space left on device (db1.corp.internal)")); err != nil {
		t.Fatal(err)
	}
	id, err := st.Enqueue(ctx, "integration.run", map[string]string{"token": "payload-secret-xyz"}, "", time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool.Exec(sys, `UPDATE jobs SET failed_at = now(), attempts = 5, last_error = 'clone https://x:payload-secret-xyz@git.acmecorp.example/r.git failed' WHERE id = $1`, id); err != nil {
		t.Fatal(err)
	}

	cfg := Config{Version: "test", Edition: "community", FeedsEnabled: true, Offline: true, Intel: intel.DefaultConfig(),
		LicenceKey: "garbage-licence-key-0000111122223333", LicenceFrom: "STACKURITY_LICENSE",
		Memory: func() MemoryInfo { return MemoryInfo{Limit: 2 << 30, LimitFrom: "container limit"} }}
	cfg.Intel.OSVBaseURL = "https://mirror-user:mirror-pw-4242@osvmirror.acmecorp.example/osv"
	rep := Doctor(ctx, st, nil, cfg)
	bundle := BuildBundle(ctx, BundleInput{Config: cfg, Store: st, Report: rep, Environ: environ})
	raw, err := bundle.JSON(environ, cfg.Intel)
	if err != nil {
		t.Fatal(err)
	}
	out := string(raw)
	for _, s := range secrets {
		if strings.Contains(strings.ToLower(out), strings.ToLower(s)) {
			t.Errorf("the bundle contains %q", s)
		}
	}
	if t.Failed() {
		t.Log(out)
	}

	// What support needs is there.
	var got Bundle
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	env := map[string]string{}
	for _, e := range got.Environment {
		env[e.Name] = e.Value
	}
	for name, v := range map[string]string{"STACKURITY_LOG_LEVEL": "debug", "GOMEMLIMIT": "1100MiB", "STACKURITY_STALE_AFTER": Redacted,
		"STACKURITY_BRAND_NEW_WEBHOOK_TOKEN": Redacted, "STACKURITY_DATABASE_URL": Redacted} {
		if env[name] != v {
			t.Errorf("environment %s = %q, want %q", name, env[name], v)
		}
	}
	if _, ok := env["HOME"]; ok {
		t.Error("an unrelated variable is listed")
	}
	settings := map[string]string{}
	for _, s := range got.Settings {
		settings[s.Key] = s.Value
	}
	if settings["fix_grouping"] != "asset" || settings["risk_policy"] != Redacted || settings["webhook_signing"] != Redacted {
		t.Errorf("settings = %v", settings)
	}
	if got.Migrations == nil || len(got.Migrations.Applied) == 0 || len(got.Migrations.Pending) != 0 {
		t.Errorf("migrations = %+v", got.Migrations)
	}
	if len(got.Feeds) != 1 || got.Feeds[0].Source != "mirror" || !got.Feeds[0].Stale || !strings.Contains(got.Feeds[0].LastError, "<url>") {
		t.Errorf("feeds = %+v", got.Feeds)
	}
	if got.Jobs == nil || len(got.Jobs.RecentFailures) != 1 || got.Licence == nil || got.Licence.Invalid == "" || len(got.Tasks) != 1 {
		t.Errorf("jobs %+v, licence %+v, tasks %+v", got.Jobs, got.Licence, got.Tasks)
	}
	if got.Counts == nil || got.Counts.Instance.Users != 1 || len(got.Counts.AssetsByKind) != 1 || len(got.Doctor) == 0 {
		t.Errorf("counts = %+v", got.Counts)
	}
}

func TestRedactorText(t *testing.T) {
	r := NewRedactor([]string{"STACKURITY_SMTP_PASSWORD=hunter2hunter2"}, intel.DefaultConfig())
	for in, want := range map[string]string{
		"fetch https://storage.googleapis.com/osv-vulnerabilities/npm/all.zip: 503": "fetch https://storage.googleapis.com: 503",
		"dial tcp 192.168.1.20:5432: connection refused":                            "dial tcp <ip>: connection refused",
		"smtp auth as hunter2hunter2 failed":                                        "smtp auth as <redacted> failed",
		"Authorization: Bearer abc.def":                                             "Authorization: <redacted>",
		"the sync started 2026-10-29 14:05:33 UTC was interrupted":                  "the sync started 2026-10-29 14:05:33 UTC was interrupted",
		"lookup mail.example.org: no such host":                                     "lookup <host>: no such host",
		"Intelligence feed osv:PyPI is stale: last synced 2d ago":                   "Intelligence feed osv:PyPI is stale: last synced 2d ago",
		"the server log for feed.sync":                                              "the server log for feed.sync",
	} {
		if got := r.Text(in); got != want {
			t.Errorf("%q -> %q, want %q", in, got, want)
		}
	}
}
