package metrics

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/http/httptest"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stackurity/stackurity/internal/health"
	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/tenant"
	"github.com/stackurity/stackurity/internal/testdb"
)

var (
	helpLine   = regexp.MustCompile(`^# HELP ([a-zA-Z_:][a-zA-Z0-9_:]*) .+$`)
	typeLine   = regexp.MustCompile(`^# TYPE ([a-zA-Z_:][a-zA-Z0-9_:]*) (counter|gauge|histogram)$`)
	sampleLine = regexp.MustCompile(`^([a-zA-Z_:][a-zA-Z0-9_:]*)(\{([a-zA-Z_][a-zA-Z0-9_]*="(\\.|[^"\\])*",?)*\})? (-?[0-9.eE+-]+|\+Inf|-Inf|NaN)$`)
)

// validate checks text exposition format 0.0.4: every sample belongs to the
// family declared just before it, and no family is declared twice.
func validate(t *testing.T, text string) map[string]string {
	t.Helper()
	types := map[string]string{}
	current := ""
	sc := bufio.NewScanner(strings.NewReader(text))
	for n := 1; sc.Scan(); n++ {
		line := sc.Text()
		switch {
		case helpLine.MatchString(line):
			name := helpLine.FindStringSubmatch(line)[1]
			if _, dup := types[name]; dup {
				t.Errorf("line %d: family %s declared twice", n, name)
			}
			current = name
		case typeLine.MatchString(line):
			m := typeLine.FindStringSubmatch(line)
			if m[1] != current {
				t.Errorf("line %d: TYPE for %s after HELP for %s", n, m[1], current)
			}
			types[m[1]] = m[2]
		case sampleLine.MatchString(line):
			name := sampleLine.FindStringSubmatch(line)[1]
			base := name
			if types[current] == "histogram" {
				for _, suf := range []string{"_bucket", "_sum", "_count"} {
					base = strings.TrimSuffix(base, suf)
				}
			}
			if base != current {
				t.Errorf("line %d: sample %s outside its family (current %s)", n, name, current)
			}
		default:
			t.Errorf("line %d: not valid exposition format: %q", n, line)
		}
	}
	if !strings.HasSuffix(text, "\n") {
		t.Error("output must end with a newline")
	}
	return types
}

func TestWriterEscaping(t *testing.T) {
	var b bytes.Buffer
	w := NewWriter(&b)
	w.Family("x_total", "counter", "Help with a \\ backslash\nand newline.")
	w.Sample("x_total", 3, "path", `a"b\c`+"\n")
	w.Sample("x_total", 0.5)
	want := "# HELP x_total Help with a \\\\ backslash\\nand newline.\n# TYPE x_total counter\n" +
		`x_total{path="a\"b\\c\n"} 3` + "\nx_total 0.5\n"
	if b.String() != want {
		t.Errorf("got\n%s\nwant\n%s", b.String(), want)
	}
	validate(t, b.String())
}

func TestHTTPHistogram(t *testing.T) {
	h := NewHTTP()
	h.Observe("GET", "/api/v1/assets/{id}", 200, 3*time.Millisecond)
	h.Observe("GET", "/api/v1/assets/{id}", 404, 300*time.Millisecond)
	h.Observe("GET", "/api/v1/assets/{id}", 0, 2*time.Minute) // nothing written: 200, beyond the last bucket
	h.Observe("BREW", "", 418, time.Millisecond)
	var b bytes.Buffer
	h.Write(NewWriter(&b))
	out := b.String()
	types := validate(t, out)
	if types["stackurity_http_request_duration_seconds"] != "histogram" || types["stackurity_http_requests_total"] != "counter" {
		t.Errorf("types = %v", types)
	}
	for _, want := range []string{
		`stackurity_http_requests_total{method="GET",route="/api/v1/assets/{id}",code="2xx"} 2`,
		`stackurity_http_requests_total{method="GET",route="/api/v1/assets/{id}",code="4xx"} 1`,
		`stackurity_http_requests_total{method="OTHER",route="unmatched",code="4xx"} 1`,
		`stackurity_http_request_duration_seconds_bucket{method="GET",route="/api/v1/assets/{id}",le="0.005"} 1`,
		`stackurity_http_request_duration_seconds_bucket{method="GET",route="/api/v1/assets/{id}",le="0.25"} 1`,
		`stackurity_http_request_duration_seconds_bucket{method="GET",route="/api/v1/assets/{id}",le="0.5"} 2`,
		`stackurity_http_request_duration_seconds_bucket{method="GET",route="/api/v1/assets/{id}",le="60"} 2`,
		`stackurity_http_request_duration_seconds_bucket{method="GET",route="/api/v1/assets/{id}",le="+Inf"} 3`,
		`stackurity_http_request_duration_seconds_count{method="GET",route="/api/v1/assets/{id}"} 3`,
	} {
		if !strings.Contains(out, want+"\n") {
			t.Errorf("missing %s in\n%s", want, out)
		}
	}
}

func TestHandlerOutput(t *testing.T) {
	st := store.New(testdb.New(t))
	sys := tenant.System(context.Background())
	exec := func(sql string) {
		t.Helper()
		if _, err := st.Pool.Exec(sys, sql); err != nil {
			t.Fatal(err)
		}
	}
	exec(`INSERT INTO feeds (name, kind, last_attempt, last_success, records) VALUES ('osv:npm', 'vulnerability', now(), now(), 42)`)
	exec(`INSERT INTO feeds (name, kind, last_attempt, last_error) VALUES ('kev', 'vulnerability', now(), 'timeout')`)
	exec(`INSERT INTO periodic_tasks (name, every, last_success_at, last_duration) VALUES ('alerts', '1 minute', now(), '2 seconds')`)
	exec(`INSERT INTO jobs (kind, payload) VALUES ('evaluate', '{}')`)
	exec(`INSERT INTO jobs (kind, payload, failed_at, attempts, max_attempts) VALUES ('feed.sync', '{}', now(), 5, 5)`)
	if _, err := st.Pool.Exec(tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace),
		`INSERT INTO jobs (kind, payload) VALUES ('integration.run', '{}')`); err != nil {
		t.Fatal(err)
	}
	// A webhook that failed its last send: one delivery retrying, one that
	// ran out of attempts, one overdue and one sent.
	wsCtx := tenant.WithWorkspace(context.Background(), tenant.DefaultWorkspace)
	for _, sql := range []string{
		`INSERT INTO channels (kind, name, config, last_error) VALUES ('webhook', 'hook', '{}', 'HTTP 503')`,
		`INSERT INTO deliveries (channel_id, event, dedupe_key, payload, attempts, last_error, next_attempt)
			SELECT id, 'opened', 'a', '{}', 2, 'HTTP 503', now() + interval '1 minute' FROM channels`,
		`INSERT INTO deliveries (channel_id, event, dedupe_key, payload, attempts, last_error, status, failed_at)
			SELECT id, 'opened', 'b', '{}', 8, 'HTTP 503', 'failed', now() FROM channels`,
		`INSERT INTO deliveries (channel_id, event, dedupe_key, payload, next_attempt)
			SELECT id, 'opened', 'c', '{}', now() - interval '20 minutes' FROM channels`,
		`INSERT INTO deliveries (channel_id, event, dedupe_key, payload, status, sent_at)
			SELECT id, 'opened', 'd', '{}', 'sent', now() FROM channels`,
	} {
		if _, err := st.Pool.Exec(wsCtx, sql); err != nil {
			t.Fatal(err)
		}
	}

	httpm := NewHTTP()
	httpm.Observe("GET", "/healthz", 200, time.Millisecond)
	h := &Handler{Store: st, Health: &health.Checker{Store: st, FeedsEnabled: true}, HTTP: httpm,
		Log: slog.New(slog.NewTextHandler(io.Discard, nil)), Version: "1.2.3", Edition: "community", Started: time.Unix(1700000000, 0)}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/metrics", nil))
	if rec.Code != 200 || rec.Header().Get("Content-Type") != ContentType {
		t.Fatalf("status %d, type %q", rec.Code, rec.Header().Get("Content-Type"))
	}
	out := rec.Body.String()
	validate(t, out)
	for _, want := range []string{
		`stackurity_build_info{version="1.2.3",edition="community",go_version="`,
		"stackurity_database_up 1\n",
		"stackurity_scrape_errors 0\n",
		`stackurity_jobs{kind="evaluate",state="queued"} 1`,
		`stackurity_jobs{kind="integration.run",state="queued"} 1`,
		`stackurity_jobs{kind="feed.sync",state="failed"} 1`,
		`stackurity_periodic_task_interval_seconds{task="alerts"} 60`,
		`stackurity_periodic_task_consecutive_failures{task="alerts"} 0`,
		`stackurity_periodic_task_last_duration_seconds{task="alerts"} 2`,
		`stackurity_feed_stale{feed="osv:npm",kind="vulnerability"} 0`,
		`stackurity_feed_failing{feed="kev",kind="vulnerability"} 1`,
		`stackurity_feed_last_success_timestamp_seconds{feed="kev",kind="vulnerability"} 0`,
		`stackurity_feed_records{feed="osv:npm",kind="vulnerability"} 42`,
		"stackurity_assets_stale 0\n",
		`stackurity_notification_deliveries{kind="webhook",state="retrying"} 1`,
		`stackurity_notification_deliveries{kind="webhook",state="failed"} 1`,
		`stackurity_notification_deliveries{kind="webhook",state="pending"} 1`,
		`stackurity_notification_channels_failing{kind="webhook"} 1`,
		`stackurity_health_problems{severity="critical"} 1`,
		`stackurity_http_requests_total{method="GET",route="/healthz",code="2xx"} 1`,
		`stackurity_db_pool_connections{state="idle"}`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %s", want)
		}
	}
	if strings.Contains(out, `state="sent"`) {
		t.Error("sent deliveries are not counted")
	}
	if age := sampleValue(t, out, "stackurity_notification_oldest_due_age_seconds"); age < 20*60 || age > 30*60 {
		t.Errorf("oldest due notification age = %v, want about 20 minutes", age)
	}
	if strings.Contains(out, "workspace=") || strings.Contains(out, "asset=") {
		t.Error("workspace and asset ids must not be labels")
	}

	// With the database gone the scrape still answers, saying so.
	st.Pool.Close()
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/metrics", nil))
	out = rec.Body.String()
	validate(t, out)
	if rec.Code != 200 || !strings.Contains(out, "stackurity_database_up 0\n") || !strings.Contains(out, "stackurity_scrape_errors 1\n") {
		t.Errorf("database down: %d\n%s", rec.Code, out)
	}
}

// sampleValue returns the value of an unlabelled series.
func sampleValue(t *testing.T, text, name string) float64 {
	t.Helper()
	for _, line := range strings.Split(text, "\n") {
		if v, ok := strings.CutPrefix(line, name+" "); ok {
			f, err := strconv.ParseFloat(v, 64)
			if err != nil {
				t.Fatal(err)
			}
			return f
		}
	}
	t.Fatalf("no %s in the output", name)
	return 0
}
