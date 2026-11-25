package threats

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestEmbedded(t *testing.T) {
	c := Embedded()
	if c.Schema != Schema || c.Serial < 1 || len(c.Threats) == 0 {
		t.Fatalf("embedded catalogue: %+v", c)
	}
	a, ok := c.Find("  ScopeWeaver ")
	if !ok || a.ID != "artex" || a.Source != "embedded" {
		t.Fatalf("Find(ScopeWeaver) = %+v, %v", a, ok)
	}
	if _, ok := c.Find("ARTEX"); !ok {
		t.Error("Find(ARTEX) by name")
	}
	if _, ok := c.Find("nothing"); ok {
		t.Error("Find(nothing) matched")
	}
	want := []string{"attack-tool-artex", "attack-tool-artex-backdoored-image"}
	if strings.Join(a.Detects.ConfigRules, ",") != strings.Join(want, ",") || strings.Join(a.Detects.SignalRules, ",") != "attack-tool-artex-name" {
		t.Errorf("ARTEX rules = %v / %v, want %v and the name rule as a signal (internal/collect/confcheck/attacktools.go)",
			a.Detects.ConfigRules, a.Detects.SignalRules, want)
	}
	cs, ok := c.Find("cyberstrike-ai")
	if !ok || cs.ID != "cyberstrikeai" || cs.Kind != KindAttackTool ||
		strings.Join(cs.Detects.ConfigRules, ",") != "attack-tool-cyberstrikeai" ||
		strings.Join(cs.Detects.SignalRules, ",") != "attack-tool-cyberstrikeai-name" {
		t.Errorf("Find(cyberstrike-ai) = %+v, %v (rules: internal/collect/confcheck/attacktools.go)", cs, ok)
	}
	n, ok := c.Find("CVE-2026-123007")
	if !ok || n.ID != "nginx2root" || n.Kind != KindDisclosedVuln || len(n.Detects.CVEs) != 5 || len(n.Detects.ConfigRules) != 0 {
		// Only the CVEs make it found: a loadable SCTP module is a risky
		// setting of its own, not a sign that nginx2root is there.
		t.Errorf("Find(CVE-2026-123007) = %+v, %v", n, ok)
	}
	if c.ExpiresAt != nil {
		t.Error("the embedded catalogue never expires")
	}
	if len(TrustedKeyIDs()) == 0 {
		t.Error("no embedded feed key")
	}
}

func catalogue(t *testing.T, edit func(*Threat)) []byte {
	t.Helper()
	c := *Embedded()
	th := c.Threats[0]
	th.Aliases = append([]string(nil), th.Aliases...)
	th.Source = ""
	edit(&th)
	c.Threats = []Threat{th}
	b, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestParseRefuses(t *testing.T) {
	cases := map[string]func(*Threat){
		"bad id":          func(x *Threat) { x.ID = "ARTEX!" },
		"unknown kind":    func(x *Threat) { x.Kind = "rumour" },
		"http source":     func(x *Threat) { x.Sources = []string{"http://example.com/a"} },
		"foreign help":    func(x *Threat) { x.Needs[0].Help = "https://evil.example/help" },
		"javascript help": func(x *Threat) { x.Needs[0].Help = "javascript:alert(1)" },
		"unknown conn":    func(x *Threat) { x.Needs = []Need{{Connection: "telepathy", Checks: "x", Help: "/help/x"}} },
		"no detects":      func(x *Threat) { x.Detects = Detects{} },
		"no needs":        func(x *Threat) { x.Needs = nil },
		"bad version":     func(x *Threat) { x.MinVersion = "latest" },
		"bad cve":         func(x *Threat) { x.Detects.CVEs = []string{"cve 2026"} },
		"bad date":        func(x *Threat) { x.PublishedAt = "2026-13-40" },
	}
	for name, edit := range cases {
		b := catalogue(t, func(th *Threat) {
			th.Needs = append([]Need(nil), th.Needs...)
			edit(th)
		})
		if _, err := Parse(b); err == nil {
			t.Errorf("%s: parsed", name)
		}
	}
	if _, err := Parse([]byte(`{"schema":1,"serial":1,"threats":[],"extra":true}`)); err == nil {
		t.Error("unknown field parsed")
	}
	if _, err := Parse([]byte(`{"schema":2,"serial":1,"threats":[]}`)); !errors.Is(err, ErrNewerSchema) {
		t.Errorf("schema 2: %v", err)
	}
	// stackurity.ai pages are fine as Help links.
	if _, err := Parse(catalogue(t, func(th *Threat) {
		th.Needs = []Need{{Connection: ConnHostAgent, Required: true, Checks: "x", Help: "https://stackurity.ai/docs/agent"}}
	})); err != nil {
		t.Errorf("stackurity.ai help: %v", err)
	}
}

func TestMergeNewerRevisionWins(t *testing.T) {
	base := Embedded()
	feedJSON := catalogue(t, func(th *Threat) { th.Revision = 2; th.Summary = "updated" })
	feed, err := Parse(feedJSON)
	if err != nil {
		t.Fatal(err)
	}
	feed.Serial = 7
	feed.Threats = append(feed.Threats, Threat{ID: "new-one", Revision: 1, Name: "New", Kind: KindExploitedVuln, Severity: "critical",
		Summary: "s", FirstSeen: "2026-11-01", PublishedAt: "2026-11-21", MinVersion: "0.1.0",
		Detects: Detects{CVEs: []string{"CVE-2026-0001"}}, Needs: []Need{{Connection: ConnHostAgent, Checks: "c", Help: "/help/add-server"}}})
	m := Merge(base, feed)
	if n, ok := m.Get("new-one"); m.Serial != 7 || len(m.Threats) != len(base.Threats)+1 || !ok || n.Source != "feed" {
		t.Fatalf("merged: serial %d, %+v", m.Serial, m.Threats)
	}
	for i := 1; i < len(m.Threats); i++ {
		if m.Threats[i-1].PublishedAt < m.Threats[i].PublishedAt {
			t.Errorf("not newest first: %s before %s", m.Threats[i-1].ID, m.Threats[i].ID)
		}
	}
	a, _ := m.Get("artex")
	if a.Summary != "updated" || a.Source != "feed" {
		t.Errorf("artex from feed with a higher revision: %+v", a)
	}
	// An older revision in the feed does not replace the embedded entry.
	old, _ := Parse(catalogue(t, func(th *Threat) { th.Summary = "stale" }))
	if a, _ := Merge(base, old).Get("artex"); a.Summary == "stale" || a.Source != "embedded" {
		t.Errorf("same revision replaced the embedded entry: %+v", a)
	}
	if a, _ := Merge(base, nil).Get("artex"); a.Source != "embedded" {
		t.Error("nil feed")
	}
}

func TestSignVerify(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	keys := map[string]ed25519.PublicKey{KeyID(pub): pub}
	feed := []byte(`{"schema":1}`)
	sig := Sign(feed, priv)
	if err := verifyWith(keys, feed, sig); err != nil {
		t.Fatalf("valid signature: %v", err)
	}
	for name, c := range map[string]struct{ feed, sig []byte }{
		"changed feed": {[]byte(`{"schema":2}`), sig},
		"unsigned":     {feed, nil},
		"garbage":      {feed, []byte("not json")},
		"other key":    {feed, Sign(feed, func() ed25519.PrivateKey { _, p, _ := ed25519.GenerateKey(rand.Reader); return p }())},
	} {
		if err := verifyWith(keys, c.feed, c.sig); !errors.Is(err, ErrBadSignature) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// The envelope carries both; a changed feed inside it fails.
	env := SignEnvelope(feed, priv)
	if got, err := openWith(keys, env); err != nil || string(got) != string(feed) {
		t.Fatalf("envelope: %q %v", got, err)
	}
	var e Envelope
	_ = json.Unmarshal(env, &e)
	e.Feed = base64.StdEncoding.EncodeToString([]byte(`{"schema":2}`))
	bad, _ := json.Marshal(e)
	if _, err := openWith(keys, bad); !errors.Is(err, ErrBadSignature) {
		t.Errorf("changed envelope: %v", err)
	}
	if _, err := openWith(keys, []byte(`{"schema":1}`)); !errors.Is(err, ErrBadSignature) {
		t.Errorf("a bare catalogue: %v", err)
	}
	// The embedded keys do not trust a key made up here.
	if err := Verify(feed, sig); !errors.Is(err, ErrBadSignature) {
		t.Errorf("Verify with an untrusted key: %v", err)
	}
}

func TestAssess(t *testing.T) {
	artex, _ := Embedded().Get("artex")
	all := map[string]int{ConnHostAgent: 2, ConnDocker: 1, ConnRepository: 3}
	cases := []struct {
		name    string
		ev      Evidence
		conns   map[string]int
		running string
		cloud   bool
		want    string
		ok      bool
		missing int
	}{
		{"found", Evidence{Findings: 1, Assets: 1}, all, "0.20.17", false, Found, true, 0},
		{"found on an older server (a CVE)", Evidence{Findings: 1, Assets: 1}, all, "0.20.10", false, Found, true, 0},
		{"covered", Evidence{}, all, "0.20.17", false, Covered, true, 0},
		{"covered, repositories would widen it", Evidence{}, map[string]int{ConnHostAgent: 1}, "0.20.18", false, Covered, true, 2},
		{"no agent", Evidence{}, map[string]int{ConnRepository: 1, ConnDocker: 1}, "0.20.17", false, NeedsConnection, true, 1},
		{"nothing connected", Evidence{}, nil, "0.20.17", false, NeedsConnection, true, 3},
		{"older self-hosted", Evidence{}, all, "0.20.15", false, Upgrade, true, 0},
		{"older cloud waits", Evidence{}, all, "0.20.15", true, "", false, 0},
		{"development build", Evidence{}, all, "", false, Covered, true, 0},
		{"cloud never upgrade", Evidence{}, nil, "0.20.17", true, NeedsConnection, true, 3},
	}
	for _, c := range cases {
		a, ok := Assess(artex, c.ev, c.conns, nil, c.running, c.cloud)
		if ok != c.ok || (ok && (a.Verdict != c.want || len(a.Missing) != c.missing)) {
			t.Errorf("%s: %s ok=%v missing=%d, want %s ok=%v missing=%d", c.name, a.Verdict, ok, len(a.Missing), c.want, c.ok, c.missing)
		}
	}
	// Servers whose agent predates the check are not connected: the
	// threat is not covered, the notice says to update them.
	a, _ := Assess(artex, Evidence{Signals: 2}, nil, map[string]int{ConnHostAgent: 3}, "0.20.17", true)
	if a.Verdict != NeedsConnection || a.Outdated[ConnHostAgent] != 3 || a.Evidence.Signals != 2 {
		t.Errorf("outdated agents: %+v", a)
	}
	// A signal rule alone is never found.
	if a, _ := Assess(artex, Evidence{Signals: 1}, all, nil, "0.20.17", true); a.Verdict != Covered {
		t.Errorf("signals only: %s", a.Verdict)
	}
	// One updated agent among old ones is not covered: the required
	// connection still has outdated servers.
	a, _ = Assess(artex, Evidence{}, map[string]int{ConnHostAgent: 1, ConnDocker: 1, ConnRepository: 1}, map[string]int{ConnHostAgent: 9}, "0.20.17", true)
	if a.Verdict != NeedsConnection || a.Outdated[ConnHostAgent] != 9 || len(a.Missing) != 1 || a.Missing[0].Connection != ConnHostAgent {
		t.Errorf("1 of 10 agents updated: %+v", a)
	}
	// Outdated optional assets with others checked do not stop covered.
	if a, _ := Assess(artex, Evidence{}, all, map[string]int{ConnDocker: 4}, "0.20.17", true); a.Verdict != Covered {
		t.Errorf("old images beside checked ones: %s", a.Verdict)
	}
	for _, c := range []struct {
		id, v string
		dev   bool
		want  bool
	}{
		{"linux-agent", "0.20.17", false, true},
		{"linux-agent", "v0.20.18-ee", false, true},
		{"linux-docker", "0.20.17-3-gabcdef0", false, true},
		{"linux-agent", "0.20.16", false, false},
		{"linux-agent", "dev", false, false},
		{"linux-agent", "", false, false},
		{"plugin:kubernetes", "1.0.0", false, false},
		{"stackurity-scan", "9.9.9", false, false},
		{"linux-agent", "dev", true, true},
	} {
		if got := artex.CollectorChecked(c.id, c.v, c.dev); got != c.want {
			t.Errorf("CollectorChecked(%q, %q, dev %v) = %v", c.id, c.v, c.dev, got)
		}
	}
	if !Worsened(Covered, Found) || !Worsened(NeedsConnection, Found) || Worsened(Found, Covered) || Worsened(Covered, NeedsConnection) || Worsened(Found, Found) {
		t.Error("Worsened")
	}
}
