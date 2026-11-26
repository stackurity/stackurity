package license

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"
	"time"
)

func TestIssueParseAndStates(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Date(2026, 10, 25, 0, 0, 0, 0, time.UTC)
	key, err := Issue(License{ID: "lic_1", Customer: "Acme", Edition: Pro, MaxAssets: 100, IssuedAt: now, ExpiresAt: now.AddDate(1, 0, 0)}, priv)
	if err != nil {
		t.Fatal(err)
	}
	l, err := parseWith(key, pub)
	if err != nil || l.Customer != "Acme" || l.Edition != Pro {
		t.Fatalf("parse: %+v %v", l, err)
	}
	if _, err := Parse(key); err == nil {
		t.Error("a licence signed by another key was accepted")
	}
	// Changing any byte breaks the signature.
	payload, sig, _ := strings.Cut(key, ".")
	if _, err := parseWith(payload[:len(payload)-2]+"xx."+sig, pub); err == nil {
		t.Error("tampered licence accepted")
	}

	if s := StatusAt(l, now); s.State != StateActive || !s.Edition.Includes(Remediation) || s.Edition.Includes(EnterprisePacks) {
		t.Errorf("active: %+v", s)
	}
	if s := StatusAt(l, now.AddDate(1, 0, 10)); s.State != StateGrace || s.Edition != Pro || s.GraceEnds == nil {
		t.Errorf("grace: %+v", s)
	}
	if s := StatusAt(l, now.AddDate(1, 2, 0)); s.State != StateExpired || s.Edition != Community || len(s.Features) != 0 {
		t.Errorf("expired: %+v", s)
	}
	if s := StatusAt(nil, now); s.State != StateNone || s.Edition != Community {
		t.Errorf("none: %+v", s)
	}
	if _, err := Issue(License{Edition: "free"}, priv); err == nil {
		t.Error("issued an unknown edition")
	}
	if _, err := Issue(License{Edition: Community}, priv); err == nil {
		t.Error("issued a licence without an expiry")
	}
}

func TestGateCapsByWorkspacePlan(t *testing.T) {
	h := &Holder{now: func() time.Time { return time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC) }}
	h.Set(&License{Version: 1, Edition: Enterprise, ExpiresAt: time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)})
	type key struct{}
	g := &Gate{Licence: h, Plan: func(ctx context.Context) Edition {
		if e, ok := ctx.Value(key{}).(Edition); ok {
			return e
		}
		return Community
	}}
	if !g.Has(context.WithValue(context.Background(), key{}, Enterprise), EnterprisePacks) {
		t.Error("enterprise workspace lacks enterprise packs")
	}
	if g.Has(context.WithValue(context.Background(), key{}, Pro), EnterprisePacks) || !g.Has(context.WithValue(context.Background(), key{}, Pro), Teams) {
		t.Error("pro workspace plan not applied")
	}
	if g.Has(context.Background(), Teams) {
		t.Error("community workspace has a paid feature")
	}
	h.Set(&License{Version: 1, Edition: Pro, ExpiresAt: time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)})
	if g.Has(context.WithValue(context.Background(), key{}, Enterprise), EnterprisePacks) {
		t.Error("a workspace plan exceeded the instance licence")
	}
	var none *Gate
	if none.Has(context.Background(), Teams) {
		t.Error("nil gate allowed a feature")
	}
}

func TestAddons(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Date(2026, 11, 16, 0, 0, 0, 0, time.UTC)
	base := License{ID: "lic_2", Customer: "Acme", Edition: Pro, IssuedAt: now, ExpiresAt: now.AddDate(1, 0, 0)}
	withAddon := base
	withAddon.Addons = []Feature{ComplianceAddon}
	signed, err := Issue(withAddon, priv)
	if err != nil {
		t.Fatal(err)
	}
	l, err := parseWith(signed, pub)
	if err != nil || len(l.Addons) != 1 || l.Addons[0] != ComplianceAddon {
		t.Fatalf("parse: %+v %v", l, err)
	}
	has := func(s Status, f Feature) bool {
		for _, x := range s.Features {
			if x == f {
				return true
			}
		}
		return false
	}
	if s := StatusAt(l, now); !has(s, ComplianceAddon) || !has(s, EvidenceReport) {
		t.Errorf("active Pro with the add-on: %+v", s.Features)
	}
	if s := StatusAt(&base, now); has(s, ComplianceAddon) {
		t.Error("Pro without the add-on has it")
	}
	if s := StatusAt(l, now.AddDate(1, 2, 0)); has(s, ComplianceAddon) {
		t.Error("an expired licence keeps its add-on")
	}
	if !Enterprise.Includes(ComplianceAddon) || Pro.Includes(ComplianceAddon) {
		t.Error("Enterprise includes the add-on; Pro does not")
	}
	bad := base
	bad.Addons = []Feature{SSO}
	if _, err := Issue(bad, priv); err == nil {
		t.Error("issued a feature that is not an add-on as one")
	}
	bad = withAddon
	bad.Edition = Community
	if _, err := Issue(bad, priv); err == nil {
		t.Error("issued an add-on on Community")
	}

	// The gate: a Pro licence with the add-on turns it on for paid
	// workspaces only, never above the workspace's plan.
	h := &Holder{now: func() time.Time { return now }}
	h.Set(l)
	type key struct{}
	g := &Gate{Licence: h, Plan: func(ctx context.Context) Edition {
		if e, ok := ctx.Value(key{}).(Edition); ok {
			return e
		}
		return Community
	}}
	if !g.Has(context.WithValue(context.Background(), key{}, Pro), ComplianceAddon) {
		t.Error("Pro workspace on a licence with the add-on lacks it")
	}
	if g.Has(context.Background(), ComplianceAddon) {
		t.Error("Community workspace got the add-on")
	}
	h.Set(&base)
	if g.Has(context.WithValue(context.Background(), key{}, Enterprise), ComplianceAddon) {
		t.Error("add-on without it on the licence")
	}
	// An Enterprise licence includes the add-on, but a workspace capped at
	// Pro does not get it (review, 17 Nov).
	ent := base
	ent.Edition = Enterprise
	h.Set(&ent)
	if g.Has(context.WithValue(context.Background(), key{}, Pro), ComplianceAddon) {
		t.Error("an Enterprise licence gave the add-on to a Pro workspace")
	}
	if !g.Has(context.WithValue(context.Background(), key{}, Enterprise), ComplianceAddon) {
		t.Error("an Enterprise workspace lacks the add-on")
	}
}

func TestSSOEnterpriseOnly(t *testing.T) {
	if Pro.Includes(SSO) || !Enterprise.Includes(SSO) {
		t.Fatal("single sign-on must be Enterprise only")
	}
	if LowestEdition(SSO) != Enterprise {
		t.Errorf("LowestEdition(SSO) = %s", LowestEdition(SSO))
	}
	if o := SelfHostedOffer(SSO); len(o.IncludedIn) != 1 || o.IncludedIn[0] != "Enterprise" || o.Addon != nil {
		t.Errorf("offer = %+v", o)
	}
	now := time.Date(2026, 12, 1, 0, 0, 0, 0, time.UTC)
	before := SSOEnterpriseFrom.Add(-time.Hour)
	cases := []struct {
		name string
		l    *License
		plan Edition
		want bool
	}{
		{"none", nil, Enterprise, false},
		{"new Pro", &License{Edition: Pro, IssuedAt: SSOEnterpriseFrom, ExpiresAt: now.AddDate(1, 0, 0)}, Enterprise, false},
		{"Pro without issue date", &License{Edition: Pro, ExpiresAt: now.AddDate(1, 0, 0)}, Enterprise, false},
		{"old Pro keeps it", &License{Edition: Pro, IssuedAt: before, ExpiresAt: now.AddDate(1, 0, 0)}, Enterprise, true},
		{"old Pro in grace", &License{Edition: Pro, IssuedAt: before, ExpiresAt: now.Add(-24 * time.Hour)}, Enterprise, true},
		{"old Pro expired", &License{Edition: Pro, IssuedAt: before, ExpiresAt: now.Add(-Grace - time.Hour)}, Enterprise, false},
		{"old Pro, Community workspace", &License{Edition: Pro, IssuedAt: before, ExpiresAt: now.AddDate(1, 0, 0)}, Community, false},
		{"old Pro, Pro workspace", &License{Edition: Pro, IssuedAt: before, ExpiresAt: now.AddDate(1, 0, 0)}, Pro, true},
		{"Enterprise", &License{Edition: Enterprise, IssuedAt: SSOEnterpriseFrom, ExpiresAt: now.AddDate(1, 0, 0)}, Enterprise, true},
		{"Enterprise, Pro workspace", &License{Edition: Enterprise, IssuedAt: SSOEnterpriseFrom, ExpiresAt: now.AddDate(1, 0, 0)}, Pro, false},
	}
	for _, c := range cases {
		h := &Holder{now: func() time.Time { return now }}
		h.Set(c.l)
		plan := c.plan
		g := &Gate{Licence: h, Plan: func(context.Context) Edition { return plan }}
		if got := g.Has(context.Background(), SSO); got != c.want {
			t.Errorf("%s: Gate.Has(SSO) = %v, want %v", c.name, got, c.want)
		}
		if c.plan == Enterprise {
			st := StatusAt(c.l, now)
			in := false
			for _, f := range st.Features {
				in = in || f == SSO
			}
			if in != c.want {
				t.Errorf("%s: Status.Features has SSO = %v, want %v", c.name, in, c.want)
			}
		}
	}
}
