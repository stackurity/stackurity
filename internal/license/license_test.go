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
