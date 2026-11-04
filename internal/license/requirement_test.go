package license

import (
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"
	"time"
)

func communityKey(t *testing.T, priv ed25519.PrivateKey, now time.Time) string {
	t.Helper()
	key, err := Issue(License{ID: "ck_1", Customer: "Acme", Name: "Asha", Email: "asha@acme.example", Edition: Community,
		IssuedAt: now, ExpiresAt: now.Add(CommunityValidity)}, priv)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

// A free Community key is a licence like a paid one, verified offline: by
// the licence key, or by the free-key issuer's key, which may sign only
// Community keys.
func TestCommunityKeyVerification(t *testing.T) {
	now := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	mainPub, mainPriv, _ := ed25519.GenerateKey(rand.Reader)
	freePub, freePriv, _ := ed25519.GenerateKey(rand.Reader)
	_, otherPriv, _ := ed25519.GenerateKey(rand.Reader)

	// Community, from the free-key issuer.
	l, err := ParseWithKeys(communityKey(t, freePriv, now), mainPub, freePub)
	if err != nil || l.Edition != Community || l.Name != "Asha" || l.Email != "asha@acme.example" {
		t.Fatalf("community key: %+v %v", l, err)
	}
	if s := StatusAt(l, now.AddDate(50, 0, 0)); s.State != StateActive || s.Edition != Community || len(s.Features) != 0 {
		t.Errorf("community key status after 50 years: %+v", s)
	}
	// Community, from the licence issuer (manual issue with tools/license).
	if _, err := ParseWithKeys(communityKey(t, mainPriv, now), mainPub, freePub); err != nil {
		t.Errorf("community key from the licence issuer: %v", err)
	}
	// Paid, from the licence issuer.
	paid, _ := Issue(License{ID: "lic_1", Customer: "Acme", Edition: Pro, IssuedAt: now, ExpiresAt: now.AddDate(1, 0, 0)}, mainPriv)
	if l, err := ParseWithKeys(paid, mainPub, freePub); err != nil || l.Edition != Pro {
		t.Errorf("paid licence: %+v %v", l, err)
	}
	// Paid, signed by the free-key issuer: refused.
	forged, _ := Issue(License{ID: "lic_2", Customer: "Acme", Edition: Enterprise, IssuedAt: now, ExpiresAt: now.AddDate(1, 0, 0)}, freePriv)
	if _, err := ParseWithKeys(forged, mainPub, freePub); err == nil {
		t.Error("a paid licence signed by the free-key issuer was accepted")
	}
	// Another key, any edition: refused.
	if _, err := ParseWithKeys(communityKey(t, otherPriv, now), mainPub, freePub); err == nil {
		t.Error("a community key from an unknown issuer was accepted")
	}
	// Without a free-key issuer in the build, its keys are refused.
	if _, err := ParseWithKeys(communityKey(t, freePriv, now), mainPub, nil); err == nil {
		t.Error("community key accepted without the issuer's public key")
	}
	// Tampered: the edition changed after signing.
	key := communityKey(t, freePriv, now)
	payload, sig, _ := strings.Cut(key, ".")
	if _, err := ParseWithKeys(payload[:len(payload)-3]+"abc."+sig, mainPub, freePub); err == nil {
		t.Error("tampered community key accepted")
	}
	for _, bad := range []string{"", "nonsense", "a.b", key + "x"} {
		if _, err := ParseWithKeys(bad, mainPub, freePub); err == nil {
			t.Errorf("invalid key %q accepted", bad)
		}
	}
}

// The embedded issuer key, when present, is a valid Ed25519 public key that
// differs from the licence key.
func TestEmbeddedCommunityKey(t *testing.T) {
	k := CommunityVerifyKey()
	if k == nil {
		t.Skip("no free-key issuer key in this build yet (keys/community.pub)")
	}
	if string(k) == string(LicenceVerifyKey()) {
		t.Error("the free-key issuer must have its own key, not the licence key")
	}
}

func TestRequirementStates(t *testing.T) {
	now := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }
	h := &Holder{}

	var none *Requirement
	if none.Blocked() || none.Status().State != KeyInstalled {
		t.Error("a nil requirement (Cloud) blocked")
	}
	// A new install: needed at once.
	fresh := &Requirement{From: now.Add(-time.Minute), Licence: h, Now: clock}
	if s := fresh.Status(); s.State != KeyRequired || !fresh.Blocked() || s.SignupURL != SignupURL {
		t.Errorf("fresh install: %+v", s)
	}
	// An upgrade: 30 days, then needed.
	up := &Requirement{From: now.Add(KeyGrace), Upgraded: true, Licence: h, Now: clock}
	if s := up.Status(); s.State != KeyGraceTime || up.Blocked() || s.GraceEnds == nil || !s.GraceEnds.Equal(now.Add(KeyGrace)) || !s.Upgraded {
		t.Errorf("upgrade in grace: %+v", s)
	}
	// The date passes after 30 days of running: held back.
	up.Now = func() time.Time { return now.Add(KeyGrace + time.Second) }
	up.SetObserved(KeyGrace - time.Hour)
	if !up.Blocked() {
		t.Error("grace period over, not blocked")
	}
	// The clock jumps a year ahead a day after the upgrade: a banner, no
	// lock-out, until the server has run MinObserved.
	up.Now = func() time.Time { return now.AddDate(1, 0, 0) }
	up.SetObserved(24 * time.Hour)
	if s := up.Status(); up.Blocked() || s.State != KeyGraceTime {
		t.Errorf("clock jumped forward: %+v", s)
	}
	up.SetObserved(MinObserved)
	if !up.Blocked() {
		t.Error("past the date and run a week: not blocked")
	}
	// The clock is set back: running 30 days ends the grace period anyway.
	up.Now = func() time.Time { return now.AddDate(-1, 0, 0) }
	up.SetObserved(KeyGrace - time.Minute)
	if up.Blocked() {
		t.Error("blocked before 30 days of running")
	}
	up.SetObserved(KeyGrace)
	if !up.Blocked() {
		t.Error("a clock set back kept the grace period going")
	}
	// Any licence satisfies it: Community, paid, even an expired paid one.
	for _, l := range []*License{
		{Version: 1, Edition: Community, ExpiresAt: now.Add(CommunityValidity)},
		{Version: 1, Edition: Pro, ExpiresAt: now.AddDate(1, 0, 0)},
		{Version: 1, Edition: Enterprise, ExpiresAt: now.AddDate(-1, 0, 0)},
	} {
		h.Set(l)
		if fresh.Blocked() || up.Blocked() || fresh.Status().State != KeyInstalled {
			t.Errorf("%s licence did not satisfy the requirement", l.Edition)
		}
	}
	h.Set(nil)
	if !fresh.Blocked() || !up.Blocked() {
		t.Error("removing the key did not require it again")
	}
}
