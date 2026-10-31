// Package license verifies Stackurity licences and answers which paid
// features are on. A licence is a signed statement, checked offline: no
// phone-home, so air-gapped installs work. Without a paid licence
// Stackurity runs as Community, and detection, alerting and the free
// features are never switched off by licensing.
//
// A self-hosted server also needs a key to use its dashboard and API: the
// free Community key, from a sign-up, or any paid licence (requirement.go).
// Agents, CLI scans and uploads work without one.
package license

import (
	"context"
	"crypto/ed25519"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/stackurity/stackurity/internal/tenant"
)

// Feature is a paid capability.
type Feature string

const (
	// Remediation: policy-controlled upgrades on hosts and Renovate pull requests.
	Remediation Feature = "remediation"
	// Teams: more than one team, routing by team, deadlines and escalation.
	Teams Feature = "teams"
	// EvidenceReport: the patch-management evidence report for audits.
	EvidenceReport Feature = "evidence_report"
	// SSO: sign-in through an OpenID Connect or SAML 2.0 provider.
	SSO Feature = "sso"
	// EnterprisePacks: stack packs for enterprise technologies (SAP, Oracle, ...).
	EnterprisePacks Feature = "enterprise_packs"
)

// Edition is a plan: the set of features it includes.
type Edition string

const (
	Community  Edition = "community"
	Pro        Edition = "pro"
	Enterprise Edition = "enterprise"
)

var editionFeatures = map[Edition][]Feature{
	Community:  nil,
	Pro:        {Remediation, Teams, EvidenceReport, SSO},
	Enterprise: {Remediation, Teams, EvidenceReport, SSO, EnterprisePacks},
}

// Features lists what an edition includes.
func (e Edition) Features() []Feature { return editionFeatures[e] }

func (e Edition) Valid() bool { _, ok := editionFeatures[e]; return ok }

// Includes reports whether the edition has a feature.
func (e Edition) Includes(f Feature) bool {
	for _, x := range editionFeatures[e] {
		if x == f {
			return true
		}
	}
	return false
}

// rank orders editions, so a workspace plan can be capped by the licence.
func (e Edition) rank() int {
	switch e {
	case Pro:
		return 1
	case Enterprise:
		return 2
	}
	return 0
}

// Min returns the lower of two editions.
func Min(a, b Edition) Edition {
	if a.rank() <= b.rank() {
		return a
	}
	return b
}

// Grace is how long paid features keep working after a licence expires.
const Grace = 30 * 24 * time.Hour

// License is the signed statement.
type License struct {
	Version  int    `json:"v"`
	ID       string `json:"id"`
	Customer string `json:"customer"`
	// Name is the person a free Community key was issued to (Customer is
	// then their company, or their name when they gave none).
	Name      string    `json:"name,omitempty"`
	Email     string    `json:"email,omitempty"`
	Edition   Edition   `json:"edition"`
	MaxAssets int       `json:"max_assets"` // 0 = unlimited
	IssuedAt  time.Time `json:"issued_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

// State says where a licence stands.
type State string

const (
	StateNone    State = "none"    // Community
	StateActive  State = "active"  // valid
	StateGrace   State = "grace"   // expired less than Grace ago: still works, renew now
	StateExpired State = "expired" // paid features off
)

// Status is what the dashboard shows.
type Status struct {
	State     State      `json:"state"`
	Edition   Edition    `json:"edition"` // the edition in effect now
	License   *License   `json:"license,omitempty"`
	GraceEnds *time.Time `json:"grace_ends,omitempty"`
	Features  []Feature  `json:"features"`
}

//go:embed keys/license.pub
var publicKey string

// communityPublicKey verifies free Community keys, which the sign-up on
// Stackurity Cloud issues with a key of its own: a server that hands out
// free keys never holds the key that signs paid licences. A key it signs is
// accepted only for the Community edition. Empty until the issuer's key
// pair exists (a release must ship it: tools/releaselint).
//
//go:embed keys/community.pub
var communityPublicKey string

func verifyKey() ed25519.PublicKey {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(publicKey))
	if err != nil || len(raw) != ed25519.PublicKeySize {
		panic("license: invalid embedded public key")
	}
	return raw
}

// CommunityVerifyKey is the embedded key that verifies free Community keys,
// or nil when this build has none.
func CommunityVerifyKey() ed25519.PublicKey {
	s := strings.TrimSpace(communityPublicKey)
	if s == "" {
		return nil
	}
	raw, err := base64.StdEncoding.DecodeString(s)
	if err != nil || len(raw) != ed25519.PublicKeySize {
		panic("license: invalid embedded community public key")
	}
	return raw
}

// LicenceVerifyKey is the embedded key that verifies paid licences.
func LicenceVerifyKey() ed25519.PublicKey { return verifyKey() }

// Parse verifies a licence key ("payload.signature", both base64url) and
// returns its contents. Expiry is not an error here; see StatusAt.
func Parse(key string) (*License, error) {
	return parseKeys(key, verifyKey(), CommunityVerifyKey())
}

// ParseWithKey verifies a licence against another public key (tests and
// private issuing tools).
func ParseWithKey(key string, pub ed25519.PublicKey) (*License, error) { return parseWith(key, pub) }

// ParseWithKeys verifies a licence as Parse does, against other keys: pub
// for any edition, community (may be nil) for Community keys only.
func ParseWithKeys(key string, pub, community ed25519.PublicKey) (*License, error) {
	return parseKeys(key, pub, community)
}

func parseKeys(key string, pub, community ed25519.PublicKey) (*License, error) {
	l, err := parseWith(key, pub)
	if err == nil || community == nil || !errors.Is(err, errSignature) {
		return l, err
	}
	l, err = parseWith(key, community)
	if err != nil {
		return nil, err
	}
	if l.Edition != Community {
		// The free-key issuer cannot sign paid licences.
		return nil, errSignature
	}
	return l, nil
}

var errSignature = errors.New("the licence signature is not valid")

func parseWith(key string, pub ed25519.PublicKey) (*License, error) {
	key = strings.TrimSpace(key)
	payload, sig, ok := strings.Cut(key, ".")
	if !ok {
		return nil, errors.New("not a Stackurity licence key")
	}
	body, err1 := base64.RawURLEncoding.DecodeString(payload)
	s, err2 := base64.RawURLEncoding.DecodeString(sig)
	if err1 != nil || err2 != nil {
		return nil, errors.New("not a Stackurity licence key")
	}
	if !ed25519.Verify(pub, body, s) {
		return nil, errSignature
	}
	var l License
	if err := json.Unmarshal(body, &l); err != nil {
		return nil, fmt.Errorf("licence contents: %w", err)
	}
	if l.Version != 1 || !l.Edition.Valid() || l.ExpiresAt.IsZero() {
		return nil, errors.New("this licence is for a different Stackurity version")
	}
	return &l, nil
}

// CommunityValidity is how long a free Community key is valid: it does not
// expire in practice. It carries an expiry only because every licence
// version 1 does, so servers from before Community keys accept it too.
const CommunityValidity = 100 * 365 * 24 * time.Hour

// Issue signs a licence. Only the licence issuer holds priv (for Community
// keys, the free-key issuer).
func Issue(l License, priv ed25519.PrivateKey) (string, error) {
	l.Version = 1
	if !l.Edition.Valid() {
		return "", errors.New("edition must be community, pro or enterprise")
	}
	if l.ExpiresAt.IsZero() {
		return "", errors.New("the licence needs an expiry")
	}
	body, err := json.Marshal(l)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(body) + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(priv, body)), nil
}

// StatusAt evaluates a licence (nil for none) at time now.
func StatusAt(l *License, now time.Time) Status {
	if l == nil {
		return Status{State: StateNone, Edition: Community, Features: []Feature{}}
	}
	st := Status{License: l, Edition: l.Edition}
	ends := l.ExpiresAt.Add(Grace)
	switch {
	case now.Before(l.ExpiresAt):
		st.State = StateActive
	case now.Before(ends):
		st.State, st.GraceEnds = StateGrace, &ends
	default:
		st.State, st.Edition = StateExpired, Community
	}
	st.Features = append([]Feature{}, st.Edition.Features()...)
	return st
}

// Holder keeps the installation's current licence. It is safe for
// concurrent use; the server sets it at start and when an admin uploads one.
type Holder struct {
	mu  sync.RWMutex
	lic *License
	now func() time.Time
}

func (h *Holder) Set(l *License) {
	h.mu.Lock()
	h.lic = l
	h.mu.Unlock()
}

// License returns the licence in effect, or nil for Community.
func (h *Holder) License() *License {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.lic
}

func (h *Holder) Status() Status {
	h.mu.RLock()
	l := h.lic
	h.mu.RUnlock()
	now := time.Now()
	if h.now != nil {
		now = h.now()
	}
	return StatusAt(l, now)
}

// Edition is the instance's edition in effect now.
func (h *Holder) Edition() Edition { return h.Status().Edition }

// --- per-workspace plans

// PlanFunc returns the plan of the workspace in ctx: the edition its
// organisation pays for. On a self-hosted install every workspace inherits
// the licence; on a hosted platform each workspace has its own plan.
type PlanFunc func(ctx context.Context) Edition

// Gate answers feature checks: a feature is on when both the installation's
// licence and the workspace's plan include it.
type Gate struct {
	Licence *Holder
	Plan    PlanFunc
}

// Has reports whether the feature is on for the workspace in ctx.
func (g *Gate) Has(ctx context.Context, f Feature) bool {
	if g == nil || g.Licence == nil {
		return false
	}
	e := g.Licence.Edition()
	if g.Plan != nil {
		e = Min(e, g.Plan(ctx))
	}
	return e.Includes(f)
}

// Edition is the edition in effect for the workspace in ctx.
func (g *Gate) Edition(ctx context.Context) Edition {
	if g == nil || g.Licence == nil {
		return Community
	}
	e := g.Licence.Edition()
	if g.Plan != nil {
		e = Min(e, g.Plan(ctx))
	}
	return e
}

// CachedPlan turns a lookup of the current workspace's plan ("inherit",
// "community", "pro", "enterprise") into a PlanFunc, caching each answer
// briefly. "inherit" means the licence decides. Errors count as Community.
func CachedPlan(lookup func(ctx context.Context) (string, error), ttl time.Duration) PlanFunc {
	type entry struct {
		plan Edition
		at   time.Time
	}
	var mu sync.Mutex
	cache := map[int64]entry{}
	return func(ctx context.Context) Edition {
		ws, ok := tenant.Workspace(ctx)
		if !ok {
			return Enterprise // system scope: the licence alone decides
		}
		mu.Lock()
		e, hit := cache[ws]
		mu.Unlock()
		if hit && time.Since(e.at) < ttl {
			return e.plan
		}
		p, err := lookup(ctx)
		plan := Community
		switch {
		case err != nil:
		case p == "inherit":
			plan = Enterprise
		case Edition(p).Valid():
			plan = Edition(p)
		}
		mu.Lock()
		cache[ws] = entry{plan, time.Now()}
		mu.Unlock()
		return plan
	}
}
