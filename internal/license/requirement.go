package license

import (
	"sync/atomic"
	"time"
)

// SignupURL is where a free Community key is requested: a sign-up on
// Stackurity Cloud that emails the key. The key is then checked offline,
// like any licence.
const SignupURL = "https://app.stackurity.dev/self-hosted-key"

// KeyGrace is how long a server that already had users or data when it
// first ran a version needing a key keeps working without one.
const KeyGrace = 30 * 24 * time.Hour

// MinObserved is the least running time an upgraded server gets after its
// grace date has passed before it is held back: a clock that jumps forward
// shows the banner, never a lock-out, until the server has really run this
// long since the upgrade.
const MinObserved = 7 * 24 * time.Hour

// KeyState says whether a self-hosted server has the key it needs.
type KeyState string

const (
	KeyInstalled KeyState = "installed" // a free Community key or a paid licence is installed
	KeyGraceTime KeyState = "grace"     // none yet, but the server works until GraceEnds
	KeyRequired  KeyState = "required"  // none: the dashboard and API wait for one
)

// KeyStatus is what the dashboard shows about the key.
type KeyStatus struct {
	State     KeyState   `json:"state"`
	GraceEnds *time.Time `json:"grace_ends,omitempty"`
	// Upgraded: the server already had users or data when it first ran a
	// version needing a key, so it got a grace period.
	Upgraded  bool   `json:"upgraded"`
	SignupURL string `json:"signup_url"`
}

// Requirement is a self-hosted server's need for a key: a free Community
// key from a sign-up, or any paid licence. Until one is installed the
// dashboard and the API wait for it, except signing in, entering the key,
// health checks, and what agents, CLI scans and CI uploads use, so data
// keeps arriving. A nil Requirement requires nothing (Stackurity Cloud,
// where the platform holds the licence).
type Requirement struct {
	// From is when the server stops working without a key: when it was
	// installed, or KeyGrace after an existing server first started a
	// version needing one (migration 0072).
	From     time.Time
	Upgraded bool
	Licence  *Holder
	// Now replaces the clock in tests.
	Now func() time.Time
	// observed is how long servers have been seen running since an
	// upgrade's grace period started (nanoseconds; SetObserved).
	observed atomic.Int64
}

// SetObserved records how long servers have been seen running since the
// grace period started (store.TickLicenseRequirement).
func (q *Requirement) SetObserved(d time.Duration) {
	if q != nil {
		q.observed.Store(int64(d))
	}
}

// Status evaluates the requirement now.
func (q *Requirement) Status() KeyStatus {
	if q == nil {
		return KeyStatus{State: KeyInstalled, SignupURL: SignupURL}
	}
	st := KeyStatus{State: KeyInstalled, Upgraded: q.Upgraded, SignupURL: SignupURL}
	// Any licence that verifies counts, whatever its edition and even
	// expired: its holder signed up with us, and an expired paid licence
	// takes paid features away, never the server.
	if q.Licence != nil && q.Licence.License() != nil {
		return st
	}
	now := time.Now()
	if q.Now != nil {
		now = q.Now()
	}
	if q.Upgraded {
		// The grace period ends after KeyGrace of running time, or once its
		// date has passed and the server has run MinObserved: neither a
		// clock set back nor one jumping forward changes the outcome much.
		obs := time.Duration(q.observed.Load())
		if obs >= KeyGrace || (!now.Before(q.From) && obs >= MinObserved) {
			st.State = KeyRequired
			return st
		}
		ends := q.From
		st.State, st.GraceEnds = KeyGraceTime, &ends
		return st
	}
	if now.Before(q.From) {
		ends := q.From
		st.State, st.GraceEnds = KeyGraceTime, &ends
		return st
	}
	st.State = KeyRequired
	return st
}

// Blocked reports whether the dashboard and API wait for a key now.
func (q *Requirement) Blocked() bool { return q != nil && q.Status().State == KeyRequired }
