package releaselint

import (
	"os"
	"testing"

	"github.com/stackurity/stackurity/internal/license"
)

// TestCommunityKeyIssuer: a release must ship the public key of the
// free-key issuer (internal/license/keys/community.pub), or the free keys
// the sign-up hands out would not verify on the servers that need them.
// Pull requests may leave it empty until the key pair exists. The issuer's
// private key stays on the server that runs the sign-up; it is never the
// key that signs paid licences.
func TestCommunityKeyIssuer(t *testing.T) {
	k := license.CommunityVerifyKey() // panics on a malformed key
	if k == nil {
		if os.Getenv("STACKURITY_RELEASE_TAG") != "" {
			t.Fatal("internal/license/keys/community.pub is empty: a release must ship the free-key issuer's public key (docs/install.md, \"The free key\")")
		}
		t.Skip("no free-key issuer key yet; a release (STACKURITY_RELEASE_TAG) needs one")
	}
	if string(k) == string(license.LicenceVerifyKey()) {
		t.Fatal("community.pub must not be the licence key: the server that issues free keys must not hold the key that signs paid licences")
	}
}
