// Package auth holds password hashing, token generation and role checks.
package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

type Role string

const (
	RoleViewer    Role = "viewer"
	RoleEngineer  Role = "engineer"
	RoleSecurity  Role = "security"
	RoleAdmin     Role = "admin"
	RoleCollector Role = "collector" // agents and CI: may only submit observations
)

var rank = map[Role]int{RoleViewer: 1, RoleEngineer: 2, RoleSecurity: 3, RoleAdmin: 4}

func (r Role) ValidUser() bool { _, ok := rank[r]; return ok }

func (r Role) ValidToken() bool { return r.ValidUser() || r == RoleCollector }

// AtLeast reports whether r has at least min's privileges. Collector tokens
// never satisfy a user role.
func (r Role) AtLeast(min Role) bool {
	return rank[r] >= rank[min] && rank[r] > 0
}

// Lower returns the lesser of two user roles; "" when either is not a user
// role (no access).
func Lower(a, b Role) Role {
	if !a.ValidUser() || !b.ValidUser() {
		return ""
	}
	if rank[a] <= rank[b] {
		return a
	}
	return b
}

// Higher returns the greater of two user roles, ignoring one that is not a
// user role; "" when neither is.
func Higher(a, b Role) Role {
	switch {
	case !a.ValidUser() && !b.ValidUser():
		return ""
	case rank[a] >= rank[b]:
		return a
	}
	return b
}

// CanIngest: collectors plus any engineer-or-higher user (CLI uploads).
func (r Role) CanIngest() bool { return r == RoleCollector || r.AtLeast(RoleEngineer) }

// argon2id parameters (OWASP baseline: m=19MiB, t=2, p=1).
const (
	argonTime    = 2
	argonMemory  = 19 * 1024
	argonThreads = 1
	argonKeyLen  = 32
)

var ErrBadPassword = errors.New("password must be 12-256 characters")

func ValidPassword(pw string) error {
	if len(pw) < 12 || len(pw) > 256 {
		return ErrBadPassword
	}
	return nil
}

func HashPassword(pw string) (string, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key := argon2.IDKey([]byte(pw), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	enc := base64.RawStdEncoding
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s", argon2.Version, argonMemory, argonTime, argonThreads,
		enc.EncodeToString(salt), enc.EncodeToString(key)), nil
}

func CheckPassword(hash, pw string) bool {
	parts := strings.Split(hash, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return false
	}
	var m, t uint32
	var p uint8
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &m, &t, &p); err != nil {
		return false
	}
	enc := base64.RawStdEncoding
	salt, err1 := enc.DecodeString(parts[4])
	want, err2 := enc.DecodeString(parts[5])
	if err1 != nil || err2 != nil {
		return false
	}
	got := argon2.IDKey([]byte(pw), salt, t, m, p, uint32(len(want)))
	return subtle.ConstantTimeCompare(got, want) == 1
}

// dummyHash lets login spend the same time whether or not the user exists.
var dummyHash, _ = HashPassword("timing-equaliser-password")

func CheckPasswordOrDummy(hash string, exists bool, pw string) bool {
	if !exists {
		CheckPassword(dummyHash, pw)
		return false
	}
	return CheckPassword(hash, pw)
}

var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// NewToken returns a random secret with a readable prefix, e.g.
// "stk_ABCD...". prefix is the first characters, safe to display.
func NewToken(kind string) (secret, prefix string, err error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", "", err
	}
	secret = kind + "_" + strings.ToLower(b32.EncodeToString(buf))
	return secret, secret[:len(kind)+9], nil
}

func HashToken(secret string) []byte {
	h := sha256.Sum256([]byte(secret))
	return h[:]
}
