package store

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/stackurity/stackurity/internal/auth"
)

// Passkeys and security keys (WebAuthn, migration 0066). The ceremonies
// themselves are checked in the api package with go-webauthn; this file
// keeps the credential records, each account's user handle, and the
// challenges between the two steps of a ceremony.

// MaxPasskeys caps the passkeys of one account.
const MaxPasskeys = 20

// Passkey is a registered credential as its owner sees it.
type Passkey struct {
	ID   int64  `json:"id"`
	Name string `json:"name"`
	// BackedUp: a synced passkey (in a password manager or a platform
	// account), rather than one device.
	BackedUp bool `json:"backed_up"`
	// Discoverable: it can sign in without an email (null: unknown).
	Discoverable   *bool      `json:"discoverable"`
	CreatedAt      time.Time  `json:"created_at"`
	LastUsedAt     *time.Time `json:"last_used_at"`
	CloneWarningAt *time.Time `json:"clone_warning_at"`
}

// PasskeyRecord is a credential with its go-webauthn record (JSON).
type PasskeyRecord struct {
	ID     int64
	Name   string
	Record []byte
}

// WebAuthnHandle returns userID's WebAuthn user handle, making it at the
// first registration (64 random bytes, never the account id or email).
func (s *Store) WebAuthnHandle(ctx context.Context, userID int64) ([]byte, error) {
	h := make([]byte, 64)
	if _, err := rand.Read(h); err != nil {
		return nil, err
	}
	var out []byte
	err := s.Pool.QueryRow(ctx, `UPDATE users SET webauthn_handle = COALESCE(webauthn_handle, $2) WHERE id = $1 RETURNING webauthn_handle`,
		userID, h).Scan(&out)
	return out, notFound(err)
}

// ExistingWebAuthnHandle returns userID's handle, nil when it has none.
func (s *Store) ExistingWebAuthnHandle(ctx context.Context, userID int64) ([]byte, error) {
	var out []byte
	err := s.Pool.QueryRow(ctx, `SELECT webauthn_handle FROM users WHERE id = $1`, userID).Scan(&out)
	return out, notFound(err)
}

// UserByWebAuthnHandle resolves a user handle from a passkey to an enabled
// account.
func (s *Store) UserByWebAuthnHandle(ctx context.Context, handle []byte) (int64, error) {
	var id int64
	err := s.Pool.QueryRow(ctx, `SELECT id FROM users WHERE webauthn_handle = $1 AND NOT disabled`, handle).Scan(&id)
	return id, notFound(err)
}

// PasskeyRecords returns userID's credentials with their records.
func (s *Store) PasskeyRecords(ctx context.Context, userID int64) ([]PasskeyRecord, error) {
	rows, err := s.Pool.Query(ctx, `SELECT id, name, record FROM webauthn_credentials WHERE user_id = $1 ORDER BY id`, userID)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByPos[PasskeyRecord])
}

// ListPasskeys lists userID's passkeys, oldest first.
func (s *Store) ListPasskeys(ctx context.Context, userID int64) ([]Passkey, error) {
	rows, err := s.Pool.Query(ctx, `SELECT id, name, backed_up, discoverable, created_at, last_used_at, clone_warning_at
		FROM webauthn_credentials WHERE user_id = $1 ORDER BY id`, userID)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByPos[Passkey])
}

// CleanPasskeyName trims a passkey's name and checks its length.
func CleanPasskeyName(name string) (string, error) {
	name = strings.Join(strings.Fields(name), " ")
	if n := len([]rune(name)); n == 0 || n > 64 {
		return "", fmt.Errorf("give the passkey a name of 1 to 64 characters, such as \"MacBook Touch ID\" or \"YubiKey 5\": %w", ErrInvalid)
	}
	return name, nil
}

// NewPasskey is a credential just registered.
type NewPasskey struct {
	CredentialID []byte
	Name         string
	Record       []byte
	BackedUp     bool
	Discoverable *bool
}

// ErrPasskeyExists: the credential is already registered (to anyone).
var ErrPasskeyExists = fmt.Errorf("this passkey is already registered: %w", ErrConflict)

// AddPasskey stores a registered credential for userID. When it is the
// account's first strong factor, the recovery codes' hashes are stored
// (issued reports it) and email codes end.
func (s *Store) AddPasskey(ctx context.Context, userID int64, p NewPasskey, recovery [][]byte) (pk Passkey, issued bool, err error) {
	if p.Name, err = CleanPasskeyName(p.Name); err != nil {
		return pk, false, err
	}
	err = pgx.BeginFunc(ctx, s.Pool, func(tx pgx.Tx) error {
		first, err := firstStrongFactor(ctx, tx, userID)
		if err != nil {
			return err
		}
		var n int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM webauthn_credentials WHERE user_id = $1`, userID).Scan(&n); err != nil {
			return err
		}
		if n >= MaxPasskeys {
			return fmt.Errorf("an account can have at most %d passkeys; remove one first: %w", MaxPasskeys, ErrConflict)
		}
		rows, err := tx.Query(ctx, `INSERT INTO webauthn_credentials (user_id, credential_id, name, record, backed_up, discoverable)
			VALUES ($1, $2, $3, $4, $5, $6) ON CONFLICT (credential_id) DO NOTHING
			RETURNING id, name, backed_up, discoverable, created_at, last_used_at, clone_warning_at`,
			userID, p.CredentialID, p.Name, p.Record, p.BackedUp, p.Discoverable)
		if err != nil {
			return err
		}
		pk, err = pgx.CollectExactlyOneRow(rows, pgx.RowToStructByPos[Passkey])
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrPasskeyExists
		}
		if err != nil {
			return err
		}
		if !first {
			return nil
		}
		issued = true
		return addedStrongFactor(ctx, tx, userID, recovery)
	})
	return pk, issued, err
}

// PasskeyUsed records a successful assertion: the updated record (sign
// counter, backup state) and the time.
func (s *Store) PasskeyUsed(ctx context.Context, userID, id int64, record []byte, backedUp bool) error {
	tag, err := s.Pool.Exec(ctx, `UPDATE webauthn_credentials SET record = $3, backed_up = $4, last_used_at = now()
		WHERE id = $2 AND user_id = $1`, userID, id, record, backedUp)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}

// PasskeyCloneWarning marks a credential whose signature counter went
// backwards (the sign-in was refused).
func (s *Store) PasskeyCloneWarning(ctx context.Context, userID, id int64) error {
	_, err := s.Pool.Exec(ctx, `UPDATE webauthn_credentials SET clone_warning_at = now() WHERE id = $2 AND user_id = $1`, userID, id)
	return err
}

// RenamePasskey renames one of userID's passkeys and returns its old name.
func (s *Store) RenamePasskey(ctx context.Context, userID, id int64, name string) (string, error) {
	name, err := CleanPasskeyName(name)
	if err != nil {
		return "", err
	}
	var old string
	err = s.Pool.QueryRow(ctx, `UPDATE webauthn_credentials c SET name = $3 FROM webauthn_credentials o
		WHERE c.id = $2 AND c.user_id = $1 AND o.id = c.id RETURNING o.name`, userID, id, name).Scan(&old)
	return old, notFound(err)
}

// RemovePasskey removes one of userID's passkeys and returns its name.
// The recovery codes go with the last strong factor.
func (s *Store) RemovePasskey(ctx context.Context, userID, id int64) (string, error) {
	var name string
	err := pgx.BeginFunc(ctx, s.Pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SELECT 1 FROM users WHERE id = $1 FOR UPDATE`, userID); err != nil {
			return err
		}
		if err := tx.QueryRow(ctx, `DELETE FROM webauthn_credentials WHERE id = $2 AND user_id = $1 RETURNING name`, userID, id).Scan(&name); err != nil {
			return notFound(err)
		}
		return removedStrongFactor(ctx, tx, userID)
	})
	return name, err
}

// Ceremony purposes (webauthn_ceremonies.purpose).
const (
	CeremonyRegister     = "register"
	CeremonySecondFactor = "second_factor"
	CeremonyPasswordless = "passwordless"
	CeremonyStepUp       = "step_up"
)

// CeremonyTTL is how long the second step of a WebAuthn ceremony may take.
const CeremonyTTL = 5 * time.Minute

// CreateCeremony stores the server's half of a WebAuthn ceremony for
// userID (0: a passwordless sign-in, whose user is not known yet) and
// returns the secret for its cookie.
func (s *Store) CreateCeremony(ctx context.Context, userID int64, purpose string, data []byte) (string, error) {
	secret, _, err := auth.NewToken("wa")
	if err != nil {
		return "", err
	}
	var uid *int64
	if userID > 0 {
		uid = &userID
	}
	_, err = s.Pool.Exec(ctx, `INSERT INTO webauthn_ceremonies (token_hash, user_id, purpose, session_data, expires_at)
		VALUES ($1, $2, $3, $4, now() + make_interval(secs => $5))`, auth.HashToken(secret), uid, purpose, data, CeremonyTTL.Seconds())
	return secret, err
}

// TakeCeremony ends a live ceremony of purpose and returns its user (0 for
// passwordless) and data. Each ceremony is used once, whatever the result.
func (s *Store) TakeCeremony(ctx context.Context, secret, purpose string) (int64, []byte, error) {
	var uid *int64
	var data []byte
	var live bool
	err := s.Pool.QueryRow(ctx, `DELETE FROM webauthn_ceremonies WHERE token_hash = $1
		RETURNING user_id, session_data, purpose = $2 AND expires_at > now()`, auth.HashToken(secret), purpose).Scan(&uid, &data, &live)
	if err != nil {
		return 0, nil, notFound(err)
	}
	if !live {
		return 0, nil, ErrNotFound
	}
	var id int64
	if uid != nil {
		id = *uid
	}
	return id, data, nil
}
