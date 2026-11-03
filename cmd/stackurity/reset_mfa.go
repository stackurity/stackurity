package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/stackurity/stackurity/internal/store"
)

// resetMFA is `stackurity admin reset-mfa`: the operator's way out for an
// account no admin can reset in the dashboard (a single admin whose only
// passkey is lost or marked as possibly copied, where only passkeys count
// for admins). It removes the account's second factors and ends its
// sessions; user.mfa_reset is recorded in every workspace the account
// belongs to (the platform's log when it belongs to none) in the same
// transaction, so a reset without its record cannot happen.
func resetMFA(ctx context.Context, st *store.Store, email string, w io.Writer) error {
	if strings.TrimSpace(email) == "" {
		return errors.New("--email is required")
	}
	r, err := st.ResetAccountMFA(ctx, email, store.Actor{Type: "system", Name: "cli"}, "stackurity admin reset-mfa")
	if errors.Is(err, store.ErrNotFound) {
		return fmt.Errorf("no account has the address %q", email)
	}
	if err != nil {
		return err
	}
	logs := max(len(r.Workspaces), 1)
	fmt.Fprintf(w, "reset the two-factor sign-in of %s (user %d): removed %s and the recovery codes; %d sessions ended; recorded in %d audit logs\n",
		r.Email, r.UserID, strings.Join(r.Removed, ", "), r.SessionsEnded, logs)
	fmt.Fprintln(w, "they sign in with their password and set up a second factor again")
	return nil
}
