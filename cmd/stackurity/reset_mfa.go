package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/stackurity/stackurity/internal/store"
	"github.com/stackurity/stackurity/internal/tenant"
)

// resetMFA is `stackurity admin reset-mfa`: the operator's way out for an
// account no admin can reset in the dashboard (a single admin whose only
// passkey is lost or marked as possibly copied, where only passkeys count
// for admins). It removes the account's second factors, ends its sessions,
// and records user.mfa_reset in every workspace the account belongs to
// (the platform's log when it belongs to none), as the dashboard's reset
// does in the workspace it is made from.
func resetMFA(ctx context.Context, st *store.Store, email string, w io.Writer) error {
	if strings.TrimSpace(email) == "" {
		return errors.New("--email is required")
	}
	r, err := st.ResetAccountMFA(ctx, email)
	if errors.Is(err, store.ErrNotFound) {
		return fmt.Errorf("no account has the address %q", email)
	}
	if err != nil {
		return err
	}
	actor := store.Actor{Type: "system", Name: "cli"}
	detail := map[string]any{"email": r.Email, "methods": r.Removed, "sessions_ended": r.SessionsEnded, "via": "stackurity admin reset-mfa"}
	scopes := []context.Context{tenant.System(ctx)}
	if len(r.Workspaces) > 0 {
		scopes = scopes[:0]
		for _, ws := range r.Workspaces {
			scopes = append(scopes, tenant.WithWorkspace(ctx, ws))
		}
	}
	var failed []string
	for _, c := range scopes {
		if err := st.Audit(c, actor, "user.mfa_reset", "user", fmt.Sprint(r.UserID), detail); err != nil {
			ws, _ := tenant.Workspace(c)
			failed = append(failed, fmt.Sprintf("workspace %d: %v", ws, err))
		}
	}
	fmt.Fprintf(w, "reset the two-factor sign-in of %s (user %d): removed %s and the recovery codes; %d sessions ended; recorded in %d audit logs\n",
		r.Email, r.UserID, strings.Join(r.Removed, ", "), r.SessionsEnded, len(scopes)-len(failed))
	fmt.Fprintln(w, "they sign in with their password and set up a second factor again")
	if len(failed) > 0 {
		return fmt.Errorf("the reset was made, but recording it in the audit log failed (%s)", strings.Join(failed, "; "))
	}
	return nil
}
