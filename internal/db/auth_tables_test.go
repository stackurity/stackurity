package db_test

func init() {
	// Account security (migrations 0053 onwards): accounts are global, and
	// these are read by user id before a workspace is known.
	for name, why := range map[string]string{
		"user_mfa":           "an account's second factor; accounts are global",
		"mfa_recovery_codes": "an account's recovery codes; accounts are global",
		"mfa_challenges":     "sign-in flow state, before a workspace is known",
		"password_resets":    "password reset links, used before anyone is signed in",
		// Migration 0066: passkeys and email codes.
		"webauthn_credentials": "an account's passkeys; accounts are global",
		"webauthn_ceremonies":  "sign-in and registration flow state, before a workspace is known",
		"user_email_mfa":       "an account's email-code second factor; accounts are global",
	} {
		globalTables[name] = why
	}
}
