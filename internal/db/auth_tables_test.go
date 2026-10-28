package db_test

func init() {
	// Account security (migrations 0053 onwards): accounts are global, and
	// these are read by user id before a workspace is known.
	for name, why := range map[string]string{
		"user_mfa":           "an account's second factor; accounts are global",
		"mfa_recovery_codes": "an account's recovery codes; accounts are global",
		"mfa_challenges":     "sign-in flow state, before a workspace is known",
	} {
		globalTables[name] = why
	}
}
