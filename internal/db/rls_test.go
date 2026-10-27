package db_test

import (
	"context"
	"sort"
	"strings"
	"testing"

	"github.com/stackurity/stackurity/internal/tenant"
	"github.com/stackurity/stackurity/internal/testdb"
)

// globalTables hold no workspace data and are read without a workspace
// scope (docs/design/workspaces.md). Every other table must enforce
// row-level security; a new table that does not fails this test until it
// is given policies or added here with a reason.
var globalTables = map[string]string{
	"advisories":            "public intelligence",
	"advisory_packages":     "public intelligence",
	"feed_pending_packages": "public intelligence: packages a feed sync changed, before re-evaluation is queued",
	"feeds":                 "public intelligence; changed only by instance admins",
	"known_exploited":       "public intelligence",
	"lifecycle_cycles":      "public intelligence",
	"lifecycle_products":    "public intelligence",
	"license_key":           "installation licence",
	"oidc_logins":           "sign-in flow state, before a workspace is known",
	"packs":                 "stack packs, installed by instance admins",
	"schema_migrations":     "migration bookkeeping",
	"users":                 "accounts are global; roles live in workspace_members",
	"workspaces":            "the workspaces themselves",
	"sessions":              "looked up before the workspace is known; carries the active workspace",
	"workspace_members":     "memberships span workspaces; read by user id",
}

func TestEveryTenantTableHasRowLevelSecurity(t *testing.T) {
	pool := testdb.New(t)
	rows, err := pool.Query(tenant.System(context.Background()), `SELECT c.relname, c.relrowsecurity, c.relforcerowsecurity,
		(SELECT count(*) FROM pg_policy p WHERE p.polrelid = c.oid)
		FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
		WHERE n.nspname = current_schema() AND c.relkind = 'r' ORDER BY 1`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var bad []string
	for rows.Next() {
		var name string
		var rls, force bool
		var policies int
		if err := rows.Scan(&name, &rls, &force, &policies); err != nil {
			t.Fatal(err)
		}
		if _, ok := globalTables[name]; ok {
			continue
		}
		if !rls || !force || policies == 0 {
			bad = append(bad, name)
		}
	}
	sort.Strings(bad)
	if len(bad) > 0 {
		t.Errorf("tables without enforced row-level security: %s", strings.Join(bad, ", "))
	}
}
