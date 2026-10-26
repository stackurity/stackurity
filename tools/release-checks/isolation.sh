#!/usr/bin/env bash
# The workspace-isolation suite: every test that shows one workspace cannot
# read, count, change or delete another's data, and that the database
# enforces it (row-level security). A failure, a skip or a missing test
# blocks the pull request and the release (docs/security-audit.md,
# "Tenant-isolation incidents"). The same tests also run in ci.yml's go job;
# this script runs them by name so the result is its own required check,
# and fails if one of them was renamed or deleted without updating the list.
#
# Usage: STACKURITY_TEST_DATABASE_URL=postgres://... tools/release-checks/isolation.sh [go test flags]
#   e.g. for the licensed build: tools/release-checks/isolation.sh -tags ee -overlay ee-overlay.json
set -euo pipefail

: "${STACKURITY_TEST_DATABASE_URL:?set STACKURITY_TEST_DATABASE_URL to a PostgreSQL the tests may create databases in}"
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
cd "$ROOT"

TESTS=(
  # internal/api: every route classified and swept with every kind of
  # credential from another workspace.
  TestEveryRouteIsClassified
  TestIsolationSweep
  TestWorkspaceIsolation
  TestSearchWorkspaceIsolation
  TestCrossWorkspaceReferences
  TestNoScopeSeesNothing
  TestWorkspaceSecrets
  TestWorkspaceMembership
  TestWorkspaceAdminCannotTakeOverInstanceAdmin
  TestCredentialChangesTakeEffectImmediately
  TestPluginsNeedCredentialsOutsideDefault
  # internal/db: row-level security on every workspace table, and the
  # application role that cannot bypass it.
  TestEveryTenantTableHasRowLevelSecurity
  TestMigrateRestoresAppRoleGrants
  # internal/store, internal/notify, internal/worker
  TestReferencesStayInTheirWorkspace
  TestOutcomesAreWorkspaceScoped
  TestSharedSetupTokenAndPlatformIsolation
  TestRateLimitPlatformIsolation
  TestJiraWorkspaceBoundaries
  TestEveryWorkspaceScopes
)
PACKAGES=(./internal/api ./internal/db ./internal/store ./internal/notify ./internal/worker)

pattern="^($(IFS='|'; echo "${TESTS[*]}"))\$"
out=$(mktemp)
trap 'rm -f "$out"' EXIT
status=0
go test -count=1 -race -v "$@" -run "$pattern" "${PACKAGES[@]}" >"$out" 2>&1 || status=$?
grep -E '^(--- |ok |FAIL|panic)' "$out" || true

missing=()
for t in "${TESTS[@]}"; do
  grep -qE "^--- PASS: $t \(" "$out" || missing+=("$t")
done
if [ "$status" -ne 0 ] || [ "${#missing[@]}" -gt 0 ]; then
  [ "$status" -ne 0 ] && tail -100 "$out"
  [ "${#missing[@]}" -gt 0 ] && echo "isolation: did not pass (failed, skipped or no longer exists): ${missing[*]}"
  echo "isolation: FAILED. This blocks the release; see docs/security-audit.md, Tenant-isolation incidents."
  exit 1
fi
echo "isolation: all ${#TESTS[@]} tests passed"
