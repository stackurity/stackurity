#!/bin/bash
# Which releases in the upgrade matrix (release-checks.yml, `from:`) this run
# tests an upgrade from. Prints a JSON list.
#
#   tools/release-checks/select.sh full    # one release per database schema
#   tools/release-checks/select.sh quick   # the oldest and the two newest
#
# Releases with the same migrations upgrade through the same steps, so
# "full" keeps the newest release of each set of migrations (69 releases
# were 39 schemas on 23 Nov 2026). "quick" is for pull requests that change
# no migration and nothing under tools/release-checks/: they cannot change
# what an upgrade runs, and the release still runs "full" on its tag.
#
# Needs the release tags (vX.Y.Z) in the checkout. Plain bash 3 (macOS).
set -euo pipefail
mode=${1:-full}
cd "$(dirname "$0")/../.."
versions=$(grep -o 'from: \[[^]]*\]' .github/workflows/release-checks.yml | head -1 | grep -oE '"[0-9]+\.[0-9]+\.[0-9]+"' | tr -d '"')
[ -n "$versions" ] || { echo "select.sh: no from: list in release-checks.yml" >&2; exit 1; }

if [ "$mode" = quick ]; then
  { echo "$versions" | head -1; echo "$versions" | tail -2; } | awk '!seen[$0]++' | jq -R . | jq -sc .
  exit 0
fi

# full: "<migrations key> <version>" per release, then the newest release of
# each key, in the order the keys first appear. A missing tag fails rather
# than silently testing less.
for v in $versions; do
  git rev-parse -q --verify "refs/tags/v$v" >/dev/null || { echo "select.sh: tag v$v not found (fetch the tags)" >&2; exit 1; }
  key=$(git ls-tree --name-only "v$v" internal/db/migrations/ | grep '\.sql$' | shasum -a 256 | cut -c1-16)
  echo "$key $v"
done | awk '{ if (!($1 in last)) order[n++] = $1; last[$1] = $2 } END { for (i = 0; i < n; i++) print last[order[i]] }' | jq -R . | jq -sc .
