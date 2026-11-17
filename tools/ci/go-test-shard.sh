#!/usr/bin/env bash
# Runs one shard of the Go tests for the go job in ci.yml. Each shard runs
# on its own runner against its own PostgreSQL, so the slowest packages no
# longer share four cores and one database with everything else.
#
#   tools/ci/go-test-shard.sh api 1 3   a third of internal/api, by recorded time
#   tools/ci/go-test-shard.sh pkg ./internal/intel
#   tools/ci/go-test-shard.sh rest      every package not given a shard above
#
# Shards of one package split its top-level tests by the run times recorded
# in tools/ci/test-times.json (tools/testshard: longest first, onto the
# shard with the least time so far), so the shards finish together. Together
# they run every test exactly once; a new test counts as a median one until
# the times are refreshed with `make test-times`.
set -euo pipefail

flags=(-race -count=1 -timeout 40m)
# Packages with shards of their own (keep in step with the matrix in ci.yml).
own='/internal/(api|intel|store|notify)$'

case "${1:?usage: go-test-shard.sh api N OF | pkg PATH | rest}" in
api)
  n=${2:?} of=${3:?}
  names=$(go test -race -list '^Test' ./internal/api |
    go run ./tools/testshard -shard "$n" -of "$of" -times tools/ci/test-times.json)
  [ -n "$names" ] || { echo "no tests in shard $n of $of" >&2; exit 1; }
  echo "shard $n of $of: $(echo "$names" | wc -l) tests"
  go test "${flags[@]}" -run "^($(echo "$names" | paste -sd '|' -))\$" ./internal/api
  ;;
pkg)
  go test "${flags[@]}" "${2:?}"
  ;;
rest)
  # shellcheck disable=SC2046 # one argument per package
  go test "${flags[@]}" $(go list ./... | grep -Ev "$own")
  ;;
*)
  echo "unknown shard kind: $1" >&2
  exit 2
  ;;
esac
