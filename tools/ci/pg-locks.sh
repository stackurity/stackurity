#!/usr/bin/env bash
# Raises max_locks_per_transaction on the job's PostgreSQL service container
# and restarts it. GitHub service containers cannot take server flags, and
# the default (64) runs out under the migration-heavy parallel tests:
# "out of shared memory (SQLSTATE 53200)" failed random tests on main
# (internal/ask, cmd/stackurity, Workspace isolation). Local test databases
# already use 512 (Makefile test-ee notes).
set -euo pipefail

cid=$(docker ps -q --filter "publish=5432")
if [ -z "$cid" ]; then
  echo "no PostgreSQL service container on port 5432" >&2
  exit 1
fi
docker exec "$cid" psql -U "${PGUSER:-stackurity}" -d postgres -qc "ALTER SYSTEM SET max_locks_per_transaction = 512"
docker restart "$cid" >/dev/null
for _ in $(seq 1 60); do
  if docker exec "$cid" pg_isready -U "${PGUSER:-stackurity}" -q; then
    docker exec "$cid" psql -U "${PGUSER:-stackurity}" -d postgres -Atc "SHOW max_locks_per_transaction"
    exit 0
  fi
  sleep 1
done
echo "PostgreSQL did not come back after the restart" >&2
exit 1
