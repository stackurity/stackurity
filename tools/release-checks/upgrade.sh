#!/usr/bin/env bash
# Release checks against a real installation of an earlier release:
#
#   upgrade   install PREVIOUS, load the demo estate, a second workspace and
#             findings, then start CURRENT on the same database: migrations
#             apply, /readyz is 200, the API answers, and every count is
#             unchanged.
#   restore   pg_dump the upgraded database, restore it into a new
#             PostgreSQL server (which has no stackurity_app role), start
#             CURRENT: ready, role recreated, counts unchanged.
#   mixed     versions: once CURRENT has migrated the database, PREVIOUS
#             must refuse to start (server and migrate) and leave the schema
#             as it is, and a PREVIOUS server already running must fail
#             /readyz. Only releases after 0.4.0 have this guard, and only a
#             CURRENT that adds migrations triggers it; otherwise the step
#             says why it was skipped.
#   rollback  the documented downgrade on the upgraded server: recreate the
#             database, restore the backup taken before the upgrade, start
#             PREVIOUS: ready, counts as before the upgrade; then upgrade
#             again.
#
# Usage: tools/release-checks/upgrade.sh PREVIOUS_IMAGE CURRENT_IMAGE
#   e.g. tools/release-checks/upgrade.sh ghcr.io/stackurity/stackurity:0.3.0 stackurity:ci
#
# Needs docker, curl and jq. Everything runs in throwaway containers on a
# private network, removed on exit.
set -euo pipefail

PREV=${1:?previous release image}
CUR=${2:?current build image}
PG_IMAGE=${PG_IMAGE:-postgres:17.6-alpine}
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
ID=stk-rc-$$
NET=$ID-net
PW='release-check-password-1'
WORK=$(mktemp -d)

log() { printf '\n== %s %s\n' "$(date +%T)" "$*"; }
# fail records a failed check and carries on; failures inside $(...) count too.
fail() { printf 'FAIL: %s\n' "$*" | tee -a "$WORK/failures" >&2; }

cleanup() {
	docker ps -aq --filter "name=^$ID-" | xargs -r docker rm -f >/dev/null 2>&1 || true
	docker network rm "$NET" >/dev/null 2>&1 || true
	rm -rf "$WORK"
}
trap cleanup EXIT

docker network create "$NET" >/dev/null

# postgres NAME: start a PostgreSQL server and wait until it accepts connections.
postgres() {
	docker run -d --name "$ID-$1" --network "$NET" -e POSTGRES_USER=stackurity -e POSTGRES_PASSWORD=stk \
		-e POSTGRES_DB=stackurity "$PG_IMAGE" >/dev/null
	for _ in $(seq 60); do
		if docker exec "$ID-$1" pg_isready -U stackurity -d stackurity -h 127.0.0.1 >/dev/null 2>&1; then
			return 0
		fi
		sleep 1
	done
	fail "postgres $1 did not start"
	exit 1
}

dburl() { echo "postgres://stackurity:stk@$ID-$1:5432/stackurity?sslmode=disable"; }

# cli IMAGE DB ARGS...: run a one-off stackurity command against database DB.
cli() {
	local img=$1 db=$2
	shift 2
	docker run --rm --network "$NET" -e STACKURITY_DATABASE_URL="$(dburl "$db")" -e STACKURITY_FEEDS=off \
		-e STACKURITY_PASSWORD="$PW" -e STACKURITY_LOG_FORMAT=text "$img" "$@"
}

# psql DB SQL: run SQL as the database owner (superuser, so row-level
# security does not hide other workspaces' rows).
psql() { docker exec -i "$ID-$1" psql -U stackurity -d stackurity -v ON_ERROR_STOP=1 -At -c "$2"; }

# counts DB: what must survive an upgrade, a restore and a rollback. Open
# and resolved findings are not compared: with feeds off the matcher may
# re-evaluate them, which is not data loss.
counts() {
	psql "$1" "SELECT 'workspaces', count(*)::text FROM workspaces
		UNION ALL SELECT 'users', count(*)::text FROM users
		UNION ALL SELECT 'members', count(*)::text FROM workspace_members
		UNION ALL SELECT 'assets ws' || workspace_id, count(*)::text FROM assets GROUP BY workspace_id
		UNION ALL SELECT 'identifiers', count(*)::text FROM asset_identifiers
		UNION ALL SELECT 'inventory', count(*)::text FROM inventory WHERE removed_at IS NULL
		UNION ALL SELECT 'findings', count(*)::text FROM findings
		UNION ALL SELECT 'tokens', count(*)::text FROM api_tokens
		UNION ALL SELECT 'digest assets', md5(string_agg(workspace_id || '/' || kind || '/' || name, ',' ORDER BY id)) FROM assets
		UNION ALL SELECT 'digest findings', md5(string_agg(asset_id || '/' || inventory_id || '/' || key, ',' ORDER BY id)) FROM findings
		ORDER BY 1"
}

# server NAME IMAGE DB [DOCKER-ARGS...]: start a server and wait for
# /readyz; prints the URL.
server() {
	local name=$1 img=$2 db=$3
	shift 3
	docker run -d --name "$ID-$name" --network "$NET" -p 127.0.0.1::8080 -e STACKURITY_DATABASE_URL="$(dburl "$db")" \
		-e STACKURITY_FEEDS=off -e STACKURITY_COOKIE_SECURE=false "$@" "$img" server >/dev/null
	local port url
	port=$(docker port "$ID-$name" 8080/tcp | head -1 | sed 's/.*://')
	url="http://127.0.0.1:$port"
	for _ in $(seq 90); do
		if [ "$(curl -s -o /dev/null -w '%{http_code}' "$url/readyz")" = 200 ]; then
			echo "$url"
			return 0
		fi
		if [ "$(docker inspect -f '{{.State.Running}}' "$ID-$name")" != true ]; then
			break
		fi
		sleep 1
	done
	docker logs "$ID-$name" >&2 || true
	fail "$name ($img) did not become ready"
	exit 1
}

# stop NAME: stop a server and keep its log; error-level lines fail the check.
stop() {
	docker stop -t 20 "$ID-$1" >/dev/null
	docker logs "$ID-$1" >"$WORK/$1.log" 2>&1
	if grep -E '"level":"ERROR"|level=ERROR' "$WORK/$1.log" >"$WORK/$1.errors"; then
		cat "$WORK/$1.errors" >&2
		fail "$1 logged errors"
	fi
	docker rm "$ID-$1" >/dev/null
}

# api URL: sign in as the admin and read through the API; prints the asset total.
api() {
	local url=$1 jar=$WORK/cookies code
	rm -f "$jar"
	code=$(curl -s -o "$WORK/login.json" -w '%{http_code}' -c "$jar" -H 'Content-Type: application/json' -H 'X-Stackurity-CSRF: 1' \
		-d "{\"email\":\"admin@example.com\",\"password\":\"$PW\"}" "$url/api/v1/auth/login")
	[ "$code" = 200 ] || { cat "$WORK/login.json" >&2; fail "sign-in returned $code"; return 0; }
	for path in /api/v1/overview /api/v1/findings /api/v1/inventory /api/v1/incidents; do
		code=$(curl -s -o /dev/null -w '%{http_code}' -b "$jar" "$url$path")
		[ "$code" = 200 ] || fail "GET $path returned $code"
	done
	curl -s -b "$jar" "$url/api/v1/assets?limit=1" | jq -r '.total'
}

# has_schema_guard IMAGE: whether the release refuses a database a newer
# version migrated. Releases up to 0.4.0 do not; a build from source does.
has_schema_guard() {
	local v
	v=$(docker run --rm "$1" --version | awk '{print $NF}')
	v=${v#v}
	case "$v" in "" | dev) return 0 ;; esac
	[ "$(printf '%s\n%s\n' "$v" 0.4.0 | sort -V | tail -1)" != 0.4.0 ]
}

# refuses NAME IMAGE DB ARGS...: the command must exit non-zero with the
# newer-schema error within a minute.
refuses() {
	local name=$1 img=$2 db=$3 code
	shift 3
	docker run -d --name "$ID-$name" --network "$NET" -e STACKURITY_DATABASE_URL="$(dburl "$db")" \
		-e STACKURITY_FEEDS=off -e STACKURITY_LOG_FORMAT=text "$img" "$@" >/dev/null
	for _ in $(seq 60); do
		[ "$(docker inspect -f '{{.State.Running}}' "$ID-$name")" = true ] || break
		sleep 1
	done
	if [ "$(docker inspect -f '{{.State.Running}}' "$ID-$name")" = true ]; then
		fail "$img $* started against a database a newer version migrated"
	else
		code=$(docker inspect -f '{{.State.ExitCode}}' "$ID-$name")
		docker logs "$ID-$name" >"$WORK/$name.log" 2>&1
		if [ "$code" = 0 ] || ! grep -q 'upgraded by a newer Stackurity' "$WORK/$name.log"; then
			cat "$WORK/$name.log" >&2
			fail "$img $* exited $code without the newer-schema error"
		else
			echo "$img $* refused the newer schema (exit $code)"
		fi
	fi
	docker rm -f "$ID-$name" >/dev/null
}

same() {
	if ! diff -u "$WORK/$1" "$WORK/$2"; then
		fail "$3: counts differ ($1 vs $2)"
	else
		echo "counts unchanged ($3)"
	fi
}

log "install $PREV"
postgres old-db
cli "$PREV" old-db migrate
cli "$PREV" old-db admin create-user --email admin@example.com --name Admin --role admin
cli "$PREV" old-db admin load-demo
cli "$PREV" old-db admin create-workspace --name "Second org" --admin-email second@example.com
cli "$PREV" old-db admin create-token --name agent >/dev/null
url=$(server old "$PREV" old-db)
api "$url" >"$WORK/assets-prev"
stop old
# Findings as the matcher records them (feeds are off here): one per
# installed package that has none yet, two of them resolved.
psql old-db "INSERT INTO findings (workspace_id, kind, key, inventory_id, asset_id, component_id, verification, severity, fixed_version)
	SELECT i.workspace_id, 'vulnerability', 'CVE-2099-' || i.id, i.id, i.asset_id, i.component_id, 'confirmed', 'high', '99.0'
	FROM inventory i WHERE i.removed_at IS NULL ON CONFLICT DO NOTHING" >/dev/null
psql old-db "UPDATE findings SET status = 'resolved', resolved_at = now() WHERE id IN (SELECT id FROM findings ORDER BY id LIMIT 2)" >/dev/null
prev_migrations=$(psql old-db "SELECT count(*) FROM schema_migrations")
counts old-db >"$WORK/before"
cat "$WORK/before"
grep -q '^workspaces|2$' "$WORK/before" || fail "expected two workspaces"
grep -q '^findings|[1-9]' "$WORK/before" || fail "expected findings"
docker exec "$ID-old-db" pg_dump -U stackurity -Fc stackurity >"$WORK/pre-upgrade.dump"

want=$(ls "$ROOT"/internal/db/migrations/*.sql | wc -l | tr -d ' ')
mixed=""
if [ "$want" -le "$prev_migrations" ]; then
	mixed="$CUR adds no migration to the $prev_migrations of $PREV"
elif ! has_schema_guard "$PREV"; then
	mixed="$PREV predates the newer-schema guard (added after 0.4.0)"
fi
if [ -z "$mixed" ]; then
	# A replica of the previous version still running when the upgrade
	# starts: it must notice and fail /readyz.
	stale_url=$(server stale "$PREV" old-db -e STACKURITY_TEST_TIMINGS=schema-check=2s)
fi

log "upgrade to $CUR"
url=$(server new "$CUR" old-db)
got=$(psql old-db "SELECT count(*) FROM schema_migrations")
[ "$got" = "$want" ] || fail "schema_migrations has $got entries, the build has $want migrations"
api "$url" >"$WORK/assets-new"
same assets-prev assets-new "API asset total"
cli "$CUR" old-db admin list-workspaces

log "mixed versions: $PREV against the database $CUR migrated"
if [ -n "$mixed" ]; then
	echo "skipped: $mixed"
else
	code=""
	for _ in $(seq 30); do
		code=$(curl -s -o "$WORK/stale-readyz.json" -w '%{http_code}' "$stale_url/readyz" || true)
		[ "$code" = 503 ] && break
		sleep 1
	done
	if [ "$code" = 503 ] && grep -q schema_newer "$WORK/stale-readyz.json"; then
		echo "running $PREV replica fails /readyz: $(jq -r .error.message "$WORK/stale-readyz.json")"
	else
		fail "running $PREV replica: /readyz returned $code, want 503 schema_newer"
	fi
	docker rm -f "$ID-stale" >/dev/null
	migrations_before=$(psql old-db "SELECT string_agg(name, ',' ORDER BY name) FROM schema_migrations")
	refuses old-server "$PREV" old-db server
	refuses old-migrate "$PREV" old-db migrate
	[ "$(psql old-db "SELECT string_agg(name, ',' ORDER BY name) FROM schema_migrations")" = "$migrations_before" ] ||
		fail "$PREV changed schema_migrations of a newer database"
fi
stop new
counts old-db >"$WORK/after-upgrade"
same before after-upgrade upgrade

log "backup the upgraded database and restore it into a new server"
docker exec "$ID-old-db" pg_dump -U stackurity -Fc stackurity >"$WORK/upgraded.dump"
postgres restored-db
# A new server has no stackurity_app role: pg_restore reports those grants
# and exits 1 (docs/install.md); any other error fails the check.
docker exec -i "$ID-restored-db" pg_restore -U stackurity -d stackurity --clean --if-exists <"$WORK/upgraded.dump" 2>"$WORK/restore.err" || true
if grep -i 'error' "$WORK/restore.err" | grep -v 'stackurity_app' | grep -v 'errors ignored on restore' >&2; then
	fail "pg_restore reported errors other than the missing role"
fi
url=$(server restored "$CUR" restored-db)
[ "$(psql restored-db "SELECT count(*) FROM pg_roles WHERE rolname = 'stackurity_app'")" = 1 ] || fail "stackurity_app role was not recreated"
api "$url" >"$WORK/assets-restored"
same assets-prev assets-restored "API asset total after restore"
stop restored
counts restored-db >"$WORK/after-restore"
same after-upgrade after-restore restore

log "roll back in place: recreate the database, restore the pre-upgrade backup, start $PREV"
# The procedure in docs/install.md (Upgrading > Rolling back), on the
# upgraded server itself.
psql_admin() { docker exec -i "$ID-old-db" psql -U stackurity -d postgres -v ON_ERROR_STOP=1 -q -c "$1"; }
psql_admin "DROP DATABASE stackurity WITH (FORCE)"
psql_admin "CREATE DATABASE stackurity"
docker exec -i "$ID-old-db" pg_restore -U stackurity -d stackurity <"$WORK/pre-upgrade.dump" || fail "pg_restore of the pre-upgrade backup failed"
url=$(server rolledback "$PREV" old-db)
api "$url" >"$WORK/assets-rolledback"
same assets-prev assets-rolledback "API asset total after rollback"
stop rolledback
counts old-db >"$WORK/after-rollback"
same before after-rollback rollback
# Upgrading again after a rollback works too.
url=$(server again "$CUR" old-db)
stop again
counts old-db >"$WORK/after-reupgrade"
same before after-reupgrade "upgrade after rollback"

if [ -s "$WORK/failures" ]; then
	log "release checks FAILED ($PREV -> $CUR)"
	exit 1
fi
log "release checks passed ($PREV -> $CUR)"
