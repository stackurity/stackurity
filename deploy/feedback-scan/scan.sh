#!/bin/bash
# On-demand virus scan of feedback attachments (docs/feedback-queue.md).
#
# Run by a systemd timer on the host of the server that runs the feedback
# queue with STACKURITY_FEEDBACK_SCAN=required. It asks the server which
# attachments wait for a scan, runs clamscan once over them in a throwaway
# container (memory-capped, no network, read-only, lowest CPU and I/O
# priority), and reports each verdict. Nothing stays resident between runs.
#
# It does nothing, and the timer tries again later, while:
#   - another scan runs, or a release holds /run/stackurity-release.lock;
#   - a build or migration rehearsal runs (docker build, buildx, buildkitd,
#     rehearse-*.sh);
#   - the host has less than FEEDBACK_SCAN_MIN_FREE_MIB available.
#
# Settings (environment, e.g. from /etc/stackurity/feedback-scan.env):
#   FEEDBACK_SCAN_API        server base URL      (default http://127.0.0.1:8180)
#   FEEDBACK_SCAN_TOKEN_FILE scanner token file   (a stkfb_ token with scope "scanner")
#   FEEDBACK_SCAN_DIR        the queue's directory on the host (the data volume)
#   FEEDBACK_SCAN_IMAGE      ClamAV image, pinned (default below)
#   FEEDBACK_SCAN_DB_VOLUME  volume holding the signatures (default stackurity-clamav-db)
#   FEEDBACK_SCAN_MEMORY     container memory cap (default 1536m)
#   FEEDBACK_SCAN_MIN_FREE_MIB  (default 1740)
#
# Exit 0 also when it skipped; it logs why to the journal.

set -euo pipefail

API="${FEEDBACK_SCAN_API:-http://127.0.0.1:8180}"
TOKEN_FILE="${FEEDBACK_SCAN_TOKEN_FILE:-/opt/stackurity/secrets/feedback_scanner_token}"
DIR="${FEEDBACK_SCAN_DIR:?set FEEDBACK_SCAN_DIR to the feedback queue directory on the host}"
IMAGE="${FEEDBACK_SCAN_IMAGE:-clamav/clamav:1.5.4_base}"
DB_VOLUME="${FEEDBACK_SCAN_DB_VOLUME:-stackurity-clamav-db}"
MEMORY="${FEEDBACK_SCAN_MEMORY:-1536m}"
MIN_FREE_MIB="${FEEDBACK_SCAN_MIN_FREE_MIB:-1740}"

log() { echo "feedback-scan: $*"; }

# One scan at a time.
exec 9>/run/stackurity-feedback-scan.lock
flock -n 9 || { log "another scan is running; skipped"; exit 0; }

# Not during a release (release scripts hold this lock while they run).
if { [ -e /run/stackurity-release.lock ] && ! flock -n /run/stackurity-release.lock true; } ||
	{ [ -e /run/stackurity-backup.lock ] && ! flock -n /run/stackurity-backup.lock true; }; then
	log "a release or backup is running; skipped"
	exit 0
fi
if pgrep -f 'docker build|docker buildx|buildkitd|rehearse-' >/dev/null; then
	log "a build or rehearsal is running; skipped"
	exit 0
fi
free_mib=$(awk '/^MemAvailable:/ {print int($2/1024)}' /proc/meminfo)
if [ "$free_mib" -lt "$MIN_FREE_MIB" ]; then
	log "only ${free_mib} MiB available (need ${MIN_FREE_MIB}); skipped"
	exit 0
fi

token=$(cat "$TOKEN_FILE")
api() { curl -sS --fail --max-time 30 -H "Authorization: Bearer $token" -H 'Content-Type: application/json' "$@"; }

pending=$(api "$API/api/v1/admin/feedback/scan/pending")
mapfile -t rows < <(jq -r '.attachments[] | "\(.id) \(.storage_key)"' <<<"$pending")
[ "${#rows[@]}" -gt 0 ] || exit 0

if ! docker volume inspect "$DB_VOLUME" >/dev/null 2>&1; then
	log "no signatures yet (run freshclam.sh); skipped"
	exit 0
fi

declare -A key_of
files=()
for row in "${rows[@]}"; do
	id=${row%% *}
	key=${row#* }
	# Keys are 32 hex characters; anything else is not passed to the scanner.
	[[ "$key" =~ ^[0-9a-f]{32}$ ]] || { log "skipping attachment $id: unexpected key"; continue; }
	[ -f "$DIR/$key" ] || { log "attachment $id: file missing"; continue; }
	key_of[$key]=$id
	files+=("/scan/$key")
done
[ "${#files[@]}" -gt 0 ] || exit 0

log "scanning ${#files[@]} attachment(s) with ${free_mib} MiB available"
out=$(mktemp)
trap 'rm -f "$out"' EXIT
set +e
nice -n 19 ionice -c 3 docker run --rm --network none --read-only --cap-drop ALL \
	--security-opt no-new-privileges --memory "$MEMORY" --memory-swap "$MEMORY" --cpus 1 --cpu-shares 64 \
	--pids-limit 64 --tmpfs /tmp:size=64m \
	-v "$DB_VOLUME":/var/lib/clamav:ro -v "$DIR":/scan:ro \
	--entrypoint clamscan "$IMAGE" --no-summary --stdout --database=/var/lib/clamav \
	--max-filesize=60M --max-scansize=200M "${files[@]}" >"$out" 2>&1
rc=$?
set -e
# clamscan: 0 nothing found, 1 something found, 2 an error. Only lines that
# name a file get a verdict; on an error the rest stay pending.
if [ "$rc" -gt 1 ]; then
	log "clamscan failed (exit $rc); attachments stay pending: $(tail -n 3 "$out" | tr '\n' ' ')"
fi
while IFS= read -r line; do
	if [[ "$line" =~ ^/scan/([0-9a-f]{32}):\ OK$ ]]; then
		key=${BASH_REMATCH[1]}
		api -X POST "$API/api/v1/admin/feedback/scan/${key_of[$key]}" -d '{"result":"clean"}' >/dev/null
	elif [[ "$line" =~ ^/scan/([0-9a-f]{32}):\ ([A-Za-z0-9._:/+-]{1,200})\ FOUND$ ]]; then
		key=${BASH_REMATCH[1]}
		sig=${BASH_REMATCH[2]}
		api -X POST "$API/api/v1/admin/feedback/scan/${key_of[$key]}" \
			-d "$(jq -cn --arg s "$sig" '{result:"infected",signature:$s}')" >/dev/null
		log "attachment ${key_of[$key]} flagged: $sig"
	fi
done <"$out"
log "done (clamscan exit $rc)"
