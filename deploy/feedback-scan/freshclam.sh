#!/bin/bash
# Daily ClamAV signature update for scan.sh, in a throwaway container with
# a memory cap, at the lowest priority. Skipped while a release, build or
# rehearsal runs, or memory is short (the timer runs it again tomorrow, and
# scan.sh keeps using the last signatures).
set -euo pipefail
IMAGE="${FEEDBACK_SCAN_IMAGE:-clamav/clamav:1.5.4_base}"
DB_VOLUME="${FEEDBACK_SCAN_DB_VOLUME:-stackurity-clamav-db}"
MIN_FREE_MIB="${FEEDBACK_SCAN_MIN_FREE_MIB:-1740}"
log() { echo "feedback-freshclam: $*"; }

exec 9>/run/stackurity-feedback-scan.lock
flock -n 9 || { log "a scan is running; skipped"; exit 0; }
if { [ -e /run/stackurity-release.lock ] && ! flock -n /run/stackurity-release.lock true; } ||
	{ [ -e /run/stackurity-backup.lock ] && ! flock -n /run/stackurity-backup.lock true; }; then
	log "a release or backup is running; skipped"; exit 0
fi
if pgrep -f 'docker build|docker buildx|buildkitd|rehearse-' >/dev/null; then
	log "a build or rehearsal is running; skipped"; exit 0
fi
free_mib=$(awk '/^MemAvailable:/ {print int($2/1024)}' /proc/meminfo)
[ "$free_mib" -ge "$MIN_FREE_MIB" ] || { log "only ${free_mib} MiB available; skipped"; exit 0; }

nice -n 19 ionice -c 3 docker run --rm --cap-drop ALL --cap-add SETUID --cap-add SETGID --cap-add CHOWN \
	--security-opt no-new-privileges --memory 768m --memory-swap 768m --cpus 1 --cpu-shares 64 \
	-v "$DB_VOLUME":/var/lib/clamav --entrypoint freshclam "$IMAGE" --stdout --foreground
log "signatures updated"
