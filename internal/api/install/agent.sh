#!/bin/sh
# Install or upgrade the Stackurity agent on a Linux host.
#
#   curl -fsSL __SERVER__/install/agent.sh | sudo STACKURITY_ENROLL_CODE=enr_... sh
#
# Add STACKURITY_DOCKER=1 to also check the images of running Docker
# containers. That gives the agent's user access to the Docker socket,
# which is equivalent to root on this host (see docs/install.md).
# STACKURITY_DOCKER=0 turns it off again; without either, an upgrade keeps
# the setting it had.
#
# Add STACKURITY_PROCESSES=1 to let the agent see which packages running
# processes use (CAP_SYS_PTRACE and CAP_DAC_READ_SEARCH, also equivalent to root; see
# docs/reachability.md). STACKURITY_PROCESSES=0 turns it off; an upgrade
# keeps the setting it had.
#
# It downloads the agent from your Stackurity server and checks its SHA-256,
# creates an unprivileged "stackurity" user, exchanges the one-time
# enrollment code for a collector token, and runs the agent as a hardened
# systemd service. Run it again (without a code) to upgrade the agent.
# The agent only reads: it never installs or changes software.
set -eu

# The server fills this in, single-quoted, from its own URL.
SERVER='__SERVER__'
SERVER="${STACKURITY_SERVER:-$SERVER}"
CODE="${STACKURITY_ENROLL_CODE:-}"
CONF=/etc/stackurity
BIN=/usr/local/bin/stackurity
UNIT=/etc/systemd/system/stackurity-agent.service

say() { printf 'stackurity: %s\n' "$*"; }
die() { printf 'stackurity: error: %s\n' "$*" >&2; exit 1; }

# is_local URL: true when URL is http:// to this machine (localhost,
# 127.0.0.0/8 or [::1], any port), e.g. an SSH tunnel. The host is parsed
# out whole, so http://127.0.0.1.evil.example is not local.
is_local() (
  rest=${1#http://}
  [ "$rest" != "$1" ] || exit 1
  hostport=${rest%%/*}
  hostport=${hostport%%\?*}
  hostport=${hostport%%#*}
  case $hostport in
    *@*) exit 1 ;;
    \[*\]) host=${hostport#\[}; host=${host%\]}; port= ;;
    \[*\]:*) host=${hostport%%\]:*}; host=${host#\[}; port=${hostport##*\]:} ;;
    \[*) exit 1 ;;
    *:*) host=${hostport%%:*}; port=${hostport#*:} ;;
    *) host=$hostport; port= ;;
  esac
  case $port in *[!0-9]*) exit 1 ;; esac
  case $host in
    localhost | ::1) exit 0 ;;
    127.*.*.*) ;;
    *) exit 1 ;;
  esac
  case $host in *[!0-9.]* | *..* | *.) exit 1 ;; esac
  set -f
  IFS=.
  # shellcheck disable=SC2086 # split on dots on purpose
  set -- $host
  [ $# = 4 ] || exit 1
  for o; do
    [ ${#o} -le 3 ] && [ "$o" -le 255 ] || exit 1
  done
)

[ "$(id -u)" = 0 ] || die "run as root (pipe to 'sudo sh')"
[ "$(uname -s)" = Linux ] || die "this installer is for Linux; on macOS use $SERVER/install/agent-macos.sh"
command -v systemctl >/dev/null 2>&1 || die "systemd is required"
case "$(uname -m)" in
  x86_64 | amd64) ARCH=amd64 ;;
  aarch64 | arm64) ARCH=arm64 ;;
  *) die "unsupported architecture $(uname -m)" ;;
esac
case "$SERVER" in
  https://*) ;;
  *) is_local "$SERVER" || [ "${STACKURITY_ALLOW_HTTP:-}" = 1 ] ||
    die "the server URL must use https (set STACKURITY_ALLOW_HTTP=1 to override)" ;;
esac
SERVER="${SERVER%/}"

if command -v curl >/dev/null 2>&1; then
  fetch() { curl -fsSL --proto '=https,http' -o "$2" "$1"; }
elif command -v wget >/dev/null 2>&1; then
  fetch() { wget -q -O "$2" "$1"; }
else
  die "curl or wget is required"
fi
command -v sha256sum >/dev/null 2>&1 || die "sha256sum is required"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
say "downloading the agent for linux/$ARCH from $SERVER"
fetch "$SERVER/download/agent/linux-$ARCH" "$TMP/stackurity" || die "download failed"
fetch "$SERVER/download/agent/linux-$ARCH.sha256" "$TMP/stackurity.sha256" || die "checksum download failed"
want="$(cut -d' ' -f1 "$TMP/stackurity.sha256")"
got="$(sha256sum "$TMP/stackurity" | cut -d' ' -f1)"
[ -n "$want" ] && [ "$want" = "$got" ] || die "checksum mismatch: refusing to install"
install -m 0755 "$TMP/stackurity" "$BIN"
say "installed $("$BIN" --version)"

if ! id stackurity >/dev/null 2>&1; then
  useradd --system --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin stackurity 2>/dev/null ||
    adduser -S -H -h /nonexistent -s /sbin/nologin stackurity
fi
install -d -m 0750 -o root -g stackurity "$CONF"

if [ ! -s "$CONF/token" ]; then
  [ -n "$CODE" ] || die "no enrollment code: create one under Assets > Add server and set STACKURITY_ENROLL_CODE"
  STACKURITY_ENROLL_CODE="$CODE" "$BIN" enroll --server "$SERVER" --dir "$CONF"
elif [ ! -f "$CONF/agent.env" ]; then
  # Installed by hand: its service unit holds settings this script cannot
  # know (application directories, an SSH tunnel), so leave it alone.
  say "the agent was installed by hand; replaced the binary only"
  if systemctl is-active --quiet stackurity-agent; then systemctl restart stackurity-agent; fi
  exit 0
else
  say "already enrolled; upgrading the agent only"
fi
chown root:stackurity "$CONF/token" "$CONF/agent.env"
chmod 0640 "$CONF/token" "$CONF/agent.env"

# Docker containers: opt-in, kept across upgrades.
DOCKER="${STACKURITY_DOCKER:-}"
if [ -z "$DOCKER" ] && grep -q '^STACKURITY_DOCKER=true$' "$CONF/agent.env"; then DOCKER=1; fi
SUPPLEMENTARY=""
case "$DOCKER" in
  1 | true)
    SOCK=/var/run/docker.sock
    [ -S "$SOCK" ] || die "STACKURITY_DOCKER=1: no Docker socket at $SOCK (is Docker running? rootless Docker is not supported)"
    GROUP="$(stat -c %G "$SOCK")"
    case "$GROUP" in
      "" | root | UNKNOWN) die "STACKURITY_DOCKER=1: $SOCK belongs to group '$GROUP'; the agent is only given a group made for Docker (usually 'docker')" ;;
    esac
    SUPPLEMENTARY="SupplementaryGroups=$GROUP"
    sed -i '/^STACKURITY_DOCKER=/d' "$CONF/agent.env"
    echo "STACKURITY_DOCKER=true" >>"$CONF/agent.env"
    say "Docker containers: the agent's user joins group '$GROUP' for $SOCK."
    say "warning: access to the Docker socket is equivalent to root on this host. The agent only lists containers and exports images; run with STACKURITY_DOCKER=0 to turn it off."
    ;;
  *)
    sed -i '/^STACKURITY_DOCKER=/d' "$CONF/agent.env"
    ;;
esac

# Process access: opt-in, kept across upgrades. It lets the agent see which
# programs and libraries running processes use, so packages nothing runs
# can be told apart (docs/reachability.md).
PROCS="${STACKURITY_PROCESSES:-}"
if [ -z "$PROCS" ] && grep -q '^STACKURITY_PROCESSES=true$' "$CONF/agent.env"; then PROCS=1; fi
CAPS="CapabilityBoundingSet="
case "$PROCS" in
  1 | true)
    CAPS="CapabilityBoundingSet=CAP_SYS_PTRACE CAP_DAC_READ_SEARCH
AmbientCapabilities=CAP_SYS_PTRACE CAP_DAC_READ_SEARCH
SystemCallFilter=~ptrace process_vm_readv process_vm_writev pidfd_getfd kcmp
StateDirectory=stackurity-agent
StateDirectoryMode=0700"
    sed -i '/^STACKURITY_PROCESSES=/d' "$CONF/agent.env"
    echo "STACKURITY_PROCESSES=true" >>"$CONF/agent.env"
    say "Process access: the agent reads each process's program, the file names in its memory map and its open sockets under /proc, and the crontabs that start programs (/var/spool/cron, closed to other users on Debian and Ubuntu)."
    say "warning: CAP_SYS_PTRACE and CAP_DAC_READ_SEARCH are equivalent to root on this host: a process holding them can read any process's memory (through /proc/<pid>/mem, which cannot be blocked) and any file. The agent never reads process memory or environments. Blocking the ptrace, process_vm, pidfd_getfd and kcmp system calls narrows what it can be made to do, but is not protection. Run with STACKURITY_PROCESSES=0 to turn it off."
    ;;
  *)
    sed -i '/^STACKURITY_PROCESSES=/d' "$CONF/agent.env"
    ;;
esac

cat >"$UNIT" <<UNIT
[Unit]
Description=Stackurity inventory agent (read-only)
After=network-online.target
Wants=network-online.target

[Service]
User=stackurity
EnvironmentFile=$CONF/agent.env
ExecStart=$BIN agent --interval 6h
$SUPPLEMENTARY
Restart=on-failure
RestartSec=60
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=read-only
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictSUIDSGID=yes
LockPersonality=yes
$CAPS
# A background job: the server's own work comes first.
Nice=10
IOSchedulingClass=best-effort
IOSchedulingPriority=7

[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload
systemctl enable --quiet stackurity-agent
systemctl restart stackurity-agent
say "the agent is running; it reports every 6 hours. Logs: journalctl -u stackurity-agent"
