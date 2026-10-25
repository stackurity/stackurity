#!/bin/sh
# Install or upgrade the Stackurity agent on a Linux host.
#
#   curl -fsSL __SERVER__/install/agent.sh | sudo STACKURITY_ENROLL_CODE=enr_... sh
#
# It downloads the agent from your Stackurity server and checks its SHA-256,
# creates an unprivileged "stackurity" user, exchanges the one-time
# enrollment code for a collector token, and runs the agent as a hardened
# systemd service. Run it again (without a code) to upgrade the agent.
# The agent only reads: it never installs or changes software.
set -eu

SERVER="${STACKURITY_SERVER:-__SERVER__}"
CODE="${STACKURITY_ENROLL_CODE:-}"
CONF=/etc/stackurity
BIN=/usr/local/bin/stackurity
UNIT=/etc/systemd/system/stackurity-agent.service

say() { printf 'stackurity: %s\n' "$*"; }
die() { printf 'stackurity: error: %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" = 0 ] || die "run as root (pipe to 'sudo sh')"
[ "$(uname -s)" = Linux ] || die "this installer is for Linux; see the documentation for other systems"
command -v systemctl >/dev/null 2>&1 || die "systemd is required"
case "$(uname -m)" in
  x86_64 | amd64) ARCH=amd64 ;;
  aarch64 | arm64) ARCH=arm64 ;;
  *) die "unsupported architecture $(uname -m)" ;;
esac
case "$SERVER" in
  https://*) ;;
  http://127.0.0.1* | http://localhost* | http://\[::1\]*) ;; # a local port, e.g. an SSH tunnel
  *) [ "${STACKURITY_ALLOW_HTTP:-}" = 1 ] || die "the server URL must use https (set STACKURITY_ALLOW_HTTP=1 to override)" ;;
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

cat >"$UNIT" <<UNIT
[Unit]
Description=Stackurity inventory agent (read-only)
After=network-online.target
Wants=network-online.target

[Service]
User=stackurity
EnvironmentFile=$CONF/agent.env
ExecStart=$BIN agent --interval 6h
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
CapabilityBoundingSet=

[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload
systemctl enable --quiet stackurity-agent
systemctl restart stackurity-agent
say "the agent is running; it reports every 6 hours. Logs: journalctl -u stackurity-agent"
