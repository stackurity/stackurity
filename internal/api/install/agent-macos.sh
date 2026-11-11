#!/bin/sh
# Install or upgrade the Stackurity agent on a Mac.
#
#   curl -fsSL __SERVER__/install/agent-macos.sh | sudo STACKURITY_ENROLL_CODE=enr_... sh
#
# It downloads the agent from your Stackurity server and checks its SHA-256,
# creates a hidden, unprivileged "_stackurity" account, exchanges the
# one-time enrollment code for a collector token, and runs the agent as a
# LaunchDaemon under that account. Run it again (without a code) to upgrade
# the agent; with STACKURITY_UNINSTALL=1 it removes everything it installed.
# The agent only reads: it never installs or changes software, and it needs
# no root to read /Applications and Homebrew.
#
# MDM: run the same command as root from a policy script, with a code that
# allows as many uses as Macs in scope.
set -eu

SERVER='__SERVER__'
SERVER="${STACKURITY_SERVER:-$SERVER}"
CODE="${STACKURITY_ENROLL_CODE:-}"
LABEL=com.stackurity.agent
HOME_DIR="/Library/Application Support/Stackurity"
BIN="$HOME_DIR/bin/stackurity"
CONF="$HOME_DIR/conf"
LOGS=/Library/Logs/Stackurity
PLIST="/Library/LaunchDaemons/$LABEL.plist"
ROTATE=/etc/newsyslog.d/stackurity.conf
ACCOUNT=_stackurity

say() { printf 'stackurity: %s\n' "$*"; }
die() { printf 'stackurity: error: %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" = 0 ] || die "run as root (pipe to 'sudo sh')"
[ "$(uname -s)" = Darwin ] || die "this installer is for macOS; on Linux use $SERVER/install/agent.sh"

if [ "${STACKURITY_UNINSTALL:-}" = 1 ]; then
  launchctl bootout "system/$LABEL" 2>/dev/null || true
  rm -f "$PLIST" "$ROTATE"
  rm -rf "$HOME_DIR" "$LOGS"
  if dscl . -read "/Users/$ACCOUNT" >/dev/null 2>&1; then dscl . -delete "/Users/$ACCOUNT"; fi
  if dscl . -read "/Groups/$ACCOUNT" >/dev/null 2>&1; then dscl . -delete "/Groups/$ACCOUNT"; fi
  say "removed the agent. Its host stays on the server until an admin deletes it (and its token under Integrations > API tokens)."
  exit 0
fi

# Apple silicon reports x86_64 to a shell running under Rosetta.
if [ "$(sysctl -n hw.optional.arm64 2>/dev/null || echo 0)" = 1 ]; then
  ARCH=arm64
else
  case "$(uname -m)" in
    x86_64) ARCH=amd64 ;;
    arm64) ARCH=arm64 ;;
    *) die "unsupported architecture $(uname -m)" ;;
  esac
fi

# is_local reports whether URL $1 is plain HTTP to this machine (an SSH
# tunnel): localhost, 127.0.0.0/8 or [::1], with an optional numeric port.
# The whole host is compared, so http://127.0.0.1.example.com is not local.
is_local() (
  rest="${1#http://}"
  hostport="${rest%%/*}"
  case "$hostport" in *@*) return 1 ;; esac
  case "$hostport" in
    \[::1\]) return 0 ;;
    \[::1\]:*) port="${hostport#\[::1\]:}" ;;
    *:*) host="${hostport%:*}"; port="${hostport##*:}" ;;
    *) host="$hostport"; port= ;;
  esac
  if [ -n "${port:-}" ]; then
    case "$port" in *[!0-9]*) return 1 ;; esac
  fi
  case "${host:-}" in
    "") return 0 ;; # [::1]:port
    localhost) return 0 ;;
  esac
  IFS=. read -r a b c d extra <<EOF
$host
EOF
  [ "$a" = 127 ] && [ -z "$extra" ] || return 1
  for o in "$b" "$c" "$d"; do
    case "$o" in "" | *[!0-9]*) return 1 ;; esac
    [ "$o" -le 255 ] || return 1
  done
)

case "$SERVER" in
  https://*) ;;
  http://*)
    if ! is_local "$SERVER" && [ "${STACKURITY_ALLOW_HTTP:-}" != 1 ]; then
      die "the server URL must use https (set STACKURITY_ALLOW_HTTP=1 to override)"
    fi
    ;;
  *) die "the server URL must start with https://" ;;
esac
SERVER="${SERVER%/}"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
fetch() { curl -fsSL --proto '=https,http' -o "$2" "$1"; }
say "downloading the agent for darwin/$ARCH from $SERVER"
fetch "$SERVER/download/agent/darwin-$ARCH" "$TMP/stackurity" || die "download failed"
fetch "$SERVER/download/agent/darwin-$ARCH.sha256" "$TMP/stackurity.sha256" || die "checksum download failed"
want="$(cut -d' ' -f1 "$TMP/stackurity.sha256")"
got="$(shasum -a 256 "$TMP/stackurity" | cut -d' ' -f1)"
[ -n "$want" ] && [ "$want" = "$got" ] || die "checksum mismatch: refusing to install"
install -d -m 0755 -o root -g wheel "$HOME_DIR" "$HOME_DIR/bin"
install -m 0755 -o root -g wheel "$TMP/stackurity" "$BIN"
say "installed $("$BIN" --version)"

# A dedicated hidden account, like Apple's own daemons (_www, _postgres):
# nobody's token file would be readable by every other daemon running as
# nobody. The ID is the first free one from 401 to 499 (below 500, so the
# account is not listed as a person).
if ! dscl . -read "/Users/$ACCOUNT" >/dev/null 2>&1; then
  used="$( (dscl . -list /Users UniqueID; dscl . -list /Groups PrimaryGroupID) | awk '{print $2}')"
  id=401
  while [ "$id" -lt 500 ] && printf '%s\n' "$used" | grep -qx "$id"; do id=$((id + 1)); done
  [ "$id" -lt 500 ] || die "no free account ID between 401 and 499"
  dscl . -create "/Groups/$ACCOUNT"
  dscl . -create "/Groups/$ACCOUNT" PrimaryGroupID "$id"
  dscl . -create "/Groups/$ACCOUNT" RealName "Stackurity agent"
  dscl . -create "/Groups/$ACCOUNT" Password '*'
  dscl . -create "/Users/$ACCOUNT"
  dscl . -create "/Users/$ACCOUNT" UniqueID "$id"
  dscl . -create "/Users/$ACCOUNT" PrimaryGroupID "$id"
  dscl . -create "/Users/$ACCOUNT" UserShell /usr/bin/false
  dscl . -create "/Users/$ACCOUNT" NFSHomeDirectory /var/empty
  dscl . -create "/Users/$ACCOUNT" RealName "Stackurity agent"
  dscl . -create "/Users/$ACCOUNT" Password '*'
  dscl . -create "/Users/$ACCOUNT" IsHidden 1
  say "created the $ACCOUNT account (ID $id)"
fi
install -d -m 0750 -o root -g "$ACCOUNT" "$CONF"
install -d -m 0750 -o "$ACCOUNT" -g "$ACCOUNT" "$LOGS"

if [ ! -s "$CONF/token" ]; then
  [ -n "$CODE" ] || die "no enrollment code: create one under Assets > Add server and set STACKURITY_ENROLL_CODE"
  STACKURITY_ENROLL_CODE="$CODE" "$BIN" enroll --server "$SERVER" --dir "$CONF"
elif [ ! -f "$CONF/agent.env" ]; then
  # Installed by hand: its LaunchDaemon holds settings this script cannot
  # know, so leave it alone.
  say "the agent was installed by hand; replaced the binary only"
  launchctl kickstart -k "system/$LABEL" 2>/dev/null || true
  exit 0
else
  say "already enrolled; upgrading the agent only"
fi
chown root:"$ACCOUNT" "$CONF/token" "$CONF/agent.env"
chmod 0640 "$CONF/token" "$CONF/agent.env"

# xml escapes a value for the property list.
xml() { printf '%s' "$1" | sed -e 's/&/\&amp;/g' -e 's/</\&lt;/g' -e 's/>/\&gt;/g'; }

# The daemon's environment, from the settings enroll wrote. Only
# STACKURITY_ variables are taken; nothing in the file is run.
envxml=""
while IFS= read -r line || [ -n "$line" ]; do
  key="${line%%=*}"
  val="${line#*=}"
  case "$key" in
    *[!A-Z0-9_]*) continue ;;
    STACKURITY_?*) ;;
    *) continue ;;
  esac
  envxml="$envxml
    <key>$key</key><string>$(xml "$val")</string>"
done <"$CONF/agent.env"

cat >"$TMP/agent.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>$LABEL</string>
  <key>ProgramArguments</key>
  <array>
    <string>$(xml "$BIN")</string>
    <string>agent</string>
    <string>--interval</string>
    <string>6h</string>
  </array>
  <key>UserName</key><string>$ACCOUNT</string>
  <key>GroupName</key><string>$ACCOUNT</string>
  <key>EnvironmentVariables</key>
  <dict>$envxml
  </dict>
  <key>WorkingDirectory</key><string>/var/empty</string>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>ThrottleInterval</key><integer>60</integer>
  <key>Umask</key><integer>23</integer>
  <!-- A background job: the Mac's own work comes first. -->
  <key>ProcessType</key><string>Background</string>
  <key>LowPriorityIO</key><true/>
  <key>Nice</key><integer>10</integer>
  <key>StandardOutPath</key><string>$LOGS/agent.log</string>
  <key>StandardErrorPath</key><string>$LOGS/agent.log</string>
</dict>
</plist>
PLIST
# Keep five compressed 1 MB logs (newsyslog runs from launchd).
printf '%s\n' "$LOGS/agent.log $ACCOUNT:$ACCOUNT 640 5 1024 * JN" >"$ROTATE"
plutil -lint -s "$TMP/agent.plist" || die "generated an invalid LaunchDaemon property list"
install -m 0644 -o root -g wheel "$TMP/agent.plist" "$PLIST"
launchctl bootout "system/$LABEL" 2>/dev/null || true
launchctl bootstrap system "$PLIST"
launchctl enable "system/$LABEL"
say "the agent is running; it reports every 6 hours. Logs: $LOGS/agent.log"
