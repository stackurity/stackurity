#!/bin/sh
# Builds the Stackurity Teams app package (a zip of manifest.json and the two
# icons) to upload in the Teams admin center or with "Upload a custom app".
#
#   TEAMS_APP_ID=<Microsoft App ID> BASE_URL=https://stackurity.example.com \
#     scripts/teams-app-package.sh [out.zip]
#
# TEAMS_APP_ID is the Azure Bot's Microsoft App ID (STACKURITY_TEAMS_APP_ID).
# BASE_URL is the server's STACKURITY_BASE_URL; its host goes in validDomains.
# Optional: PRIVACY_URL, TERMS_URL, WEBSITE_URL, APP_VERSION (default 1.0.0).
# See docs/teams-app.md.
set -eu

: "${TEAMS_APP_ID:?set TEAMS_APP_ID to the bot's Microsoft App ID}"
: "${BASE_URL:?set BASE_URL to the server's STACKURITY_BASE_URL}"
out=${1:-stackurity-teams-app.zip}
src=$(cd "$(dirname "$0")/../docs/teams-app" && pwd)

if ! printf '%s' "$TEAMS_APP_ID" | grep -Eq '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'; then
  echo "TEAMS_APP_ID must be a GUID" >&2
  exit 2
fi
host=$(printf '%s' "$BASE_URL" | sed -E 's#^https://([^/:]+).*$#\1#')
case "$BASE_URL" in
  https://*) ;;
  *) echo "BASE_URL must start with https://" >&2; exit 2 ;;
esac

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
id=$(printf '%s' "$TEAMS_APP_ID" | tr 'A-F' 'a-f')
sed -e "s#00000000-0000-0000-0000-000000000000#$id#g" \
    -e "s#\"app.stackurity.dev\"#\"$host\"#" \
    -e "s#\"version\": \"1.0.0\"#\"version\": \"${APP_VERSION:-1.0.0}\"#" \
    ${PRIVACY_URL:+-e "s#\"privacyUrl\": \"[^\"]*\"#\"privacyUrl\": \"$PRIVACY_URL\"#"} \
    ${TERMS_URL:+-e "s#\"termsOfUseUrl\": \"[^\"]*\"#\"termsOfUseUrl\": \"$TERMS_URL\"#"} \
    ${WEBSITE_URL:+-e "s#\"websiteUrl\": \"[^\"]*\"#\"websiteUrl\": \"$WEBSITE_URL\"#"} \
    "$src/manifest.json" > "$tmp/manifest.json"
cp "$src/color.png" "$src/outline.png" "$tmp/"
case "$out" in
  /*) dest=$out ;;
  *) dest=$(pwd)/$out ;;
esac
rm -f "$dest"
(cd "$tmp" && zip -q -X "$dest" manifest.json color.png outline.png)
echo "wrote $dest (app id $id, valid domain $host)"
