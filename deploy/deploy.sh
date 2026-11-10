#!/usr/bin/env bash
# Install or update the passkey two-factor module in a WHMCS installation.
# Usage: DOCROOT=/path/to/whmcs ./deploy/deploy.sh
set -euo pipefail

DOCROOT="${DOCROOT:?set DOCROOT to the WHMCS document root}"
SRC="$(cd "$(dirname "$0")/.." && pwd)/modules/security/webauthn"
DEST="$DOCROOT/modules/security/webauthn"

[ -d "$DOCROOT/modules/security" ] || { echo "No modules/security under $DOCROOT" >&2; exit 1; }

if [ -d "$DEST" ]; then
    BACKUP="$DOCROOT/modules/security/.webauthn.bak-$(date +%Y%m%d%H%M%S)"
    echo "Backing up the installed module to $BACKUP"
    cp -a "$DEST" "$BACKUP"
fi

mkdir -p "$DEST"
cp -R "$SRC/." "$DEST/"

# Match the owner of the neighbouring modules, when we are allowed to.
chown -R --reference="$DOCROOT/modules/security" "$DEST" 2>/dev/null || true

echo "Installed to $DEST"
echo "Activate it under Configuration > System Settings > Two-Factor Authentication."
