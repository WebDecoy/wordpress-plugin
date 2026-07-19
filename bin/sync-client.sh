#!/usr/bin/env bash
#
# Refresh the bundled @webdecoy/client browser script.
#
# The plugin serves the clearance-minting client from its own origin (bundled)
# rather than a CDN, per WordPress.org guidelines. This copies the built
# global bundle from the @webdecoy/node monorepo and prepends a provenance
# header. Run it whenever the pinned client version changes.
#
# Usage: bin/sync-client.sh [path-to-webdecoy-node-repo] [version]
#
set -euo pipefail

NODE_REPO="${1:-$HOME/Dev/webdecoy-node}"
VERSION="${2:-}"
SRC="${NODE_REPO}/packages/client/dist/webdecoy.global.js"
DEST="$(cd "$(dirname "$0")/.." && pwd)/public/js/webdecoy-clearance.js"

if [[ ! -f "$SRC" ]]; then
  echo "error: built bundle not found at $SRC" >&2
  echo "       build it first: (cd $NODE_REPO && npx turbo build --filter=@webdecoy/client)" >&2
  exit 1
fi

if [[ -z "$VERSION" ]]; then
  VERSION="$(grep '"version"' "${NODE_REPO}/packages/client/package.json" | head -1 | sed -E 's/.*"version": *"([^"]+)".*/\1/')"
fi

{
  echo "/*!"
  echo " * WebDecoy clearance client — bundled from @webdecoy/client v${VERSION}"
  echo " * Source: WebDecoy/node packages/client (dist/webdecoy.global.js)"
  echo " * DO NOT EDIT BY HAND. Refresh via bin/sync-client.sh when bumping the pinned version."
  echo " *"
  echo " * Silently mints a wd_clearance cookie for real browsers (idle-deferred,"
  echo " * once per session, no proof-of-work) so tripwire/decoy hits can be bound to"
  echo " * the actor's device fingerprint. The wdfp1 fingerprint algorithm is a"
  echo " * byte-exact cross-repo contract — never reimplement it here."
  echo " */"
  cat "$SRC"
} > "$DEST"

echo "synced @webdecoy/client v${VERSION} -> $DEST ($(wc -c < "$DEST" | tr -d ' ') bytes)"
