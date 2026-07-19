#!/bin/bash
#
# WebDecoy WordPress Plugin Release Script
#
# Builds the plugin and prepares CDN files for deployment.
#
# Usage: ./release.sh <version>
# Example: ./release.sh 1.0.1
#

set -e

VERSION="$1"

if [ -z "$VERSION" ]; then
    echo "Usage: ./release.sh <version>"
    echo "Example: ./release.sh 1.0.1"
    exit 1
fi

echo "🚀 Releasing WebDecoy WordPress Plugin v${VERSION}"
echo "================================================"

# Build the plugin
./build.sh "$VERSION"

# Compute the SHA-256 of the built ZIP. The self-hosted updater REQUIRES this
# checksum in update-info.json and refuses to install a package whose hash does
# not match (prevents installing a tampered ZIP). build.sh also writes a
# dist/<zip>.sha256 file; we recompute here so release.sh is self-contained.
ZIP_PATH="./dist/webdecoy-${VERSION}.zip"
if [ ! -f "$ZIP_PATH" ]; then
    echo "❌ Build artifact not found: ${ZIP_PATH}"
    exit 1
fi
SHA256="$(shasum -a 256 "$ZIP_PATH" | awk '{print $1}')"
if ! printf '%s' "$SHA256" | grep -Eq '^[a-f0-9]{64}$'; then
    echo "❌ Failed to compute a valid SHA-256 for ${ZIP_PATH}"
    exit 1
fi
echo "🔐 Package SHA-256: ${SHA256}"

# Update CDN files
echo "📝 Updating CDN metadata files..."

CDN_DIR="./cdn-files"
mkdir -p "$CDN_DIR"

# Update update-info.json
# NOTE: "sha256" MUST be present and match the ZIP, or self-hosted auto-updates
# will be rejected by the plugin's upgrader_pre_download integrity check.
cat > "${CDN_DIR}/update-info.json" << EOF
{
    "version": "${VERSION}",
    "download_url": "https://cdn.webdecoy.com/wordpress/webdecoy-${VERSION}.zip",
    "sha256": "${SHA256}",
    "details_url": "https://webdecoy.com/wordpress/changelog",
    "tested": "6.7",
    "requires_php": "7.4",
    "icons": {
        "1x": "https://cdn.webdecoy.com/wordpress/assets/icon-128x128.png",
        "2x": "https://cdn.webdecoy.com/wordpress/assets/icon-256x256.png"
    },
    "banners": {
        "low": "https://cdn.webdecoy.com/wordpress/assets/banner-772x250.png",
        "high": "https://cdn.webdecoy.com/wordpress/assets/banner-1544x500.png"
    }
}
EOF

echo "✅ Wrote update-info.json with sha256=${SHA256}"

# Update version in plugin-info.json
sed -i '' "s/\"version\": \".*\"/\"version\": \"${VERSION}\"/" "${CDN_DIR}/plugin-info.json"
sed -i '' "s|webdecoy-.*\.zip|webdecoy-${VERSION}.zip|g" "${CDN_DIR}/plugin-info.json"

echo ""
echo "✅ Release v${VERSION} prepared!"
echo "================================================"
echo ""
echo "Files to upload to CDN (https://cdn.webdecoy.com/wordpress/):"
echo ""
echo "  dist/webdecoy-${VERSION}.zip"
echo "  cdn-files/update-info.json"
echo "  cdn-files/plugin-info.json"
echo ""
echo "CDN Directory Structure:"
echo ""
echo "  cdn.webdecoy.com/"
echo "  └── wordpress/"
echo "      ├── webdecoy-${VERSION}.zip"
echo "      ├── update-info.json"
echo "      ├── plugin-info.json"
echo "      └── assets/"
echo "          ├── icon-128x128.png"
echo "          ├── icon-256x256.png"
echo "          ├── banner-772x250.png"
echo "          └── banner-1544x500.png"
echo ""
echo "Upload commands (adjust for your CDN):"
echo ""
echo "  # AWS S3"
echo "  aws s3 cp dist/webdecoy-${VERSION}.zip s3://cdn-bucket/wordpress/"
echo "  aws s3 cp cdn-files/update-info.json s3://cdn-bucket/wordpress/"
echo "  aws s3 cp cdn-files/plugin-info.json s3://cdn-bucket/wordpress/"
echo ""
echo "  # Generic SCP"
echo "  scp dist/webdecoy-${VERSION}.zip user@cdn.webdecoy.com:/var/www/wordpress/"
echo "  scp cdn-files/*.json user@cdn.webdecoy.com:/var/www/wordpress/"
echo ""
