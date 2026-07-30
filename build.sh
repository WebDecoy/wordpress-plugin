#!/bin/bash
#
# WebDecoy WordPress Plugin Build Script
#
# Creates a distributable ZIP file for the WordPress plugin
# that can be uploaded to a CDN or WordPress marketplace.
#
# Usage: ./build.sh [version] [--org]
# Example: ./build.sh 2.2.0            # CDN / self-hosted build (includes self-updater + clearance client)
#          ./build.sh 2.2.0 --org      # WordPress.org build (strips both — .org guideline compliance)
#

set -e

# Configuration
PLUGIN_SLUG="webdecoy"
BUILD_DIR="./build"
DIST_DIR="./dist"

# Parse args: a --org flag anywhere selects the WordPress.org variant; the
# remaining positional arg is the version.
ORG_BUILD=0
VERSION="1.0.0"
for arg in "$@"; do
    case "$arg" in
        --org) ORG_BUILD=1 ;;
        *) VERSION="$arg" ;;
    esac
done

if [ "$ORG_BUILD" = "1" ]; then
    ARTIFACT="${PLUGIN_SLUG}-${VERSION}-wporg"
    echo "Building WebDecoy WordPress Plugin v${VERSION} (WordPress.org variant)"
else
    ARTIFACT="${PLUGIN_SLUG}-${VERSION}"
    echo "Building WebDecoy WordPress Plugin v${VERSION}"
fi
echo "================================================"

# Clean previous builds
echo "Cleaning previous builds..."
rm -rf "${BUILD_DIR}"
rm -rf "${DIST_DIR}"
mkdir -p "${BUILD_DIR}/${PLUGIN_SLUG}"
mkdir -p "${DIST_DIR}"

# Copy plugin files into build directory
echo "Copying plugin files..."
# Excludes are anchored with a leading slash to the plugin root so we only drop
# the top-level dev vendor/ (composer dev tools) — NOT admin/js/vendor/, which
# holds the bundled Chart.js.
rsync -a \
    --exclude='/build' --exclude='/dist' --exclude='/build.sh' \
    --exclude='/.svn-wporg' \
    `# Every top-level dot entry. Named individually before, which meant each new` \
    `# editor or tool directory (.claude, .idea, .vscode, .cursor) silently entered` \
    `# the build and, from there, the WordPress.org SVN trunk. Nothing the plugin` \
    `# ships lives in a dotfile, so exclude the class rather than chasing members.` \
    --exclude='/.*' \
    --exclude='/vendor' --exclude='/sdk/vendor' \
    --exclude='node_modules' --exclude='/tests' \
    --exclude='/composer.json' --exclude='/composer.lock' \
    --exclude='/phpcs.xml.dist' --exclude='/phpstan.neon' \
    . "${BUILD_DIR}/${PLUGIN_SLUG}/"

# Update version in main plugin file
echo "Setting version to ${VERSION}..."
sed -i '' "s/Version: .*/Version: ${VERSION}/" "${BUILD_DIR}/${PLUGIN_SLUG}/webdecoy.php"
sed -i '' "s/define('WEBDECOY_VERSION', '.*');/define('WEBDECOY_VERSION', '${VERSION}');/" "${BUILD_DIR}/${PLUGIN_SLUG}/webdecoy.php"

# Install Composer dependencies (production only)
echo "Installing Composer dependencies..."
cd "${BUILD_DIR}/${PLUGIN_SLUG}/sdk"
if command -v composer &> /dev/null; then
    composer install --no-dev --optimize-autoloader --no-interaction 2>/dev/null || {
        echo "Composer install failed or no dependencies - continuing..."
    }
fi
cd - > /dev/null

# Remove development files
echo "Cleaning development files..."
find "${BUILD_DIR}" -name ".git*" -exec rm -rf {} + 2>/dev/null || true
find "${BUILD_DIR}" -name ".DS_Store" -exec rm -f {} + 2>/dev/null || true
find "${BUILD_DIR}" -name "*.md" -not -name "README.md" -exec rm -f {} + 2>/dev/null || true
find "${BUILD_DIR}" -name "phpunit.xml*" -exec rm -f {} + 2>/dev/null || true
find "${BUILD_DIR}" -name "phpcs.xml*" -exec rm -f {} + 2>/dev/null || true
find "${BUILD_DIR}" -name ".phpcs*" -exec rm -f {} + 2>/dev/null || true
find "${BUILD_DIR}" -name "tests" -type d -exec rm -rf {} + 2>/dev/null || true

# WordPress.org variant: strip the self-hosted update mechanism (forbidden on
# .org) and the bundled minified clearance client, plus CDN release tooling.
if [ "$ORG_BUILD" = "1" ]; then
    echo "Applying WordPress.org adjustments (removing self-updater + clearance client + CDN tooling)..."
    rm -f  "${BUILD_DIR}/${PLUGIN_SLUG}/includes/class-webdecoy-updater.php"
    rm -f  "${BUILD_DIR}/${PLUGIN_SLUG}/public/js/webdecoy-clearance.js"
    rm -rf "${BUILD_DIR}/${PLUGIN_SLUG}/cdn-files"
    rm -f  "${BUILD_DIR}/${PLUGIN_SLUG}/release.sh"
    rm -rf "${BUILD_DIR}/${PLUGIN_SLUG}/bin"
fi

# Create ZIP file (folder inside is always the slug, as WordPress requires)
echo "Creating ZIP archive..."
cd "${BUILD_DIR}"
zip -r "../${DIST_DIR}/${ARTIFACT}.zip" "${PLUGIN_SLUG}" -x "*.DS_Store" -x "*__MACOSX*"
cd - > /dev/null

# Generate checksums
echo "Generating checksums..."
cd "${DIST_DIR}"
shasum -a 256 "${ARTIFACT}.zip" > "${ARTIFACT}.zip.sha256"
md5 -q "${ARTIFACT}.zip" > "${ARTIFACT}.zip.md5"
cd - > /dev/null

# Calculate file size
FILE_SIZE=$(ls -lh "${DIST_DIR}/${ARTIFACT}.zip" | awk '{print $5}')

echo ""
echo "Build complete!"
echo "================================================"
echo "Output: ${DIST_DIR}/${ARTIFACT}.zip"
echo "Size: ${FILE_SIZE}"
echo ""
echo "Checksums:"
cat "${DIST_DIR}/${ARTIFACT}.zip.sha256"
echo "MD5: $(cat "${DIST_DIR}/${ARTIFACT}.zip.md5")"
echo ""
if [ "$ORG_BUILD" = "1" ]; then
    echo "WordPress.org submission ZIP — self-updater + clearance client excluded."
else
    echo "Upload to CDN for self-hosted distribution."
fi
