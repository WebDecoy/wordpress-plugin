#!/bin/bash
#
# WebDecoy WordPress Plugin Build Script
#
# Creates a distributable ZIP file for the WordPress plugin
# that can be uploaded to a CDN or WordPress marketplace.
#
# Usage: ./build.sh [version]
# Example: ./build.sh 1.0.0
#

set -e

# Configuration
PLUGIN_SLUG="webdecoy"
VERSION="${1:-1.0.0}"
BUILD_DIR="./build"
DIST_DIR="./dist"

echo "Building WebDecoy WordPress Plugin v${VERSION}"
echo "================================================"

# Clean previous builds
echo "Cleaning previous builds..."
rm -rf "${BUILD_DIR}"
rm -rf "${DIST_DIR}"
mkdir -p "${BUILD_DIR}/${PLUGIN_SLUG}"
mkdir -p "${DIST_DIR}"

# Copy plugin files into build directory
echo "Copying plugin files..."
rsync -a --exclude='build' --exclude='dist' --exclude='build.sh' . "${BUILD_DIR}/${PLUGIN_SLUG}/"

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

# Create ZIP file
echo "Creating ZIP archive..."
cd "${BUILD_DIR}"
zip -r "../${DIST_DIR}/${PLUGIN_SLUG}-${VERSION}.zip" "${PLUGIN_SLUG}" -x "*.DS_Store" -x "*__MACOSX*"
cd - > /dev/null

# Generate checksums
echo "Generating checksums..."
cd "${DIST_DIR}"
shasum -a 256 "${PLUGIN_SLUG}-${VERSION}.zip" > "${PLUGIN_SLUG}-${VERSION}.zip.sha256"
md5 -q "${PLUGIN_SLUG}-${VERSION}.zip" > "${PLUGIN_SLUG}-${VERSION}.zip.md5"
cd - > /dev/null

# Calculate file size
FILE_SIZE=$(ls -lh "${DIST_DIR}/${PLUGIN_SLUG}-${VERSION}.zip" | awk '{print $5}')

echo ""
echo "Build complete!"
echo "================================================"
echo "Output: ${DIST_DIR}/${PLUGIN_SLUG}-${VERSION}.zip"
echo "Size: ${FILE_SIZE}"
echo ""
echo "Checksums:"
cat "${DIST_DIR}/${PLUGIN_SLUG}-${VERSION}.zip.sha256"
echo "MD5: $(cat "${DIST_DIR}/${PLUGIN_SLUG}-${VERSION}.zip.md5")"
echo ""
echo "Upload to CDN or WordPress.org for distribution"
