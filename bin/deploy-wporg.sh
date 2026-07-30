#!/usr/bin/env bash
#
# Deploy an approved WebDecoy release to the WordPress.org plugin SVN repo.
#
# Prerequisites (all one-time, after the Plugins Team approves the plugin):
#   - The plugin is approved and its SVN repo exists at
#     https://plugins.svn.wordpress.org/webdecoy/
#   - `svn` is installed and you have wp.org commit access (you'll be prompted
#     for your wordpress.org username/password on commit).
#   - `rsvg-convert` is available to (re)generate the icon/banner PNGs from the
#     SVGs in assets/ (optional — skipped with a warning if missing).
#
# Usage:
#   bin/deploy-wporg.sh <version>            # stage everything, then PRINT the
#                                            # svn commit command (nothing is
#                                            # published — review first)
#   bin/deploy-wporg.sh <version> --commit   # stage AND commit/publish
#
# What it does: builds the .org variant, syncs it into SVN trunk/, refreshes the
# directory assets (icon/banner) in assets/, tags tags/<version>/, and either
# prints or runs the commit.
#
set -euo pipefail

VERSION="${1:?usage: bin/deploy-wporg.sh <version> [--commit]}"
DO_COMMIT=0
for arg in "$@"; do [ "$arg" = "--commit" ] && DO_COMMIT=1; done

SLUG="webdecoy"
PLUGIN_DIR="$(cd "$(dirname "$0")/.." && pwd)"
SVN_URL="https://plugins.svn.wordpress.org/${SLUG}"
BUILD_SRC="${PLUGIN_DIR}/build/${SLUG}"
SVN_DIR="${PLUGIN_DIR}/.svn-wporg"

echo "==> Building WordPress.org variant v${VERSION}"
cd "${PLUGIN_DIR}"
./build.sh "${VERSION}" --org >/dev/null
[ -d "${BUILD_SRC}" ] || { echo "error: build tree not found at ${BUILD_SRC}"; exit 1; }

echo "==> Checking out / updating SVN working copy"
if [ -d "${SVN_DIR}/.svn" ]; then
    svn update --quiet "${SVN_DIR}"
else
    svn checkout --quiet "${SVN_URL}" "${SVN_DIR}"
fi

echo "==> Syncing build tree into trunk/"
mkdir -p "${SVN_DIR}/trunk"
rsync -a --delete --exclude='.svn' "${BUILD_SRC}/" "${SVN_DIR}/trunk/"

echo "==> Refreshing directory assets (icon + banner)"
mkdir -p "${SVN_DIR}/assets"
if command -v rsvg-convert >/dev/null 2>&1; then
    rsvg-convert -w 128 -h 128  "${PLUGIN_DIR}/assets/icon.svg"   -o "${SVN_DIR}/assets/icon-128x128.png"
    rsvg-convert -w 256 -h 256  "${PLUGIN_DIR}/assets/icon.svg"   -o "${SVN_DIR}/assets/icon-256x256.png"
    rsvg-convert -w 772 -h 250  "${PLUGIN_DIR}/assets/banner.svg" -o "${SVN_DIR}/assets/banner-772x250.png"
    rsvg-convert -w 1544 -h 500 "${PLUGIN_DIR}/assets/banner.svg" -o "${SVN_DIR}/assets/banner-1544x500.png"
else
    echo "    ! rsvg-convert not found — add PNGs to ${SVN_DIR}/assets/ manually"
fi

echo "==> Asserting trunk carries nothing WordPress.org forbids"
# Two failure modes this has already caught in practice:
#   1. Syncing from a build/ tree left behind by release.sh (the CDN variant)
#      instead of the --org variant. That stages includes/class-webdecoy-updater.php,
#      a self-updater that pulls releases from our own CDN — an outright guideline
#      violation that gets plugins pulled from the directory.
#   2. rsync carrying local dotfile directories (.claude, .idea, .vscode) into trunk.
# Neither is visible in a casual `svn status` read, and both are unrecoverable once
# committed: wp.org SVN history is public and permanent.
WPORG_FORBIDDEN=(
    "includes/class-webdecoy-updater.php"
    "public/js/webdecoy-clearance.js"
    "release.sh"
    "build.sh"
    "cdn-files"
    "bin"
    "dist"
    "build"
    "tests"
    "vendor"
    "node_modules"
    "composer.json"
    "composer.lock"
    "phpcs.xml.dist"
    "phpstan.neon"
    ".svn-wporg"
)
violations=0
for path in "${WPORG_FORBIDDEN[@]}"; do
    if [ -e "${SVN_DIR}/trunk/${path}" ]; then
        echo "    ✗ trunk/${path} must not ship to WordPress.org"
        violations=$((violations + 1))
    fi
done
# Any dotfile or dot-directory at the top of trunk, other than SVN's own.
while IFS= read -r dotpath; do
    [ -z "${dotpath}" ] && continue
    echo "    ✗ ${dotpath#"${SVN_DIR}/"} is a local artifact and must not ship"
    violations=$((violations + 1))
done < <(find "${SVN_DIR}/trunk" -maxdepth 1 -name '.*' -not -name '.svn' -not -name 'trunk' 2>/dev/null)

if [ "${violations}" -gt 0 ]; then
    echo ""
    echo "error: ${violations} forbidden path(s) staged in trunk — refusing to continue."
    echo "       The usual cause is a stale build/ tree from release.sh. Fix with:"
    echo "         ./build.sh ${VERSION} --org && bin/deploy-wporg.sh ${VERSION}"
    echo "       Nothing has been committed. Run 'svn revert -R ${SVN_DIR}' to reset."
    exit 1
fi
echo "    ✓ clean"

echo "==> Asserting the staged version is the one requested"
for f in webdecoy.php readme.txt; do
    if ! grep -qE "(Version|Stable tag): *${VERSION}\$" "${SVN_DIR}/trunk/${f}"; then
        echo "error: trunk/${f} does not declare version ${VERSION}."
        echo "       Bump it on main and rebuild before deploying."
        exit 1
    fi
done
echo "    ✓ webdecoy.php and readme.txt both say ${VERSION}"

echo "==> Tagging tags/${VERSION}"
rm -rf "${SVN_DIR}/tags/${VERSION}"
mkdir -p "${SVN_DIR}/tags"
cp -R "${SVN_DIR}/trunk" "${SVN_DIR}/tags/${VERSION}"

echo "==> Reconciling svn add/delete"
cd "${SVN_DIR}"
# Add anything new; then delete anything gone from the working tree.
svn add --force trunk tags assets >/dev/null 2>&1 || true
svn status | awk '/^!/ {print $2}' | while read -r p; do svn delete --force "$p" >/dev/null 2>&1 || true; done

echo ""
echo "==> Staged. Summary:"
svn status | sed 's/^/    /'
echo ""

if [ "${DO_COMMIT}" = "1" ]; then
    echo "==> Committing to WordPress.org"
    svn ci -m "Release ${VERSION}"
    echo "Published v${VERSION} to https://wordpress.org/plugins/${SLUG}/"
else
    echo "Dry run complete (nothing published). Review the staged changes above, then run:"
    echo "    (cd ${SVN_DIR} && svn ci -m \"Release ${VERSION}\")"
    echo "or re-run: bin/deploy-wporg.sh ${VERSION} --commit"
fi
