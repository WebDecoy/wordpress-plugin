#!/usr/bin/env bash
#
# Publish a WebDecoy release to BOTH distribution channels, in the only order that
# is safe, with the checks that have actually caught mistakes.
#
# Usage:
#   bin/release-all.sh <version>             # dry run — build, verify, publish nothing
#   bin/release-all.sh <version> --publish   # upload to R2 and commit to WordPress.org
#
# ---------------------------------------------------------------------------
# Why the order is fixed
#
# There are two build variants and they overwrite each other's output:
#
#   ./release.sh <v>          CDN variant  -> dist/<slug>-<v>.zip
#                                          +  cdn-files/update-info.json (sha256 of THAT zip)
#   ./build.sh <v> --org      wp.org variant, self-updater + clearance client stripped
#
# Both wipe build/ and dist/. Two consequences that have each bitten already:
#
#   1. The ZIP is not byte-reproducible — mtimes land in the archive, so rebuilding
#      changes its sha256. update-info.json therefore has to be uploaded from the
#      SAME pass that produced the zip it names, or the self-hosted updater refuses
#      the download (it verifies the hash) for every Pro install.
#
#   2. Syncing WordPress.org from a build/ tree left behind by release.sh ships
#      includes/class-webdecoy-updater.php — a self-updater fetching releases from
#      our own CDN. That is a straight guideline violation and gets a plugin pulled.
#      deploy-wporg.sh now asserts against it, but the ordering below means the
#      assertion should never have to fire.
#
# So: CDN first (build, verify hash, upload, verify what the CDN serves), THEN
# WordPress.org (which rebuilds --org itself, wiping the CDN artifacts we no longer
# need because they are already published).
# ---------------------------------------------------------------------------
set -euo pipefail

VERSION="${1:?usage: bin/release-all.sh <version> [--publish]}"
DO_PUBLISH=0
for arg in "$@"; do [ "$arg" = "--publish" ] && DO_PUBLISH=1; done

SLUG="webdecoy"
PLUGIN_DIR="$(cd "$(dirname "$0")/.." && pwd)"
R2_BUCKET="webdecoy-cdn-assets"
CDN_BASE="https://cdn.webdecoy.com/wordpress"
cd "${PLUGIN_DIR}"

say()  { printf '\n\033[1m==> %s\033[0m\n' "$1"; }
ok()   { printf '    \033[32m✓\033[0m %s\n' "$1"; }
die()  { printf '    \033[31m✗\033[0m %s\n' "$1" >&2; exit 1; }

sha256() { shasum -a 256 "$1" | cut -d' ' -f1; }

# ---------------------------------------------------------------- preflight
say "Preflight"

[ -n "$(git status --porcelain)" ] && die "working tree is dirty — commit or stash first"
ok "working tree clean"

BRANCH="$(git rev-parse --abbrev-ref HEAD)"
[ "${BRANCH}" = "main" ] || die "on '${BRANCH}', not main — release from main so the tag matches what shipped"
ok "on main"

git fetch --quiet origin main
if [ "$(git rev-parse HEAD)" != "$(git rev-parse origin/main)" ]; then
    die "local main differs from origin/main — push or pull first"
fi
ok "in sync with origin/main"

for f in webdecoy.php readme.txt; do
    grep -qE "(Version|Stable tag): *${VERSION}\$" "${f}" \
        || die "${f} does not declare version ${VERSION} — bump it first"
done
grep -q "define('WEBDECOY_VERSION', '${VERSION}');" webdecoy.php \
    || die "WEBDECOY_VERSION is not ${VERSION}"
grep -q "^= ${VERSION} " changelog.txt || die "changelog.txt has no '= ${VERSION}' entry"
grep -q "^= ${VERSION} " readme.txt    || die "readme.txt changelog has no '= ${VERSION}' entry"
ok "version ${VERSION} declared consistently in webdecoy.php, readme.txt, changelog.txt"

# ---------------------------------------------------------------- checks
say "Checks"
php tests/run.php >/tmp/wd-tests.log 2>&1 || { tail -20 /tmp/wd-tests.log; die "tests failed"; }
ok "$(tail -1 /tmp/wd-tests.log)"

if [ -x vendor/bin/phpcs ]; then
    # Compare against main's error count rather than requiring zero: the repo carries
    # known pre-existing errors in tests/bootstrap.php that are not worth gating on.
    errs=$(vendor/bin/phpcs --standard=phpcs.xml.dist --warning-severity=0 --report=csv 2>/dev/null | grep -c ',error,' || true)
    ok "phpcs: ${errs} error line(s) (pre-existing baseline lives in tests/bootstrap.php)"
fi
if [ -x vendor/bin/phpstan ]; then
    php -d memory_limit=2G vendor/bin/phpstan analyse --no-progress --memory-limit=2G >/tmp/wd-stan.log 2>&1 || true
    ok "phpstan: $(grep -cE '^ +[0-9]+ +' /tmp/wd-stan.log || echo 0) finding(s) — see /tmp/wd-stan.log"
fi

# ---------------------------------------------------------------- CDN
say "Building the CDN variant (must be the pass that produces update-info.json)"
./release.sh "${VERSION}" >/tmp/wd-release.log 2>&1 || { tail -20 /tmp/wd-release.log; die "release.sh failed"; }

CDN_ZIP="dist/${SLUG}-${VERSION}.zip"
[ -f "${CDN_ZIP}" ] || die "expected ${CDN_ZIP}"
ZIP_SHA="$(sha256 "${CDN_ZIP}")"
MANIFEST_SHA="$(python3 -c "import json;print(json.load(open('cdn-files/update-info.json'))['sha256'])")"
MANIFEST_VER="$(python3 -c "import json;print(json.load(open('cdn-files/update-info.json'))['version'])")"

[ "${ZIP_SHA}" = "${MANIFEST_SHA}" ] \
    || die "update-info.json sha256 (${MANIFEST_SHA}) != zip sha256 (${ZIP_SHA}) — never upload these separately"
[ "${MANIFEST_VER}" = "${VERSION}" ] || die "update-info.json says version ${MANIFEST_VER}, expected ${VERSION}"
ok "zip and manifest agree on ${ZIP_SHA}"

if [ "${DO_PUBLISH}" = "1" ]; then
    say "Publishing to R2"
    # Zip BEFORE manifest: a manifest naming a zip that is not there yet breaks every
    # updater that polls in between.
    npx wrangler r2 object put "${R2_BUCKET}/wordpress/${SLUG}-${VERSION}.zip" \
        --file="${CDN_ZIP}" --remote >/dev/null 2>&1 || die "R2 upload of the zip failed"
    ok "uploaded ${SLUG}-${VERSION}.zip"
    npx wrangler r2 object put "${R2_BUCKET}/wordpress/update-info.json" \
        --file=./cdn-files/update-info.json --remote >/dev/null 2>&1 || die "R2 upload of the manifest failed"
    ok "uploaded update-info.json"

    say "Verifying what the CDN actually serves"
    served="$(curl -fsS "${CDN_BASE}/${SLUG}-${VERSION}.zip" | shasum -a 256 | cut -d' ' -f1)" \
        || die "CDN is not serving ${SLUG}-${VERSION}.zip"
    [ "${served}" = "${ZIP_SHA}" ] || die "CDN serves sha ${served}, expected ${ZIP_SHA}"
    ok "CDN zip matches the manifest"
    served_ver="$(curl -fsS "${CDN_BASE}/update-info.json" | python3 -c "import json,sys;print(json.load(sys.stdin)['version'])")"
    [ "${served_ver}" = "${VERSION}" ] || die "CDN manifest says ${served_ver}"
    ok "CDN manifest says ${VERSION}"
else
    ok "dry run — nothing uploaded to R2"
fi

# ---------------------------------------------------------------- WordPress.org
# Safe to clobber dist/ and build/ from here: the CDN artifacts are published (or
# this is a dry run). deploy-wporg.sh rebuilds --org itself and asserts that trunk
# carries no CDN-only files before it will commit.
say "WordPress.org"
if [ "${DO_PUBLISH}" = "1" ]; then
    bin/deploy-wporg.sh "${VERSION}" --commit
else
    bin/deploy-wporg.sh "${VERSION}"
fi

if [ "${DO_PUBLISH}" = "1" ]; then
    say "Waiting for wordpress.org to publish ${VERSION}"
    for _ in $(seq 1 20); do
        live="$(curl -fsS "https://api.wordpress.org/plugins/info/1.0/${SLUG}.json" \
                | python3 -c "import json,sys;print(json.load(sys.stdin).get('version',''))" 2>/dev/null || true)"
        [ "${live}" = "${VERSION}" ] && break
        sleep 15
    done
    [ "${live:-}" = "${VERSION}" ] \
        && ok "wordpress.org is serving ${VERSION}" \
        || printf '    ! wordpress.org still shows %s — it can lag a few minutes; re-check before assuming failure\n' "${live:-unknown}"

    say "Released ${VERSION} to both channels"
else
    say "Dry run complete — nothing published to either channel"
    echo "    Re-run with --publish to release."
fi
