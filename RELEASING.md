# Releasing the WebDecoy WordPress plugin

**This repository (`WebDecoy/wordpress-plugin`) is the canonical home of the
plugin.** Releases are cut here. The copy under `php-sdk/wordpress/` in the app
monorepo is a deprecated mirror — do not develop or release from it.

## 1. Bump the version

Update the version string in **all** of these:

1. `webdecoy.php` — the `Version:` header and the `WEBDECOY_VERSION` constant
2. `readme.txt` — `Stable tag:` and the changelog section
3. `changelog.txt` — add the new version entry at the top

The SDK `User-Agent` derives from `WEBDECOY_VERSION` automatically — nothing to
bump there.

## Two distribution channels / two builds

There are two builds from one codebase:

- **CDN / self-hosted** — `./build.sh <version>` → `dist/webdecoy-<version>.zip`. Includes the self-hosted updater (`includes/class-webdecoy-updater.php`) and the bundled clearance client (`public/js/webdecoy-clearance.js`). This is what `release.sh` builds and uploads to the CDN.
- **WordPress.org** — `./build.sh <version> --org` → `dist/webdecoy-<version>-wporg.zip`. Strips the self-updater (the directory forbids self-updating plugins) and the minified clearance client, and drops CDN release tooling. This is what you submit to / commit to WordPress.org SVN. Chart.js is bundled locally in both builds.

## 2. Build + prepare CDN metadata

```bash
./release.sh <version>     # e.g. ./release.sh 2.2.1  (CDN build)
```

This runs `build.sh`, produces `dist/webdecoy-<version>.zip`, and regenerates
`cdn-files/update-info.json` with the ZIP's SHA-256 (the self-hosted updater
rejects a package whose hash doesn't match). `cdn-files/update-info.json` is
git-ignored on purpose — it's a per-build artifact, uploaded to the CDN rather
than committed. `cdn-files/plugin-info.json` (the "View details" metadata) is
tracked; bump its `version`/`download_url`/changelog when they change.

## 3. Upload to the CDN

The plugin ZIP and CDN JSON are hosted on Cloudflare R2
(`webdecoy-cdn-assets` bucket, served at `https://cdn.webdecoy.com/wordpress/`):

```bash
npx wrangler r2 object put webdecoy-cdn-assets/wordpress/webdecoy-<version>.zip \
  --file=./dist/webdecoy-<version>.zip --remote
npx wrangler r2 object put webdecoy-cdn-assets/wordpress/update-info.json \
  --file=./cdn-files/update-info.json --remote
npx wrangler r2 object put webdecoy-cdn-assets/wordpress/plugin-info.json \
  --file=./cdn-files/plugin-info.json --remote
```

Self-hosted auto-updates are gated behind the `WEBDECOY_SELF_HOSTED` constant
and read `update-info.json` from the CDN — so the CDN's `update-info.json` must
always point at a ZIP that actually exists there with a matching SHA-256.

## 4. Tag

```bash
git tag -a v<version> -m "v<version> — <summary>"
git push origin v<version>
```

## 5. WordPress.org SVN release

The directory listing at <https://wordpress.org/plugins/webdecoy> is driven by
the SVN repo (`https://plugins.svn.wordpress.org/webdecoy`). A working copy
lives at `.svn-wporg/` (git-ignored, excluded from builds). Credentials:
username `webdecoy1`, SVN password set separately at
<https://profiles.wordpress.org/me/profile/edit/group/3/?screen=svn-password>.

```bash
./build.sh <version> --org
rm -rf .svn-wporg/trunk/* && unzip -q dist/webdecoy-<version>-wporg.zip -d /tmp/wporg
cp -R /tmp/wporg/webdecoy/. .svn-wporg/trunk/ && rm -rf /tmp/wporg
cd .svn-wporg
svn add --force trunk assets
svn status   # sanity-check: no unexpected deletes/adds; `svn rm` any removed files
svn ci -m "Release <version>" --username webdecoy1
svn cp trunk tags/<version>
svn ci -m "Tag <version>" --username webdecoy1
```

`readme.txt`'s `Stable tag:` must match the SVN tag name — the directory serves
whatever tag `Stable tag:` in `trunk/readme.txt` points at. Listing images
(icon/banner PNGs, regenerated from `assets/*.svg` per `assets/README.md`) and
`screenshot-N.png` files go in the SVN top-level `assets/` dir, not trunk.
