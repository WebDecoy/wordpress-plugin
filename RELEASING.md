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
