# WordPress compatibility smoke test

What backs a `Tested up to:` bump. Spins up a throwaway WordPress in Docker
with the working tree mounted as the plugin and `WP_DEBUG_LOG` on, then walks
the plugin end to end. Not part of the shipped ZIPs (`tests/` is excluded).

```bash
cd tests/wp-compat
WP_IMAGE=wordpress:7.1-php8.3-apache docker compose up -d db wp   # any tag on hub.docker.com/_/wordpress
bash smoke.sh                                                      # ends with SMOKE OK, debug.log must be empty
bash woo.sh                                                        # installs latest WooCommerce; ends with WOO OK (WOO_VERSION=x.y.z to pin)
docker compose up -d proxy && bash proxy.sh                        # proxy notice behind nginx; ends with PROXY OK
docker compose run --rm cli plugin install plugin-check --activate # optional: what WordPress.org runs
docker compose run --rm cli plugin check webdecoy --ignore-warnings \
  --exclude-directories=vendor,tests,.git,.svn-wporg,dist,build,cdn-files,bin,.github
docker compose down -v                                             # throw the site away
```

`woo.sh` backs the `WC tested up to:` header the same way: block and classic
checkout, the honeytoken coupon, checkout velocity, order-status hooks under
HPOS, and the WooCommerce admin screens, from a fresh install's defaults.

The site is `http://localhost:8071`, admin `admin` / `admin`, if you want to
click around after the script. `WP_PORT` changes the port. Plugin Check will
also list the dev-repo files (`build.sh`, `.gitattributes`, the self-updater);
`build.sh --org` strips those, so only findings inside `includes/`, `admin/`,
`public/`, `templates/`, `sdk/`, or `webdecoy.php` matter.

`proxy.sh` puts an nginx reverse proxy (`http://localhost:8072`) in front of
the site and checks the "behind a proxy it has not been told about" notice in
each way a site can be reached: directly; through a proxy the host already
resolves (the official `wordpress` image ships `mod_remoteip` on, as
WordPress.com and most managed hosts effectively do, so `REMOTE_ADDR` is the
visitor while `X-Forwarded-For` is still passed); through a proxy nobody
resolved (`mod_remoteip` switched off, so `REMOTE_ADDR` is the proxy), where
the notice must show and its button must open the trusted-proxies field; and
with that proxy configured as trusted. 2.10.4 fails it on the false notice and
the button's 403; the script restores `mod_remoteip` on exit.
