# Installed-plugin HTTP compatibility fixture

Disposable local tests only. This changes plugin activation/settings and creates
an administrator in the supplied **test database**. It never targets production.
It requires Docker, Python3, cached `wordpress:7.1-php8.3-apache` and `mariadb:11`
images, and an existing temporary WordPress7.1.4 tree with these public plugins:
WebDecoy2.11.4, Redirection5.10.1, WPS Hide Login1.9.20, Wordfence9.1.1.
Do not copy production files or credentials into the fixture.

The source tree is mounted read-only. Writable DB, logs, uploads and Wordfence
storage are bounded tmpfs. Both services share a namespace with only loopback;
no ports are published and vendor downloads/cloud reporting cannot work.
`run.py` refuses an unlabeled container, exposed host ports, a writable root,
or a shared namespace whose database has external networking.

## Prepare an existing temporary source tree

Set `COMPAT_WORDPRESS_DIR` to a fresh, disposable WordPress directory with the
four plugin packages already extracted under `wp-content/plugins`. This fixture
does not download or install dependencies. The supplied configuration contains
public dummy credentials only.

From this directory:

```sh
cp wp-config.fixture.php "$COMPAT_WORDPRESS_DIR/wp-config.php"
mkdir -p "$COMPAT_WORDPRESS_DIR/wp-content/mu-plugins" "$COMPAT_WORDPRESS_DIR/wp-content/uploads" "$COMPAT_WORDPRESS_DIR/wp-content/wflogs"
cp observer.fixture.php "$COMPAT_WORDPRESS_DIR/wp-content/mu-plugins/compat-observer.php"
docker compose -p wd-plugin-stack up -d
export WP_COMPAT_CONTAINER=$(docker compose -p wd-plugin-stack ps -q wp)
export WP_COMPAT_OUTPUT=/tmp/wd-plugin-stack-results
docker exec "$WP_COMPAT_CONTAINER" php /fixture/control.php install
python3 run.py
python3 run.py --waf-enabled
```

The default run covers six plugin/load-order scenarios. The enforcement run
covers two combined-stack orders with a manually configured Wordfence UA block.
A test-only trusted-loopback proxy supplies `192.0.2.42` through `X-Real-IP` so
Wordfence's loopback allowlist does not mask the blocking check. This is a
controlled fixture identity, not a production proxy configuration recommendation.

## Native Wordfence prepend mode

Start a second listener on a different address in the same private loopback
namespace. There is deliberately **no router script**: PHP's native index
fallback must execute `auto_prepend_file` for pretty URLs as well as PHP files.
The client preserves the original host/port with `CURLOPT_CONNECT_TO`.

```sh
docker exec -d "$WP_COMPAT_CONTAINER" sh -c 'exec php -d auto_prepend_file=/fixture/wordfence-waf.php -d display_errors=0 -d log_errors=1 -d error_log=/scratch/php-extended-errors.log -d memory_limit=128M -d max_execution_time=10 -d session.save_path=/scratch -S 127.0.0.3:8080 -t /site > /scratch/extended-server.log 2>&1'
python3 run.py --extended
```

Every case must match exactly one independent server receipt and its status.
Every extended-mode receipt must prove `WFWAF_AUTO_PREPEND=true`; Wordfence's
manual deny must occur before WordPress loads. Each run uses unique markers and
cookie jars and resets only fixture IP blocks between scenarios. A PHP failure,
timeout, missing SQL record, wrong redirect/login result, or wrong crawler-counter
increment fails the run. The `X-Compat-Case` observer never logs passwords/cookies.

AI cases spoof GPTBot's UA solely to exercise the counter, and assert it is not
counted as a verified identity. This tests no external vendor rule feed or cloud
reporting. The client-side scanner is disabled; browser JavaScript, Apache/FPM,
multisite, actual proxies/CDNs and full-page caches need separate validation.
Wordfence uses an unlicensed offline install and a local manual UA rule, not
licensed signatures. These are synthetic cases, never customer traffic/efficacy.

## Clean up

The database and runtime files are tmpfs; removal discards the whole test site.
The output directory contains only parsed measurements and can be retained.

```sh
docker compose -p wd-plugin-stack down
```
