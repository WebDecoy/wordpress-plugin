#!/usr/bin/env bash
# Smoke-test the plugin on the throwaway WordPress site from docker-compose.yml.
# Exercises what a "Tested up to" bump claims: install, activate, front-end
# injection, tripwires in monitor and block mode, the block page, the test UA,
# every admin page, a settings save, cron, WP-CLI, deactivate. Anything PHP
# complains about lands in debug.log, which is printed at the end and must be
# empty. Usage:  bash tests/wp-compat/smoke.sh
set -u
cd "$(dirname "$0")"
WP() { docker compose run --rm -T cli "$@" 2>/dev/null; }
BASE="http://localhost:${WP_PORT:-8071}"
UA_HUMAN="Mozilla/5.0 (Macintosh) Chrome/128 Safari/537.36"
UA_BOT="python-requests/2.31"
CJ=$(mktemp); TMP=$(mktemp)
trap 'rm -f "$CJ" "$TMP"' EXIT
fail=0
mark() { grep -c -E "<b>(Warning|Fatal error|Deprecated|Notice)</b>|There has been a critical error" "$1"; }

echo "## waiting for wp-config.php"
for _ in $(seq 1 90); do docker compose exec -T wp test -f /var/www/html/wp-config.php 2>/dev/null && break; sleep 2; done
docker compose exec -T wp test -f /var/www/html/wp-config.php || { echo "wp-config.php never appeared"; exit 1; }

echo "## core install"
WP core is-installed || WP core install --url="$BASE" --title="WebDecoy compat" --admin_user=admin --admin_password=admin --admin_email=admin@example.com --skip-email
echo "WordPress $(WP core version) / PHP $(WP eval 'echo PHP_VERSION;')"
WP option update permalink_structure '/%postname%/' >/dev/null; WP rewrite flush >/dev/null
docker compose exec -T wp sh -c ': > /var/www/html/wp-content/debug.log' 2>/dev/null

echo "## activate"
WP plugin activate webdecoy | tail -1
WP webdecoy status | head -4

echo "## front end"
curl -s -A "$UA_HUMAN" "$BASE/" > "$TMP"
echo "home: $(wc -c < "$TMP" | tr -d ' ') bytes, scanner enqueued: $(grep -c webdecoy-scanner "$TMP"), footer link injected: $(grep -c -i webdecoy "$TMP")"
for p in "" wp-login.php wp-json/ feed/; do curl -s -A "$UA_HUMAN" -o /dev/null -w "/$p -> %{http_code}\n" "$BASE/$p"; done
echo "## test user-agent (expects 403 JSON receipt)"
curl -s -A "WebDecoy-Test/1.0" -o "$TMP" -w "-> %{http_code} " "$BASE/"; head -c 120 "$TMP"; echo
echo "## traps, monitor mode (recorded, not blocked)"
for p in .env wp-config.php.bak phpinfo.php backup.sql; do curl -s -A "$UA_BOT" -o /dev/null -w "/$p -> %{http_code}\n" "$BASE/$p"; done

echo "## admin"
curl -s -c "$CJ" -b "$CJ" -o /dev/null "$BASE/wp-login.php"
curl -s -c "$CJ" -b "$CJ" -o /dev/null -w "login -> %{http_code}\n" --data-urlencode log=admin --data-urlencode pwd=admin -d "wp-submit=Log+In&testcookie=1" "$BASE/wp-login.php"
for p in index.php plugins.php "admin.php?page=webdecoy" "admin.php?page=webdecoy&tab=tripwires" "admin.php?page=webdecoy&tab=cloud" "admin.php?page=webdecoy-blocked" "admin.php?page=webdecoy-detections" "admin.php?page=webdecoy-statistics" post-new.php edit.php; do
  code=$(curl -s -b "$CJ" -o "$TMP" -w "%{http_code}" "$BASE/wp-admin/$p"); m=$(mark "$TMP")
  echo "$p -> $code, php error markers: $m"; [ "$code" = 200 ] && [ "$m" = 0 ] || fail=1
done
echo "## settings save round trip"
python3 "$(pwd)/roundtrip.py" "$BASE" || fail=1

echo "## cron"
WP cron event run --due-now | tail -1
echo "## block mode: traps get the block page, bot IP gets blocked"
WP webdecoy config set mode block | tail -1
curl -s -A "$UA_BOT" -o "$TMP" -w "/.env -> %{http_code} " "$BASE/.env"; grep -oE "<title>[^<]*</title>" "$TMP"
curl -s -A "$UA_BOT" -o "$TMP" -w "/ (same bot) -> %{http_code} " "$BASE/"; grep -oE "<title>[^<]*</title>" "$TMP"
WP webdecoy status | grep -E "^(mode|detections_total|active_blocks)"
WP webdecoy config set mode monitor | tail -1

echo "## deactivate / reactivate"
WP plugin deactivate webdecoy | tail -1; WP plugin activate webdecoy | tail -1

echo "## debug.log (must be empty)"
log=$(docker compose exec -T wp sh -c 'cat /var/www/html/wp-content/debug.log 2>/dev/null')
if [ -n "$log" ]; then echo "$log"; fail=1; else echo "(empty)"; fi
echo; [ "$fail" = 0 ] && echo "SMOKE OK" || { echo "SMOKE FAILED"; exit 1; }
