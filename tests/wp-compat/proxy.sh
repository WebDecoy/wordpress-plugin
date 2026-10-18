#!/usr/bin/env bash
# Check the "behind a proxy it has not been told about" admin notice against a
# real reverse proxy (the proxy service, nginx) in front of the wp service.
#
#   direct            no proxy                                 -> no notice
#   resolving host    mod_remoteip sets REMOTE_ADDR to the     -> no notice
#                     visitor, X-Forwarded-For still passed       (2.10.4 showed one)
#   unresolved proxy  mod_remoteip off: REMOTE_ADDR is the     -> notice, and
#                     proxy                                       its button works
#   trusted proxy     the proxy's address configured           -> no notice
#
# The official wordpress image ships mod_remoteip ON, trusting private ranges for
# X-Forwarded-For, so it is itself a "resolving host" out of the box. The
# unresolved case turns the module and its conf off; the EXIT trap restores them.
#
# Requests go to the proxy with Host: localhost:8071 (curl --connect-to), so
# WordPress sees its own address and the login cookie works on either path.
# Usage:  docker compose up -d db wp proxy && bash proxy.sh
set -u
cd "$(dirname "$0")"
WP() { docker compose run --rm -T cli "$@" 2>/dev/null; }
WP_PORT="${WP_PORT:-8071}"
BASE="http://localhost:${WP_PORT}"
VIA_PROXY=(--connect-to "localhost:${WP_PORT}:localhost:${PROXY_PORT:-8072}")
NOTICE="behind a proxy it has not been told about"
CJ=$(mktemp); TMP=$(mktemp)
fail=0

# remoteip on|off: switch the image's stock mod_remoteip setup. A broken config
# makes graceful keep the old one running, so validate before reloading.
remoteip() {
    local mod=a2enmod conf=a2enconf
    [ "$1" = off ] && mod=a2dismod conf=a2disconf
    docker compose exec -T wp sh -c "$mod -q remoteip >/dev/null && $conf -q remoteip >/dev/null && apache2ctl configtest 2>/dev/null && apache2ctl -k graceful" >/dev/null 2>&1 \
        || { echo "  FAIL  could not switch mod_remoteip $1"; exit 1; }
    sleep 2
}
trap 'remoteip on; rm -f "$CJ" "$TMP"' EXIT

echo "## waiting for wp-config.php"
for _ in $(seq 1 90); do docker compose exec -T wp test -f /var/www/html/wp-config.php 2>/dev/null && break; sleep 2; done
docker compose exec -T wp test -f /var/www/html/wp-config.php || { echo "wp-config.php never appeared"; exit 1; }
WP core is-installed || WP core install --url="$BASE" --title="WebDecoy compat" --admin_user=admin --admin_password=admin --admin_email=admin@example.com --skip-email
WP plugin activate webdecoy | tail -1
# Start from no flag and no trusted proxy, whatever an earlier run left behind.
WP option delete webdecoy_proxy_detected >/dev/null
WP eval '$o = get_option("webdecoy_options", []); $o["trusted_proxies"] = ""; $o["behind_cloudflare"] = false; update_option("webdecoy_options", $o);' >/dev/null
remoteip on

curl -s -c "$CJ" -b "$CJ" -o /dev/null "$BASE/wp-login.php"
curl -s -c "$CJ" -b "$CJ" -o /dev/null --data-urlencode log=admin --data-urlencode pwd=admin -d "wp-submit=Log+In&testcookie=1" "$BASE/wp-login.php"

# admin_page <label> <expect: notice|none> [curl args...]
admin_page() {
    local label=$1 expect=$2; shift 2
    local code n
    code=$(curl -s -b "$CJ" -o "$TMP" -w "%{http_code}" "$@" "$BASE/wp-admin/index.php")
    n=$(grep -c "$NOTICE" "$TMP")
    local shown=none
    [ "$n" -gt 0 ] && shown=notice
    if [ "$code" = 200 ] && [ "$shown" = "$expect" ]; then
        echo "  ok    $label: $code, notice shown: $n"
    else
        echo "  FAIL  $label: $code, notice shown: $n, expected: $expect"; fail=1
    fi
}

echo "## direct"
admin_page "direct request" none

echo "## host resolves the visitor (stock mod_remoteip), X-Forwarded-For still forwarded"
admin_page "via proxy, REMOTE_ADDR resolved to the visitor" none "${VIA_PROXY[@]}"

echo "## unresolved proxy (mod_remoteip off)"
remoteip off
admin_page "via proxy, REMOTE_ADDR is the proxy" notice "${VIA_PROXY[@]}"
href=$(grep -oE 'href="[^"]*"[^>]*>Configure trusted proxies' "$TMP" | sed -E 's/^href="([^"]*)".*/\1/; s/&#038;/\&/g; s/&amp;/\&/g')
echo "  button -> $href"
case "$href" in *"#webdecoy_trusted_proxies") ;; *) echo "  FAIL  button is not anchored to the trusted-proxies field"; fail=1 ;; esac
code=$(curl -s -b "$CJ" -o "$TMP" -w "%{http_code}" "${VIA_PROXY[@]}" "${href%%#*}")
if [ "$code" = 200 ] && grep -q 'id="webdecoy_trusted_proxies"' "$TMP"; then
    echo "  ok    button opens the settings page with the field: $code"
else
    echo "  FAIL  button target: $code, field present: $(grep -c 'id="webdecoy_trusted_proxies"' "$TMP")"; fail=1
fi

echo "## proxy configured as trusted"
proxy_ip=$(docker compose exec -T wp getent hosts proxy | awk '{print $1}')
[ -n "$proxy_ip" ] || { echo "  FAIL  cannot resolve the proxy service; is it up?"; exit 1; }
WP eval "\$o = get_option('webdecoy_options', []); \$o['trusted_proxies'] = '$proxy_ip'; update_option('webdecoy_options', \$o);" >/dev/null
admin_page "via proxy, proxy now trusted" none "${VIA_PROXY[@]}"
WP eval '$o = get_option("webdecoy_options", []); $o["trusted_proxies"] = ""; update_option("webdecoy_options", $o);' >/dev/null
WP option delete webdecoy_proxy_detected >/dev/null
remoteip on

echo; [ "$fail" = 0 ] && echo "PROXY OK" || { echo "PROXY FAILED"; exit 1; }
