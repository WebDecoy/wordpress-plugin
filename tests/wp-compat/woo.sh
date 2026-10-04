#!/usr/bin/env bash
# WooCommerce leg of the compatibility smoke test. Run after smoke.sh (or at
# least after `docker compose up -d db wp` + core install + plugin activate).
# Installs the latest WooCommerce, then drives what "WC tested up to" claims:
# HPOS + blocks compatibility declarations, a Store API (block) checkout, a
# classic shortcode checkout, the honeytoken coupon, checkout velocity, the
# order-status tracking hooks, and the WooCommerce admin screens. debug.log
# and wc-logs are printed at the end and must be empty.
# Usage: bash tests/wp-compat/woo.sh            (WOO_VERSION=10.9.4 to pin)
set -u
cd "$(dirname "$0")"
WP() { docker compose run --rm -T cli "$@" 2>/dev/null; }
BASE="http://localhost:${WP_PORT:-8071}"
UA_HUMAN="Mozilla/5.0 (Macintosh) Chrome/128 Safari/537.36"
UA_BOT="python-requests/2.31"
CJ=$(mktemp); TMP=$(mktemp); HDR=$(mktemp)
trap 'rm -f "$CJ" "$TMP" "$HDR"' EXIT
fail=0
mark() { grep -c -E "<b>(Warning|Fatal error|Deprecated|Notice)</b>|There has been a critical error" "$1"; }

echo "## install / activate WooCommerce"
WP plugin is-installed woocommerce || WP plugin install woocommerce ${WOO_VERSION:+--version=$WOO_VERSION} | tail -1
WP plugin activate woocommerce | tail -1
echo "WooCommerce $(WP plugin get woocommerce --field=version) on WordPress $(WP core version) / PHP $(WP eval 'echo PHP_VERSION;')"

echo "## store setup (guest checkout, COD, one virtual product)"
WP option update woocommerce_onboarding_profile '{"skipped":true}' --format=json >/dev/null
WP option update woocommerce_coming_soon no >/dev/null
WP option update woocommerce_enable_guest_checkout yes >/dev/null
WP option update woocommerce_enable_checkout_login_reminder no >/dev/null
WP option update woocommerce_calc_taxes no >/dev/null
WP option update woocommerce_default_country US:CA >/dev/null
WP option update woocommerce_cod_settings '{"enabled":"yes","title":"Cash on delivery","description":"","instructions":"","enable_for_methods":[],"enable_for_virtual":"yes"}' --format=json >/dev/null
PID=$(WP wc product create --name="Widget" --type=simple --regular_price=10 --virtual=true --user=admin --porcelain)
echo "product id: $PID"
# Deliberately no settings save: a fresh install's defaults must be enough for
# checkout protection and the honeytoken coupon to be live.
docker compose exec -T wp sh -c ': > /var/www/html/wp-content/debug.log' 2>/dev/null

echo "## WooCommerce feature compatibility as WooCommerce sees it"
WP eval 'print_r(\Automattic\WooCommerce\Utilities\FeaturesUtil::get_compatible_features_for_plugin("webdecoy/webdecoy.php"));' | tr -s ' \n' ' '; echo

store_checkout() {  # $1 = user agent; prints "code body-snippet"
  local jar; jar=$(mktemp)
  curl -s -c "$jar" -b "$jar" -A "$1" -D "$HDR" -o /dev/null "$BASE/wp-json/wc/store/v1/cart"
  local nonce; nonce=$(grep -i '^nonce:' "$HDR" | awk '{print $2}' | tr -d '\r')
  curl -s -c "$jar" -b "$jar" -A "$1" -H "Nonce: $nonce" -H "Content-Type: application/json" -d "{\"id\":$PID,\"quantity\":1}" -o /dev/null "$BASE/wp-json/wc/store/v1/cart/add-item"
  local code; code=$(curl -s -c "$jar" -b "$jar" -A "$1" -H "Nonce: $nonce" -H "Content-Type: application/json" -o "$TMP" -w "%{http_code}" -d '{"billing_address":{"first_name":"Test","last_name":"Buyer","address_1":"1 Main St","city":"Los Angeles","state":"CA","postcode":"90001","country":"US","email":"buyer@example.com","phone":"5555555555"},"payment_method":"cod"}' "$BASE/wp-json/wc/store/v1/checkout")
  echo "$code $(python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print("order", d.get("order_id"), d.get("status") or d.get("code"), d.get("message",""))' "$TMP" 2>/dev/null | head -c 120)"
  rm -f "$jar"
}

echo "## Store API (block) checkout, human"
r=$(store_checkout "$UA_HUMAN"); echo "$r"; [[ "$r" == 200* ]] || fail=1

echo "## classic shortcode checkout, human (coupon bait must render)"
CHK=$(WP option get woocommerce_checkout_page_id)
WP post update "$CHK" --post_content='[woocommerce_checkout]' >/dev/null
# Add to the PHP SESSION cart (not the Store API cart, which uses its own token),
# so the classic checkout renders its form and the woocommerce_before_checkout_form
# bait hook fires.
curl -s -c "$CJ" -b "$CJ" -A "$UA_HUMAN" -o /dev/null "$BASE/?add-to-cart=$PID&quantity=1"
code=$(curl -s -c "$CJ" -b "$CJ" -A "$UA_HUMAN" -o "$TMP" -w "%{http_code}" "$BASE/checkout/")
COUPON=$(grep -oE 'data-coupon="[^"]+"' "$TMP" | head -1 | cut -d'"' -f2)
PNONCE=$(grep -oE 'id="woocommerce-process-checkout-nonce"[^>]*value="[^"]+"' "$TMP" | grep -oE 'value="[^"]+"' | cut -d'"' -f2)
ANONCE=$(grep -oE '"apply_coupon_nonce":"[^"]+"' "$TMP" | head -1 | cut -d'"' -f4)
echo "/checkout/ -> $code, php error markers: $(mark "$TMP"), coupon bait: ${COUPON:-MISSING}, checkout nonce: ${PNONCE:+yes}"
[ "$code" = 200 ] && [ -n "$COUPON" ] && [ -n "$PNONCE" ] || fail=1
echo "## applying the honeytoken coupon (bot) — must be refused and recorded"
before=$(WP webdecoy status | awk -F'\t' '$1=="detections_total"{print $2}')
curl -s -c "$CJ" -b "$CJ" -A "$UA_BOT" -o "$TMP" -w "apply_coupon -> %{http_code}\n" -d "coupon_code=$COUPON&security=$ANONCE" "$BASE/?wc-ajax=apply_coupon"
after=$(WP webdecoy status | awk -F'\t' '$1=="detections_total"{print $2}')
echo "detections before/after coupon: $before -> $after"; [ "${after:-0}" -gt "${before:-0}" ] || fail=1
echo "## classic checkout POST (wc-ajax=checkout)"
curl -s -c "$CJ" -b "$CJ" -A "$UA_HUMAN" -o "$TMP" -w "checkout -> %{http_code} " -d "billing_first_name=Test&billing_last_name=Buyer&billing_address_1=1+Main+St&billing_city=Los+Angeles&billing_state=CA&billing_postcode=90001&billing_country=US&billing_email=buyer@example.com&billing_phone=5555555555&payment_method=cod&woocommerce-process-checkout-nonce=$PNONCE&_wp_http_referer=%2Fcheckout%2F" "$BASE/?wc-ajax=checkout"
python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print(d.get("result"), (d.get("redirect") or d.get("messages",""))[:100])' "$TMP" 2>/dev/null || head -c 200 "$TMP"

echo "## checkout velocity: 6 rapid Store API checkouts from one bot IP"
for i in 1 2 3 4 5 6; do echo "  #$i $(store_checkout "$UA_BOT")"; done
WP webdecoy status | grep -E "^(mode|detections_total|active_blocks)"
echo "## orders as WooCommerce recorded them (HPOS)"
WP wc shop_order list --user=admin --fields=id,status,total,payment_method --format=csv | head -12
echo "## order status hooks: mark one order failed, then completed"
OID=$(WP wc shop_order list --user=admin --field=id | head -1)
WP wc shop_order update "$OID" --status=failed --user=admin --porcelain >/dev/null && WP wc shop_order update "$OID" --status=completed --user=admin --porcelain >/dev/null && echo "order $OID: failed -> completed OK"

echo "## admin screens with WooCommerce active"
curl -s -c "$CJ" -b "$CJ" -o /dev/null "$BASE/wp-login.php"
curl -s -c "$CJ" -b "$CJ" -o /dev/null --data-urlencode log=admin --data-urlencode pwd=admin -d "wp-submit=Log+In&testcookie=1" "$BASE/wp-login.php"
for p in index.php "admin.php?page=wc-orders" "admin.php?page=wc-orders&action=edit&id=$OID" "admin.php?page=wc-settings" "admin.php?page=wc-settings&tab=advanced&section=features" "edit.php?post_type=product" "admin.php?page=webdecoy" "admin.php?page=webdecoy-detections" "admin.php?page=webdecoy-statistics" plugins.php; do
  code=$(curl -sL -b "$CJ" -o "$TMP" -w "%{http_code}" "$BASE/wp-admin/$p"); m=$(mark "$TMP")
  echo "$p -> $code, php error markers: $m"; [ "$code" = 200 ] && [ "$m" = 0 ] || fail=1
done
echo "## incompatible-plugin notice on the features screen?"
curl -s -b "$CJ" "$BASE/wp-admin/admin.php?page=wc-settings&tab=advanced&section=features" | grep -ioE "webdecoy[^<]{0,80}(incompatible|not declared)[^<]{0,40}" | head -2 || true

echo "## debug.log + wc-logs (must be empty)"
log=$(docker compose exec -T wp sh -c 'cat /var/www/html/wp-content/debug.log 2>/dev/null; cat /var/www/html/wp-content/uploads/wc-logs/fatal-errors*.log 2>/dev/null')
if [ -n "$log" ]; then echo "$log"; fail=1; else echo "(empty)"; fi
echo; [ "$fail" = 0 ] && echo "WOO OK" || { echo "WOO FAILED"; exit 1; }
