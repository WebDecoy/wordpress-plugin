<?php

declare(strict_types=1);

/**
 * Checkout Monitor compatibility.
 *
 * Checkout Monitor places signed test orders as often as every 3 minutes. Our
 * velocity and card-testing checks would refuse them. We stand down only when
 * Checkout Monitor's own plugin has verified the signature, never on its
 * User-Agent. Run: php tests/run.php
 */

require_once __DIR__ . '/WooOrderStatusTest.php';

$t = ['TestRunner', 'test'];
$true = ['TestRunner', 'assertTrue'];

echo "\nCheckout Monitor compatibility\n";

$t('nothing is exempt without Checkout Monitor saying so', function () use ($true) {
    WebDecoy_Checkout_Monitor::reset();
    $_SERVER['HTTP_USER_AGENT'] = 'CheckoutMonitor/1.0 (+https://checkoutmonitor.app/bot)';
    $_SERVER['HTTP_X_CM_SIGNATURE'] = 'anything';
    $true(!WebDecoy_Checkout_Monitor::is_verified_test_request(), 'a claimed User-Agent and headers are not proof');
    $true(!WebDecoy_Checkout_Monitor::is_test_order(new stdClass()), 'no helper, no exempt orders');
    unset($_SERVER['HTTP_USER_AGENT'], $_SERVER['HTTP_X_CM_SIGNATURE']);
});

$t('the verified hook exempts the request', function () use ($true) {
    WebDecoy_Checkout_Monitor::reset();
    WebDecoy_Checkout_Monitor::on_verified(['route' => '/wc/store/v1/checkout']);
    $true(WebDecoy_Checkout_Monitor::is_verified_test_request(), 'verified');
    WebDecoy_Checkout_Monitor::reset();
});

$t('the helper answers when no hook has fired yet', function () use ($true) {
    if (!function_exists('checkout_monitor_is_test_request')) {
        function checkout_monitor_is_test_request()
        {
            return $GLOBALS['__cm_request'] ?? false;
        }
        function checkout_monitor_is_test_order($order)
        {
            return $GLOBALS['__cm_order'] ?? false;
        }
    }
    WebDecoy_Checkout_Monitor::reset();
    $GLOBALS['__cm_request'] = true;
    $true(WebDecoy_Checkout_Monitor::is_verified_test_request(), 'helper says verified');
    $GLOBALS['__cm_request'] = false;
    $true(!WebDecoy_Checkout_Monitor::is_verified_test_request(), 'helper says not verified');

    $GLOBALS['__cm_order'] = true;
    $true(WebDecoy_Checkout_Monitor::is_test_order(new stdClass()), 'helper says test order');
    $true(!WebDecoy_Checkout_Monitor::is_test_order(null), 'no order is never a test order');
    unset($GLOBALS['__cm_request'], $GLOBALS['__cm_order']);
});

$t('a rejected signature wins over everything else', function () use ($true) {
    WebDecoy_Checkout_Monitor::reset();
    $GLOBALS['__cm_request'] = true;
    WebDecoy_Checkout_Monitor::on_rejected('bad_signature', []);
    $true(!WebDecoy_Checkout_Monitor::is_verified_test_request(), 'rejected must not be exempt');
    unset($GLOBALS['__cm_request']);
    WebDecoy_Checkout_Monitor::reset();
});

// Both checkout paths and attempt tracking must ask, before anything that can
// refuse an order or count an attempt. Read from source: the Store API check is
// a closure inside a WooCommerce Blocks hook that a unit test cannot reach.
$t('every checkout path asks before it can refuse or count', function () use ($true) {
    $src = (string) file_get_contents(dirname(__DIR__) . '/includes/class-webdecoy-woocommerce.php');

    $section = function (string $from, string $to) use ($src): string {
        $a = strpos($src, $from);
        $b = $a === false ? false : strpos($src, $to, $a);
        return ($a === false || $b === false) ? '' : substr($src, $a, $b - $a);
    };

    $classic = $section('public function check_checkout', 'private function check_velocity');
    $store = $section("'woocommerce_store_api_checkout_update_order_from_request'", "'woocommerce_store_api_checkout_order_processed'");
    $track = $section('public function track_attempt', 'private const ACCEPTED_ORDER_STATUSES');

    foreach (['classic checkout' => [$classic, 'wc_add_notice'], 'Store API checkout' => [$store, 'RouteException'], 'attempt tracking' => [$track, '$wpdb->insert']] as $name => [$body, $effect]) {
        $ask = strpos($body, 'WebDecoy_Checkout_Monitor::is_verified_test_request()');
        $act = strpos($body, $effect);
        $true($body !== '' && $ask !== false && $act !== false && $ask < $act, "{$name} must ask Checkout Monitor before {$effect}");
    }
});
