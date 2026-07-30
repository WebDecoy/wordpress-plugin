<?php

declare(strict_types=1);

/**
 * Tests for the order-status rule behind issue #60.
 *
 * The card-testing and velocity filters exclude checkout attempts that resulted in
 * a real order. Resolving "real order" from `woocommerce_payment_complete` alone was
 * wrong: Cash on Delivery, Direct Bank Transfer and Cheque move an order to
 * processing or on-hold and never call WC_Order::payment_complete(). On a store
 * using only those gateways no attempt row was ever closed, so the filter excluded
 * nothing and every paid order counted as a card-testing attempt.
 *
 * These assert the pure status rule, which is the part that decides it.
 * Run: php tests/run.php
 */

if (!defined('ABSPATH')) {
    define('ABSPATH', '/tmp/');
}

// The class file registers hooks at the top level, so the handful of WordPress
// functions it touches on load have to exist. Guarded so they don't collide with
// other tests or a real WP runtime.
if (!function_exists('add_action')) {
    function add_action($hook, $cb, $priority = 10, $args = 1)
    {
        return true;
    }
}
if (!function_exists('add_filter')) {
    function add_filter($hook, $cb, $priority = 10, $args = 1)
    {
        return true;
    }
}
if (!isset($GLOBALS['__wd_opts'])) {
    $GLOBALS['__wd_opts'] = [];
}
if (!function_exists('get_option')) {
    function get_option($k, $d = false)
    {
        return $GLOBALS['__wd_opts'][$k] ?? $d;
    }
}

require_once dirname(__DIR__) . '/includes/class-webdecoy-woocommerce.php';

$t = ['TestRunner', 'test'];
$true = ['TestRunner', 'assertTrue'];

echo "\nWooCommerce order-status rule (#60)\n";

$t('the offline gateways that never fire payment_complete are still accepted', function () use ($true) {
    // Cash on Delivery and most "payment on pickup" flows land here.
    $true(
        WebDecoy_WooCommerce::is_accepted_order_status('processing'),
        'processing is a real order (Cash on Delivery)'
    );
    // Direct Bank Transfer (BACS) and Cheque leave a legitimate order awaiting funds.
    $true(
        WebDecoy_WooCommerce::is_accepted_order_status('on-hold'),
        'on-hold is a real order (BACS / Cheque)'
    );
});

$t('a card-paid order is accepted', function () use ($true) {
    $true(WebDecoy_WooCommerce::is_accepted_order_status('completed'), 'completed');
    $true(WebDecoy_WooCommerce::is_accepted_order_status('refunded'), 'refunded was still a real order');
});

$t('the statuses that mean no sale keep counting as attempts', function () use ($true) {
    foreach (['failed', 'cancelled', 'pending'] as $status) {
        $true(
            !WebDecoy_WooCommerce::is_accepted_order_status($status),
            "{$status} must keep counting — it is the card-testing signal"
        );
    }
});

$t('the wc- prefix WooCommerce passes around is tolerated', function () use ($true) {
    // woocommerce_order_status_changed hands over the bare status, but plenty of
    // callers and stored values carry the wc- prefix. Both must resolve the same.
    $true(WebDecoy_WooCommerce::is_accepted_order_status('wc-processing'), 'wc-processing');
    $true(WebDecoy_WooCommerce::is_accepted_order_status('wc-on-hold'), 'wc-on-hold');
    $true(!WebDecoy_WooCommerce::is_accepted_order_status('wc-failed'), 'wc-failed');
});

$t('an unknown status is not silently treated as a sale', function () use ($true) {
    // A gateway or extension adding its own status must not accidentally close an
    // attempt — degrading to "still an attempt" is the safe direction here.
    $true(!WebDecoy_WooCommerce::is_accepted_order_status('checkout-draft'), 'checkout-draft');
    $true(!WebDecoy_WooCommerce::is_accepted_order_status(''), 'empty string');
});
