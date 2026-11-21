<?php
/**
 * Checkout Monitor compatibility.
 *
 * Checkout Monitor (https://checkoutmonitor.app/bot) places scheduled test
 * orders through the WooCommerce Store API on stores whose owner asked for it,
 * as often as every 3 minutes from one address. Our checkout protection would
 * read that as card testing or checkout velocity and refuse the order, and the
 * store owner would get a "checkout is broken" alert that we caused.
 *
 * Checkout Monitor's own plugin verifies an HMAC signature on each request and
 * tells other plugins the result. We stand down only on that verified answer.
 * The CheckoutMonitor User-Agent and the X-CM-* headers can be sent by anyone,
 * so they are never enough on their own.
 *
 * @package WebDecoy
 */

if (!defined('ABSPATH')) {
    exit;
}

final class WebDecoy_Checkout_Monitor
{
    /**
     * What Checkout Monitor's hooks said about this request: true after
     * checkout_monitor_request_verified, false after
     * checkout_monitor_request_rejected, null when neither fired.
     *
     * @var bool|null
     */
    private static $verdict = null;

    public static function register(): void
    {
        add_action('checkout_monitor_request_verified', [self::class, 'on_verified'], 10, 1);
        add_action('checkout_monitor_request_rejected', [self::class, 'on_rejected'], 10, 2);
    }

    /**
     * @param mixed $context Route, method, path and timestamp. Unused.
     */
    public static function on_verified($context = null): void
    {
        self::$verdict = true;
    }

    /**
     * A request claimed to be Checkout Monitor and failed its signature check.
     * It gets no exemption, whatever its User-Agent says.
     *
     * @param mixed $reason
     * @param mixed $context
     */
    public static function on_rejected($reason = '', $context = null): void
    {
        self::$verdict = false;
    }

    /**
     * True only when Checkout Monitor has verified this request's signature.
     *
     * A rejection always wins. Without either hook, ask Checkout Monitor's
     * helper, so the answer does not depend on which plugin's hook ran first.
     */
    public static function is_verified_test_request(): bool
    {
        if (self::$verdict !== null) {
            return self::$verdict;
        }
        if (function_exists('checkout_monitor_is_test_request')) {
            return (bool) checkout_monitor_is_test_request();
        }
        return false;
    }

    /**
     * True when Checkout Monitor says this order is one of its test orders.
     * Answered by its helper only: with the plugin gone, nothing is exempt.
     *
     * @param mixed $order WC_Order
     */
    public static function is_test_order($order): bool
    {
        if (!$order || !function_exists('checkout_monitor_is_test_order')) {
            return false;
        }
        return (bool) checkout_monitor_is_test_order($order);
    }

    /**
     * Forget the verdict. Tests only; a PHP request starts fresh anyway.
     */
    public static function reset(): void
    {
        self::$verdict = null;
    }
}

WebDecoy_Checkout_Monitor::register();
