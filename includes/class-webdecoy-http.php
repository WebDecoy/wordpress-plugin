<?php
/**
 * WordPress HTTP transport with bounded VIP requests and GET circuit breaking.
 *
 * Response caching belongs to each caller: feeds, entitlements and enrichment
 * have different lifetimes and authorization scopes. Never cache a token exchange.
 *
 * @package WebDecoy
 */

if (!defined('ABSPATH')) {
    exit;
}

final class WebDecoy_HTTP
{
    /** @return array|WP_Error WordPress HTTP response, including transport errors. */
    public static function get(string $url, array $args = [])
    {
        if (function_exists('vip_safe_wp_remote_get')) {
            $timeout = self::vip_timeout($args);
            $args['timeout'] = $timeout;
            // VIP's signature is URL, fallback, threshold, timeout, retry, args.
            // A WP_Error fallback keeps caller failure/backoff behavior intact.
            return vip_safe_wp_remote_get($url, new WP_Error('webdecoy_remote_unavailable', 'Remote service unavailable.'), 3, $timeout, 20, $args);
        }

        // phpcs:ignore WordPressVIPMinimum.Functions.RestrictedFunctions.wp_remote_get_wp_remote_get -- Non-VIP fallback only; VIP uses the circuit breaker above.
        return wp_remote_get($url, $args);
    }

    /** @return array|WP_Error POST requests are never retried or cached here. */
    public static function post(string $url, array $args = [])
    {
        if (function_exists('vip_safe_wp_remote_get')) {
            $args['timeout'] = self::vip_timeout($args);
        }
        return wp_remote_post($url, $args);
    }

    /** Clamp VIP network waits while preserving shorter caller timeouts. */
    private static function vip_timeout(array $args): float
    {
        $timeout = $args['timeout'] ?? 3;
        return is_numeric($timeout) ? max(0.1, min(3.0, (float) $timeout)) : 3.0;
    }
}
