<?php
/**
 * WP Super Cache plugin file, registered through WP Super Cache's own
 * wpsc_add_plugin action only while "Count crawlers on cached pages" is on
 * (see WebDecoy_Page_Cache), and removed with wpsc_delete_plugin when it is
 * turned off.
 *
 * WP Super Cache loads this in its phase 1, before WordPress, and fires
 * cache_init before it looks for a cached page. Setting $cache_enabled to
 * false there is the documented way for a cache_init action to skip the cache
 * for one request: the page is neither served from nor written to the cache,
 * so a known crawler reaches WordPress and is counted. Every other visitor is
 * untouched.
 *
 * @package WebDecoy
 */

if (!defined('ABSPATH')) {
    exit;
}

if (function_exists('add_cacheaction') && !function_exists('webdecoy_wpsc_cache_init')) {
    /**
     * Turn the cache off for this request when the User-Agent names a crawler.
     */
    function webdecoy_wpsc_cache_init(): void
    {
        global $cache_enabled;

        // phpcs:ignore WordPress.Security.ValidatedSanitizedInput, WordPressVIPMinimum.Variables.RestrictedVariables.cache_constraints___SERVER__HTTP_USER_AGENT__ -- Decides only whether this request skips the page cache; compared as a lower-cased substring, never stored or output.
        $ua = isset($_SERVER['HTTP_USER_AGENT']) ? (string) $_SERVER['HTTP_USER_AGENT'] : '';
        if ($ua === '') {
            return;
        }

        if (!class_exists('WebDecoy\AgentRegistry', false)) {
            require_once dirname(__DIR__) . '/sdk/src/AgentRegistry.php';
        }
        require_once __DIR__ . '/class-webdecoy-crawler-visits.php';
        require_once __DIR__ . '/class-webdecoy-page-cache.php';

        if (WebDecoy_Page_Cache::ua_matches($ua, WebDecoy_Page_Cache::crawler_tokens())) {
            $cache_enabled = false; // phpcs:ignore WordPress.WP.GlobalVariablesOverride.Prohibited -- WP Super Cache's own per-request switch.
        }
    }

    add_cacheaction('cache_init', 'webdecoy_wpsc_cache_init');
}
