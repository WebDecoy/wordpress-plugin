<?php
/** Privacy-safe, opt-in operational diagnostics. @package WebDecoy */
if (!defined('ABSPATH')) {
    exit;
}

final class WebDecoy_Diagnostics
{
    /** Never log exception messages, credentials, IPs, or request payloads. */
    public static function report(string $code): void
    {
        if (!in_array($code, ['api_error', 'client_error', 'ingest_unconfigured'], true)) {
            return;
        }
        if (defined('WP_DEBUG') && WP_DEBUG && defined('WP_DEBUG_LOG') && WP_DEBUG_LOG) {
            // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log -- Explicit WordPress debug logging opt-in; only fixed, non-sensitive event codes are emitted.
            error_log('WebDecoy: ' . $code);
        }
    }
}
