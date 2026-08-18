<?php
/**
 * Code-level configuration via wp-config.php constants.
 *
 * Agencies deploying WebDecoy across many client sites configure it in code,
 * not in wp-admin: constants in wp-config.php survive database resets, ship in
 * boilerplate repositories, and cannot be switched off by a curious client.
 *
 * Supported constants:
 *
 *   WEBDECOY_DISABLE           (bool)   Emergency kill switch (since 2.3.2).
 *   WEBDECOY_DEFAULT_MODE      (string) 'monitor' or 'block'. When defined it
 *                                       FORCES the mode, overriding the stored
 *                                       setting and locking the admin toggle.
 *   WEBDECOY_HIDE_ADMIN_UI     (bool)   Hides the WebDecoy admin menu, the
 *                                       dashboard widget and admin notices.
 *                                       The plugin still appears in the
 *                                       Plugins list: hiding an installed
 *                                       plugin from the site owner entirely
 *                                       is rootkit behavior, not white-label.
 *   WEBDECOY_MAX_LOG_RETENTION (int)    Days of detection history to keep
 *                                       (default 30, min 1, max 3650).
 *
 * Every method takes an optional raw value so the parsing logic is testable
 * without defining constants; with no argument it reads the real constant.
 *
 * This file has no side effects and no WordPress dependencies at parse time.
 *
 * @package WebDecoy
 */

if (!defined('ABSPATH')) {
    exit;
}

class WebDecoy_Runtime_Config
{
    public const RETENTION_DEFAULT = 30;
    public const RETENTION_MIN = 1;
    public const RETENTION_MAX = 3650;

    /**
     * The mode forced by WEBDECOY_DEFAULT_MODE, if any.
     *
     * @param mixed $raw Raw constant value, or null to read the constant.
     * @return bool|null true = monitor mode, false = blocking, null = not forced.
     */
    public static function forced_monitor_mode($raw = null): ?bool
    {
        if ($raw === null) {
            if (!defined('WEBDECOY_DEFAULT_MODE')) {
                return null;
            }
            $raw = constant('WEBDECOY_DEFAULT_MODE');
        }

        if (!is_string($raw)) {
            return null;
        }

        switch (strtolower(trim($raw))) {
            case 'monitor':
                return true;
            case 'block':
                return false;
            default:
                // An unrecognized value must not silently pick a side: forcing
                // 'block' on a typo would enforce on a site that asked to
                // watch, and forcing 'monitor' would disarm one that asked to
                // enforce. Ignore it and keep the stored setting.
                return null;
        }
    }

    /**
     * Whether the admin UI (menu, dashboard widget, notices) is hidden.
     *
     * @param mixed $raw Raw constant value, or null to read the constant.
     */
    public static function hide_admin_ui($raw = null): bool
    {
        if ($raw === null) {
            $raw = defined('WEBDECOY_HIDE_ADMIN_UI') ? constant('WEBDECOY_HIDE_ADMIN_UI') : false;
        }
        return (bool) $raw;
    }

    /**
     * Days of detection history the cleanup cron keeps.
     *
     * Out-of-range values clamp rather than reject: a site that defined 0 or
     * -1 wanted "as little as possible", which is the minimum, and one that
     * defined 999999 wanted "everything", which is the maximum.
     *
     * @param mixed $raw Raw constant value, or null to read the constant.
     */
    public static function log_retention_days($raw = null): int
    {
        if ($raw === null) {
            $raw = defined('WEBDECOY_MAX_LOG_RETENTION') ? constant('WEBDECOY_MAX_LOG_RETENTION') : self::RETENTION_DEFAULT;
        }

        if (!is_numeric($raw)) {
            return self::RETENTION_DEFAULT;
        }

        return max(self::RETENTION_MIN, min(self::RETENTION_MAX, (int) $raw));
    }

    /**
     * Validate and normalize one allowlist entry (IP or CIDR).
     *
     * Same acceptance rules as the settings screen's proxy/allowlist
     * sanitizer: a bare IPv4/IPv6 address, or address/bits with bits 0-128.
     *
     * @return string|null The trimmed entry, or null if invalid.
     */
    public static function validate_ip_or_cidr($entry): ?string
    {
        $entry = trim((string) $entry);
        if ($entry === '') {
            return null;
        }

        if (strpos($entry, '/') !== false) {
            [$addr, $bits] = array_pad(explode('/', $entry, 2), 2, '');
            if (filter_var($addr, FILTER_VALIDATE_IP) && ctype_digit($bits) && (int) $bits >= 0 && (int) $bits <= 128) {
                return $entry;
            }
            return null;
        }

        return filter_var($entry, FILTER_VALIDATE_IP) ? $entry : null;
    }
}
