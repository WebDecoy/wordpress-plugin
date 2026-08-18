<?php
/**
 * WP-CLI commands: everything an agency's deploy script needs, no wp-admin.
 *
 *   wp webdecoy status
 *   wp webdecoy config list
 *   wp webdecoy config get <key>
 *   wp webdecoy config set <key> <value>
 *   wp webdecoy allowlist list|add|remove [<ip-or-cidr>]
 *   wp webdecoy logs flush [--yes]
 *
 * Deliberately a plain class (no `extends WP_CLI_Command`) so this file can
 * be parsed and its pure helpers tested without WP-CLI present.
 *
 * @package WebDecoy
 */

if (!defined('ABSPATH')) {
    exit;
}

class WebDecoy_CLI_Command
{
    /**
     * The settings a deploy script may touch, with their validation.
     *
     * A closed list on purpose: api_key, site_key and the organization fields
     * are managed by the connect flow (and the stored api_key is encrypted, so
     * writing it raw here would corrupt it). `mode` is a virtual key mapping
     * to monitor_mode, because "monitor or block" is the question an agency
     * actually asks.
     *
     * @var array<string, array{type: string, values?: array<int, string>, min?: int, max?: int}>
     */
    private const CONFIG_KEYS = [
        'mode'                 => ['type' => 'mode'],
        'enabled'              => ['type' => 'bool'],
        'sensitivity'          => ['type' => 'enum', 'values' => ['low', 'medium', 'high']],
        'min_score_to_block'   => ['type' => 'int', 'min' => 0, 'max' => 100],
        'block_action'         => ['type' => 'enum', 'values' => ['block', 'challenge', 'log']],
        'block_duration'       => ['type' => 'int', 'min' => 0, 'max' => 8760],
        'allow_search_engines' => ['type' => 'bool'],
        'allow_social_bots'    => ['type' => 'bool'],
        'block_ai_crawlers'    => ['type' => 'bool'],
        'protect_comments'     => ['type' => 'bool'],
        'protect_login'        => ['type' => 'bool'],
        'protect_registration' => ['type' => 'bool'],
        'rate_limit_enabled'   => ['type' => 'bool'],
        'rate_limit_requests'  => ['type' => 'int', 'min' => 1, 'max' => 100000],
        'rate_limit_window'    => ['type' => 'int', 'min' => 1, 'max' => 86400],
        'behind_cloudflare'    => ['type' => 'bool'],
    ];

    /**
     * Show what WebDecoy is doing on this site.
     *
     * ## EXAMPLES
     *
     *     wp webdecoy status
     *
     * @when after_wp_load
     */
    public function status($args, $assoc_args): void
    {
        global $wpdb;
        $options = get_option('webdecoy_options', []);

        if (defined('WEBDECOY_DISABLE') && WEBDECOY_DISABLE) {
            $mode = 'DISABLED (WEBDECOY_DISABLE constant)';
        } elseif (!empty($options['monitor_mode'])) {
            $mode = 'monitor (detects and records, blocks nothing)';
        } else {
            $mode = 'blocking';
        }
        if (WebDecoy_Runtime_Config::forced_monitor_mode() !== null) {
            $mode .= ' [forced by WEBDECOY_DEFAULT_MODE]';
        }

        $detections = $wpdb->prefix . 'webdecoy_detections';
        $blocked = $wpdb->prefix . 'webdecoy_blocked_ips';
        $now = gmdate('Y-m-d H:i:s');

        $total = (int) $wpdb->get_var("SELECT COUNT(*) FROM {$detections}"); // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- table name from $wpdb->prefix
        $last24 = (int) $wpdb->get_var($wpdb->prepare(
            "SELECT COUNT(*) FROM {$detections} WHERE created_at > %s", // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
            gmdate('Y-m-d H:i:s', strtotime('-24 hours'))
        ));
        $active_blocks = (int) $wpdb->get_var($wpdb->prepare(
            "SELECT COUNT(*) FROM {$blocked} WHERE expires_at IS NULL OR expires_at > %s", // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
            $now
        ));

        $cloud = 'not connected (100% local)';
        if (!empty($options['api_key'])) {
            $org = $options['organization_name'] ?: 'connected';
            $plan = $options['plan'] ?: 'unknown plan';
            $cloud = sprintf('%s (%s)', $org, $plan);
        }

        $rows = [
            ['field' => 'version', 'value' => WEBDECOY_VERSION],
            ['field' => 'mode', 'value' => $mode],
            ['field' => 'cloud', 'value' => $cloud],
            ['field' => 'detections_total', 'value' => (string) $total],
            ['field' => 'detections_24h', 'value' => (string) $last24],
            ['field' => 'active_blocks', 'value' => (string) $active_blocks],
            ['field' => 'allowlist_entries', 'value' => (string) count((array) ($options['ip_allowlist'] ?? []))],
            ['field' => 'log_retention_days', 'value' => (string) WebDecoy_Runtime_Config::log_retention_days()],
        ];
        \WP_CLI\Utils\format_items('table', $rows, ['field', 'value']);
    }

    /**
     * Read or write WebDecoy settings.
     *
     * ## OPTIONS
     *
     * <action>
     * : list, get, or set.
     *
     * [<key>]
     * : The setting name. `wp webdecoy config list` shows the available keys.
     *
     * [<value>]
     * : The new value (for set).
     *
     * ## EXAMPLES
     *
     *     wp webdecoy config set mode monitor
     *     wp webdecoy config set block_ai_crawlers true
     *     wp webdecoy config get sensitivity
     *
     * @when after_wp_load
     */
    public function config($args, $assoc_args): void
    {
        $action = $args[0] ?? 'list';
        $key = $args[1] ?? null;
        $options = get_option('webdecoy_options', []);
        if (!is_array($options)) {
            $options = [];
        }

        if ($action === 'list') {
            $rows = [];
            foreach (self::CONFIG_KEYS as $name => $spec) {
                $rows[] = [
                    'key' => $name,
                    'value' => self::display_value($name, $options),
                    'type' => $spec['type'] === 'enum' ? implode('|', $spec['values']) : $spec['type'],
                ];
            }
            \WP_CLI\Utils\format_items('table', $rows, ['key', 'value', 'type']);
            return;
        }

        if ($key === null || !isset(self::CONFIG_KEYS[$key])) {
            \WP_CLI::error(sprintf(
                'Unknown setting %s. Run `wp webdecoy config list` for the available keys.',
                $key === null ? '(none)' : "'{$key}'"
            ));
        }

        if ($action === 'get') {
            \WP_CLI::log(self::display_value($key, $options));
            return;
        }

        if ($action !== 'set') {
            \WP_CLI::error("Unknown action '{$action}'. Use list, get, or set.");
        }

        if (!isset($args[2])) {
            \WP_CLI::error("Missing value: wp webdecoy config set {$key} <value>");
        }

        $parsed = self::parse_config_value($key, $args[2]);
        if ($parsed === null) {
            \WP_CLI::error(self::value_help($key, $args[2]));
        }

        [$real_key, $value] = $parsed;
        $options[$real_key] = $value;
        update_option('webdecoy_options', $options);

        if ($real_key === 'monitor_mode' && WebDecoy_Runtime_Config::forced_monitor_mode() !== null) {
            \WP_CLI::warning('WEBDECOY_DEFAULT_MODE is defined in wp-config.php and overrides this setting at runtime.');
        }
        \WP_CLI::success("{$key} = " . self::display_value($key, $options));
    }

    /**
     * Manage the IP allowlist (addresses that bypass all detection).
     *
     * ## OPTIONS
     *
     * <action>
     * : list, add, or remove.
     *
     * [<ip>]
     * : An IPv4/IPv6 address or CIDR range (for add/remove).
     *
     * ## EXAMPLES
     *
     *     wp webdecoy allowlist add 203.0.113.7
     *     wp webdecoy allowlist add 2001:db8::/48
     *     wp webdecoy allowlist remove 203.0.113.7
     *
     * @when after_wp_load
     */
    public function allowlist($args, $assoc_args): void
    {
        $action = $args[0] ?? 'list';
        $options = get_option('webdecoy_options', []);
        if (!is_array($options)) {
            $options = [];
        }
        $list = array_values(array_filter(array_map('strval', (array) ($options['ip_allowlist'] ?? []))));

        if ($action === 'list') {
            if ($list === []) {
                \WP_CLI::log('(empty)');
                return;
            }
            foreach ($list as $entry) {
                \WP_CLI::log($entry);
            }
            return;
        }

        if ($action !== 'add' && $action !== 'remove') {
            \WP_CLI::error("Unknown action '{$action}'. Use list, add, or remove.");
        }

        $entry = WebDecoy_Runtime_Config::validate_ip_or_cidr($args[1] ?? '');
        if ($entry === null) {
            \WP_CLI::error('Not a valid IP address or CIDR range.');
        }

        if ($action === 'add') {
            if (in_array($entry, $list, true)) {
                \WP_CLI::log("{$entry} is already on the allowlist.");
                return;
            }
            $list[] = $entry;
        } else {
            if (!in_array($entry, $list, true)) {
                \WP_CLI::error("{$entry} is not on the allowlist.");
            }
            $list = array_values(array_diff($list, [$entry]));
        }

        $options['ip_allowlist'] = $list;
        update_option('webdecoy_options', $options);
        \WP_CLI::success(sprintf('%s %s. Allowlist now has %d entr%s.',
            $action === 'add' ? 'Added' : 'Removed', $entry, count($list), count($list) === 1 ? 'y' : 'ies'));
    }

    /**
     * Manage the local detection log.
     *
     * ## OPTIONS
     *
     * <action>
     * : flush deletes every recorded detection.
     *
     * [--yes]
     * : Skip the confirmation prompt.
     *
     * ## EXAMPLES
     *
     *     wp webdecoy logs flush --yes
     *
     * @when after_wp_load
     */
    public function logs($args, $assoc_args): void
    {
        global $wpdb;
        $action = $args[0] ?? '';

        if ($action !== 'flush') {
            \WP_CLI::error("Unknown action '{$action}'. Use: wp webdecoy logs flush");
        }

        \WP_CLI::confirm('Delete ALL recorded detections on this site?', $assoc_args);

        $detections = $wpdb->prefix . 'webdecoy_detections';
        $deleted = $wpdb->query("DELETE FROM {$detections}"); // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- table name from $wpdb->prefix
        \WP_CLI::success(sprintf('Deleted %d detection%s.', (int) $deleted, (int) $deleted === 1 ? '' : 's'));
    }

    /**
     * Parse and validate a config value.
     *
     * Pure, so it is testable without WP-CLI. Returns [stored_key, value] or
     * null when the value is invalid for the key.
     *
     * @return array{0: string, 1: mixed}|null
     */
    public static function parse_config_value(string $key, string $raw): ?array
    {
        $spec = self::CONFIG_KEYS[$key] ?? null;
        if ($spec === null) {
            return null;
        }

        switch ($spec['type']) {
            case 'mode':
                $monitor = WebDecoy_Runtime_Config::forced_monitor_mode($raw);
                return $monitor === null ? null : ['monitor_mode', $monitor];
            case 'bool':
                $lowered = strtolower(trim($raw));
                if (in_array($lowered, ['true', '1', 'on', 'yes'], true)) {
                    return [$key, true];
                }
                if (in_array($lowered, ['false', '0', 'off', 'no'], true)) {
                    return [$key, false];
                }
                return null;
            case 'int':
                if (!is_numeric($raw)) {
                    return null;
                }
                $value = (int) $raw;
                if ($value < ($spec['min'] ?? PHP_INT_MIN) || $value > ($spec['max'] ?? PHP_INT_MAX)) {
                    return null;
                }
                return [$key, $value];
            case 'enum':
                $lowered = strtolower(trim($raw));
                return in_array($lowered, $spec['values'], true) ? [$key, $lowered] : null;
            default:
                return null;
        }
    }

    /**
     * Human-readable current value for a config key. Pure.
     *
     * @param array<string, mixed> $options
     */
    public static function display_value(string $key, array $options): string
    {
        if ($key === 'mode') {
            return empty($options['monitor_mode']) ? 'block' : 'monitor';
        }
        $value = $options[$key] ?? null;
        if (is_bool($value)) {
            return $value ? 'true' : 'false';
        }
        return (string) ($value ?? '');
    }

    /**
     * The error message for an invalid value. Pure.
     */
    public static function value_help(string $key, string $raw): string
    {
        $spec = self::CONFIG_KEYS[$key];
        switch ($spec['type']) {
            case 'mode':
                return "'{$raw}' is not a mode. Use: monitor or block.";
            case 'bool':
                return "'{$raw}' is not a boolean. Use: true or false.";
            case 'int':
                return sprintf("'%s' is out of range for %s (%d-%d).", $raw, $key, $spec['min'] ?? 0, $spec['max'] ?? 0);
            case 'enum':
                return sprintf("'%s' is not valid for %s. Use: %s.", $raw, $key, implode(', ', $spec['values']));
            default:
                return "'{$raw}' is not valid for {$key}.";
        }
    }
}
