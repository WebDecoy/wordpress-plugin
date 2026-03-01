<?php
/**
 * WebDecoy Activator
 *
 * Handles plugin activation and deactivation tasks including
 * creating database tables and setting default options.
 *
 * @package WebDecoy
 */

// Prevent direct access
if (!defined('ABSPATH')) {
    exit;
}

/**
 * WebDecoy Activator Class
 */
class WebDecoy_Activator
{
    /**
     * Database version for migrations
     */
    private const DB_VERSION = '2.0.0';

    /**
     * Plugin activation
     */
    public static function activate(): void
    {
        self::create_tables();
        self::set_default_options();
        self::schedule_cleanup();

        // Store DB version
        update_option('webdecoy_db_version', self::DB_VERSION);

        // Flush rewrite rules
        flush_rewrite_rules();
    }

    /**
     * Plugin deactivation
     */
    public static function deactivate(): void
    {
        // Clear scheduled events
        wp_clear_scheduled_hook('webdecoy_cleanup_expired');
        wp_clear_scheduled_hook('webdecoy_sync_blocked_ips');

        // Flush rewrite rules
        flush_rewrite_rules();
    }

    /**
     * Create database tables
     */
    private static function create_tables(): void
    {
        global $wpdb;

        $charset_collate = $wpdb->get_charset_collate();

        // Blocked IPs table
        $sql_blocked = "CREATE TABLE IF NOT EXISTS {$wpdb->prefix}webdecoy_blocked_ips (
            id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
            ip_address VARCHAR(45) NOT NULL,
            reason VARCHAR(255) DEFAULT '',
            blocked_at DATETIME NOT NULL,
            expires_at DATETIME DEFAULT NULL,
            created_by VARCHAR(100) DEFAULT 'system',
            PRIMARY KEY (id),
            UNIQUE KEY ip_address (ip_address),
            KEY expires_at (expires_at)
        ) $charset_collate;";

        // Local detections table (cache)
        $sql_detections = "CREATE TABLE IF NOT EXISTS {$wpdb->prefix}webdecoy_detections (
            id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
            remote_id VARCHAR(36) DEFAULT NULL,
            ip_address VARCHAR(45) NOT NULL,
            user_agent TEXT,
            score INT UNSIGNED DEFAULT 0,
            threat_level VARCHAR(20) DEFAULT 'MINIMAL',
            source VARCHAR(50) DEFAULT 'bot_scanner',
            flags TEXT DEFAULT NULL,
            created_at DATETIME NOT NULL,
            PRIMARY KEY (id),
            KEY ip_address (ip_address),
            KEY created_at (created_at),
            KEY threat_level (threat_level)
        ) $charset_collate;";

        // Rate limiting table
        $sql_rate_limits = "CREATE TABLE IF NOT EXISTS {$wpdb->prefix}webdecoy_rate_limits (
            ip_address VARCHAR(45) NOT NULL,
            request_count INT UNSIGNED DEFAULT 1,
            window_start DATETIME NOT NULL,
            PRIMARY KEY (ip_address),
            KEY window_start (window_start)
        ) $charset_collate;";

        // Checkout attempts table (WooCommerce)
        $sql_checkout = "CREATE TABLE IF NOT EXISTS {$wpdb->prefix}webdecoy_checkout_attempts (
            id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
            ip_address VARCHAR(45) NOT NULL,
            order_id BIGINT UNSIGNED DEFAULT NULL,
            status VARCHAR(20) DEFAULT 'attempt',
            amount DECIMAL(10, 2) DEFAULT 0.00,
            card_last4 VARCHAR(4) DEFAULT NULL,
            created_at DATETIME NOT NULL,
            PRIMARY KEY (id),
            KEY ip_address (ip_address),
            KEY created_at (created_at),
            KEY status (status)
        ) $charset_collate;";

        require_once ABSPATH . 'wp-admin/includes/upgrade.php';

        dbDelta($sql_blocked);
        dbDelta($sql_detections);
        dbDelta($sql_rate_limits);
        dbDelta($sql_checkout);
    }

    /**
     * Set default options
     */
    private static function set_default_options(): void
    {
        $defaults = [
            // API Configuration
            'api_key' => '',

            // Detection Settings
            'enabled' => true,
            'sensitivity' => 'medium',
            'min_score_to_block' => 75,
            'min_threat_level' => 'HIGH',

            // Good Bot Handling
            'allow_search_engines' => true,
            'allow_social_bots' => true,
            'block_ai_crawlers' => false,
            'custom_allowlist' => [],

            // Blocking Settings
            'block_action' => 'block',
            'block_duration' => 24,
            'show_block_page' => true,
            'block_page_message' => 'Access to this site has been restricted.',

            // Rate Limiting
            'rate_limit_enabled' => true,
            'rate_limit_requests' => 60,
            'rate_limit_window' => 60,

            // Form Protection
            'protect_comments' => true,
            'protect_login' => true,
            'protect_registration' => true,
            'inject_honeypot' => true,

            // WooCommerce
            'protect_checkout' => true,
            'checkout_velocity_limit' => 5,
            'checkout_velocity_window' => 3600,

            // Client-side Scanner
            'scanner_enabled' => true,
            'scanner_min_score' => 20,
            'scanner_on_all_pages' => true,
            'scanner_exclude_logged_in' => false,

            // Proof-of-Work
            'pow_enabled' => true,
            'pow_difficulty' => 4,
            'challenge_duration' => 15,
        ];

        // Only set if not already configured
        if (!get_option('webdecoy_options')) {
            add_option('webdecoy_options', $defaults);
        }
    }

    /**
     * Schedule cleanup tasks
     */
    private static function schedule_cleanup(): void
    {
        // Schedule expired block cleanup
        if (!wp_next_scheduled('webdecoy_cleanup_expired')) {
            wp_schedule_event(time(), 'hourly', 'webdecoy_cleanup_expired');
        }

        // Schedule blocked IP sync (every 15 minutes)
        if (!wp_next_scheduled('webdecoy_sync_blocked_ips')) {
            wp_schedule_event(time(), 'fifteen_minutes', 'webdecoy_sync_blocked_ips');
        }
    }

    /**
     * Check and run migrations if needed
     */
    public static function maybe_upgrade(): void
    {
        $current_version = get_option('webdecoy_db_version', '0');

        if (version_compare($current_version, self::DB_VERSION, '<')) {
            self::create_tables();
            update_option('webdecoy_db_version', self::DB_VERSION);
        }
    }

    /**
     * Uninstall plugin (called from uninstall.php)
     */
    public static function uninstall(): void
    {
        global $wpdb;

        // Drop tables
        $tables = [
            $wpdb->prefix . 'webdecoy_blocked_ips',
            $wpdb->prefix . 'webdecoy_detections',
            $wpdb->prefix . 'webdecoy_rate_limits',
            $wpdb->prefix . 'webdecoy_checkout_attempts',
        ];

        foreach ($tables as $table) {
            // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- Table name is safe, built from $wpdb->prefix
            $wpdb->query("DROP TABLE IF EXISTS {$table}");
        }

        // Delete options
        delete_option('webdecoy_options');
        delete_option('webdecoy_db_version');

        // Clear scheduled events
        wp_clear_scheduled_hook('webdecoy_cleanup_expired');
        wp_clear_scheduled_hook('webdecoy_sync_blocked_ips');
    }
}

// Register cleanup cron
add_action('webdecoy_cleanup_expired', function () {
    global $wpdb;

    // Clean up expired blocks
    $wpdb->query($wpdb->prepare(
        "DELETE FROM {$wpdb->prefix}webdecoy_blocked_ips WHERE expires_at IS NOT NULL AND expires_at < %s",
        current_time('mysql', true)
    ));

    // Clean up old rate limit entries
    $wpdb->query($wpdb->prepare(
        "DELETE FROM {$wpdb->prefix}webdecoy_rate_limits WHERE window_start < %s",
        gmdate('Y-m-d H:i:s', strtotime('-1 hour'))
    ));

    // Clean up old detections (keep 30 days)
    $wpdb->query($wpdb->prepare(
        "DELETE FROM {$wpdb->prefix}webdecoy_detections WHERE created_at < %s",
        gmdate('Y-m-d H:i:s', strtotime('-30 days'))
    ));

    // Clean up old checkout attempts (keep 7 days)
    $wpdb->query($wpdb->prepare(
        "DELETE FROM {$wpdb->prefix}webdecoy_checkout_attempts WHERE created_at < %s",
        gmdate('Y-m-d H:i:s', strtotime('-7 days'))
    ));
});

// Register custom cron interval
add_filter('cron_schedules', function ($schedules) {
    $schedules['fifteen_minutes'] = [
        'interval' => 15 * 60,
        'display' => 'Every 15 minutes',
    ];
    return $schedules;
});

// Check for upgrades on admin init
add_action('admin_init', ['WebDecoy_Activator', 'maybe_upgrade']);
