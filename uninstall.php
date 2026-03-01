<?php
/**
 * WebDecoy Plugin Uninstall
 *
 * Fired when the plugin is uninstalled.
 * Cleans up all plugin data including database tables, options, and transients.
 *
 * @package WebDecoy
 */

// If uninstall not called from WordPress, exit
if (!defined('WP_UNINSTALL_PLUGIN')) {
    exit;
}

// Load the activator class if not already loaded
$activator_file = __DIR__ . '/includes/class-webdecoy-activator.php';
if (file_exists($activator_file)) {
    require_once $activator_file;

    // Use the uninstall method if available
    if (class_exists('WebDecoy_Activator') && method_exists('WebDecoy_Activator', 'uninstall')) {
        WebDecoy_Activator::uninstall();
    }
} else {
    // Fallback: manually clean up if activator not available
    global $wpdb;

    // Drop custom tables
    $tables = [
        $wpdb->prefix . 'webdecoy_blocked_ips',
        $wpdb->prefix . 'webdecoy_detections',
        $wpdb->prefix . 'webdecoy_rate_limits',
        $wpdb->prefix . 'webdecoy_checkout_attempts',
    ];

    foreach ($tables as $table) {
        // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery.SchemaChange -- Table name is safe, built from $wpdb->prefix
        $wpdb->query("DROP TABLE IF EXISTS {$table}");
    }

    // Delete plugin options
    delete_option('webdecoy_options');
    delete_option('webdecoy_db_version');
    delete_option('webdecoy_api_status');
    delete_option('webdecoy_api_last_check');
    delete_option('webdecoy_api_last_error');
    delete_option('webdecoy_encryption_key');

    // Clear scheduled events
    wp_clear_scheduled_hook('webdecoy_cleanup_expired');
    wp_clear_scheduled_hook('webdecoy_sync_blocked_ips');
}

// Delete all transients with webdecoy_ prefix
global $wpdb;

// Delete transients from options table
$wpdb->query(
    "DELETE FROM {$wpdb->options} WHERE option_name LIKE '%_transient_webdecoy_%'"
); // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery

$wpdb->query(
    "DELETE FROM {$wpdb->options} WHERE option_name LIKE '%_transient_timeout_webdecoy_%'"
); // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery

// For multisite, clean up each site
if (is_multisite()) {
    $sites = get_sites(['fields' => 'ids']);

    foreach ($sites as $site_id) {
        switch_to_blog($site_id);

        // Drop tables for this site
        $tables = [
            $wpdb->prefix . 'webdecoy_blocked_ips',
            $wpdb->prefix . 'webdecoy_detections',
            $wpdb->prefix . 'webdecoy_rate_limits',
            $wpdb->prefix . 'webdecoy_checkout_attempts',
        ];

        foreach ($tables as $table) {
            // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery.SchemaChange -- Table name is safe, built from $wpdb->prefix
            $wpdb->query("DROP TABLE IF EXISTS {$table}");
        }

        // Delete options for this site
        delete_option('webdecoy_options');
        delete_option('webdecoy_db_version');
        delete_option('webdecoy_api_status');
        delete_option('webdecoy_api_last_check');
        delete_option('webdecoy_api_last_error');
        delete_option('webdecoy_encryption_key');

        // Clear scheduled events for this site
        wp_clear_scheduled_hook('webdecoy_cleanup_expired');
        wp_clear_scheduled_hook('webdecoy_sync_blocked_ips');

        // Delete transients for this site
        $wpdb->query(
            "DELETE FROM {$wpdb->options} WHERE option_name LIKE '%_transient_webdecoy_%'"
        ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery

        $wpdb->query(
            "DELETE FROM {$wpdb->options} WHERE option_name LIKE '%_transient_timeout_webdecoy_%'"
        ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery

        restore_current_blog();
    }
}
