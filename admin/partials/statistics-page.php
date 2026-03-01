<?php
/**
 * WebDecoy Statistics Page
 *
 * @package WebDecoy
 */

// Prevent direct access
if (!defined('ABSPATH')) {
    exit;
}

if (!current_user_can('manage_options')) {
    wp_die(esc_html__('You do not have sufficient permissions to access this page.', 'webdecoy'));
}

global $wpdb;

$detections_table = $wpdb->prefix . 'webdecoy_detections';
$blocked_table = $wpdb->prefix . 'webdecoy_blocked_ips';
$checkout_table = $wpdb->prefix . 'webdecoy_checkout_attempts';

// 30-day detection trend
$thirty_days_ago = date('Y-m-d H:i:s', strtotime('-30 days'));
$daily_counts = $wpdb->get_results($wpdb->prepare(
    "SELECT DATE(created_at) as date, COUNT(*) as count FROM {$detections_table} WHERE created_at > %s GROUP BY DATE(created_at) ORDER BY date ASC",
    $thirty_days_ago
), ARRAY_A);

// Fill in missing days with 0
$daily_data = [];
for ($i = 29; $i >= 0; $i--) {
    $date = date('Y-m-d', strtotime("-{$i} days"));
    $daily_data[$date] = 0;
}
foreach ($daily_counts as $row) {
    if (isset($daily_data[$row['date']])) {
        $daily_data[$row['date']] = (int) $row['count'];
    }
}

// Threat level distribution
$threat_distribution = $wpdb->get_results($wpdb->prepare(
    "SELECT threat_level, COUNT(*) as count FROM {$detections_table} WHERE created_at > %s GROUP BY threat_level ORDER BY count DESC",
    $thirty_days_ago
), ARRAY_A);

// Top flagged signals (parse from JSON flags)
$recent_flags = $wpdb->get_results($wpdb->prepare(
    "SELECT flags FROM {$detections_table} WHERE created_at > %s AND flags IS NOT NULL AND flags != '' LIMIT 500",
    $thirty_days_ago
), ARRAY_A);

$signal_counts = [];
foreach ($recent_flags as $row) {
    $flags_data = json_decode($row['flags'], true);
    if (!is_array($flags_data)) {
        continue;
    }
    // Handle structured format
    $flags_arr = [];
    if (isset($flags_data['flags']) && is_array($flags_data['flags'])) {
        $flags_arr = $flags_data['flags'];
    } elseif (isset($flags_data['f']) && is_array($flags_data['f'])) {
        $flags_arr = $flags_data['f'];
    } elseif (!isset($flags_data['flags']) && !isset($flags_data['f']) && !isset($flags_data['metadata'])) {
        // Plain array of flags
        $flags_arr = array_filter($flags_data, 'is_string');
    }
    foreach ($flags_arr as $flag) {
        if (is_string($flag)) {
            $signal_counts[$flag] = ($signal_counts[$flag] ?? 0) + 1;
        }
    }
}
arsort($signal_counts);
$top_signals = array_slice($signal_counts, 0, 10, true);

// Top blocked IPs
$top_ips = $wpdb->get_results($wpdb->prepare(
    "SELECT ip_address, COUNT(*) as count, MAX(created_at) as last_seen FROM {$detections_table} WHERE created_at > %s GROUP BY ip_address ORDER BY count DESC LIMIT 10",
    $thirty_days_ago
), ARRAY_A);

// Source distribution
$source_distribution = $wpdb->get_results($wpdb->prepare(
    "SELECT source, COUNT(*) as count FROM {$detections_table} WHERE created_at > %s GROUP BY source ORDER BY count DESC",
    $thirty_days_ago
), ARRAY_A);

// Overall stats
$total_30d = array_sum($daily_data);
$total_7d = $wpdb->get_var($wpdb->prepare(
    "SELECT COUNT(*) FROM {$detections_table} WHERE created_at > %s",
    date('Y-m-d H:i:s', strtotime('-7 days'))
));
$total_today = $wpdb->get_var($wpdb->prepare(
    "SELECT COUNT(*) FROM {$detections_table} WHERE created_at > %s",
    date('Y-m-d 00:00:00')
));
// phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared -- static query, no user input
$active_blocks = $wpdb->get_var(
    "SELECT COUNT(*) FROM {$blocked_table} WHERE expires_at IS NULL OR expires_at > NOW()"
);

// WooCommerce stats (if active)
$woo_stats = null;
if (class_exists('WooCommerce')) {
    $woo_stats = [
        'attempts' => (int) $wpdb->get_var($wpdb->prepare(
            "SELECT COUNT(*) FROM {$checkout_table} WHERE created_at > %s",
            $thirty_days_ago
        )),
        'blocked' => (int) $wpdb->get_var($wpdb->prepare(
            "SELECT COUNT(*) FROM {$checkout_table} WHERE created_at > %s AND status = 'blocked'",
            $thirty_days_ago
        )),
    ];
}

$options = get_option('webdecoy_options', []);
?>

<div class="wrap">
    <h1><?php esc_html_e('WebDecoy Statistics', 'webdecoy'); ?></h1>

    <!-- Summary Stats -->
    <div class="webdecoy-stats-summary">
        <div class="webdecoy-stat-box">
            <span class="value"><?php echo esc_html(number_format($total_today)); ?></span>
            <span class="label"><?php esc_html_e('Today', 'webdecoy'); ?></span>
        </div>
        <div class="webdecoy-stat-box">
            <span class="value"><?php echo esc_html(number_format((int) $total_7d)); ?></span>
            <span class="label"><?php esc_html_e('Last 7 Days', 'webdecoy'); ?></span>
        </div>
        <div class="webdecoy-stat-box">
            <span class="value"><?php echo esc_html(number_format($total_30d)); ?></span>
            <span class="label"><?php esc_html_e('Last 30 Days', 'webdecoy'); ?></span>
        </div>
        <div class="webdecoy-stat-box webdecoy-stat-success">
            <span class="value"><?php echo esc_html(number_format((int) $active_blocks)); ?></span>
            <span class="label"><?php esc_html_e('Active Blocks', 'webdecoy'); ?></span>
        </div>
    </div>

    <!-- Charts Grid -->
    <div class="webdecoy-charts-grid">
        <!-- Detection Trend -->
        <div class="webdecoy-chart-card webdecoy-chart-wide">
            <h3><?php esc_html_e('Detection Trend (30 Days)', 'webdecoy'); ?></h3>
            <canvas id="webdecoyTrendChart" height="300"></canvas>
        </div>

        <!-- Threat Distribution -->
        <div class="webdecoy-chart-card">
            <h3><?php esc_html_e('Threat Level Distribution', 'webdecoy'); ?></h3>
            <canvas id="webdecoyThreatChart" height="300"></canvas>
        </div>

        <!-- Top Signals -->
        <div class="webdecoy-chart-card">
            <h3><?php esc_html_e('Top Detection Signals', 'webdecoy'); ?></h3>
            <canvas id="webdecoySignalsChart" height="300"></canvas>
        </div>
    </div>

    <!-- Top IPs Table -->
    <div class="webdecoy-chart-card">
        <h3><?php esc_html_e('Top Detected IPs (30 Days)', 'webdecoy'); ?></h3>
        <?php if (empty($top_ips)) : ?>
            <p class="description"><?php esc_html_e('No detections in the last 30 days.', 'webdecoy'); ?></p>
        <?php else : ?>
            <table class="wp-list-table widefat fixed striped">
                <thead>
                    <tr>
                        <th><?php esc_html_e('IP Address', 'webdecoy'); ?></th>
                        <th><?php esc_html_e('Detections', 'webdecoy'); ?></th>
                        <th><?php esc_html_e('Last Seen', 'webdecoy'); ?></th>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach ($top_ips as $ip_row) : ?>
                    <tr>
                        <td><code><?php echo esc_html($ip_row['ip_address']); ?></code></td>
                        <td><strong><?php echo esc_html($ip_row['count']); ?></strong></td>
                        <td><?php echo esc_html(date_i18n(get_option('date_format') . ' ' . get_option('time_format'), strtotime($ip_row['last_seen']))); ?></td>
                    </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
        <?php endif; ?>
    </div>

    <!-- Source Distribution -->
    <?php if (!empty($source_distribution)) : ?>
    <div class="webdecoy-chart-card">
        <h3><?php esc_html_e('Detection Sources', 'webdecoy'); ?></h3>
        <table class="wp-list-table widefat fixed striped">
            <thead>
                <tr>
                    <th><?php esc_html_e('Source', 'webdecoy'); ?></th>
                    <th><?php esc_html_e('Count', 'webdecoy'); ?></th>
                </tr>
            </thead>
            <tbody>
                <?php foreach ($source_distribution as $src) : ?>
                <tr>
                    <td><?php echo esc_html(str_replace('_', ' ', ucfirst($src['source']))); ?></td>
                    <td><strong><?php echo esc_html(number_format((int) $src['count'])); ?></strong></td>
                </tr>
                <?php endforeach; ?>
            </tbody>
        </table>
    </div>
    <?php endif; ?>

    <!-- WooCommerce Stats -->
    <?php if ($woo_stats) : ?>
    <div class="webdecoy-chart-card">
        <h3><?php esc_html_e('WooCommerce Protection', 'webdecoy'); ?></h3>
        <div class="webdecoy-stats-summary">
            <div class="webdecoy-stat-box">
                <span class="value"><?php echo esc_html(number_format($woo_stats['attempts'])); ?></span>
                <span class="label"><?php esc_html_e('Checkout Attempts', 'webdecoy'); ?></span>
            </div>
            <div class="webdecoy-stat-box webdecoy-stat-danger">
                <span class="value"><?php echo esc_html(number_format($woo_stats['blocked'])); ?></span>
                <span class="label"><?php esc_html_e('Blocked', 'webdecoy'); ?></span>
            </div>
        </div>
    </div>
    <?php endif; ?>

    <!-- Cloud Upsell -->
    <?php if (empty($options['api_key'])) : ?>
    <div class="webdecoy-cloud-upsell">
        <h3><?php esc_html_e('Want deeper insights?', 'webdecoy'); ?></h3>
        <p><?php esc_html_e('WebDecoy Cloud provides IP reputation scoring, VPN/proxy detection, geographic analysis, and indefinite data retention. Local data is automatically cleaned up after 30 days.', 'webdecoy'); ?></p>
        <a href="https://webdecoy.com/pricing" class="button button-primary" target="_blank" rel="noopener">
            <?php esc_html_e('Explore WebDecoy Cloud', 'webdecoy'); ?>
        </a>
    </div>
    <?php endif; ?>
</div>

<!-- Chart Data -->
<script>
window.webdecoyChartData = {
    trend: {
        labels: <?php echo wp_json_encode(array_keys($daily_data)); ?>,
        data: <?php echo wp_json_encode(array_values($daily_data)); ?>
    },
    threats: {
        labels: <?php echo wp_json_encode(array_column($threat_distribution, 'threat_level')); ?>,
        data: <?php echo wp_json_encode(array_map('intval', array_column($threat_distribution, 'count'))); ?>
    },
    signals: {
        labels: <?php echo wp_json_encode(array_keys($top_signals)); ?>,
        data: <?php echo wp_json_encode(array_values($top_signals)); ?>
    }
};
</script>
