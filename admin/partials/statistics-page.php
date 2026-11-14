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

$detections_table = esc_sql($wpdb->prefix . 'webdecoy_detections');
$blocked_table = esc_sql($wpdb->prefix . 'webdecoy_blocked_ips');
$checkout_table = esc_sql($wpdb->prefix . 'webdecoy_checkout_attempts');

// 30-day detection trend
$thirty_days_ago = gmdate('Y-m-d H:i:s', strtotime('-30 days'));
$daily_counts = $wpdb->get_results($wpdb->prepare(
    "SELECT DATE(created_at) as date, COUNT(*) as count FROM {$detections_table} WHERE created_at > %s GROUP BY DATE(created_at) ORDER BY date ASC", // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- table name from $wpdb->prefix, not user input
    $thirty_days_ago
), ARRAY_A);

// Fill in missing days with 0
$daily_data = [];
for ($i = 29; $i >= 0; $i--) {
    $date = gmdate('Y-m-d', strtotime("-{$i} days"));
    $daily_data[$date] = 0;
}
foreach ($daily_counts as $row) {
    if (isset($daily_data[$row['date']])) {
        $daily_data[$row['date']] = (int) $row['count'];
    }
}

// Threat level distribution
$threat_distribution = $wpdb->get_results($wpdb->prepare(
    "SELECT threat_level, COUNT(*) as count FROM {$detections_table} WHERE created_at > %s GROUP BY threat_level ORDER BY count DESC", // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- table name from $wpdb->prefix, not user input
    $thirty_days_ago
), ARRAY_A);

// Top flagged signals (parse from JSON flags)
$recent_flags = $wpdb->get_results($wpdb->prepare(
    "SELECT flags FROM {$detections_table} WHERE created_at > %s AND flags IS NOT NULL AND flags != '' LIMIT 500", // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- table name from $wpdb->prefix, not user input
    $thirty_days_ago
), ARRAY_A);

$signal_counts = [];
foreach ($recent_flags as $row) {
    // flags is TEXT DEFAULT NULL; cast so a null row never reaches json_decode()
    // (a deprecation on PHP 8.1+). '' decodes to null and is skipped just below.
    $flags_data = json_decode((string) ($row['flags'] ?? ''), true);
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
    "SELECT ip_address, COUNT(*) as count, MAX(created_at) as last_seen FROM {$detections_table} WHERE created_at > %s GROUP BY ip_address ORDER BY count DESC LIMIT 10", // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- table name from $wpdb->prefix, not user input
    $thirty_days_ago
), ARRAY_A);

// Source distribution
$source_distribution = $wpdb->get_results($wpdb->prepare(
    "SELECT source, COUNT(*) as count FROM {$detections_table} WHERE created_at > %s GROUP BY source ORDER BY count DESC", // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- table name from $wpdb->prefix, not user input
    $thirty_days_ago
), ARRAY_A);

// Overall stats
$total_30d = array_sum($daily_data);
$total_7d = $wpdb->get_var($wpdb->prepare(
    "SELECT COUNT(*) FROM {$detections_table} WHERE created_at > %s", // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- table name from $wpdb->prefix, not user input
    gmdate('Y-m-d H:i:s', strtotime('-7 days'))
));
$total_today = $wpdb->get_var($wpdb->prepare(
    "SELECT COUNT(*) FROM {$detections_table} WHERE created_at >= %s", // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- table name from $wpdb->prefix, not user input
    gmdate('Y-m-d 00:00:00')
));
// expires_at is stored in UTC, so it must be compared against a UTC value. MySQL's
// NOW() resolves in the database session time zone (SYSTEM by default, which
// WordPress never sets), so it disagrees with the column on any DB host not on UTC.
$active_blocks = $wpdb->get_var($wpdb->prepare(
    "SELECT COUNT(*) FROM {$blocked_table} WHERE expires_at IS NULL OR expires_at > %s", // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- table name from $wpdb->prefix, not user input
    gmdate('Y-m-d H:i:s')
));

// WooCommerce stats (if active)
$woo_stats = null;
if (class_exists('WooCommerce')) {
    $woo_stats = [
        'attempts' => (int) $wpdb->get_var($wpdb->prepare(
            "SELECT COUNT(*) FROM {$checkout_table} WHERE created_at > %s", // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- table name from $wpdb->prefix, not user input
            $thirty_days_ago
        )),
        'blocked' => (int) $wpdb->get_var($wpdb->prepare(
            "SELECT COUNT(*) FROM {$checkout_table} WHERE created_at > %s AND status = 'blocked'", // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- table name from $wpdb->prefix, not user input
            $thirty_days_ago
        )),
    ];
}

// Known crawlers, AI agents and bot tools over 7 days (counters only).
$crawler_summary = class_exists('WebDecoy_Crawler_Visits') ? WebDecoy_Crawler_Visits::summary(7 * 24) : null;

$request_windows = [1 => WebDecoy_Request_Counts::summary(1), 7 => WebDecoy_Request_Counts::summary(7), 30 => WebDecoy_Request_Counts::summary(30)];
$options = get_option('webdecoy_options', []);
?>

<div class="wrap">
    <h1><?php esc_html_e('WebDecoy Statistics', 'webdecoy'); ?></h1>

    <!-- Summary Stats -->
    <div class="webdecoy-stats-summary">
        <div class="webdecoy-stat-box">
            <span class="value"><?php echo esc_html(number_format($total_today)); ?></span>
            <span class="label"><?php esc_html_e('Detection rows today', 'webdecoy'); ?></span>
        </div>
        <div class="webdecoy-stat-box">
            <span class="value"><?php echo esc_html(number_format((int) $total_7d)); ?></span>
            <span class="label"><?php esc_html_e('Detection rows (rolling 7 days)', 'webdecoy'); ?></span>
        </div>
        <div class="webdecoy-stat-box">
            <span class="value"><?php echo esc_html(number_format($total_30d)); ?></span>
            <span class="label"><?php esc_html_e('Detection rows (30 days)', 'webdecoy'); ?></span>
        </div>
        <div class="webdecoy-stat-box webdecoy-stat-success">
            <span class="value"><?php echo esc_html(number_format((int) $active_blocks)); ?></span>
            <span class="label"><?php esc_html_e('Active blocked IPs', 'webdecoy'); ?></span>
        </div>
    </div>

    <div class="webdecoy-chart-card">
        <h2><?php esc_html_e('Detection rows and request outcomes', 'webdecoy'); ?></h2>
        <p class="description"><?php esc_html_e('Detection rows are saved findings, not a request total. One request can create several findings, while a repeat IP block may create no new finding. Each request is counted once under its strongest outcome below.', 'webdecoy'); ?></p>
        <table class="wp-list-table widefat striped">
            <thead><tr>
                <th scope="col"><?php esc_html_e('Metric', 'webdecoy'); ?></th>
                <th scope="col"><?php esc_html_e('Today (UTC)', 'webdecoy'); ?></th>
                <th scope="col"><?php esc_html_e('7 calendar days (UTC)', 'webdecoy'); ?></th>
                <th scope="col"><?php esc_html_e('30 calendar days (UTC)', 'webdecoy'); ?></th>
            </tr></thead>
            <tbody>
                <?php foreach ([
                    'detections' => __('Detection rows', 'webdecoy'),
                    'blocked' => __('Blocked requests (403)', 'webdecoy'),
                    'throttled' => __('Throttled requests (429)', 'webdecoy'),
                    'challenged' => __('Challenges served', 'webdecoy'),
                    'withheld' => __('Requests with enforcement withheld', 'webdecoy'),
                ] as $metric => $label) : ?>
                <tr><th scope="row"><?php echo esc_html($label); ?></th>
                    <?php foreach ($request_windows as $days => $counts) : ?>
                    <td data-webdecoy-outcome="<?php echo esc_attr($metric); ?>" data-window="<?php echo esc_attr($days); ?>"><?php echo $counts['available'] ? esc_html(number_format($counts[$metric])) : '&mdash;'; ?></td>
                    <?php endforeach; ?>
                </tr>
                <?php endforeach; ?>
            </tbody>
        </table>
        <p class="description"><?php esc_html_e('Calendar windows include today. Blocked and throttled counts require an actual denial from WebDecoy; challenges are separate. Withheld enforcement includes monitor mode and is not a block. Setup-test responses, decoy pages, form-validation notices and requests stopped earlier by another firewall or cache are excluded from request-denial counts.', 'webdecoy'); ?></p>
        <?php if ($request_windows[1]['available']) : ?>
        <p class="description"><?php echo esc_html(sprintf(
            /* translators: %s: UTC date and time when request tracking started */
            __('Request tracking started %s UTC. Earlier request totals cannot be reconstructed from detection rows. Request counters retain 30 calendar days.', 'webdecoy'),
            gmdate('Y-m-d H:i', $request_windows[1]['started_at'])
        )); ?></p>
        <?php else : ?>
        <p class="description"><?php esc_html_e('Request counters are not available yet. Reload after the database update finishes.', 'webdecoy'); ?></p>
        <?php endif; ?>
    </div>

    <!-- Charts Grid -->
    <div class="webdecoy-charts-grid">
        <!-- Detection Trend -->
        <div class="webdecoy-chart-card webdecoy-chart-wide">
            <h3><?php esc_html_e('Detection Trend (30 Days)', 'webdecoy'); ?></h3>
            <div class="webdecoy-chart-box">
                <canvas id="webdecoyTrendChart"></canvas>
            </div>
        </div>

        <!-- Threat Distribution -->
        <div class="webdecoy-chart-card">
            <h3><?php esc_html_e('Threat Level Distribution', 'webdecoy'); ?></h3>
            <div class="webdecoy-chart-box">
                <canvas id="webdecoyThreatChart"></canvas>
            </div>
        </div>

        <!-- Top Signals -->
        <div class="webdecoy-chart-card">
            <h3><?php esc_html_e('Top Detection Signals', 'webdecoy'); ?></h3>
            <div class="webdecoy-chart-box">
                <canvas id="webdecoySignalsChart"></canvas>
            </div>
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

    <!-- Known bots and AI crawlers -->
    <?php if ($crawler_summary !== null) : ?>
    <div class="webdecoy-chart-card">
        <h3><?php esc_html_e('Bots and AI Crawlers (7 Days)', 'webdecoy'); ?></h3>
        <p class="description">
            <?php esc_html_e('Every visit from a known crawler, AI agent or bot tool, counted on this server. Only a count per bot per hour is kept: no addresses, no pages, and nothing about human visitors. Verified means the address passed reverse and forward DNS for that crawler; failed means it claimed to be a crawler it is not.', 'webdecoy'); ?>
        </p>
        <?php if (empty($crawler_summary['agents'])) : ?>
            <p class="description"><?php esc_html_e('No known bot has visited in the last 7 days.', 'webdecoy'); ?></p>
        <?php else : ?>
            <table class="wp-list-table widefat fixed striped">
                <thead>
                    <tr>
                        <th><?php esc_html_e('Bot', 'webdecoy'); ?></th>
                        <th><?php esc_html_e('Type', 'webdecoy'); ?></th>
                        <th><?php esc_html_e('Visits', 'webdecoy'); ?></th>
                        <th><?php esc_html_e('Verified', 'webdecoy'); ?></th>
                        <th><?php esc_html_e('User-Agent only', 'webdecoy'); ?></th>
                        <th><?php esc_html_e('Failed verification', 'webdecoy'); ?></th>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach (array_slice($crawler_summary['agents'], 0, 50) as $agent_row) : ?>
                    <tr>
                        <td>
                            <strong><?php echo esc_html($agent_row['name']); ?></strong>
                            <?php if ($agent_row['organization'] !== '') : ?>
                                <br><span class="description"><?php echo esc_html($agent_row['organization']); ?></span>
                            <?php endif; ?>
                        </td>
                        <td><?php echo esc_html(WebDecoy_Crawler_Visits::category_label((string) $agent_row['category'])); ?></td>
                        <td><strong><?php echo esc_html(number_format((int) $agent_row['hits'])); ?></strong></td>
                        <td><?php echo esc_html(number_format((int) $agent_row['verified'])); ?></td>
                        <td><?php echo esc_html(number_format((int) $agent_row['claimed'])); ?></td>
                        <td><?php echo esc_html(number_format((int) $agent_row['failed'])); ?></td>
                    </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
            <p class="description">
                <?php esc_html_e('To refuse AI crawlers, turn on Block AI crawlers under Settings, Good Bots. Pages served from a page cache are not counted, so these are minimums.', 'webdecoy'); ?>
            </p>
        <?php endif; ?>
    </div>
    <?php endif; ?>

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
        <p><?php esc_html_e('Connect for free to see these detections in the WebDecoy dashboard alongside your other sites, and get a monthly report. Local data is automatically cleaned up after 30 days.', 'webdecoy'); ?></p>
        <a href="<?php echo esc_url(admin_url('admin.php?page=webdecoy&tab=cloud')); ?>" class="button button-primary">
            <?php esc_html_e('Connect to WebDecoy Cloud', 'webdecoy'); ?>
        </a>
    </div>
    <?php endif; ?>
</div>

<?php
// Attach the chart data to the footer-enqueued charts script. The
// 'webdecoy-charts' handle is enqueued in admin_scripts() for this page hook
// with in_footer=true, so attaching inline data here (during page render,
// before admin footer scripts print) guarantees it lands before the script.
wp_add_inline_script(
    'webdecoy-charts',
    'window.webdecoyChartData = ' . wp_json_encode([
        'trend' => [
            'labels' => array_keys($daily_data),
            'data'   => array_values($daily_data),
        ],
        'threats' => [
            'labels' => array_column($threat_distribution, 'threat_level'),
            'data'   => array_map('intval', array_column($threat_distribution, 'count')),
        ],
        'signals' => [
            'labels' => array_keys($top_signals),
            'data'   => array_values($top_signals),
        ],
    ]) . ';',
    'before'
);
