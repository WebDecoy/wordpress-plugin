<?php
/**
 * WebDecoy Dashboard Widget
 *
 * @package WebDecoy
 */

// Prevent direct access
if (!defined('ABSPATH')) {
    exit;
}

// Keep the displayed findings and active-IP totals current with request counters.
// These are admin-only reads; no cache invalidation writes are added to bot requests.
$detector = new WebDecoy_Detector();
$stats = $detector->get_stats(7);
$blocker = new WebDecoy_Blocker();
$blocked_stats = $blocker->get_stats();

// Known crawlers, AI agents and bot tools seen in the last 24 hours. Counted
// locally on every install, connected or not (WebDecoy_Crawler_Visits).
$crawlers = get_transient('webdecoy_dashboard_crawlers');
if ($crawlers === false) {
    $crawlers = class_exists('WebDecoy_Crawler_Visits')
        ? WebDecoy_Crawler_Visits::summary(24)
        : ['total' => 0, 'verified' => 0, 'claimed' => 0, 'failed' => 0, 'groups' => ['ai' => 0, 'search' => 0, 'other' => 0], 'agents' => []];
    set_transient('webdecoy_dashboard_crawlers', $crawlers, 5 * MINUTE_IN_SECONDS);
}

$request_counts_today = WebDecoy_Request_Counts::summary(1);

// Checkout bot signals in the last 24 hours: velocity, card-testing patterns,
// bot scores at checkout and the decoy coupon, all recorded as detections
// with a woocommerce_ source by WebDecoy_WooCommerce.
$checkout_flagged = null;
if (class_exists('WooCommerce')) {
    $checkout_flagged = get_transient('webdecoy_dashboard_checkout_flagged');
    if ($checkout_flagged === false) {
        global $wpdb;
        $webdecoy_dw_table = esc_sql($wpdb->prefix . 'webdecoy_detections');
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery -- cached in a transient just below
        $checkout_flagged = (int) $wpdb->get_var($wpdb->prepare(
            "SELECT COUNT(*) FROM {$webdecoy_dw_table} WHERE created_at > %s AND source LIKE %s", // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- table name from $wpdb->prefix
            gmdate('Y-m-d H:i:s', time() - DAY_IN_SECONDS),
            $wpdb->esc_like('woocommerce_') . '%'
        ));
        set_transient('webdecoy_dashboard_checkout_flagged', $checkout_flagged, 5 * MINUTE_IN_SECONDS);
    }
    $checkout_flagged = (int) $checkout_flagged;
}
?>

<div class="webdecoy-widget">
    <?php
    // Trip-it-yourself prompt (app#679): shown only while the widget has
    // nothing to report — once real detections exist, the numbers speak.
    $webdecoy_dw_options = get_option('webdecoy_options', []);
    if (
        empty($stats['total'])
        && (!isset($webdecoy_dw_options['honeytoken_enabled']) || !empty($webdecoy_dw_options['honeytoken_enabled']))
    ) :
        $webdecoy_dw_canary = home_url((new WebDecoy_Honeytoken(!empty($webdecoy_dw_options['honeytoken_rotate'])))->primary_path());
    ?>
    <p>
        <?php esc_html_e('Your canary is live. Trip it yourself and watch the detection arrive:', 'webdecoy'); ?>
        <a href="<?php echo esc_url($webdecoy_dw_canary); ?>" target="_blank" rel="noopener">
            <?php esc_html_e('open your canary', 'webdecoy'); ?>
        </a>
    </p>
    <?php endif; ?>
    <div class="webdecoy-widget-crawlers">
        <h4><?php esc_html_e('Bots seen on your site in the last 24 hours', 'webdecoy'); ?></h4>
        <div class="webdecoy-widget-stats">
            <div class="webdecoy-stat">
                <span class="webdecoy-stat-value"><?php echo esc_html(number_format((int) $crawlers['total'])); ?></span>
                <span class="webdecoy-stat-label"><?php esc_html_e('Known bot visits', 'webdecoy'); ?></span>
            </div>
            <div class="webdecoy-stat">
                <span class="webdecoy-stat-value"><?php echo esc_html(number_format((int) $crawlers['groups']['ai'])); ?></span>
                <span class="webdecoy-stat-label"><?php esc_html_e('AI crawlers and agents', 'webdecoy'); ?></span>
            </div>
            <?php if ($checkout_flagged !== null) : ?>
            <div class="webdecoy-stat">
                <span class="webdecoy-stat-value<?php echo $checkout_flagged > 0 ? ' webdecoy-stat-danger' : ''; ?>"><?php echo esc_html(number_format($checkout_flagged)); ?></span>
                <span class="webdecoy-stat-label"><?php esc_html_e('Checkout bot signals', 'webdecoy'); ?></span>
            </div>
            <?php else : ?>
            <div class="webdecoy-stat">
                <span class="webdecoy-stat-value"><?php echo esc_html(number_format((int) $crawlers['groups']['search'])); ?></span>
                <span class="webdecoy-stat-label"><?php esc_html_e('Search engines', 'webdecoy'); ?></span>
            </div>
            <?php endif; ?>
        </div>

        <?php if ((int) $crawlers['total'] > 0) : ?>
        <p class="webdecoy-widget-verification">
            <?php
            echo esc_html(sprintf(
                /* translators: 1: visits whose address passed DNS verification, 2: visits identified by User-Agent only, 3: visits that failed verification */
                __('%1$s verified by DNS, %2$s identified by User-Agent only, %3$s failed verification (impersonators).', 'webdecoy'),
                number_format((int) $crawlers['verified']),
                number_format((int) $crawlers['claimed']),
                number_format((int) $crawlers['failed'])
            ));
            ?>
        </p>
        <ul class="webdecoy-widget-agents">
            <?php foreach (array_slice($crawlers['agents'], 0, 5) as $webdecoy_dw_agent) : ?>
            <li>
                <span class="webdecoy-agent-name">
                    <strong><?php echo esc_html($webdecoy_dw_agent['name']); ?></strong>
                    <span class="webdecoy-agent-category"><?php echo esc_html(WebDecoy_Crawler_Visits::category_label((string) $webdecoy_dw_agent['category'])); ?></span>
                </span>
                <span class="webdecoy-count"><?php echo esc_html(number_format((int) $webdecoy_dw_agent['hits'])); ?></span>
            </li>
            <?php endforeach; ?>
        </ul>
        <?php else : ?>
        <p class="webdecoy-widget-verification">
            <?php esc_html_e('No known crawler has visited yet. Most public sites see search engines and AI crawlers within hours.', 'webdecoy'); ?>
        </p>
        <?php endif; ?>
        <p class="webdecoy-widget-footnote">
            <?php esc_html_e('Counted on this server with no account. Pages served from a page cache are not counted, so these are minimums.', 'webdecoy'); ?>
            <a href="<?php echo esc_url(admin_url('admin.php?page=webdecoy-statistics')); ?>"><?php esc_html_e('See every bot', 'webdecoy'); ?></a>
        </p>
    </div>

    <div class="webdecoy-widget-request-counts">
        <h4><?php esc_html_e('Detection rows and requests today (UTC)', 'webdecoy'); ?></h4>
        <?php if ($request_counts_today['available']) : ?>
        <div class="webdecoy-widget-stats">
            <?php foreach (['detections' => __('Detection rows', 'webdecoy'), 'blocked' => __('Blocked requests', 'webdecoy'), 'withheld' => __('Enforcement withheld', 'webdecoy')] as $metric => $label) : ?>
            <div class="webdecoy-stat">
                <span class="webdecoy-stat-value" data-webdecoy-count="<?php echo esc_attr($metric); ?>"><?php echo esc_html(number_format($request_counts_today[$metric])); ?></span>
                <span class="webdecoy-stat-label"><?php echo esc_html($label); ?></span>
            </div>
            <?php endforeach; ?>
        </div>
        <p>
            <?php echo esc_html(sprintf(
                /* translators: 1: requests throttled, 2: requests challenged */
                __('Throttled requests: %1$s. Challenges served: %2$s.', 'webdecoy'),
                number_format($request_counts_today['throttled']), number_format($request_counts_today['challenged'])
            )); ?>
        </p>
        <p class="description">
            <?php esc_html_e('Repeat blocks are included. Detection rows are saved findings; one request can create several. Withheld enforcement is not a block.', 'webdecoy'); ?>
            <?php echo esc_html(sprintf(
                /* translators: %s: UTC date and time when request tracking started */
                __('Request tracking started %s UTC; earlier request totals are unavailable.', 'webdecoy'),
                gmdate('Y-m-d H:i', $request_counts_today['started_at'])
            )); ?>
            <a href="<?php echo esc_url(admin_url('admin.php?page=webdecoy-statistics')); ?>"><?php esc_html_e('Compare request counts', 'webdecoy'); ?></a>
        </p>
        <?php else : ?>
        <p class="description"><?php esc_html_e('Request counters are not available yet. Reload after the database update finishes.', 'webdecoy'); ?></p>
        <?php endif; ?>
    </div>

    <div class="webdecoy-widget-stats">
        <div class="webdecoy-stat">
            <span class="webdecoy-stat-value"><?php echo esc_html(number_format($stats['total'])); ?></span>
            <span class="webdecoy-stat-label"><?php esc_html_e('Detection rows (7 days)', 'webdecoy'); ?></span>
        </div>
        <div class="webdecoy-stat">
            <span class="webdecoy-stat-value webdecoy-stat-danger"><?php echo esc_html(number_format($stats['high_risk'])); ?></span>
            <span class="webdecoy-stat-label"><?php esc_html_e('High Risk', 'webdecoy'); ?></span>
        </div>
        <div class="webdecoy-stat">
            <span class="webdecoy-stat-value"><?php echo esc_html(number_format($blocked_stats['active'])); ?></span>
            <span class="webdecoy-stat-label"><?php esc_html_e('Active blocked IPs', 'webdecoy'); ?></span>
        </div>
    </div>

    <?php if (!empty($stats['by_level'])) : ?>
    <div class="webdecoy-widget-breakdown">
        <h4><?php esc_html_e('Threat Levels', 'webdecoy'); ?></h4>
        <ul>
            <?php foreach ($stats['by_level'] as $level => $data) : ?>
            <li>
                <span class="webdecoy-level webdecoy-level-<?php echo esc_attr(strtolower($level)); ?>">
                    <?php echo esc_html($level); ?>
                </span>
                <span class="webdecoy-count"><?php echo esc_html(number_format($data->count)); ?></span>
            </li>
            <?php endforeach; ?>
        </ul>
    </div>
    <?php endif; ?>

    <div class="webdecoy-widget-actions">
        <a href="<?php echo esc_url(admin_url('admin.php?page=webdecoy-detections')); ?>" class="button">
            <?php esc_html_e('View All Detections', 'webdecoy'); ?>
        </a>
        <a href="<?php echo esc_url(admin_url('admin.php?page=webdecoy-blocked')); ?>" class="button">
            <?php esc_html_e('Manage Blocked IPs', 'webdecoy'); ?>
        </a>
    </div>

    <?php
    $options = get_option('webdecoy_options', []);
    if (empty($options['api_key'])) :
    ?>
    <div class="webdecoy-widget-upsell">
        <p>
            <strong><?php esc_html_e('Everything above works without an account.', 'webdecoy'); ?></strong>
            <?php esc_html_e('Connect for free to see these detections in the WebDecoy dashboard and get a monthly report. Paid plans add whether an address has been seen attacking other sites, and webhook alerts.', 'webdecoy'); ?>
            <a href="<?php echo esc_url(admin_url('admin.php?page=webdecoy&tab=cloud')); ?>">
                <?php esc_html_e('Connect this site', 'webdecoy'); ?>
            </a>
        </p>
    </div>
    <?php endif; ?>
</div>

<!-- Styles are loaded via webdecoy-admin.css -->
