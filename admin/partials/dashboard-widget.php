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

// Get local stats (cached for 5 minutes to avoid DB queries on every admin page)
$stats = get_transient('webdecoy_dashboard_stats');
if ($stats === false) {
    $detector = new WebDecoy_Detector();
    $stats = $detector->get_stats(7);
    set_transient('webdecoy_dashboard_stats', $stats, 5 * MINUTE_IN_SECONDS);
}

$blocked_stats = get_transient('webdecoy_dashboard_blocked_stats');
if ($blocked_stats === false) {
    $blocker = new WebDecoy_Blocker();
    $blocked_stats = $blocker->get_stats();
    set_transient('webdecoy_dashboard_blocked_stats', $blocked_stats, 5 * MINUTE_IN_SECONDS);
}
?>

<div class="webdecoy-widget">
    <div class="webdecoy-widget-stats">
        <div class="webdecoy-stat">
            <span class="webdecoy-stat-value"><?php echo esc_html(number_format($stats['total'])); ?></span>
            <span class="webdecoy-stat-label"><?php esc_html_e('Detections (7 days)', 'webdecoy'); ?></span>
        </div>
        <div class="webdecoy-stat">
            <span class="webdecoy-stat-value webdecoy-stat-danger"><?php echo esc_html(number_format($stats['high_risk'])); ?></span>
            <span class="webdecoy-stat-label"><?php esc_html_e('High Risk', 'webdecoy'); ?></span>
        </div>
        <div class="webdecoy-stat">
            <span class="webdecoy-stat-value"><?php echo esc_html(number_format($blocked_stats['active'])); ?></span>
            <span class="webdecoy-stat-label"><?php esc_html_e('Blocked IPs', 'webdecoy'); ?></span>
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
            <strong><?php esc_html_e('Want more intelligence?', 'webdecoy'); ?></strong>
            <?php esc_html_e('Connect to WebDecoy Cloud for IP reputation, VPN detection, and cross-site threat data.', 'webdecoy'); ?>
            <a href="<?php echo esc_url(admin_url('admin.php?page=webdecoy#tab-cloud')); ?>">
                <?php esc_html_e('Learn more', 'webdecoy'); ?>
            </a>
        </p>
    </div>
    <?php endif; ?>
</div>

<!-- Styles are loaded via webdecoy-admin.css -->
