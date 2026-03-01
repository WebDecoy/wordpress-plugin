<?php
/**
 * WebDecoy Blocked IPs Page
 *
 * @package WebDecoy
 */

// Prevent direct access
if (!defined('ABSPATH')) {
    exit;
}

// Capability check
if (!current_user_can('manage_options')) {
    wp_die(esc_html__('You do not have sufficient permissions to access this page.', 'webdecoy'));
}

$blocker = new WebDecoy_Blocker();

// Handle actions
if (isset($_POST['webdecoy_block_ip']) && isset($_POST['_wpnonce']) && wp_verify_nonce(sanitize_text_field(wp_unslash($_POST['_wpnonce'])), 'webdecoy_block_ip') && current_user_can('manage_options')) {
    $ip = sanitize_text_field($_POST['ip_address']);
    $reason = sanitize_text_field($_POST['reason'] ?? '');
    $duration = intval($_POST['duration'] ?? 24);

    if (filter_var($ip, FILTER_VALIDATE_IP)) {
        $blocker->block($ip, $reason, $duration > 0 ? $duration : null);
        echo '<div class="notice notice-success"><p>' . esc_html__('IP blocked successfully.', 'webdecoy') . '</p></div>';
    } else {
        echo '<div class="notice notice-error"><p>' . esc_html__('Invalid IP address.', 'webdecoy') . '</p></div>';
    }
}

if (isset($_GET['unblock']) && isset($_GET['_wpnonce']) && wp_verify_nonce(sanitize_text_field(wp_unslash($_GET['_wpnonce'])), 'webdecoy_unblock') && current_user_can('manage_options')) {
    $ip = sanitize_text_field($_GET['unblock']);
    $blocker->unblock($ip);
    echo '<div class="notice notice-success"><p>' . esc_html__('IP unblocked successfully.', 'webdecoy') . '</p></div>';
}

// Get blocked IPs
$page = isset($_GET['paged']) ? max(1, intval($_GET['paged'])) : 1;
$per_page = 20;
$blocked_ips = $blocker->get_blocked_ips([
    'page' => $page,
    'per_page' => $per_page,
]);
$total = $blocker->get_blocked_count();
$total_pages = ceil($total / $per_page);

$stats = $blocker->get_stats();
?>

<div class="wrap">
    <h1><?php esc_html_e('Blocked IPs', 'webdecoy'); ?></h1>

    <div class="webdecoy-blocked-stats">
        <div class="webdecoy-stat-box">
            <span class="value"><?php echo esc_html(number_format($stats['active'])); ?></span>
            <span class="label"><?php esc_html_e('Active Blocks', 'webdecoy'); ?></span>
        </div>
        <div class="webdecoy-stat-box">
            <span class="value"><?php echo esc_html(number_format($stats['permanent'])); ?></span>
            <span class="label"><?php esc_html_e('Permanent', 'webdecoy'); ?></span>
        </div>
        <div class="webdecoy-stat-box">
            <span class="value"><?php echo esc_html(number_format($stats['last_24h'])); ?></span>
            <span class="label"><?php esc_html_e('Last 24 Hours', 'webdecoy'); ?></span>
        </div>
    </div>

    <div class="webdecoy-add-block">
        <h2><?php esc_html_e('Block an IP', 'webdecoy'); ?></h2>
        <form method="post" class="webdecoy-inline-form">
            <?php wp_nonce_field('webdecoy_block_ip'); ?>
            <input type="hidden" name="webdecoy_block_ip" value="1" />

            <label>
                <?php esc_html_e('IP Address:', 'webdecoy'); ?>
                <input type="text" name="ip_address" required placeholder="192.168.1.1" />
            </label>

            <label>
                <?php esc_html_e('Reason:', 'webdecoy'); ?>
                <input type="text" name="reason" placeholder="<?php esc_attr_e('Optional reason', 'webdecoy'); ?>" />
            </label>

            <label>
                <?php esc_html_e('Duration:', 'webdecoy'); ?>
                <select name="duration">
                    <option value="1"><?php esc_html_e('1 hour', 'webdecoy'); ?></option>
                    <option value="24" selected><?php esc_html_e('24 hours', 'webdecoy'); ?></option>
                    <option value="168"><?php esc_html_e('7 days', 'webdecoy'); ?></option>
                    <option value="720"><?php esc_html_e('30 days', 'webdecoy'); ?></option>
                    <option value="0"><?php esc_html_e('Permanent', 'webdecoy'); ?></option>
                </select>
            </label>

            <button type="submit" class="button button-primary">
                <?php esc_html_e('Block IP', 'webdecoy'); ?>
            </button>
        </form>
    </div>

    <?php if (empty($blocked_ips)) : ?>
        <p><?php esc_html_e('No blocked IPs.', 'webdecoy'); ?></p>
    <?php else : ?>
        <table class="wp-list-table widefat fixed striped">
            <thead>
                <tr>
                    <th><?php esc_html_e('IP Address', 'webdecoy'); ?></th>
                    <th><?php esc_html_e('Reason', 'webdecoy'); ?></th>
                    <th><?php esc_html_e('Blocked At', 'webdecoy'); ?></th>
                    <th><?php esc_html_e('Expires', 'webdecoy'); ?></th>
                    <th><?php esc_html_e('Blocked By', 'webdecoy'); ?></th>
                    <th><?php esc_html_e('Actions', 'webdecoy'); ?></th>
                </tr>
            </thead>
            <tbody>
                <?php foreach ($blocked_ips as $block) : ?>
                <tr>
                    <td><code><?php echo esc_html($block['ip_address']); ?></code></td>
                    <td><?php echo esc_html($block['reason'] ?: '-'); ?></td>
                    <td><?php echo esc_html(date_i18n(get_option('date_format') . ' ' . get_option('time_format'), strtotime($block['blocked_at']))); ?></td>
                    <td>
                        <?php if ($block['expires_at']) : ?>
                            <?php echo esc_html(date_i18n(get_option('date_format') . ' ' . get_option('time_format'), strtotime($block['expires_at']))); ?>
                        <?php else : ?>
                            <em><?php esc_html_e('Never (permanent)', 'webdecoy'); ?></em>
                        <?php endif; ?>
                    </td>
                    <td><?php echo esc_html($block['created_by'] ?? 'system'); ?></td>
                    <td>
                        <a href="<?php echo esc_url(wp_nonce_url(add_query_arg('unblock', $block['ip_address']), 'webdecoy_unblock')); ?>"
                           class="button button-small"
                           onclick="return confirm('<?php esc_attr_e('Are you sure you want to unblock this IP?', 'webdecoy'); ?>')">
                            <?php esc_html_e('Unblock', 'webdecoy'); ?>
                        </a>
                    </td>
                </tr>
                <?php endforeach; ?>
            </tbody>
        </table>

        <?php if ($total_pages > 1) : ?>
        <div class="tablenav bottom">
            <div class="tablenav-pages">
                <?php
                // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- paginate_links returns safe HTML
                echo paginate_links([
                    'base' => add_query_arg('paged', '%#%'),
                    'format' => '',
                    'prev_text' => '&laquo;',
                    'next_text' => '&raquo;',
                    'total' => $total_pages,
                    'current' => $page,
                ]);
                ?>
            </div>
        </div>
        <?php endif; ?>
    <?php endif; ?>
</div>

<!-- Styles are loaded via webdecoy-admin.css -->
