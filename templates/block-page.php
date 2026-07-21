<?php
/**
 * WebDecoy Block Page Template
 *
 * This page is shown to visitors who have been blocked.
 * It can be customized by copying to your theme directory.
 *
 * @package WebDecoy
 */

// Prevent direct access
if (!defined('ABSPATH')) {
    exit;
}

// Get options
$options = get_option('webdecoy_options', []);
// Saved setting key is 'block_page_message' (fall back to legacy 'block_message').
$custom_message = $options['block_page_message'] ?? ($options['block_message'] ?? '');
$show_contact = $options['show_contact_on_block'] ?? false;
$contact_email = $options['contact_email'] ?? get_option('admin_email');

// Get block reason if available
$block_reason = isset($block_info['reason']) ? $block_info['reason'] : '';
$expires_at = isset($block_info['expires_at']) ? $block_info['expires_at'] : null;

// This is a standalone interstitial served before the theme renders (the
// request exits after this template), so the wp_enqueue_scripts hook never
// fires here. The stylesheet is still registered through the WordPress
// dependency API and printed with wp_print_styles() below.
wp_register_style(
    'webdecoy-block',
    WEBDECOY_PLUGIN_URL . 'public/css/webdecoy-block.css',
    [],
    WEBDECOY_VERSION
);
?>
<!DOCTYPE html>
<html <?php language_attributes(); ?>>
<head>
    <meta charset="<?php bloginfo('charset'); ?>">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta name="robots" content="noindex, nofollow">
    <title><?php esc_html_e('Access Denied', 'webdecoy'); ?> - <?php bloginfo('name'); ?></title>
    <?php wp_print_styles(['webdecoy-block']); ?>
</head>
<body>
    <div class="block-container">
        <div class="block-icon">
            <svg viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
                <path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zM4 12c0-4.42 3.58-8 8-8 1.85 0 3.55.63 4.9 1.69L5.69 16.9C4.63 15.55 4 13.85 4 12zm8 8c-1.85 0-3.55-.63-4.9-1.69L18.31 7.1C19.37 8.45 20 10.15 20 12c0 4.42-3.58 8-8 8z"/>
            </svg>
        </div>

        <h1><?php esc_html_e('Access Denied', 'webdecoy'); ?></h1>

        <p class="block-message">
            <?php if ($custom_message) : ?>
                <?php echo wp_kses_post($custom_message); ?>
            <?php else : ?>
                <?php esc_html_e('Your access to this website has been temporarily restricted due to suspicious activity detected from your connection.', 'webdecoy'); ?>
            <?php endif; ?>
        </p>

        <div class="block-details">
            <dl>
                <dt><?php esc_html_e('Your IP:', 'webdecoy'); ?></dt>
                <dd><?php echo esc_html($visitor_ip ?? sanitize_text_field(wp_unslash($_SERVER['REMOTE_ADDR'] ?? ''))); ?></dd>
            </dl>
            <?php if ($expires_at) : ?>
            <dl>
                <dt><?php esc_html_e('Block expires:', 'webdecoy'); ?></dt>
                <dd><?php echo esc_html(date_i18n(get_option('date_format') . ' ' . get_option('time_format'), strtotime($expires_at))); ?></dd>
            </dl>
            <?php endif; ?>
        </div>

        <?php if ($show_contact && $contact_email) : ?>
        <div class="contact-section">
            <p><?php esc_html_e('If you believe this is a mistake, please contact us:', 'webdecoy'); ?></p>
            <a href="mailto:<?php echo esc_attr($contact_email); ?>?subject=<?php
            /* translators: %s: visitor IP address */
            echo esc_attr(sprintf(__('Block Appeal - %s', 'webdecoy'), $visitor_ip ?? sanitize_text_field(wp_unslash($_SERVER['REMOTE_ADDR'] ?? '')))); ?>" class="contact-link">
                <?php esc_html_e('Contact Support', 'webdecoy'); ?>
            </a>
        </div>
        <?php endif; ?>

        <p class="reference-id">
            <?php esc_html_e('Reference ID:', 'webdecoy'); ?>
            <code><?php echo esc_html(substr(md5(($visitor_ip ?? sanitize_text_field(wp_unslash($_SERVER['REMOTE_ADDR'] ?? ''))) . gmdate('Ymd')), 0, 12)); ?></code>
        </p>
    </div>
</body>
</html>
