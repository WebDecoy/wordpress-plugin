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
$custom_message = $options['block_message'] ?? '';
$show_contact = $options['show_contact_on_block'] ?? false;
$contact_email = $options['contact_email'] ?? get_option('admin_email');

// Get block reason if available
$block_reason = isset($block_info['reason']) ? $block_info['reason'] : '';
$expires_at = isset($block_info['expires_at']) ? $block_info['expires_at'] : null;

?>
<!DOCTYPE html>
<html <?php language_attributes(); ?>>
<head>
    <meta charset="<?php bloginfo('charset'); ?>">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta name="robots" content="noindex, nofollow">
    <title><?php esc_html_e('Access Denied', 'webdecoy'); ?> - <?php bloginfo('name'); ?></title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
        }
        .block-container {
            background: #fff;
            border-radius: 12px;
            box-shadow: 0 20px 60px rgba(0, 0, 0, 0.3);
            max-width: 500px;
            width: 100%;
            padding: 40px;
            text-align: center;
        }
        .block-icon {
            width: 80px;
            height: 80px;
            background: #f44336;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            margin: 0 auto 24px;
        }
        .block-icon svg {
            width: 40px;
            height: 40px;
            fill: #fff;
        }
        h1 {
            color: #333;
            font-size: 28px;
            margin-bottom: 16px;
            font-weight: 600;
        }
        .block-message {
            color: #666;
            font-size: 16px;
            line-height: 1.6;
            margin-bottom: 24px;
        }
        .block-details {
            background: #f5f5f5;
            border-radius: 8px;
            padding: 16px;
            margin-bottom: 24px;
            font-size: 14px;
            color: #666;
        }
        .block-details dt {
            font-weight: 600;
            color: #333;
            display: inline;
        }
        .block-details dd {
            display: inline;
            margin-left: 8px;
        }
        .block-details dl {
            margin: 8px 0;
        }
        .contact-section {
            border-top: 1px solid #eee;
            padding-top: 24px;
            margin-top: 24px;
        }
        .contact-section p {
            color: #666;
            font-size: 14px;
            margin-bottom: 12px;
        }
        .contact-link {
            display: inline-block;
            background: #667eea;
            color: #fff;
            padding: 12px 24px;
            border-radius: 6px;
            text-decoration: none;
            font-weight: 500;
            transition: background 0.2s;
        }
        .contact-link:hover {
            background: #5a6fd6;
        }
        .reference-id {
            font-size: 12px;
            color: #999;
            margin-top: 24px;
        }
        .reference-id code {
            background: #f5f5f5;
            padding: 2px 6px;
            border-radius: 4px;
            font-family: monospace;
        }
    </style>
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
            <a href="mailto:<?php echo esc_attr($contact_email); ?>?subject=<?php echo esc_attr(sprintf(__('Block Appeal - %s', 'webdecoy'), $visitor_ip ?? sanitize_text_field(wp_unslash($_SERVER['REMOTE_ADDR'] ?? '')))); ?>" class="contact-link">
                <?php esc_html_e('Contact Support', 'webdecoy'); ?>
            </a>
        </div>
        <?php endif; ?>

        <p class="reference-id">
            <?php esc_html_e('Reference ID:', 'webdecoy'); ?>
            <code><?php echo esc_html(substr(md5(($visitor_ip ?? sanitize_text_field(wp_unslash($_SERVER['REMOTE_ADDR'] ?? ''))) . date('Ymd')), 0, 12)); ?></code>
        </p>
    </div>
</body>
</html>
