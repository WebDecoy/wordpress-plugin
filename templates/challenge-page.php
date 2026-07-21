<?php
/**
 * WebDecoy Challenge Page
 *
 * Displays a proof-of-work challenge to suspicious visitors.
 * Solves a SHA-256 puzzle in the background using a Web Worker,
 * then verifies server-side before allowing access.
 *
 * This is a standalone interstitial served before the theme renders
 * (the request exits after this template), so the wp_enqueue_scripts
 * hook never fires here. Assets are still managed through the WordPress
 * dependency APIs: wp_register_style()/wp_register_script() with
 * wp_print_styles()/wp_print_scripts() for targeted output, and
 * wp_add_inline_script() for the per-request configuration.
 *
 * @package WebDecoy
 */

// Prevent direct access
if (!defined('ABSPATH')) {
    exit;
}

if (!isset($challenge_data, $message, $redirect_url, $ajax_url, $nonce)) {
    wp_die('Invalid template context.', 403);
}

$webdecoy_options = get_option('webdecoy_options', []);
// Attribution is opt-in only (Settings > Blocking), per WordPress.org guideline 10.
$show_credit = !empty($webdecoy_options['challenge_show_credit']);

wp_register_style(
    'webdecoy-challenge',
    WEBDECOY_PLUGIN_URL . 'public/css/webdecoy-challenge.css',
    [],
    WEBDECOY_VERSION
);

wp_register_script(
    'webdecoy-challenge',
    WEBDECOY_PLUGIN_URL . 'public/js/webdecoy-challenge.js',
    [],
    WEBDECOY_VERSION,
    true
);

wp_add_inline_script(
    'webdecoy-challenge',
    'window.webdecoyChallengeConfig = ' . wp_json_encode([
        'challenge'   => $challenge_data,
        'ajaxUrl'     => $ajax_url,
        'nonce'       => $nonce,
        'redirectUrl' => $redirect_url,
        'i18n'        => [
            'solving'       => __('Solving challenge...', 'webdecoy'),
            'working'       => __('Working...', 'webdecoy'),
            'unsolvable'    => __('Challenge could not be solved. Please try again.', 'webdecoy'),
            'browserError'  => __('Browser error. Please try a different browser.', 'webdecoy'),
            'noWorkers'     => __('Browser does not support Web Workers. Please try a different browser.', 'webdecoy'),
            'verifying'     => __('Verifying...', 'webdecoy'),
            'verified'      => __('Verified! Redirecting...', 'webdecoy'),
            'failed'        => __('Verification failed.', 'webdecoy'),
            'networkError'  => __('Network error. Please try again.', 'webdecoy'),
            'refreshFailed' => __('Could not refresh challenge. Please reload the page.', 'webdecoy'),
        ],
    ]) . ';',
    'before'
);
?>
<!DOCTYPE html>
<html <?php language_attributes(); ?>>
<head>
    <meta charset="<?php bloginfo('charset'); ?>">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta name="robots" content="noindex, nofollow">
    <title><?php esc_html_e('Security Check', 'webdecoy'); ?> - <?php echo esc_html(get_bloginfo('name')); ?></title>
    <?php wp_print_styles(['webdecoy-challenge']); ?>
</head>
<body>
    <div class="challenge-card">
        <div class="challenge-icon">
            <svg viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg"><path d="M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4z"/></svg>
        </div>
        <h1><?php esc_html_e('Checking your browser', 'webdecoy'); ?></h1>
        <p class="subtitle"><?php echo esc_html($message); ?></p>

        <div class="challenge-checkbox" id="challengeBox" role="button" tabindex="0" aria-label="<?php esc_attr_e("Click to verify you are not a robot", 'webdecoy'); ?>">
            <div class="checkbox-box">
                <span class="check">&#10003;</span>
                <div class="spinner"></div>
            </div>
            <span class="checkbox-label"><?php esc_html_e("I'm not a robot", 'webdecoy'); ?></span>
        </div>

        <div class="status-text" id="statusText" role="status" aria-live="polite"></div>
        <button class="retry-btn" id="retryBtn"><?php esc_html_e('Try Again', 'webdecoy'); ?></button>

        <?php if ($show_credit) : ?>
        <div class="powered-by">
            <?php esc_html_e('Protected by', 'webdecoy'); ?> <a href="https://webdecoy.com" target="_blank" rel="noopener">WebDecoy</a>
        </div>
        <?php endif; ?>
    </div>

    <?php wp_print_scripts(['webdecoy-challenge']); ?>
</body>
</html>
