<?php
/**
 * WebDecoy Settings Page
 *
 * @package WebDecoy
 */

// Prevent direct access
if (!defined('ABSPATH')) {
    exit;
}

$options = get_option('webdecoy_options', []);
?>

<div class="wrap webdecoy-settings-wrap">
    <h1><?php echo esc_html(get_admin_page_title()); ?></h1>

    <?php settings_errors('webdecoy_options'); ?>

    <form method="post" action="options.php">
        <?php settings_fields('webdecoy_options'); ?>

        <div class="webdecoy-tabs">
            <nav class="nav-tab-wrapper">
                <a href="#tab-detection" class="nav-tab nav-tab-active"><?php esc_html_e('Protection', 'webdecoy'); ?></a>
                <a href="#tab-bots" class="nav-tab"><?php esc_html_e('Good Bots', 'webdecoy'); ?></a>
                <a href="#tab-blocking" class="nav-tab"><?php esc_html_e('Blocking', 'webdecoy'); ?></a>
                <a href="#tab-forms" class="nav-tab"><?php esc_html_e('Forms', 'webdecoy'); ?></a>
                <a href="#tab-scanner" class="nav-tab"><?php esc_html_e('Scanner', 'webdecoy'); ?></a>
                <?php if (class_exists('WooCommerce')) : ?>
                    <a href="#tab-woocommerce" class="nav-tab"><?php esc_html_e('WooCommerce', 'webdecoy'); ?></a>
                <?php endif; ?>
                <a href="#tab-cloud" class="nav-tab"><?php esc_html_e('WebDecoy Cloud', 'webdecoy'); ?></a>
            </nav>

            <!-- Detection/Protection Settings Tab -->
            <div id="tab-detection-tab" class="webdecoy-tab-content active">
                <h2><?php esc_html_e('Detection Settings', 'webdecoy'); ?></h2>

                <table class="form-table">
                    <tr>
                        <th scope="row"><?php esc_html_e('Enable Protection', 'webdecoy'); ?></th>
                        <td>
                            <label>
                                <input type="checkbox" name="webdecoy_options[enabled]" value="1"
                                       <?php checked(!empty($options['enabled'])); ?> />
                                <?php esc_html_e('Enable bot detection and protection', 'webdecoy'); ?>
                            </label>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row">
                            <label for="webdecoy_sensitivity"><?php esc_html_e('Sensitivity', 'webdecoy'); ?></label>
                        </th>
                        <td>
                            <select id="webdecoy_sensitivity" name="webdecoy_options[sensitivity]">
                                <option value="low" <?php selected($options['sensitivity'] ?? 'medium', 'low'); ?>>
                                    <?php esc_html_e('Low - Fewer false positives', 'webdecoy'); ?>
                                </option>
                                <option value="medium" <?php selected($options['sensitivity'] ?? 'medium', 'medium'); ?>>
                                    <?php esc_html_e('Medium - Balanced', 'webdecoy'); ?>
                                </option>
                                <option value="high" <?php selected($options['sensitivity'] ?? 'medium', 'high'); ?>>
                                    <?php esc_html_e('High - More aggressive', 'webdecoy'); ?>
                                </option>
                            </select>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row">
                            <label for="webdecoy_min_score"><?php esc_html_e('Minimum Score to Block', 'webdecoy'); ?></label>
                        </th>
                        <td>
                            <input type="number" id="webdecoy_min_score" name="webdecoy_options[min_score_to_block]"
                                   value="<?php echo esc_attr($options['min_score_to_block'] ?? 75); ?>"
                                   min="0" max="100" step="5" class="small-text" />
                            <p class="description"><?php esc_html_e('Threat score threshold (0-100). Default: 75', 'webdecoy'); ?></p>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><?php esc_html_e('Rate Limiting', 'webdecoy'); ?></th>
                        <td>
                            <label>
                                <input type="checkbox" name="webdecoy_options[rate_limit_enabled]" value="1"
                                       <?php checked(!empty($options['rate_limit_enabled'])); ?> />
                                <?php esc_html_e('Enable rate limiting', 'webdecoy'); ?>
                            </label>
                            <br><br>
                            <label>
                                <?php esc_html_e('Allow', 'webdecoy'); ?>
                                <input type="number" name="webdecoy_options[rate_limit_requests]"
                                       value="<?php echo esc_attr($options['rate_limit_requests'] ?? 60); ?>"
                                       min="1" max="1000" class="small-text" />
                                <?php esc_html_e('requests per', 'webdecoy'); ?>
                                <input type="number" name="webdecoy_options[rate_limit_window]"
                                       value="<?php echo esc_attr($options['rate_limit_window'] ?? 60); ?>"
                                       min="1" max="3600" class="small-text" />
                                <?php esc_html_e('seconds', 'webdecoy'); ?>
                            </label>
                        </td>
                    </tr>
                </table>
            </div>

            <!-- Good Bots Tab -->
            <div id="tab-bots-tab" class="webdecoy-tab-content">
                <h2><?php esc_html_e('Good Bot Handling', 'webdecoy'); ?></h2>
                <p class="description"><?php esc_html_e('Configure how known legitimate bots are handled.', 'webdecoy'); ?></p>

                <table class="form-table">
                    <tr>
                        <th scope="row"><?php esc_html_e('Search Engines', 'webdecoy'); ?></th>
                        <td>
                            <label>
                                <input type="checkbox" name="webdecoy_options[allow_search_engines]" value="1"
                                       <?php checked($options['allow_search_engines'] ?? true); ?> />
                                <?php esc_html_e('Allow search engine bots (Googlebot, Bingbot, etc.)', 'webdecoy'); ?>
                            </label>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><?php esc_html_e('Social Media', 'webdecoy'); ?></th>
                        <td>
                            <label>
                                <input type="checkbox" name="webdecoy_options[allow_social_bots]" value="1"
                                       <?php checked($options['allow_social_bots'] ?? true); ?> />
                                <?php esc_html_e('Allow social media bots (Facebook, Twitter, LinkedIn, etc.)', 'webdecoy'); ?>
                            </label>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><?php esc_html_e('AI Crawlers', 'webdecoy'); ?></th>
                        <td>
                            <label>
                                <input type="checkbox" name="webdecoy_options[block_ai_crawlers]" value="1"
                                       <?php checked(!empty($options['block_ai_crawlers'])); ?> />
                                <?php esc_html_e('Block AI crawlers (GPTBot, ClaudeBot, PerplexityBot, etc.)', 'webdecoy'); ?>
                            </label>
                            <p class="description"><?php esc_html_e('AI crawlers are allowed by default. Enable this to block them.', 'webdecoy'); ?></p>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row">
                            <label for="webdecoy_custom_allowlist"><?php esc_html_e('Custom Allowlist', 'webdecoy'); ?></label>
                        </th>
                        <td>
                            <textarea id="webdecoy_custom_allowlist" name="webdecoy_options[custom_allowlist]"
                                      rows="5" class="large-text code"><?php echo esc_textarea(implode("\n", $options['custom_allowlist'] ?? [])); ?></textarea>
                            <p class="description"><?php esc_html_e('One bot name per line. These bots will always be allowed.', 'webdecoy'); ?></p>
                        </td>
                    </tr>
                </table>
            </div>

            <!-- Blocking Tab -->
            <div id="tab-blocking-tab" class="webdecoy-tab-content">
                <h2><?php esc_html_e('Blocking Settings', 'webdecoy'); ?></h2>

                <table class="form-table">
                    <tr>
                        <th scope="row">
                            <label for="webdecoy_block_action"><?php esc_html_e('Block Action', 'webdecoy'); ?></label>
                        </th>
                        <td>
                            <select id="webdecoy_block_action" name="webdecoy_options[block_action]">
                                <option value="block" <?php selected($options['block_action'] ?? 'block', 'block'); ?>>
                                    <?php esc_html_e('Block immediately', 'webdecoy'); ?>
                                </option>
                                <option value="challenge" <?php selected($options['block_action'] ?? 'block', 'challenge'); ?>>
                                    <?php esc_html_e('Show challenge (CAPTCHA)', 'webdecoy'); ?>
                                </option>
                                <option value="log" <?php selected($options['block_action'] ?? 'block', 'log'); ?>>
                                    <?php esc_html_e('Log only (no blocking)', 'webdecoy'); ?>
                                </option>
                            </select>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row">
                            <label for="webdecoy_block_duration"><?php esc_html_e('Block Duration', 'webdecoy'); ?></label>
                        </th>
                        <td>
                            <input type="number" id="webdecoy_block_duration" name="webdecoy_options[block_duration]"
                                   value="<?php echo esc_attr($options['block_duration'] ?? 24); ?>"
                                   min="0" step="1" class="small-text" />
                            <?php esc_html_e('hours (0 = permanent)', 'webdecoy'); ?>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><?php esc_html_e('Block Page', 'webdecoy'); ?></th>
                        <td>
                            <label>
                                <input type="checkbox" name="webdecoy_options[show_block_page]" value="1"
                                       <?php checked($options['show_block_page'] ?? true); ?> />
                                <?php esc_html_e('Show custom block page', 'webdecoy'); ?>
                            </label>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row">
                            <label for="webdecoy_block_message"><?php esc_html_e('Block Message', 'webdecoy'); ?></label>
                        </th>
                        <td>
                            <textarea id="webdecoy_block_message" name="webdecoy_options[block_page_message]"
                                      rows="3" class="large-text"><?php echo esc_textarea($options['block_page_message'] ?? __('Access to this site has been restricted.', 'webdecoy')); ?></textarea>
                        </td>
                    </tr>
                </table>
            </div>

            <!-- Forms Tab -->
            <div id="tab-forms-tab" class="webdecoy-tab-content">
                <h2><?php esc_html_e('Form Protection', 'webdecoy'); ?></h2>

                <table class="form-table">
                    <tr>
                        <th scope="row"><?php esc_html_e('Comments', 'webdecoy'); ?></th>
                        <td>
                            <label>
                                <input type="checkbox" name="webdecoy_options[protect_comments]" value="1"
                                       <?php checked($options['protect_comments'] ?? true); ?> />
                                <?php esc_html_e('Protect comment forms from spam bots', 'webdecoy'); ?>
                            </label>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><?php esc_html_e('Login', 'webdecoy'); ?></th>
                        <td>
                            <label>
                                <input type="checkbox" name="webdecoy_options[protect_login]" value="1"
                                       <?php checked($options['protect_login'] ?? true); ?> />
                                <?php esc_html_e('Protect login form from brute force attacks', 'webdecoy'); ?>
                            </label>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><?php esc_html_e('Registration', 'webdecoy'); ?></th>
                        <td>
                            <label>
                                <input type="checkbox" name="webdecoy_options[protect_registration]" value="1"
                                       <?php checked($options['protect_registration'] ?? true); ?> />
                                <?php esc_html_e('Protect registration form from spam', 'webdecoy'); ?>
                            </label>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><?php esc_html_e('Honeypot Fields', 'webdecoy'); ?></th>
                        <td>
                            <label>
                                <input type="checkbox" name="webdecoy_options[inject_honeypot]" value="1"
                                       <?php checked($options['inject_honeypot'] ?? true); ?> />
                                <?php esc_html_e('Add invisible honeypot fields to forms', 'webdecoy'); ?>
                            </label>
                            <p class="description"><?php esc_html_e('Honeypot fields catch bots that auto-fill all form fields.', 'webdecoy'); ?></p>
                        </td>
                    </tr>
                </table>
            </div>

            <!-- Scanner Tab -->
            <div id="tab-scanner-tab" class="webdecoy-tab-content">
                <h2><?php esc_html_e('Client-Side Bot Scanner', 'webdecoy'); ?></h2>
                <p class="description"><?php esc_html_e('The bot scanner runs in visitors\' browsers to detect automation tools, headless browsers, and other bot indicators.', 'webdecoy'); ?></p>

                <table class="form-table">
                    <tr>
                        <th scope="row"><?php esc_html_e('Enable Scanner', 'webdecoy'); ?></th>
                        <td>
                            <label>
                                <input type="checkbox" name="webdecoy_options[scanner_enabled]" value="1"
                                       <?php checked($options['scanner_enabled'] ?? true); ?> />
                                <?php esc_html_e('Enable client-side bot scanner', 'webdecoy'); ?>
                            </label>
                            <p class="description"><?php esc_html_e('Adds JavaScript bot detection to your site.', 'webdecoy'); ?></p>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row">
                            <label for="webdecoy_scanner_min_score"><?php esc_html_e('Minimum Score to Report', 'webdecoy'); ?></label>
                        </th>
                        <td>
                            <input type="number" id="webdecoy_scanner_min_score" name="webdecoy_options[scanner_min_score]"
                                   value="<?php echo esc_attr($options['scanner_min_score'] ?? 20); ?>"
                                   min="0" max="100" step="5" class="small-text" />
                            <p class="description"><?php esc_html_e('Only report detections with scores above this threshold. Default: 20 (filters out legitimate traffic).', 'webdecoy'); ?></p>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><?php esc_html_e('Exclude Logged-In Users', 'webdecoy'); ?></th>
                        <td>
                            <label>
                                <input type="checkbox" name="webdecoy_options[scanner_exclude_logged_in]" value="1"
                                       <?php checked(!empty($options['scanner_exclude_logged_in'])); ?> />
                                <?php esc_html_e('Don\'t run scanner for logged-in users', 'webdecoy'); ?>
                            </label>
                            <p class="description"><?php esc_html_e('Skip scanning for authenticated users to improve performance.', 'webdecoy'); ?></p>
                        </td>
                    </tr>
                </table>

                <h3><?php esc_html_e('Detection Techniques', 'webdecoy'); ?></h3>
                <p class="description"><?php esc_html_e('The scanner detects bots using multiple methods:', 'webdecoy'); ?></p>
                <ul class="ul-disc">
                    <li><?php esc_html_e('WebDriver detection (Selenium, Puppeteer, Playwright)', 'webdecoy'); ?></li>
                    <li><?php esc_html_e('Headless browser detection', 'webdecoy'); ?></li>
                    <li><?php esc_html_e('Chrome object inconsistency checks (catches stealth plugins)', 'webdecoy'); ?></li>
                    <li><?php esc_html_e('Permission API inconsistencies', 'webdecoy'); ?></li>
                    <li><?php esc_html_e('iframe anomaly detection', 'webdecoy'); ?></li>
                    <li><?php esc_html_e('API timing analysis', 'webdecoy'); ?></li>
                    <li><?php esc_html_e('Browser fingerprinting', 'webdecoy'); ?></li>
                    <li><?php esc_html_e('Honeypot field monitoring', 'webdecoy'); ?></li>
                    <li><?php esc_html_e('Known AI/ML crawler detection (GPTBot, ClaudeBot, etc.)', 'webdecoy'); ?></li>
                </ul>
            </div>

            <?php if (class_exists('WooCommerce')) : ?>
            <!-- WooCommerce Tab -->
            <div id="tab-woocommerce-tab" class="webdecoy-tab-content">
                <h2><?php esc_html_e('WooCommerce Protection', 'webdecoy'); ?></h2>
                <p class="description"><?php esc_html_e('Protect your WooCommerce checkout from carding attacks and fraud.', 'webdecoy'); ?></p>

                <table class="form-table">
                    <tr>
                        <th scope="row"><?php esc_html_e('Checkout Protection', 'webdecoy'); ?></th>
                        <td>
                            <label>
                                <input type="checkbox" name="webdecoy_options[protect_checkout]" value="1"
                                       <?php checked($options['protect_checkout'] ?? true); ?> />
                                <?php esc_html_e('Enable checkout protection', 'webdecoy'); ?>
                            </label>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><?php esc_html_e('Velocity Limit', 'webdecoy'); ?></th>
                        <td>
                            <label>
                                <?php esc_html_e('Allow', 'webdecoy'); ?>
                                <input type="number" name="webdecoy_options[checkout_velocity_limit]"
                                       value="<?php echo esc_attr($options['checkout_velocity_limit'] ?? 5); ?>"
                                       min="1" max="100" class="small-text" />
                                <?php esc_html_e('checkout attempts per', 'webdecoy'); ?>
                                <select name="webdecoy_options[checkout_velocity_window]">
                                    <option value="1800" <?php selected($options['checkout_velocity_window'] ?? 3600, 1800); ?>>
                                        <?php esc_html_e('30 minutes', 'webdecoy'); ?>
                                    </option>
                                    <option value="3600" <?php selected($options['checkout_velocity_window'] ?? 3600, 3600); ?>>
                                        <?php esc_html_e('1 hour', 'webdecoy'); ?>
                                    </option>
                                    <option value="7200" <?php selected($options['checkout_velocity_window'] ?? 3600, 7200); ?>>
                                        <?php esc_html_e('2 hours', 'webdecoy'); ?>
                                    </option>
                                    <option value="86400" <?php selected($options['checkout_velocity_window'] ?? 3600, 86400); ?>>
                                        <?php esc_html_e('24 hours', 'webdecoy'); ?>
                                    </option>
                                </select>
                            </label>
                            <p class="description"><?php esc_html_e('Block IPs that exceed this number of checkout attempts.', 'webdecoy'); ?></p>
                        </td>
                    </tr>
                </table>

                <h3><?php esc_html_e('Card Testing Detection', 'webdecoy'); ?></h3>
                <p class="description"><?php esc_html_e('Automatically detects and blocks card testing attacks based on:', 'webdecoy'); ?></p>
                <ul class="ul-disc">
                    <li><?php esc_html_e('Multiple small amount transactions (< $5)', 'webdecoy'); ?></li>
                    <li><?php esc_html_e('Multiple declined transactions', 'webdecoy'); ?></li>
                    <li><?php esc_html_e('Multiple different cards from the same IP', 'webdecoy'); ?></li>
                    <li><?php esc_html_e('Rapid succession of checkout attempts', 'webdecoy'); ?></li>
                </ul>
            </div>
            <?php endif; ?>

            <!-- WebDecoy Cloud Tab -->
            <div id="tab-cloud-tab" class="webdecoy-tab-content">
                <h2><?php esc_html_e('WebDecoy Cloud', 'webdecoy'); ?></h2>
                <p class="description"><?php esc_html_e('Optionally connect to WebDecoy Cloud for threat intelligence, IP reputation data, and centralized monitoring across all your sites.', 'webdecoy'); ?></p>

                <table class="form-table">
                    <tr>
                        <th scope="row">
                            <label for="webdecoy_api_key"><?php esc_html_e('API Key', 'webdecoy'); ?></label>
                        </th>
                        <td>
                            <input type="password" id="webdecoy_api_key" name="webdecoy_options[api_key]"
                                   value="<?php echo esc_attr($options['api_key'] ?? ''); ?>"
                                   class="regular-text" autocomplete="off" />
                            <button type="button" class="button button-secondary webdecoy-toggle-visibility">
                                <?php esc_html_e('Show', 'webdecoy'); ?>
                            </button>
                            <p class="description"><?php esc_html_e('Your WebDecoy API key (starts with sk_live_)', 'webdecoy'); ?></p>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><?php esc_html_e('API Status', 'webdecoy'); ?></th>
                        <td>
                            <?php
                            $api_status = get_transient('webdecoy_api_status');
                            $last_check = get_option('webdecoy_api_last_check');
                            $last_error = get_option('webdecoy_api_last_error');
                            ?>
                            <?php if ($api_status === 'active') : ?>
                                <span class="webdecoy-status webdecoy-status-active">
                                    <span class="dashicons dashicons-yes-alt"></span>
                                    <?php esc_html_e('Active', 'webdecoy'); ?>
                                </span>
                            <?php elseif ($api_status === 'inactive') : ?>
                                <span class="webdecoy-status webdecoy-status-inactive">
                                    <span class="dashicons dashicons-warning"></span>
                                    <?php esc_html_e('Inactive', 'webdecoy'); ?>
                                </span>
                                <?php if ($last_error) : ?>
                                    <p class="description webdecoy-error-text">
                                        <?php echo esc_html($last_error); ?>
                                    </p>
                                <?php endif; ?>
                            <?php elseif ($api_status === 'error') : ?>
                                <span class="webdecoy-status webdecoy-status-error">
                                    <span class="dashicons dashicons-info"></span>
                                    <?php esc_html_e('Connection Error', 'webdecoy'); ?>
                                </span>
                            <?php else : ?>
                                <span class="webdecoy-status webdecoy-status-unknown">
                                    <span class="dashicons dashicons-minus"></span>
                                    <?php esc_html_e('Not checked yet', 'webdecoy'); ?>
                                </span>
                            <?php endif; ?>
                            <?php if ($last_check) : ?>
                                <p class="description">
                                    <?php printf(
                                        esc_html__('Last checked: %s', 'webdecoy'),
                                        esc_html(date_i18n(get_option('date_format') . ' ' . get_option('time_format'), strtotime($last_check)))
                                    ); ?>
                                </p>
                            <?php endif; ?>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><?php esc_html_e('Connection Test', 'webdecoy'); ?></th>
                        <td>
                            <button type="button" id="webdecoy-test-connection" class="button button-secondary">
                                <?php esc_html_e('Test Connection', 'webdecoy'); ?>
                            </button>
                            <span id="webdecoy-connection-status"></span>
                            <p class="description"><?php esc_html_e('Test your API credentials and refresh the status.', 'webdecoy'); ?></p>
                        </td>
                    </tr>
                </table>

                <?php if (empty($options['api_key'])) : ?>
                <div class="webdecoy-cloud-upsell">
                    <h3><?php esc_html_e('Upgrade to WebDecoy Cloud', 'webdecoy'); ?></h3>
                    <p><?php esc_html_e('Your plugin already provides powerful local protection. WebDecoy Cloud adds:', 'webdecoy'); ?></p>
                    <ul>
                        <li><?php esc_html_e('IP reputation data (AbuseIPDB integration)', 'webdecoy'); ?></li>
                        <li><?php esc_html_e('VPN, proxy, and Tor exit node detection', 'webdecoy'); ?></li>
                        <li><?php esc_html_e('Cross-site threat intelligence from all WebDecoy users', 'webdecoy'); ?></li>
                        <li><?php esc_html_e('Advanced cloud analytics with indefinite data retention', 'webdecoy'); ?></li>
                        <li><?php esc_html_e('Webhook and email alert automation', 'webdecoy'); ?></li>
                    </ul>
                    <p>
                        <a href="https://webdecoy.com/pricing" class="button button-primary" target="_blank" rel="noopener">
                            <?php esc_html_e('Explore Plans', 'webdecoy'); ?>
                        </a>
                        <a href="https://app.webdecoy.com/register" class="button button-secondary" target="_blank" rel="noopener">
                            <?php esc_html_e('Start Free Trial', 'webdecoy'); ?>
                        </a>
                    </p>
                </div>
                <?php endif; ?>
            </div>
        </div>

        <?php submit_button(); ?>
    </form>
</div>
